"""SQLite persistence, validated save transfer and read-only course progress snapshots.

The course module owns grading. Callers pass instance IDs and expected revisions;
this module owns storage transactions and assembles snapshots from stored records.
"""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from domain import Invalid, VERSION, validate, upgrade_snapshot
from course import CATALOG, scenario, assess

# Public storage/progress surface shared by local and classroom transports.
__all__ = ('MAX_BYTES', 'MAX_BUNDLE_BYTES', 'BUNDLE_FORMAT', 'strict_json', 'checked_single_save', 'bundle_bytes', 'checked_bundle', 'checked_release', 'bundle_report', 'onedrive_roots', 'Store', 'Conflict', 'exercise_progress', 'progress_record', 'ticket_overview')

MAX_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 16 * MAX_BYTES
BUNDLE_FORMAT = "nordlicht-instance/v1"


def strict_json(text):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise Invalid('Doppeltes JSON-Feld: '+key)
            result[key]=value
        return result
    def constant(value):raise Invalid('Ungültige JSON-Zahl: '+value)
    try:return json.loads(text,object_pairs_hook=pairs,parse_constant=constant)
    except Invalid:raise
    except (ValueError,UnicodeError,RecursionError) as e:raise Invalid('Ungültige JSON-Daten.') from e


def checked_single_save(parameters, legacy_compare=False):
    if set(parameters)=={'save_text'}:
        text=parameters['save_text']
        if type(text) is not str:raise Invalid('Einzelspielstand muss JSON-Text sein.')
        try:original=text.encode('utf-8')
        except UnicodeError as e:raise Invalid('Einzelspielstand enthält ungültigen Unicode-Text.') from e
        if len(original)>MAX_BYTES:raise Invalid('Einzelspielstand maximal 1 MiB.')
        data=strict_json(text)
    elif set(parameters)=={'save'} or legacy_compare and set(parameters)=={'state'}:
        data=parameters['save'] if 'save' in parameters else dict(format='nordlicht-save/v1',state=parameters['state'])
        try:original=json.dumps(data,ensure_ascii=False,allow_nan=False).encode('utf-8')
        except (ValueError,UnicodeError,RecursionError) as e:raise Invalid('Einzelspielstand enthält ungültige Texte oder Zahlen.') from e
        if len(original)>MAX_BYTES:raise Invalid('Einzelspielstand maximal 1 MiB.')
    else:raise Invalid('Genau ein Einzelspielstand wird erwartet.')
    if type(data) is not dict or set(data)!={'format','state'} or data['format']!='nordlicht-save/v1':raise Invalid('Unbekannte Einzelspielstandhülle; eine einzelne Übung im Format nordlicht-save/v1 wählen. Stand bleibt erhalten.')
    state=upgrade_snapshot(data['state'])
    if state['task'] not in CATALOG:raise Invalid('Aufgabe des Einzelspielstands unbekannt.')
    return data,state,original


def bundle_bytes(bundle):
    try:raw=json.dumps(bundle,ensure_ascii=False,allow_nan=False,indent=2).encode('utf-8')
    except (ValueError,UnicodeError,RecursionError) as e:raise Invalid('Spielstand enthält ungültige Texte oder Zahlen.') from e
    if len(raw)>MAX_BUNDLE_BYTES:raise Invalid('Gesamtspielstand maximal 16 MiB.')
    return raw


def checked_bundle(raw):
    bundle_bytes(raw)
    if type(raw) is not dict or set(raw)!={'format','active_task','exercises'} or raw['format']!=BUNDLE_FORMAT:
        raise Invalid('Unbekanntes Gesamtspielstandformat.')
    snapshots=raw['exercises'];active=raw['active_task']
    if type(snapshots) is not dict or not 1<=len(snapshots)<=len(CATALOG) or type(active) is not str or active not in snapshots:
        raise Invalid('Aktive Übung oder Übungssammlung ungültig.')
    upgraded={}
    for task,state in snapshots.items():
        if task not in CATALOG:raise Invalid('Unbekannte Übung im Gesamtspielstand.')
        state=upgrade_snapshot(state)
        if state['task']!=task:raise Invalid('Übungskennung und Spielstand passen nicht zusammen.')
        upgraded[task]=state
    result=dict(format=BUNDLE_FORMAT,active_task=active,exercises=upgraded)
    bundle_bytes(result)
    return result


def checked_release(parameters):
    if set(parameters)!={'file_text','name'} or type(parameters['name']) is not str or not 1<=len(parameters['name'].strip())<=80:raise Invalid('Vorbereitete Datei und Instanzname mit1–80 Zeichen erforderlich.')
    text=parameters['file_text']
    if type(text) is not str:raise Invalid('Vorbereitete Datei muss JSON-Text sein.')
    try:original=text.encode('utf-8');parameters['name'].encode('utf-8')
    except UnicodeError as e:raise Invalid('Vorbereitete Datei oder Name enthält ungültigen Unicode-Text.') from e
    if len(original)>MAX_BUNDLE_BYTES:raise Invalid('Vorbereiteter Gesamtspielstand maximal16MiB; Einzelspielstand maximal1MiB.')
    raw=strict_json(text)
    if type(raw) is dict and raw.get('format')=='nordlicht-save/v1':
        _,state,_=checked_single_save(dict(save_text=text))
        bundle=dict(format=BUNDLE_FORMAT,active_task=state['task'],exercises={state['task']:state})
        legacy=raw['state']['schema']!=VERSION
    else:
        bundle=checked_bundle(raw);legacy=any(state['schema']!=VERSION for state in raw['exercises'].values())
    return bundle,original,legacy,raw['format']


def bundle_report(bundle, ident, name, revision):
    snapshots={k:json.dumps(v,ensure_ascii=False) for k,v in bundle['exercises'].items()}
    return progress_record(ident,name,revision,snapshots[bundle['active_task']],snapshots,True)


def onedrive_roots():
    values=[os.environ.get(name,'') for name in ('OneDrive','OneDriveConsumer','OneDriveCommercial')]
    if os.name=='nt':
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\OneDrive\Accounts') as accounts:
                index=0
                while True:
                    try:name=winreg.EnumKey(accounts,index)
                    except OSError:break
                    index+=1
                    try:
                        with winreg.OpenKey(accounts,name) as account:values.append(winreg.QueryValueEx(account,'UserFolder')[0])
                    except OSError:continue
        except (ImportError,OSError):pass
    return list(dict.fromkeys(Path(os.path.expandvars(value)).expanduser().resolve() for value in values if type(value) is str and value.strip()))


class Store:
    def __init__(self, root):
        self.root=Path(root).resolve()
        if any(self.root.is_relative_to(folder) for folder in onedrive_roots()):raise Invalid('Aktive Serverdaten dürfen nicht in einem konfigurierten OneDrive-Synchronisationsordner liegen. Einen lokalen, nicht synchronisierten Datenordner wählen.')
        self.root.mkdir(parents=True,exist_ok=True)
        self.path=self.root/'sessions.sqlite3'; self.lock=threading.RLock()
        with self.connect() as db:
            db.executescript('CREATE TABLE IF NOT EXISTS instances(id TEXT PRIMARY KEY,name TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL); CREATE TABLE IF NOT EXISTS exercises(instance TEXT,task TEXT,state TEXT NOT NULL,PRIMARY KEY(instance,task));')
        self.upgrade_saved_states()
        self.ensure('solo','Einzelbetrieb')

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10)
        try:
            with db: yield db
        finally: db.close()

    def ensure(self, ident, name):
        with self.lock, self.connect() as db:
            db.execute('INSERT OR IGNORE INTO instances VALUES(?,?,0,?)',(ident,name,json.dumps(scenario('intro'),ensure_ascii=False)))

    def upgrade_saved_states(self):
        """Validate every migration first, retain a SQLite backup, then commit all records."""
        pending=[]
        with self.connect() as db:
            active=db.execute('SELECT id,revision,state FROM instances').fetchall()
            exercises=db.execute('SELECT instance,task,state FROM exercises').fetchall()
        for kind,rows in [('instances',active),('exercises',exercises)]:
            for first,second,encoded in rows:
                raw=json.loads(encoded)
                if type(raw) is not dict or raw.get('task') not in CATALOG:raise Invalid('Gespeicherte Aufgabe fehlt in der Kursdatei. Ursprüngliche Kursdatei wiederherstellen; Datenbank bleibt erhalten.')
                if kind=='exercises' and raw['task']!=second:raise Invalid('Gespeicherte Übungskennung passt nicht zum Stand; Original bleibt erhalten.')
                if type(raw) is not dict or raw.get('schema')!=VERSION:
                    upgraded=upgrade_snapshot(raw)
                    if upgraded['task'] not in CATALOG: raise Invalid('Aufgabe im alten Spielstand unbekannt. Datenbank bleibt unverändert.')
                    pending.append((kind,first,second,encoded,json.dumps(upgraded,ensure_ascii=False)))
        if not pending: return
        backup=self.root/f'before-schema-{VERSION}-{secrets.token_hex(6)}.sqlite3'
        with self.connect() as source:
            destination=sqlite3.connect(backup)
            try: source.backup(destination)
            finally: destination.close()
        with self.connect() as db:
            for kind,first,second,encoded,updated in pending:
                if kind=='instances':
                    cursor=db.execute('UPDATE instances SET revision=revision+1,state=? WHERE id=? AND revision=? AND state=?',(updated,first,second,encoded))
                else:
                    cursor=db.execute('UPDATE exercises SET state=? WHERE instance=? AND task=? AND state=?',(updated,first,second,encoded))
                if cursor.rowcount!=1: raise Conflict('Spielstand während Formatmigration geändert; alte Daten und Sicherung behalten. Server neu starten.')

    def get(self, ident):
        with self.connect() as db: row=db.execute('SELECT name,revision,state FROM instances WHERE id=?',(ident,)).fetchone()
        if not row: raise Invalid('Instanz nicht vorhanden.')
        return dict(id=ident,name=row[0],revision=row[1],state=json.loads(row[2]))

    def company(self, ident):
        """Active state and parked-ticket summaries come from the same read snapshot."""
        with self.lock, self.connect() as db:
            db.execute('BEGIN')
            row=db.execute('SELECT name,revision,state FROM instances WHERE id=?',(ident,)).fetchone()
            parked=db.execute('SELECT task,state FROM exercises WHERE instance=? ORDER BY task',(ident,)).fetchall()
        if not row:raise Invalid('Instanz nicht vorhanden.')
        progress=progress_record(ident,row[0],row[1],row[2],parked)
        return dict(id=ident,name=row[0],revision=row[1],state=json.loads(row[2]),tickets=ticket_overview(progress))

    def all(self):
        with self.connect() as db: rows=db.execute('SELECT id,name,revision,state FROM instances ORDER BY name').fetchall()
        return [dict(id=r[0],name=r[1],revision=r[2],state=json.loads(r[3])) for r in rows]

    def progress(self, ident=None, details=False):
        """Read active and parked exercises from one SQLite snapshot without writes."""
        with self.lock, self.connect() as db:
            db.execute('BEGIN')
            if ident is None:
                active=db.execute('SELECT id,name,revision,state FROM instances ORDER BY name,id').fetchall()
                saved=db.execute('SELECT instance,task,state FROM exercises ORDER BY instance,task').fetchall()
            else:
                active=db.execute('SELECT id,name,revision,state FROM instances WHERE id=?',(ident,)).fetchall()
                saved=db.execute('SELECT instance,task,state FROM exercises WHERE instance=? ORDER BY task',(ident,)).fetchall()
        if ident is not None and not active: raise Invalid('Instanz nicht vorhanden.')
        parked={}
        for instance,task,encoded in saved:parked.setdefault(instance,{})[task]=encoded
        return [progress_record(instance,name,revision,encoded,parked.get(instance,{}),details) for instance,name,revision,encoded in active]

    @staticmethod
    def read_bundle(db, ident):
        row=db.execute('SELECT revision,state FROM instances WHERE id=?',(ident,)).fetchone()
        if not row:raise Invalid('Instanz nicht vorhanden.')
        active=strict_json(row[1])
        snapshots={task:strict_json(encoded) for task,encoded in db.execute('SELECT task,state FROM exercises WHERE instance=? ORDER BY task',(ident,))}
        snapshots[active['task']]=active
        return row[0],checked_bundle(dict(format=BUNDLE_FORMAT,active_task=active['task'],exercises=snapshots))

    def bundle(self, ident):
        with self.lock,self.connect() as db:
            db.execute('BEGIN')
            return self.read_bundle(db,ident)[1]

    def write_bundle_backup(self, raw, prefix):
        path=self.root/(prefix+'-'+secrets.token_hex(12)+'.json')
        try:
            with path.open('xb') as out:
                out.write(raw);out.flush();os.fsync(out.fileno())
        except OSError as e:raise Invalid('Sicherung fehlgeschlagen; Import nicht übernommen.') from e
        return path.name

    def replace_bundle(self, ident, expected, bundle, original=None):
        # Validation and backup precede mutation; a failed SQL statement rolls it all back.
        bundle=checked_bundle(bundle)
        with self.lock,self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            revision,previous=self.read_bundle(db,ident)
            if expected!=revision:raise Conflict('Instanz inzwischen geändert; Import nicht übernommen.')
            backup=self.write_bundle_backup(bundle_bytes(previous),'before-bundle-import')
            if original is not None:self.write_bundle_backup(original,'before-bundle-schema')
            db.execute('UPDATE instances SET revision=revision+1,state=? WHERE id=? AND revision=?',
                       (json.dumps(bundle['exercises'][bundle['active_task']],ensure_ascii=False),ident,expected))
            db.execute('DELETE FROM exercises WHERE instance=?',(ident,))
            db.executemany('INSERT INTO exercises VALUES(?,?,?)',[(ident,task,json.dumps(state,ensure_ascii=False))
                           for task,state in bundle['exercises'].items() if task!=bundle['active_task']])
        return backup

    def save(self, ident, expected, state):
        validate(state)
        with self.connect() as db:
            cursor=db.execute('UPDATE instances SET revision=revision+1,state=? WHERE id=? AND revision=?',(json.dumps(state,ensure_ascii=False),ident,expected))
            if cursor.rowcount!=1: raise Conflict('Stand wurde in einem anderen Client geändert. Neu geladen; Änderung bitte erneut prüfen.')

    def switch(self, ident, old, task):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO exercises VALUES(?,?,?)',(ident,old['task'],json.dumps(old,ensure_ascii=False)))
            row=db.execute('SELECT state FROM exercises WHERE instance=? AND task=?',(ident,task)).fetchone()
        return json.loads(row[0]) if row else scenario(task)

    def create_bundle(self, ident, name, bundle, original=None):
        bundle=checked_bundle(bundle)
        with self.lock,self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM instances WHERE id=?',(ident,)).fetchone():raise Invalid('Neue Instanzkennung bereits belegt; bestehende Firma bleibt erhalten.')
            if original is not None:self.write_bundle_backup(original,'before-release-schema')
            db.execute('INSERT INTO instances VALUES(?,?,?,?)',(ident,name,0,json.dumps(bundle['exercises'][bundle['active_task']],ensure_ascii=False)))
            db.executemany('INSERT INTO exercises VALUES(?,?,?)',[(ident,task,json.dumps(state,ensure_ascii=False)) for task,state in bundle['exercises'].items() if task!=bundle['active_task']])

    def erase_progress(self, ident, expected):
        replacement=scenario('intro');validate(replacement)
        name='Einzelbetrieb' if ident=='solo' else 'Lerninstanz'
        with self.lock,self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT revision FROM instances WHERE id=?',(ident,)).fetchone()
            if row is None:raise Invalid('Instanz nicht vorhanden.')
            if row[0]!=expected:raise Conflict('Instanz inzwischen geändert; Lernfortschritt nicht gelöscht. Neu laden und Ziel erneut prüfen.')
            db.execute('UPDATE instances SET name=?,revision=revision+1,state=? WHERE id=? AND revision=?',(name,json.dumps(replacement,ensure_ascii=False),ident,expected))
            db.execute('DELETE FROM exercises WHERE instance=?',(ident,))

    def delete(self, ident):
        with self.connect() as db:
            db.execute('DELETE FROM exercises WHERE instance=?',(ident,)); db.execute('DELETE FROM instances WHERE id=?',(ident,))


class Conflict(Invalid): pass


def exercise_progress(task, encoded, active, details=False):
    """Reassess actual stored data; a historical green label is never sufficient."""
    base=dict(task=task,title=CATALOG.get(task,{}).get('title','Unbekannte Aufgabe'),active=active)
    try:
        state=validate(json.loads(encoded))
        if state['task']!=task or task not in CATALOG:raise Invalid('Aufgabenkennung passt nicht zum gespeicherten Stand.')
        assessment=assess(state)
        last=copy.deepcopy(state['completed'].get(task))
        current=last is not None and last['seq']==state['seq']
        confirmed=bool(task!='free' and assessment['passed'] and current and last['passed'])
        if task=='free':status='sandbox'
        elif last is not None and not current:status='stale'
        elif confirmed:status='passed'
        elif assessment['passed']:status='ready'
        elif last is None:status='unsubmitted'
        else:status='open'
        row=dict(base,status=status,pseudonym=state['name'],minute=state['minute'],sequence=state['seq'],
                 exercise_status=state['task_status'],learning=CATALOG[task]['learning'],
                 state_passed=assessment['passed'],confirmed_passed=confirmed,last_check=last,
                 last_check_current=current,checks_passed=sum(c['passed'] for c in assessment['checks']),
                 checks_total=len(assessment['checks']),hints_used=sum(h['task']==task for h in state['hints']),
                 diagnostic_count=len(state['diagnostics']),change_count=sum(e['kind']=='change' for e in state['events']),
                 cost=state['cost'],error=None)
        if details:
            row.update(assessment=assessment,notes=state['notes'],reply=state['replies'].get(task,''),hints=copy.deepcopy([h for h in state['hints'] if h['task']==task]),
                       diagnostics=copy.deepcopy(state['diagnostics']),events=copy.deepcopy(state['events']))
        return row
    except (Invalid,ValueError,TypeError,KeyError,IndexError):
        return dict(base,status='invalid',confirmed_passed=False,state_passed=False,error='Gespeicherter Stand ist nicht auswertbar. Originaldaten bleiben unverändert.')


def progress_record(ident, name, revision, active_encoded, parked, details=False):
    active_task=None
    try:
        decoded=json.loads(active_encoded)
        if isinstance(decoded,dict) and isinstance(decoded.get('task'),str):active_task=decoded['task']
    except (ValueError,TypeError):pass
    snapshots=dict(parked)
    if active_task is not None:snapshots[active_task]=active_encoded
    rows=[exercise_progress(task,encoded,task==active_task,details) for task,encoded in sorted(snapshots.items())]
    if active_task is None:rows.append(exercise_progress('invalid-active',active_encoded,True,details))
    graded=[r for r in rows if r['task']!='free']
    totals=dict(visited=len(graded),available=sum(k!='free' for k in CATALOG),
                passed=sum(r['confirmed_passed'] for r in graded),state_passed=sum(r['state_passed'] for r in graded),
                stale=sum(r['status']=='stale' for r in graded),invalid=sum(r['status']=='invalid' for r in rows),
                hints=sum(r.get('hints_used',0) for r in rows),diagnostics=sum(r.get('diagnostic_count',0) for r in rows),
                changes=sum(r.get('change_count',0) for r in rows))
    return dict(id=ident,name=name,revision=revision,active_task=active_task,
                pseudonyms=sorted({r['pseudonym'] for r in rows if 'pseudonym' in r}),totals=totals,exercises=rows)


def ticket_overview(progress):
    """No saved exercise is inferred from another snapshot's completion labels."""
    stored={r['task']:r for r in progress['exercises']};rows=[]
    for ident,task in CATALOG.items():
        if ident=='free':continue
        actual=stored.get(ident)
        rows.append(dict(id=ident,title=task['title'],sender=task['sender'],active=bool(actual and actual['active']),saved=actual is not None,
                         status=actual['status'] if actual else 'not_started',exercise_status=actual.get('exercise_status','unknown') if actual else 'not_started'))
    totals=dict(total=len(rows),passed=sum(r['status']=='passed' for r in rows),needs_attention=sum(r['saved'] and r['status']!='passed' for r in rows),not_started=sum(not r['saved'] for r in rows),paused=sum(r['exercise_status']=='paused' for r in rows))
    return dict(revision=progress['revision'],rows=rows,totals=totals)
