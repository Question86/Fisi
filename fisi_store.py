"""One transactional Fisi workspace for lab, inventory and journal, beside legacy state."""
from copy import deepcopy
import json
from domain import Invalid
from persistence import Conflict, checked_bundle
from fisi_lab import fresh_lab, validate_lab
from fisi_inventory import COLLECTION, checked_collection, synthetic_inventory


def initial_state():
    return {"lab": fresh_lab(), "inventory": synthetic_inventory(), "journal": ""}


def checked_state(state):
    if type(state) is not dict or set(state) != {"lab", "inventory", "journal"}:
        raise Invalid("Ungültiger Workspace-Zustand.")
    validate_lab(state["lab"])
    checked_collection(state["inventory"])
    if type(state["journal"]) is not str or len(state["journal"]) > 12000:
        raise Invalid("Journal maximal 12000 Zeichen.")
    return deepcopy(state)


class FisiWorkspaceStore:
    def __init__(self, legacy_store):
        self.legacy = legacy_store
        self.lock = legacy_store.lock
        with self.legacy.connect() as db:
            db.executescript('CREATE TABLE IF NOT EXISTS fisi_workspaces(id TEXT PRIMARY KEY, name TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL); CREATE TABLE IF NOT EXISTS fisi_join_codes(code_hash TEXT PRIMARY KEY, workspace TEXT NOT NULL);')

    def ensure(self, ident, name):
        with self.lock, self.legacy.connect() as db:
            db.execute('INSERT OR IGNORE INTO fisi_workspaces VALUES(?,?,0,?)', (ident, name, json.dumps(initial_state(), ensure_ascii=False)))

    @staticmethod
    def record(db, ident):
        row = db.execute('SELECT name,revision,state FROM fisi_workspaces WHERE id=?', (ident,)).fetchone()
        if not row:
            raise Invalid("Workspace nicht vorhanden.")
        return {"id": ident, "name": row[0], "revision": row[1], "state": checked_state(json.loads(row[2]))}

    def read(self, ident):
        with self.lock, self.legacy.connect() as db:
            db.execute('BEGIN')
            record = self.record(db, ident)
            old = db.execute('SELECT revision FROM instances WHERE id=?', (ident,)).fetchone()
            if not old:
                raise Invalid("Zugehörige Referenzinstanz fehlt.")
            record['legacy_revision'] = old[0]
            return record

    def update(self, ident, expected, mutate):
        if type(expected) is not int or expected < 0:
            raise Invalid("Eine gültige Workspace-Version ist erforderlich.")
        with self.lock, self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            record = self.record(db, ident)
            if record['revision'] != expected:
                raise Conflict("Workspace wurde inzwischen geändert. Neu laden; eigene Eingaben bleiben erhalten.")
            state = checked_state(mutate(deepcopy(record['state'])))
            cursor = db.execute('UPDATE fisi_workspaces SET state=?,revision=revision+1 WHERE id=? AND revision=?', (json.dumps(state, ensure_ascii=False, allow_nan=False), ident, expected))
            if cursor.rowcount != 1:
                raise Conflict("Workspace wurde inzwischen geändert.")
        return self.read(ident)

    def create_group(self, ident, name, code_hash):
        if type(name) is not str or not 1 <= len(name.strip()) <= 80:
            raise Invalid("Workspace-Name: 1 bis 80 Zeichen.")
        with self.lock, self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT COUNT(*) FROM fisi_workspaces').fetchone()[0] >= 100:
                raise Invalid("Maximal 100 Workspaces.")
            db.execute('INSERT INTO fisi_workspaces VALUES(?,?,0,?)', (ident, name.strip(), json.dumps(initial_state(), ensure_ascii=False)))
            db.execute('INSERT INTO fisi_join_codes VALUES(?,?)', (code_hash, ident))

    def find_code(self, code_hash):
        with self.legacy.connect() as db:
            row = db.execute('SELECT workspace FROM fisi_join_codes WHERE code_hash=?', (code_hash,)).fetchone()
            return row[0] if row else None

    def groups(self):
        with self.legacy.connect() as db:
            return [{"id": row[0], "name": row[1], "revision": row[2]} for row in db.execute('SELECT id,name,revision FROM fisi_workspaces ORDER BY name,id')]

    def export(self, ident):
        with self.lock, self.legacy.connect() as db:
            db.execute('BEGIN')
            record = self.record(db, ident)
            _, legacy = self.legacy.read_bundle(db, ident)
            return {"schema": "fisi-workspace/v1", "name": record['name'], "state": record['state'], "northlight": legacy}

    def restore(self, ident, expected, legacy_expected, bundle):
        if type(bundle) is not dict or set(bundle) != {"schema", "name", "state", "northlight"} or bundle['schema'] != 'fisi-workspace/v1':
            raise Invalid("Ungültiges Fisi-Workspace-Format.")
        if type(bundle['name']) is not str or not 1 <= len(bundle['name']) <= 80:
            raise Invalid("Ungültiger Workspace-Name.")
        state = checked_state(bundle['state'])
        legacy = checked_bundle(bundle['northlight'])
        if type(expected) is not int or type(legacy_expected) is not int:
            raise Invalid("Beide Versionsstände sind erforderlich.")
        with self.lock, self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self.record(db, ident)
            old_revision, old_bundle = self.legacy.read_bundle(db, ident)
            if current['revision'] != expected or old_revision != legacy_expected:
                raise Conflict("Fisi- oder Referenzstand wurde geändert. Import nicht übernommen.")
            backup = {"schema": "fisi-workspace/v1", "name": current['name'], "state": current['state'], "northlight": old_bundle}
            self.legacy.write_bundle_backup(json.dumps(backup, ensure_ascii=False).encode('utf-8'), 'before-fisi-import')
            db.execute('UPDATE fisi_workspaces SET state=?,revision=revision+1 WHERE id=? AND revision=?', (json.dumps(state, ensure_ascii=False), ident, expected))
            db.execute('UPDATE instances SET revision=revision+1,state=? WHERE id=? AND revision=?', (json.dumps(legacy['exercises'][legacy['active_task']], ensure_ascii=False), ident, old_revision))
            db.execute('DELETE FROM exercises WHERE instance=?', (ident,))
            db.executemany('INSERT INTO exercises VALUES(?,?,?)', [(ident, key, json.dumps(value, ensure_ascii=False)) for key, value in legacy['exercises'].items() if key != legacy['active_task']])
        return self.read(ident)
