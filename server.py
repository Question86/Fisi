"""Local HTTP teaching server with per-instance CAS, sessions and atomic SQLite saves."""
import argparse
from contextlib import contextmanager
import copy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import secrets
import sqlite3
import threading
import time
import webbrowser
from domain import restore_preview, fresh, BASE_TARIFFS, Invalid, VERSION, act, validate, upgrade_snapshot, view, event
from course import DEFAULT_COURSE_DATA, configure_course, CATALOG, scenario, catalog, assess, example_actions, resolve_parameters, probe_enabled
from ui import PAGE, client_script
# Preserve the existing server import surface while storage owns its implementation.
from persistence import (MAX_BYTES, MAX_BUNDLE_BYTES, BUNDLE_FORMAT, strict_json, checked_single_save, bundle_bytes, checked_bundle, checked_release, bundle_report, onedrive_roots, Store, Conflict, exercise_progress, progress_record, ticket_overview)

TRAINER_ACTIONS = {'example_preview','release_preview','release_instance','erase_progress','availability_event','fault','advance','task_status','reset','select_task','join_code','instances','progress_overview','delete_instance','compare','example','bundle_import','bundle_compare','ticket_answer'}


def example_walkthrough(parameters):
    if 'task' not in parameters or set(parameters)-{'task','variant','failure'} or type(parameters['task']) is not str or parameters['task'] not in CATALOG:raise Invalid('Bekannte Aufgabenkennung und optionale Beispielauswahl erwartet.')
    task=parameters['task'];row=CATALOG[task];variant=parameters.get('variant');failure=parameters.get('failure')
    if 'variant' in parameters and (type(variant) is not int or not 0<=variant<len(row['variants'])):raise Invalid('Ungültige Lösungsvariante.')
    if 'failure' in parameters and (type(failure) is not int or not 0<=failure<len(row['failures'])):raise Invalid('Ungültiges Gegenbeispiel.')
    if 'variant' in parameters and 'failure' in parameters:raise Invalid('Nur einen Lösungsweg oder Fehlversuch wählen.')
    item=row['variants'][variant] if variant is not None else row['failures'][failure] if failure is not None else None
    steps=item['actions'] if item else row['solution'];state=scenario(task);initial_minute=state['minute'];initial_cost=state['cost'];trace=[];stopped=False
    for number,raw in enumerate(steps,1):
        minute=state['minute'];step=copy.deepcopy(raw);action=step.pop('action');error='';stage='parameters'
        try:
            step=resolve_parameters(step,state);stage='action';state,_=act(state,action,**step)
        except Invalid as exc:error=str(exc);stopped=True
        trace.append(dict(number=number,action=action,parameters=step,parameters_resolved=stage=='action',error_stage=stage if error else '',before_minute=minute,after_minute=state['minute'],error=error))
        if stopped:break
    probes=[]
    for probe in row['probes']:
        if probe_enabled(probe,state):
            state,result=act(state,'diagnose',test=probe['test'],args=probe['args']);probes.append(dict(test=probe['test'],args=probe['args'],result=result,minute=state['minute'],seq=state['seq']))
    reply='Beispielbegründung: Diagnose, begrenzte Änderung, erlaubte und verweigerte Zugriffe geprüft. Fachliche Diskussion durch die Lehrkraft.'
    if task!='free':state,_=act(state,'reply',text=reply)
    else:reply=''
    return dict(kind='example_preview',graded=task!='free',task=task,title=row['title'],label=item['label'] if item else 'Referenzlösung',rationale=item['rationale'] if item else row['explanation'],counterexample=failure is not None,steps=trace,stopped=stopped,diagnostics=probes,assessment=assess(state),example_reply=reply,initial_minute=initial_minute,final_minute=state['minute'],initial_cost=initial_cost,final_cost=state['cost'],sequence=state['seq'])


class Application:
    def __init__(self, root):
        self.store=Store(root); self.lock=threading.RLock(); self.sessions={}; self.codes={}
        self.trainer_code=secrets.token_urlsafe(18)
        self.codes[self.hash_code(self.trainer_code)]=dict(role='trainer',instance='solo')

    @staticmethod
    def hash_code(code): return hashlib.sha256(code.encode()).hexdigest()

    def login(self, code, name):
        with self.lock:
            match=self.codes.get(self.hash_code(code))
            if not match: raise PermissionError('Sitzungscode ungültig. Trainer nach dem Code fragen.')
            token=secrets.token_urlsafe(32); self.sessions[token]=dict(match,expires=time.monotonic()+43200,name=str(name)[:80])
            return dict(token=token,role=match['role'],instance=match['instance'])

    def session(self, token):
        s=self.sessions.get(token)
        if not s or time.monotonic()>s['expires']: raise PermissionError('Sitzung abgelaufen. Erneut anmelden.')
        return s

    def get(self, session, instance=None):
        if session.get('revoked'):raise PermissionError('Sitzung nach Löschung des Lernfortschritts gesperrt. Neu freigeben lassen.')
        ident=instance or session['instance']
        if session['role']!='trainer' and ident!=session['instance']: raise PermissionError('Fremde Instanz gesperrt.')
        return self.store.get(ident)

    def response(self, session, ident=None):
        ident=ident or session['instance']
        if session['role']!='trainer' and ident!=session['instance']:raise PermissionError('Fremde Instanz gesperrt.')
        with self.lock,self.store.lock:
            if session.get('revoked'):raise PermissionError('Sitzung nach Löschung des Lernfortschritts gesperrt. Neu freigeben lassen.')
            record=self.store.company(ident);s=record['state'];record['state']=view(s)
            record['assessment']=assess(s);record['catalog']=catalog(session['role']=='trainer');record['role']=session['role']
            record['trainer_local_warning']='Lokale Spielstände sind keine manipulationssicheren Prüfungsnachweise.'
            return record

    def dispatch(self, session, payload):
        if set(payload)-{'instance','revision','action','parameters'}: raise Invalid('Unzulässige Anforderungsfelder.')
        action=payload['action']; p=payload.get('parameters',{}); ident=payload.get('instance',session['instance'])
        if not isinstance(p,dict): raise Invalid('Parameter müssen ein Objekt sein.')
        if action in TRAINER_ACTIONS and session['role']!='trainer': raise PermissionError('Traineraktion serverseitig gesperrt.')
        with self.lock, self.store.lock:
            record=self.get(session,ident)
            if payload.get('revision')!=record['revision']: raise Conflict('Versionskonflikt: Stand inzwischen geändert. Neu laden und Änderung erneut prüfen.')
            s=record['state']; result=None
            if action=='configure' and session['role']!='trainer' and type(p.get('id')) is str and s['resources'].get(p['id'],{}).get('kind')=='Storage' and type(p.get('changes')) is dict and 'status' in p['changes']:raise PermissionError('Modellierte Storage-Verfügbarkeit ist eine Traineraktion. Speicherparameter bleiben separat bearbeitbar.')
            if action=='restore_preview':
                if not {'area','point'}<=set(p) or set(p)-{'area','point','scope','id','target','actor','outage_minute','rpo_limit','rto_limit'}:raise Invalid('Vorschaufelder fehlen oder sind unbekannt.')
                result=restore_preview(s,**p)
                if s['task_status']=='paused' and session['role']!='trainer':
                    result.update(can_start=False,blocked_reason='Aufgabe durch Trainer pausiert; Vorschau bleibt lesbar.',expected_finish_minute=None,projected_recovery_minutes=None,projected_rto_within_limit=None)
                result.update(instance=ident,revision=record['revision'])
                return dict(result=result,record=self.response(session,ident))
            if action=='bundle_export':
                if p:raise Invalid('Gesamtexport erwartet keine Parameter.')
                return dict(result=self.store.bundle(ident),record=self.response(session,ident))
            if action in ('bundle_import','bundle_compare'):
                if set(p)=={'bundle_text'}:
                    text=p['bundle_text']
                    if type(text) is not str:raise Invalid('Gesamtspielstand muss JSON-Text sein.')
                    try:original=text.encode('utf-8')
                    except UnicodeError as e:raise Invalid('Ungültiger Unicode-Text.') from e
                    if len(original)>MAX_BUNDLE_BYTES:raise Invalid('Gesamtspielstand maximal 16 MiB.')
                    raw=strict_json(text)
                elif set(p)=={'bundle'}:
                    raw=p['bundle'];original=bundle_bytes(raw)
                else:raise Invalid('Genau ein Gesamtspielstand wird erwartet.')
                incoming=checked_bundle(raw)
                if action=='bundle_compare':
                    result=dict(kind='bundle_comparison',
                                incoming=bundle_report(incoming,'import','Eingelesener Gesamtspielstand',None),
                                current=bundle_report(self.store.bundle(ident),ident,record['name'],record['revision']))
                else:
                    migrated=any(v['schema']!=VERSION for v in raw['exercises'].values())
                    backup=self.store.replace_bundle(ident,record['revision'],incoming,original if migrated else None)
                    result=dict(message='Alle Übungen der gewählten Instanz ersetzt.',exercises=len(incoming['exercises']),backup=backup)
                return dict(result=result,record=self.response(session,ident))
            if action in ('release_preview','release_instance'):
                incoming,original,legacy,source_format=checked_release(p);name=p['name'].strip()
                if action=='release_preview':
                    result=dict(kind='release_preview',name=name,source_format=source_format,legacy=legacy,report=bundle_report(incoming,'file',name,None))
                else:
                    target=secrets.token_hex(16)
                    self.store.create_bundle(target,name,incoming,original if legacy else None)
                    code=secrets.token_urlsafe(12);self.codes[self.hash_code(code)]=dict(role='learner',instance=target)
                    result=dict(kind='instance_release',instance=target,name=name,code=code,exercises=len(incoming['exercises']),active_task=incoming['active_task'])
                return dict(result=result,record=self.response(session,ident))
            if action=='join_code':
                group=str(p.get('group','')).strip()
                target=group if p.get('shared') and group else secrets.token_hex(8)
                if target=='solo' or not target.replace('-','').replace('_','').isalnum() or len(target)>60: raise Invalid('Gruppenkennung: nur Buchstaben, Ziffern, - und _.')
                self.store.ensure(target,str(p.get('name','Teilnehmer'))[:80])
                code=secrets.token_urlsafe(12); self.codes[self.hash_code(code)]=dict(role='learner',instance=target)
                return dict(result=dict(code=code,instance=target),record=self.response(session,ident))
            if action in ('instances','progress_overview'):
                if p:raise Invalid('Die Gesamtübersicht erwartet keine zusätzlichen Parameter.')
                return dict(result=dict(kind='progress_overview',instances=self.store.progress()),record=self.response(session,ident))
            if action in ('progress_detail','progress_export'):
                if set(p)-{'target','output'} or p.get('output','html') not in ('html','json'):raise Invalid('Unzulässige Berichtsparameter.')
                target=p.get('target',ident)
                if type(target) is not str:raise Invalid('Instanzkennung muss Text sein.')
                if session['role']!='trainer' and target!=session['instance']:raise PermissionError('Fremde Instanz gesperrt.')
                result=self.store.progress(target,details=True)[0]
                result.update(kind='progress_detail',format='nordlicht-progress/v1',
                              notice='Aktueller Zustand und frühere Abgabe werden getrennt dargestellt. Freitext bewertet die Lehrkraft. Lokale Stände sind keine manipulationssicheren Prüfungsnachweise.')
                return dict(result=result,record=self.response(session,ident))
            if action=='erase_progress':
                if set(p)!={'confirm'} or p['confirm'] is not True:raise Invalid('Alle Lernstände der gewählten Instanz ausdrücklich bestätigen; andere Parameter sind nicht zulässig.')
                self.store.erase_progress(ident,record['revision'])
                for value in self.sessions.values():
                    if value['instance']==ident:
                        value['name']='Lehrkraft' if value['role']=='trainer' else 'Lernende Person'
                        if value['role']=='learner':value['revoked']=True
                self.sessions={key:value for key,value in self.sessions.items() if value['instance']!=ident or value['role']=='trainer'}
                self.codes={key:value for key,value in self.codes.items() if value['instance']!=ident or value['role']=='trainer'}
                return dict(result='Lernfortschritt und Pseudonyme dieser Instanz geleert. Nur der frische Einstieg bleibt; bisherige Teilnehmercodes und -sitzungen sind gesperrt. Frühere Exporte, technische Sicherungen und fremde Browserkopien bleiben gesondert.',record=self.response(session,ident))
            if action=='delete_instance':
                if p['id']=='solo': raise Invalid('Solo-Instanz bitte zurücksetzen.')
                self.store.delete(p['id'])
                self.sessions={k:v for k,v in self.sessions.items() if v['instance']!=p['id']}
                self.codes={k:v for k,v in self.codes.items() if v['instance']!=p['id']}
                return dict(result='Instanz, Übungsstände und Sitzungsberechtigungen gelöscht.',record=self.response(session,'solo'))
            if action=='compare':
                _,other,_=checked_single_save(p,legacy_compare=True)
                current=bundle_report(dict(format=BUNDLE_FORMAT,active_task=s['task'],exercises={s['task']:s}),ident,record['name'],record['revision'])
                incoming=bundle_report(dict(format=BUNDLE_FORMAT,active_task=other['task'],exercises={other['task']:other}),'file',other['name'],None)
                result=dict(kind='save_comparison',current=current,incoming=incoming,
                            name=other['name'],task=other['task'],assessment=assess(other),cost=other['cost'],events=other['events'][-20:])
                return dict(result=result,record=self.response(session,ident))
            if action=='export':
                return dict(result=dict(format='nordlicht-save/v1',state=s),record=self.response(session,ident))
            if action=='summary':
                if p:raise Invalid('Die eigene Zusammenfassung erwartet keine zusätzlichen Parameter.')
                result=self.store.progress(ident,details=True)[0]
                result.update(kind='progress_detail',format='nordlicht-progress/v1',notice='Alle vorhandenen Übungen dieser Instanz. Freitext wird von der Lehrkraft besprochen; lokale Stände sind keine manipulationssicheren Prüfungsnachweise.')
                return dict(result=result,record=self.response(session,ident))
            if action=='import':
                if session['role']!='trainer': raise PermissionError('Import ist im gemeinsamen Modus eine Traineraktion.')
                data,new,original_bytes=checked_single_save(p)
                if data['state']['schema']!=VERSION:
                    original=self.store.root/f'before-schema-{VERSION}-import-{secrets.token_hex(6)}.json'
                    original.write_bytes(original_bytes)
                # Keep a restorable copy before replacing even a valid save.
                backup=self.store.root/f"before-import-{secrets.token_hex(6)}.json"
                backup.write_text(json.dumps(dict(format='nordlicht-save/v1',state=s),ensure_ascii=False),encoding='utf-8')
                s=new
            elif action=='select_task':
                if p['id'] not in CATALOG: raise Invalid('Aufgabe unbekannt.')
                s=self.store.switch(ident,s,p['id'])
            elif action=='reset':
                s=scenario(s['task'])
                if p.get('erase_name'): s['name']='Lernende Person'
            elif action=='task_status':
                if p['status'] not in ('active','paused'): raise Invalid('Ungültiger Aufgabenstatus.')
                s=copy.deepcopy(s); s['task_status']=p['status']
            elif action in ('ticket_ask','ticket_answer'):
                if s['task_status']=='paused' and session['role']!='trainer':raise PermissionError('Aufgabe durch Trainer pausiert.')
                row=CATALOG[s['task']]
                if action=='ticket_ask':
                    if set(p) not in ({'topic'},{'text'}):raise Invalid('Genau eine vorbereitete oder freie Rückfrage wählen.')
                    topic=None
                    if 'topic' in p:
                        topic=next((item for item in row['clarifications'] if item['id']==p['topic']),None)
                        if topic is None:raise Invalid('Rückfrage gehört nicht zu diesem Auftrag.')
                    text=topic['question'] if topic else p['text']
                    if type(text) is not str or not text.strip() or len(text)>2000:raise Invalid('Rückfrage benötigt 1–2000 Zeichen.')
                    s=copy.deepcopy(s);question=secrets.token_hex(16)
                    event(s,'ticket_message','Rückfrage: '+text,detail=dict(id=question,task=s['task'],direction='question',author=session['name'],text=text,reply_to=''))
                    if topic:event(s,'ticket_message','Antwort aus dem Auftrag: '+topic['answer'],detail=dict(id=secrets.token_hex(16),task=s['task'],direction='answer',author=row['sender'],text=topic['answer'],reply_to=question))
                    result='Vorbereitete Antwort im Ticket gespeichert.' if topic else 'Freie Rückfrage gespeichert. Die Lehrkraft kann darauf antworten; es wird keine automatische Antwort erfunden.'
                else:
                    if set(p)!={'question','text'} or type(p['question']) is not str or type(p['text']) is not str or not p['text'].strip() or len(p['text'])>5000:raise Invalid('Bestehende Frage und Antwort mit 1–5000 Zeichen erforderlich.')
                    messages=[item['detail'] for item in s['events'] if item['kind']=='ticket_message' and 'detail' in item and item['detail']['task']==s['task']]
                    if not any(item['direction']=='question' and item['id']==p['question'] for item in messages) or any(item['reply_to']==p['question'] for item in messages):raise Invalid('Frage nicht vorhanden oder bereits beantwortet.')
                    s=copy.deepcopy(s);event(s,'ticket_message','Antwort der Lehrkraft: '+p['text'],detail=dict(id=secrets.token_hex(16),task=s['task'],direction='answer',author='Lehrkraft für '+row['sender'],text=p['text'],reply_to=p['question']));result='Antwort im Ticket gespeichert.'
            elif action=='hint':
                level=p['level']
                if type(level) is not int or not 0<=level<3: raise Invalid('Hilfestufe ungültig.')
                s=copy.deepcopy(s); s['hints'].append(dict(task=s['task'],level=level+1,minute=s['minute']))
                result=CATALOG[s['task']]['hints'][level]
            elif action=='check':
                s=copy.deepcopy(s); result=assess(s)
                s['completed'][s['task']]=dict(passed=result['passed'],minute=s['minute'],seq=s['seq'])
                event(s,'assessment','Zustandsprüfung bestanden.' if result['passed'] else 'Zustandsprüfung noch offen.',detail={key:copy.deepcopy(result[key]) for key in ('passed','checks','explanation')})
            elif action=='example_preview':
                return dict(result=example_walkthrough(p),record=self.response(session,ident))
            elif action=='example':
                if set(p)-{'variant','failure'}:raise Invalid('Unbekannte Beispielparameter.')
                return dict(result=example_actions(s['task'],s,**p),record=self.response(session,ident))
            else:
                if s['task_status']=='paused' and session['role']!='trainer': raise PermissionError('Aufgabe durch Trainer pausiert.')
                s,result=act(s,action,**p)
            self.store.save(ident,record['revision'],s)
            return dict(result=result,record=self.response(session,ident))


class Handler(BaseHTTPRequestHandler):
    server_version='Nordlicht/1'
    def log_message(self,*args): pass

    @property
    def app(self): return self.server.application

    def respond(self, status, data, html=False, content_type=None):
        raw=data.encode('utf-8') if html or content_type else json.dumps(data,ensure_ascii=False,allow_nan=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type',content_type or ('text/html; charset=utf-8' if html else 'application/json; charset=utf-8'))
        self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers(); self.wfile.write(raw)

    def authenticated(self):
        value=self.headers.get('Authorization','')
        return self.app.session(value.removeprefix('Bearer '))

    def valid_host(self):
        # Only the browser's current host may issue requests; JSON + bearer auth prevent form CSRF.
        host=self.headers.get('Host','')
        allowed=self.server.allowed_hosts
        hostname=host.rsplit(':',1)[0].lower()
        if hostname not in allowed: raise PermissionError('Host nicht freigegeben (DNS-Rebinding-Schutz).')
        origin=self.headers.get('Origin')
        if origin and origin not in ('http://'+host,'https://'+host): raise PermissionError('Fremder Origin gesperrt.')

    def do_GET(self):
        try:
            self.valid_host()
            path=urlsplit(self.path).path
            if self.path=='/': self.respond(200,self.app.homepage() if hasattr(self.app,'homepage') else PAGE,True)
            elif self.path=='/reference/': self.respond(200,PAGE,True)
            elif self.path=='/static/client.js':
                self.respond(200,client_script(),content_type='text/javascript; charset=utf-8')
            elif self.path in ('/static/fisi.js','/static/fisi-style.js','/static/fisi.css') and hasattr(self.app,'asset'):
                asset=self.app.asset(self.path)
                if asset is None:self.respond(404,dict(error='Nicht gefunden.'))
                else:self.respond(200,asset,content_type='text/css; charset=utf-8' if self.path=='/static/fisi.css' else 'text/javascript; charset=utf-8')
            elif path in ('/api/fisi/state','/api/fisi/export') and hasattr(self.app,'fisi_response'):
                params=parse_qs(urlsplit(self.path).query,keep_blank_values=True,max_num_fields=8)
                if set(params)-{'instance'} or any(len(values)!=1 for values in params.values()):raise Invalid('Genau eine optionale Workspace-Kennung erwartet.')
                session=self.authenticated();ident=params.get('instance',[None])[0]
                self.respond(200,self.app.fisi_export(session,ident) if path=='/api/fisi/export' else self.app.fisi_response(session,ident))
            elif self.path.startswith('/api/state'):
                params=parse_qs(urlsplit(self.path).query)
                self.respond(200,self.app.response(self.authenticated(),params.get('instance',[None])[0]))
            else: self.respond(404,dict(error='Nicht gefunden.'))
        except PermissionError as e: self.respond(403,dict(error=str(e)))
        except (Invalid,ValueError,KeyError,TypeError) as e: self.respond(400,dict(error=str(e)))
        except Exception:
            self.server.error_logger.exception('Unhandled HTTP GET failure')
            self.respond(500,dict(error='Interner Fehler. Der gespeicherte Stand bleibt erhalten. Details stehen in server-errors.log im Datenordner.'))

    def do_POST(self):
        try:
            self.valid_host()
            if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise Invalid('JSON erwartet.')
            if self.path in ('/api/fisi/bootstrap','/api/fisi/action') and hasattr(self.app,'fisi_action'):
                bootstrap=self.path=='/api/fisi/bootstrap'
                if bootstrap:
                    if self.server.server_address[0] not in ('127.0.0.1','::1') or not self.app.local_solo:raise PermissionError('Solo-Einstieg ist im gemeinsamen Serverbetrieb gesperrt.')
                    session=None
                else:
                    session=self.authenticated()
                length=int(self.headers.get('Content-Length','0'))
                limit=1024 if bootstrap else 40*1024*1024
                if not 2<=length<=limit:
                    self.respond(413,dict(error='Fisi-Anfrage außerhalb der erlaubten Größe. Stand bleibt erhalten.'))
                    return
                data=strict_json(self.rfile.read(length))
                if bootstrap and data!={}:raise Invalid('Der lokale Einstieg erwartet ein leeres Objekt.')
                self.respond(200,self.app.solo_login() if bootstrap else self.app.fisi_action(session,data))
                return
            bundle_route=self.path=='/api/bundle'
            single_route=self.path=='/api/save'
            session=None
            if bundle_route or single_route:
                session=self.authenticated()
                if session['role']!='trainer':raise PermissionError('Spielstandimport und Vergleich sind Traineraktionen.')
            limit=2*MAX_BUNDLE_BYTES+4096 if bundle_route else 2*MAX_BYTES+4096 if single_route else MAX_BYTES
            length=int(self.headers.get('Content-Length','0'))
            if length>limit:
                # Drain only a bounded, slightly oversize body so Windows can deliver the
                # error response rather than resetting a socket with unread request data.
                if length<=limit+4096:
                    self.connection.settimeout(5)
                    try:self.rfile.read(length)
                    except OSError:pass
                self.respond(413,dict(error='Anfrage zu groß. Aktive Übung maximal 1 MiB, Gesamtspielstand maximal 16 MiB. Stand bleibt erhalten.'))
                return
            if length<2: raise Invalid('Import/Anfrage enthält keine gültigen JSON-Daten.')
            data=strict_json(self.rfile.read(length))
            if not isinstance(data,dict): raise Invalid('Objekt erwartet.')
            if self.path=='/api/login':
                self.respond(200,self.app.login(str(data.get('code','')),data.get('name','Lernende Person')))
            elif bundle_route:
                if data.get('action') not in ('bundle_import','bundle_compare','release_preview','release_instance'):raise Invalid('Unzulässige Gesamtspielstandaktion.')
                self.respond(200,self.app.dispatch(session,data))
            elif single_route:
                if data.get('action') not in ('import','compare'):raise Invalid('Unzulässige Einzelspielstandaktion.')
                self.respond(200,self.app.dispatch(session,data))
            elif self.path=='/api/action': self.respond(200,self.app.dispatch(self.authenticated(),data))
            else: self.respond(404,dict(error='Nicht gefunden.'))
        except Conflict as e: self.respond(409,dict(error=str(e)))
        except PermissionError as e: self.respond(403,dict(error=str(e)))
        except (Invalid,ValueError,KeyError,TypeError,StopIteration,OverflowError) as e: self.respond(400,dict(error='Aktion nicht übernommen: '+str(e)))
        except Exception:
            self.server.error_logger.exception('Unhandled HTTP POST failure')
            self.respond(500,dict(error='Interner Fehler. Letzter gespeicherter Stand bleibt erhalten. Details stehen in server-errors.log im Datenordner.'))


class TeachingHTTPServer(ThreadingHTTPServer):
    def server_close(self):
        super().server_close()
        logger=getattr(self,'error_logger',None)
        if logger:
            for handler in list(logger.handlers):
                handler.close();logger.removeHandler(handler)


def make_server(app, host='127.0.0.1', port=8765, allowed_hosts=()):
    server=TeachingHTTPServer((host,port),Handler); server.application=app
    server.error_logger=logging.getLogger('fisi.server.'+str(id(server)))
    server.error_logger.setLevel(logging.ERROR);server.error_logger.propagate=False
    handler=logging.FileHandler(app.store.root/'server-errors.log',encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    server.error_logger.addHandler(handler)
    server.allowed_hosts={'localhost','127.0.0.1',host.lower()} | {x.lower() for x in allowed_hosts}
    return server


def load_teaching_data(course_path=None,tariff_path=None):
    def read(path,default):
        if path is None:return copy.deepcopy(default)
        try:
            with Path(path).open('rb') as source:raw=source.read(2*MAX_BYTES+1)
        except OSError as error:raise Invalid('Datendatei nicht lesbar: '+str(path)) from error
        if len(raw)>2*MAX_BYTES:raise Invalid('Kurs-/Tarifdatei maximal 2 MiB.')
        try:return strict_json(raw.decode('utf-8-sig'))
        except UnicodeError as error:raise Invalid('Kurs-/Tarifdatei muss UTF-8 sein.') from error
    configure_course(read(course_path,DEFAULT_COURSE_DATA),read(tariff_path,BASE_TARIFFS))


def main():
    parser=argparse.ArgumentParser(description='Fisi – lokaler Lernworkspace mit deterministischer Simulation')
    parser.add_argument('--host',default='127.0.0.1'); parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--allow-host',action='append',default=[],help='Explizit erlaubter LAN-Hostname oder LAN-IP')
    parser.add_argument('--data',default=str(Path(os.environ.get('LOCALAPPDATA',Path.home()/'.local/share'))/'Fisi'))
    parser.add_argument('--shared',action='store_true',help='Gemeinsamer Serverbetrieb: lokalen automatischen Trainer-Einstieg sperren, auch hinter einem Reverse Proxy')
    base=Path(__file__).resolve().parent
    parser.add_argument('--course-data',default=str(base/'kurs.json') if (base/'kurs.json').exists() else None)
    parser.add_argument('--tariff-data',default=str(base/'tarife.json') if (base/'tarife.json').exists() else None)
    parser.add_argument('--validate-data',action='store_true',help='Kurs/Tarife prüfen und ohne Datenbank, Browser oder Server beenden')
    parser.add_argument('--no-browser',action='store_true'); args=parser.parse_args()
    try:
        load_teaching_data(args.course_data,args.tariff_data)
        if args.validate_data:
            print(json.dumps(dict(status='valid',tasks=len(CATALOG),tariff=fresh()['tariffs']['label']),ensure_ascii=False));return
        from fisi_app import FisiApplication
        app=FisiApplication(args.data,local_solo=args.host in ('127.0.0.1','::1') and not args.shared)
    except (Invalid,ValueError,TypeError,KeyError) as error:parser.error('Kurs-/Tarif-/Spielstandprüfung: '+str(error))
    server=make_server(app,args.host,args.port,args.allow_host)
    url=f'http://127.0.0.1:{server.server_port}/'+('' if app.local_solo else '#code='+app.trainer_code)
    print('Fisi – didaktische Simulation. Keine realen Cloud-Ressourcen.',flush=True)
    print('Öffnen: '+url,flush=True); print('Trainercode: '+app.trainer_code,flush=True)
    print('Daten: '+str(app.store.path)+'\nBeenden: Strg+C in diesem Fenster.',flush=True)
    if args.host!='127.0.0.1': print('LAN-Modus: nur vertrauenswürdiges Unterrichtsnetz. Keine Portfreigabe eingerichtet.',flush=True)
    if not args.no_browser: webbrowser.open(url)
    try: server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__=='__main__': main()
