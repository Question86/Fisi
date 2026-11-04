"""Validated declarative teaching data; no eval, Python callbacks or task-ID branches."""
import copy
import hashlib
import json
import math
import re
from domain import (LOCAL_ACTION_FIELDS, local_connection, local_access, local_application_access, BASE_TARIFFS, Invalid, fresh, validate, validate_tariffs, act, event, monthly,
                    effective, scopes, ROLES, metrics, connection, access, application_access, management_access, resolve_target,
                    unsafe_admin_rules, migration_fingerprint, migration_target_ready, request_access, request_monthly, document_profile, storage_monthly, unsafe_storage)

DEFAULTS={'connection':dict(source='hq',host='auftrag.intern',port=443,protocol='TCP'),
          'access':dict(user='lea',document='offer',operation='data_read',mfa=True,source='hq'),
          'request':dict(user='u11',source='hq',operation='request_read',mfa=True),
          'application':dict(user='u11',source='hq',operation='orders_read',mfa=True)}
TESTERS={'connection':connection,'access':access,'application':application_access,'request':request_access,'management':management_access}
DEFAULTS['management']=dict(user='u11',target='web',operation='read',mfa=True)
ACTION_FIELDS={
 'availability_event':({'region','zone','enabled'},set()),
 'container_config':({'id','values'},{'actor'}),
 'configure':({'id','changes'},{'actor'}),'power':({'id','operation'},{'actor'}),
 'group_create':({'id','region','department','owner'},{'actor'}),'create':({'id','name','kind','group','ip'},{'subnet','region','department','owner','actor'}),
 'delete_resource':({'id'},{'actor'}),'network':({'changes'},{'actor'}),'subnet_set':({'id','cidr'},{'actor'}),'subnet_remove':({'id'},{'actor'}),
 'rule_add':({'rule'},{'actor'}),'rule_remove':({'id'},{'actor'}),'user':({'id','changes'},set()),
 'membership':({'group','member','add'},set()),'role_add':({'principal','role','scope'},{'actor'}),'role_remove':({'principal','role','scope'},{'actor'}),
 'file_write':({'id','content'},{'actor'}),'file_delete':({'id'},{'actor'}),'version_restore':({'id','version'},{'actor'}),
 'request_deploy':({'model','reason'},{'actor'}),'request_select':({'model'},{'actor'}),'request_config':({'model','changes'},{'actor'}),'request_grant':({'model','user','role'},{'actor'}),'request_remove':({'model'},{'actor'}),
 'request_create':({'id','changes'},{'user','source','mfa'}),'request_update':({'id','version','changes'},{'user','source','mfa'}),'request_open':(set(),{'user','source','mfa'}),
 'storage_move':({'id','kind','host','reason'},{'actor'}),
 'data_policy':({'id','changes'},{'actor'}),'data_purge':({'id','reason'},{'actor'}),
 'backup_config':({'changes'},set()),'backup_run':(set(),set()),'restore':({'point','id','target'},{'actor','outage_minute','rpo_limit','rto_limit'}),
 'advance':({'minutes'},set()),'workload':({'value'},set()),'alarm_add':({'rule'},set()),'budget':({'value'},set()),
 'policy':({'changes'},set()),'decision':({'key','value'},set()),'migration_plan':({'workload','strategy','reason'},set()),
 'migration':({'step'},{'target'}),'fault':({'id','enabled'},{'resolution'}),'service_identity':({'id','changes'},set()),
 'order_create':({'id','changes'},{'user','source','mfa'}),'order_update':({'id','version','changes'},{'user','source','mfa'}),
 'application_open':(set(),{'user','source','mfa'}),'notes':({'text'},{'name'}),'reply':({'text'},set()),'diagnose':({'test'},{'args'})}
ACTION_FIELDS['local_migration']=({'step'},{'strategy','reason','actor','user'})
ACTION_FIELDS.update(business_policy=({'area','id','changes'},{'actor'}),business_purge=({'area','id','reason'},{'actor'}),local_lineage=({'id','source','reason'},{'actor'}))
ACTION_FIELDS.update(LOCAL_ACTION_FIELDS)
DEFAULTS.update(local_connection=dict(source='hq',host='auftrag.lan',port=443,protocol='TCP'),local_file=dict(user='u11',document='angebot-lokal',operation='data_read',source='hq'),local_application=dict(user='u11',source='hq',operation='orders_read'))
TESTERS.update(local_connection=local_connection,local_file=local_access,local_application=local_application_access)
READ_ROOTS=set(fresh())-{'schema','tariffs','seq','completed','diagnostics','events','hints','notes','replies','task','task_status'}
PATCH_ROOTS=READ_ROOTS-{'cost','cost_ledger','minute','metrics'}


def bounded_data(value):
    count=0
    def visit(node,depth):
        nonlocal count
        count+=1
        if count>100000 or depth>40:raise Invalid('Kursdaten zu groß oder zu tief verschachtelt.')
        if node is None or type(node) in (str,bool,int):return
        if type(node) is float and math.isfinite(node):return
        if type(node) is list:
            for item in node:visit(item,depth+1)
            return
        if type(node) is dict and all(type(key) is str for key in node):
            for item in node.values():visit(item,depth+1)
            return
        raise Invalid('Kursdaten müssen endliche JSON-Daten sein.')
    visit(value,0)
    if len(json.dumps(value,ensure_ascii=True).encode('utf-8'))>2*1024*1024:raise Invalid('Kursdaten maximal 2 MiB.')


def path_check(path,roots=None):
    if type(path) is not list or not 1<=len(path)<=12 or any(type(key) not in (str,int) or (type(key) is str and (not key or key.startswith('__'))) for key in path):raise Invalid('Ungültiger begrenzter Datenpfad.')
    if roots is not None and path[0] not in roots:raise Invalid('Datenpfad außerhalb erlaubter Zustandsfelder: '+str(path[0]))


def walk(value,path):
    for key in path:
        if type(value) is dict and type(key) is str:value=value.get(key)
        elif type(value) is list and type(key) is int and -len(value)<=key<len(value):value=value[key]
        else:return None
    return value


def expression_check(expr,bindings=frozenset(),depth=0):
    if depth>16 or type(expr) is not dict or len(expr)!=1:raise Invalid('Prüfausdruck muss genau einen bekannten Operator enthalten (max. Tiefe 16).')
    op,value=next(iter(expr.items()))
    if op=='literal':bounded_data(value)
    elif op=='path':path_check(value,READ_ROOTS)
    elif op=='var':
        path_check(value)
        if value[0] not in bindings:raise Invalid('Ungebundene Prüfvariable.')
    elif op in ('monthly','request_monthly','storage_monthly','unsafe_storage','unsafe_admin','migration_fingerprint','migration_target_ready'):
        if value is not True:raise Invalid('Berechnungsoperator benötigt true.')
    elif op=='unexpected_admin':
        if type(value) is not dict or set(value)!={'trusted','allow'} or type(value['trusted']) is not list or len(value['trusted'])>20 or any(type(p) is not str for p in value['trusted']) or type(value['allow']) is not list or len(value['allow'])>20:raise Invalid('Ungültige Administrator-Ausnahmen.')
        for grant in value['allow']:
            if type(grant) is not dict or set(grant)!={'principal','right','scope'} or any(type(v) is not str or not v for v in grant.values()) or grant['right'] not in ('manage','assign','local_admin'):raise Invalid('Ungültige begrenzte Verwaltungsfreigabe.')
    elif op=='data_access_within':
        if type(value) is not dict or len(value)>100:raise Invalid('Datenrechte-Grenze benötigt höchstens100 benannte Identitäten.')
        for principal,rights in value.items():
            if type(principal) is not str or not principal or len(principal)>120 or type(rights) is not dict or set(rights)!={'data_read','data_write'}:raise Invalid('Datenrechte-Grenze benötigt Identität, data_read und data_write.')
            for targets in rights.values():
                if type(targets) is not list or len(targets)>100 or any(type(target) is not str or not target or len(target)>120 for target in targets) or len(set(targets))!=len(targets):raise Invalid('Datenrechte-Grenze benötigt begrenzte eindeutige Dokumentkennungen.')
    elif op in ('privileged_scopes','data_targets'):
        fields={'principal','rights'} if op=='privileged_scopes' else {'principal','right'}
        if type(value) is not dict or set(value)!=fields or type(value['principal']) is not str or not value['principal']:raise Invalid('Ungültige Identitäts-Prüffelder.')
        if op=='privileged_scopes' and (type(value['rights']) is not list or not value['rights'] or any(right not in ('manage','assign') for right in value['rights'])):raise Invalid('Unbekanntes Verwaltungsrecht.')
        if op=='data_targets' and value['right'] not in ('data_read','data_write'):raise Invalid('Unbekanntes Datenrecht.')
    elif op=='target_property':
        if type(value) is not dict or set(value)!={'host','name'} or type(value['host']) is not str or not value['host'] or value['name'] not in ('resource','kind','public_ip','private_ip'):raise Invalid('Ungültige Ziel-Eigenschaft.')
    elif op=='storage_property':
        if type(value) is not dict or set(value)!={'document','name'} or type(value['document']) is not str or value['name'] not in ('kind','host','region','tier','redundancy','anonymous','public_ip','available'):raise Invalid('Unbekannte Speicherprofil-Eigenschaft.')
    elif op=='target':
        if type(value) is not str or not value:raise Invalid('DNS-Zieltext erforderlich.')
    elif op in ('rights','metric'):
        keys={'principal','target'} if op=='rights' else {'resource','name'}
        if type(value) is not dict or set(value)!=keys or any(type(v) is not str or not v for v in value.values()):raise Invalid('Ungültige berechnete Prüffelder.')
        if op=='metric' and value['name'] not in ('cpu','memory','response_ms','error_rate','healthy'):raise Invalid('Unbekannte Metrik.')
    elif op in ('all','any_of','eq','lte','gte','contains','subtract','same_records_except_modified'):
        if type(value) is not list or not (1<=len(value)<=50 if op in ('all','any_of') else len(value)==2):raise Invalid('Ungültige Anzahl Prüfargumente.')
        for child in value:expression_check(child,bindings,depth+1)
    elif op in ('not','nonempty','count'):expression_check(value,bindings,depth+1)
    elif op=='some':
        if type(value) is not dict or set(value)!={'in','as','where'} or type(value['as']) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,20}',value['as']) or value['as'] in bindings:raise Invalid('Ungültige begrenzte Listenprüfung.')
        expression_check(value['in'],bindings,depth+1);expression_check(value['where'],bindings|{value['as']},depth+1)
    else:raise Invalid('Nicht unterstützter Prüfoperator: '+op)


def evaluate(expr,state,variables=None,budget=None):
    variables={} if variables is None else variables;budget=[20000] if budget is None else budget
    budget[0]-=1
    if budget[0]<0:raise Invalid('Prüfauswertung überschreitet das begrenzte Arbeitsbudget.')
    op,value=next(iter(expr.items()));ev=lambda child:evaluate(child,state,variables,budget)
    if op=='literal':return value
    if op=='path':return walk(state,value)
    if op=='var':return walk(variables,value)
    if op=='count':
        item=ev(value);return len(item) if type(item) in (list,dict) else None
    if op=='same_records_except_modified':
        actual,expected=[ev(child) for child in value]
        if type(actual) is not dict or type(expected) is not dict or set(actual)!=set(expected):return False
        if any(type(row) is not dict for row in [*actual.values(),*expected.values()]):return False
        return all({field:item for field,item in actual[key].items() if field!='modified'}=={field:item for field,item in expected[key].items() if field!='modified'} for key in expected)
    if op=='unexpected_admin':
        trusted=set(value['trusted'])
        for grant in state['roles']:
            administrative=ROLES[grant['role']] & {'manage','assign'}
            if not administrative:continue
            identities=state['groups'].get(grant['principal'],[grant['principal']])
            for principal in identities:
                if principal in trusted:continue
                for right in sorted(administrative):
                    if not any(rule['principal']==principal and rule['right']==right and rule['scope'] in scopes(state,grant['scope']) for rule in value['allow']):return [dict(principal=principal,right=right,scope=grant['scope'])]
        for principal in state.get('onprem',{}).get('groups',{}).get('IT',[]):
            if principal not in trusted and not any(rule['principal']==principal and rule['right']=='local_admin' and rule['scope']=='onprem' for rule in value['allow']):return [dict(principal=principal,right='local_admin',scope='onprem')]
        return []
    if op=='privileged_scopes':
        candidate_scopes=set(state['resources'])|set(state['resource_groups'])|set(state['documents'])|{'subscription','orders','requests'}
        return sorted(scope for scope in candidate_scopes if set(value['rights']) & effective(state,value['principal'],scope)[0])
    if op=='data_access_within':
        principals=sorted(set(state['users'])|set(state['service_principals']));documents=sorted(state['documents'])
        # Charge role/group work as well as principal/document pairs to the
        # existing expression budget. Insufficient work means not satisfied;
        # it never invalidates or rewrites the imported save itself.
        work=len(principals)*len(documents)*(1+len(state['roles'])+sum(len(members) for members in state['groups'].values()))
        if work>budget[0]:return False
        budget[0]-=work
        for principal in principals:
            allowed=value.get(principal,{'data_read':[],'data_write':[]})
            for document in documents:
                actual=effective(state,principal,document)[0]
                if any(right in actual and document not in allowed[right] for right in ('data_read','data_write')):return False
        return True
    if op=='data_targets':return sorted(document for document in state['documents'] if value['right'] in effective(state,value['principal'],document)[0])
    if op=='target_property':
        target=resolve_target(state,value['host']);r=state['resources'].get(target,{})
        return target if value['name']=='resource' else r.get('ip') if value['name']=='private_ip' else r.get(value['name'])
    if op=='storage_property':return document_profile(state,value['document']).get(value['name']) if value['document'] in state['documents'] else None
    if op=='unsafe_storage':return unsafe_storage(state)
    if op=='storage_monthly':return storage_monthly(state)
    if op=='request_monthly':return request_monthly(state)
    if op=='monthly':return monthly(state)
    if op=='unsafe_admin':return unsafe_admin_rules(state)
    if op=='migration_fingerprint':return migration_fingerprint(state)
    if op=='migration_target_ready':return migration_target_ready(state)
    if op=='target':return resolve_target(state,value)
    if op=='rights':return sorted(effective(state,value['principal'],value['target'])[0])
    if op=='metric':return metrics(state,value['resource']).get(value['name']) if value['resource'] in state['resources'] else None
    if op=='not':return ev(value) is False
    if op=='nonempty':
        v=ev(value);return bool(v.strip()) if type(v) is str else bool(v) if type(v) in (list,dict) else False
    if op in ('all','any_of'):
        results=[ev(child) is True for child in value];return all(results) if op=='all' else any(results)
    if op=='some':
        items=ev(value['in'])
        return type(items) is list and any(evaluate(value['where'],state,dict(variables,**{value['as']:item}),budget) is True for item in items)
    a,b=map(ev,value)
    if op=='eq':return a==b and (type(a) is type(b) or (type(a) in (int,float) and type(b) in (int,float)))
    if op=='contains':return type(a) in (list,dict,set,tuple) and b in a
    if type(a) not in (int,float) or type(b) not in (int,float):return False if op!='subtract' else None
    if op=='lte':return a<=b
    if op=='gte':return a>=b
    if op=='subtract':return a-b
    raise Invalid('Unbekannter Operator.')


def resolve_parameters(value,state):
    if type(value) is dict:
        if set(value)=={'$state'}:
            result=walk(state,value['$state'])
            if result is None:raise Invalid('Aktionsreferenz fehlt im Ausgangszustand.')
            return copy.deepcopy(result)
        return {key:resolve_parameters(item,state) for key,item in value.items()}
    if type(value) is list:return [resolve_parameters(item,state) for item in value]
    return value


def action_check(step):
    if type(step) is not dict or type(step.get('action')) is not str or step['action'] not in ACTION_FIELDS:raise Invalid('Unbekannte Kursaktion.')
    required,optional=ACTION_FIELDS[step['action']];keys=set(step)-{'action'}
    if not required<=keys or keys-required-optional:raise Invalid('Fehlende/unbekannte Aktionsfelder: '+step['action'])
    def refs(value):
        if type(value) is dict:
            if '$state' in value:
                if set(value)!={'$state'}:raise Invalid('Aktionsreferenz enthält zusätzliche Felder.')
                path_check(value['$state'],READ_ROOTS)
            else:
                for item in value.values():refs(item)
        elif type(value) is list:
            for item in value:refs(item)
    refs(step)


def apply_steps(state,steps):
    for raw in steps:
        step=resolve_parameters(raw,state);action=step.pop('action');state,_=act(state,action,**step)
    return state


def make_scenario(row,tariffs=None):
    state=fresh(tariffs);state['task']=row['id']
    for patch in row['start']:
        parent=state
        for key in patch['path'][:-1]:
            if type(parent) is not dict or key not in parent:raise Invalid('Startpfad fehlt.')
            parent=parent[key]
        key=patch['path'][-1]
        if type(parent) is not dict:raise Invalid('Startänderungen benötigen einen Objektpfad.')
        if patch['op']=='remove':
            if key not in parent:raise Invalid('Zu entfernender Startwert fehlt.')
            del parent[key]
        else:parent[key]=copy.deepcopy(patch['value'])
    # Existing course-v1/v2 added documents lived in Blob before explicit placements existed.
    for ident in set(state['documents'])-set(fresh(tariffs)['documents']):
        explicit=any(patch['path'][0]=='document_storage' and (len(patch['path'])==1 or patch['path'][1]==ident) for patch in row['start'])
        if ident not in state['document_storage'] and not explicit:state['document_storage'][ident]=dict(kind='Blob',host='storage')
    validate(state);state=apply_steps(state,row['setup']);event(state,'ticket',row['message']);return state


def state_checks(s,records=None,guards=None):
    records=CATALOG if records is None else records;guards=GUARDS if guards is None else guards;row=records[s['task']]
    if row['id']=='free':return []
    return [dict(label=c['label'],passed=evaluate(c['expr'],s) is True) for c in guards+row['criteria']]


def probe_enabled(probe,state):
    if 'when' not in probe:return True
    value=evaluate(probe['when'],state) if type(probe['when']) is dict else walk(state,probe['when'])
    if type(value) is not bool:raise Invalid('Bedingte Diagnose benötigt einen booleschen Zustandspfad.')
    return value


def probe_description(test,args,state):
    titles={'connection':'Netzwerkverbindung','access':'Dokumentzugriff','application':'Auftragszugriff','request':'Kundenanfragen-Zugriff','local_connection':'Lokale Netzwerkverbindung','local_file':'Lokaler Dateizugriff','local_application':'Lokaler Auftragszugriff'}
    sources={'hq':'Hauptstandort','branch':'Außenstelle','internet':'Internet','cloud':'Cloud-Netz','home':'Homeoffice'}
    operations={'data_read':'Datei lesen','data_write':'Datei schreiben','assign':'Rollen zuweisen','orders_read':'Aufträge lesen','orders_write':'Aufträge bearbeiten','request_read':'Kundenanfragen lesen','request_write':'Kundenanfragen bearbeiten'}
    def named(ident,items):
        name=items.get(ident,{}).get('name',ident)
        return str(name)+' ('+str(ident)+')' if name!=ident else str(ident)
    if test=='management' or (test=='access' and args.get('operation')=='assign'):
        target=args.get('target',args.get('document'));names={'read':'Ressourcen ansehen','manage':'Ressourcen verwalten','assign':'Rollen zuweisen'}
        return 'Verwaltungsrechte · '+named(args['user'],state['users'])+' · '+names[args['operation']]+' · Geltungsbereich '+str(target)+' · '+('MFA bestätigt' if args['mfa'] else 'Ohne MFA-Nachweis')
    parts=[titles.get(test,str(test))]
    if test in ('connection','local_connection'):
        parts.extend([sources.get(args['source'],args['source'])+' → '+str(args['host']),str(args['protocol'])+' '+str(args['port'])])
    else:
        parts.append(named(args['user'],state['users']))
        if 'document' in args:
            documents=state.get('onprem',{}).get('documents',{}) if test=='local_file' else state['documents']
            parts.append(named(args['document'],documents))
        parts.extend([operations.get(args['operation'],str(args['operation'])),sources.get(args['source'],str(args['source']))])
        if 'mfa' in args:parts.append('MFA bestätigt' if args['mfa'] else 'Ohne MFA-Nachweis')
    return ' · '.join(parts)


def probe_identity(test,args):
    values=dict(DEFAULTS[test],**args)
    if test=='access' and values.get('operation')=='assign':
        return 'management',dict(user=values['user'],target=values['document'],operation='assign',mfa=values['mfa'])
    return test,values


def assess(s,records=None,guards=None):
    records=CATALOG if records is None else records;row=records[s['task']];checks=state_checks(s,records,guards);evidence=[]
    for probe in row['probes']:
        if not probe_enabled(probe,s):continue
        defaults=DEFAULTS[probe['test']];effective_args=dict(defaults,**probe['args'])
        result=TESTERS[probe['test']](s,**probe['args'])
        description=probe_description(probe['test'],effective_args,s)
        label=description+': '+('soll erlaubt sein' if probe['expected'] else 'soll verweigert werden')
        matching=[d for d in s['diagnostics'] if probe_identity(d['test'],d['args'])==probe_identity(probe['test'],probe['args'])]
        current=[d for d in matching if d['seq']==s['seq']]
        recorded=current[-1] if current else matching[-1] if matching else None
        tested=bool(current)
        checks.append(dict(label=label,passed=result['allowed']==probe['expected']))
        checks.append(dict(label='Nach Änderung erneut geprüft: '+label,passed=tested))
        evidence.append(dict(test=probe['test'],args=copy.deepcopy(probe['args']),effective_args=copy.deepcopy(effective_args),description=description,expected=probe['expected'],current_allowed=result['allowed'],current_passed=result['allowed']==probe['expected'],fresh=tested,recorded=None if recorded is None else dict(test=recorded['test'],minute=recorded['minute'],seq=recorded['seq'],allowed=recorded['result']['allowed'],args=copy.deepcopy(recorded['args']))))
    if row['id']!='free':checks.append(dict(label='Rückmeldung gespeichert (fachliche Begründung wird vom Trainer besprochen)',passed=bool(s['replies'].get(s['task'],'').strip())))
    return dict(passed=bool(checks) and all(c['passed'] for c in checks),checks=checks,diagnostic_evidence=evidence,explanation=row['explanation'])


def scenario(ident):
    if ident not in CATALOG:raise Invalid('Unbekannte Aufgabe.')
    return make_scenario(CATALOG[ident])


def example_actions(ident,s,variant=None,failure=None):
    if variant is not None and failure is not None:raise Invalid('Nur eine Beispielart wählen.')
    row=CATALOG[ident];steps=row['solution']
    for index,field in ((variant,'variants'),(failure,'failures')):
        if index is not None:
            if type(index) is not int or not 0<=index<len(row[field]):raise Invalid('Beispielkennung ungültig.')
            steps=row[field][index]['actions']
    return resolve_parameters(steps,s)


def solved_record(row,tariffs=None,actions=None):
    state=apply_steps(make_scenario(row,tariffs),row['solution'] if actions is None else actions)
    for probe in row['probes']:
        if probe_enabled(probe,state):state,_=act(state,'diagnose',test=probe['test'],args=probe['args'])
    state,_=act(state,'reply',text='Beispielbegründung: Diagnose, begrenzte Änderung, erlaubte und verweigerte Zugriffe geprüft. Fachliche Diskussion durch die Lehrkraft.')
    return state


def solve_example(ident):return solved_record(CATALOG[ident])



def normalize_historical_restore_deadline(row):
    if row.get('id')!='12' or type(row.get('criteria')) is not list:return
    old={'label': 'Richtiger Punkt, alternativer Ort, früherer Inhalt und RTO', 'expr': {'all': [{'eq': [{'path': ['backup', 'restore', 'status']}, {'literal': 'success'}]}, {'eq': [{'path': ['backup', 'restore', 'target']}, {'literal': 'offer-restored'}]}, {'eq': [{'path': ['backup', 'restore', 'point']}, {'path': ['backup', 'points', 0, 'id']}]}, {'lte': [{'path': ['backup', 'restore', 'duration']}, {'literal': 10}]}, {'eq': [{'path': ['documents', 'offer-restored']}, {'path': ['backup', 'points', 0, 'documents', 'offer']}]}]}}
    if old not in row['criteria']:return
    setup=[{'action': 'backup_run'}, {'action': 'advance', 'minutes': 30}, {'action': 'file_delete', 'id': 'offer'}]
    if row.get('setup')!=setup:raise Invalid('Aufgabe 12 enthält die veraltete Jobdauer-als-RTO-Prüfung bei geändertem Ausgangszustand. Kurskriterium anhand eines festgelegten Ausfallbeginns und tatsächlichen Abschlusses überarbeiten.')
    row['criteria'][row['criteria'].index(old)]={'label': 'Richtiger Punkt und früherer Inhalt am alternativen Ort; Abschluss seit Ausfall Minute 30 spätestens Minute 40', 'expr': {'all': [{'eq': [{'path': ['backup', 'restore', 'status']}, {'literal': 'success'}]}, {'eq': [{'path': ['backup', 'restore', 'target']}, {'literal': 'offer-restored'}]}, {'eq': [{'path': ['backup', 'restore', 'point']}, {'path': ['backup', 'points', 0, 'id']}]}, {'all': [{'gte': [{'path': ['backup', 'restore', 'finished_minute']}, {'literal': 30}]}, {'lte': [{'path': ['backup', 'restore', 'finished_minute']}, {'literal': 40}]}]}, {'eq': [{'path': ['documents', 'offer-restored']}, {'path': ['backup', 'points', 0, 'documents', 'offer']}]}]}}

def normalize_historical_storage_outage(row):
    if row.get('id')!='12' or type(row.get('failures')) is not list:return
    old={'label': 'Ziel fällt während der Wiederherstellung aus', 'rationale': 'Ein vorhandener Punkt genügt nicht: ein gestoppter Zielhost beendet den Job ohne Kopie und ohne erfolgreiches RTO.', 'outcome': 'incomplete', 'actions': [{'action': 'restore', 'point': {'$state': ['backup', 'points', 0, 'id']}, 'id': 'offer', 'target': 'offer-restored'}, {'action': 'power', 'id': 'storage', 'operation': 'shutdown'}, {'action': 'advance', 'minutes': 5}]}
    for case in row['failures']:
        if case==old:
            case['actions']=[dict(action='fault',id='document_source',enabled=True) if step==dict(action='power',id='storage',operation='shutdown') else step for step in case['actions']]


def normalize_historical_monitoring_event(row):
    if row.get('id')!='15' or type(row.get('criteria')) is not list:return
    old={'label': 'Passende Regel hat Alarm ausgelöst', 'expr': {'some': {'in': {'path': ['alarms']}, 'as': 'alarm', 'where': {'all': [{'eq': [{'var': ['alarm', 'metric']}, {'literal': 'cpu'}]}, {'eq': [{'var': ['alarm', 'target']}, {'literal': 'web'}]}, {'eq': [{'var': ['alarm', 'threshold']}, {'literal': 80}]}, {'eq': [{'var': ['alarm', 'window']}, {'literal': 3}]}, {'eq': [{'var': ['alarm', 'destination']}, {'literal': 'IT'}]}, {'some': {'in': {'path': ['alerts']}, 'as': 'alert', 'where': {'eq': [{'var': ['alert', 'rule']}, {'var': ['alarm', 'id']}]}}}]}}}}
    if old in row['criteria']:row['criteria'][row['criteria'].index(old)]={'label': 'Passende Regel hat einen tatsächlichen Metrikalarm ausgelöst', 'expr': {'some': {'in': {'path': ['alarms']}, 'as': 'alarm', 'where': {'all': [{'eq': [{'var': ['alarm', 'metric']}, {'literal': 'cpu'}]}, {'eq': [{'var': ['alarm', 'target']}, {'literal': 'web'}]}, {'eq': [{'var': ['alarm', 'threshold']}, {'literal': 80}]}, {'eq': [{'var': ['alarm', 'window']}, {'literal': 3}]}, {'eq': [{'var': ['alarm', 'destination']}, {'literal': 'IT'}]}, {'some': {'in': {'path': ['alerts']}, 'as': 'alert', 'where': {'all': [{'eq': [{'var': ['alert', 'rule']}, {'var': ['alarm', 'id']}]}, {'eq': [{'var': ['alert', 'kind']}, {'literal': 'metric'}]}]}}}]}}}}


LEGACY_CONTAINER_CONTRACT_SHA256='35dccf297185bbbff57a1368ab54257a73a1d2c439c3b51d8542bba247a1cf0f'


def normalize_historical_container_preservation(row):
    # Only the exact previously shipped contract is upgraded; authored variants
    # with a different contract remain under their explicit data authority.
    if row.get('id')!='16':return
    digest=hashlib.sha256(json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
    if digest==LEGACY_CONTAINER_CONTRACT_SHA256:
        current=next(task for task in DEFAULT_COURSE_DATA['tasks'] if task['id']=='16')
        row.clear();row.update(copy.deepcopy(current))


IDENTITY_LEGACY_CONTRACT_SHA256={'intro': '4ab7ca297147aea5e6581a1d2594bd2ee0b036014c0ba2e41b4e403fceb4db6a', '06': 'e85a8a366704322abb1fc5ced9a40b157e763f3534cac06e75365a267260a6dc', '07': '67b947920b04da8d8530ca1aec0b2d94ae4e170be402ea83b39b8fa3454f52b6', '08': 'e93e1cd2013fdca0e6a77ff1eff31c29c6d62c198c75e69ff37e3efb07bda3ff', '09': '0ad6805f0d4a08ace96c53000d9ae042553880bc925af73f6e7422b78230b4df', '10': 'eacb9578f4b2bfd2bd7efd5981269aa2ee4679cb772c89916d4b9293e7948565'}
IDENTITY_DATA_BOUNDARY_TEXTS={'constraints': ' Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.', 'hint': ' Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.', 'explanation': ' Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.', 'alternatives': ' Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.'}


def normalize_historical_identity_data_boundary(row):
    expected=IDENTITY_LEGACY_CONTRACT_SHA256.get(row.get('id'))
    if expected is None:return
    digest=hashlib.sha256(json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
    if digest==expected:
        current=next(task for task in DEFAULT_COURSE_DATA['tasks'] if task['id']==row['id'])
        row.clear();row.update(copy.deepcopy(current))


ORGANIZATION_LEGACY_CONTRACT_SHA256='0946b048037fc8ad684759e0e30af14b5700facc7cf1d49f8bcfd17f557addb3'
ORGANIZATION_POLICY_TEXTS={'constraints': ' Maßgeblich sind die vorbereiteten Firmenregionen Germany West Central und West Europe und die verpflichtenden Tags. Die Policy nicht um weitere Regionen erweitern oder die Tagpflicht ausschalten, um eine Gruppe passend zu machen. Eine engere Regionsauswahl oder zusätzlicher Schutz vor öffentlichem Zugriff ist zulässig; die Projektregion muss auch zur aktuellen engeren Policy passen.', 'hint': ' Vergleiche mit der Firmenvorgabe dieses Auftrags: Germany West Central oder West Europe, verpflichtende Tags. Die Richtlinie zur Umgehung zu lockern ist keine saubere Projektorganisation.', 'explanation': ' Die Firmenvorgabe des Auftrags bleibt unabhängig von nachträglich gelockerten Policy-Einstellungen. Der Prüfer vergleicht Projektregion und aktuelle Policy mit den ursprünglich freigegebenen Regionen und der Tagpflicht. Reihenfolge der Regionsliste ist unerheblich; eine echte Verschärfung bleibt zulässig.', 'alternatives': ' Die Policy darf auf eine der beiden freigegebenen Regionen eingeschränkt und öffentlicher Zugriff zusätzlich geschützt werden. Die Projektgruppe muss dann auch diese engere Policy erfüllen. Ein rückgängig gemachter Versuch mit einer neu angelegten eigenen Testressource ersetzt keine notwendige Änderung am vorgesehenen Endzustand und erzwingt keinen Klickpfad.'}


def normalize_historical_organization_policy(row):
    if row.get('id')!='02':return
    digest=hashlib.sha256(json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
    if digest==ORGANIZATION_LEGACY_CONTRACT_SHA256:
        current=next(task for task in DEFAULT_COURSE_DATA['tasks'] if task['id']=='02')
        row.clear();row.update(copy.deepcopy(current))


def normalize_course_data(data):
    bounded_data(data)
    if type(data) is not dict:raise Invalid('Kursdaten müssen ein Objekt sein.')
    result=copy.deepcopy(data)
    if result.get('format')=='nordlicht-course/v1':
        old_fields=set(DEFAULT_COURSE_DATA['tasks'][0])-{'terms','variants','failures','clarifications'}
        if type(result.get('tasks')) is not list:raise Invalid('Alte Kursaufgaben ungültig.')
        for row in result['tasks']:
            if type(row) is not dict or set(row)!=old_fields:raise Invalid('Alte Kursfelder fehlen oder sind unbekannt.')
            row.update(terms=[],variants=[],failures=[])
        result['format']='nordlicht-course/v2'
    if type(result.get('tasks')) is list:
        for row in result['tasks']:
            if type(row) is dict:
                row.setdefault('clarifications',[]);normalize_historical_restore_deadline(row);normalize_historical_monitoring_event(row);normalize_historical_storage_outage(row);normalize_historical_container_preservation(row);normalize_historical_identity_data_boundary(row);normalize_historical_organization_policy(row)
    guards=result.get('guards');required=DEFAULT_COURSE_DATA['guards'][2]
    if type(guards) is list and guards[:2]==DEFAULT_COURSE_DATA['guards'][:2] and not any(type(row) is dict and row.get('label')==required['label'] for row in guards):guards.append(copy.deepcopy(required))
    return result


def validate_course_data(data,tariffs=None):
    legacy=type(data) is dict and data.get('format')=='nordlicht-course/v1'
    data=normalize_course_data(data);tariffs=validate_tariffs(BASE_TARIFFS if tariffs is None else tariffs)
    if type(data) is not dict or set(data)!={'format','guards','tasks'} or data['format']!='nordlicht-course/v2':raise Invalid('Unbekanntes Kursdatenformat.')
    if type(data['guards']) is not list or not 3<=len(data['guards'])<=20 or data['guards'][:2]!=DEFAULT_COURSE_DATA['guards'][:2] or DEFAULT_COURSE_DATA['guards'][2] not in data['guards']:raise Invalid('Die bestehenden Basisschutzprüfungen und die Schutzprüfung aller tatsächlichen Blob-Ablagen müssen erhalten bleiben.')
    if type(data['tasks']) is not list or not 22<=len(data['tasks'])<=100:raise Invalid('Kurs benötigt Einstieg, 20 Kernaufgaben und freie Umgebung; maximal 100 Aufgaben.')
    fields=set(DEFAULT_COURSE_DATA['tasks'][0]);records={}
    for row in data['tasks']:
        if type(row) is not dict or set(row)!=fields:raise Invalid('Fehlende oder unbekannte Aufgabenfelder.')
        ident=row['id']
        if type(ident) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,50}',ident) or ident in records:raise Invalid('Ungültige/doppelte Aufgabenkennung.')
        records[ident]=copy.deepcopy(row)
        for key in fields-{'minutes','solution','probes','hints','start','setup','criteria','terms','variants','failures','clarifications'}:
            if type(row[key]) is not str or not row[key].strip() or len(row[key])>20000:raise Invalid('Aufgabentext fehlt oder ist zu lang: '+key)
        if type(row['minutes']) is not int or not 0<=row['minutes']<=240:raise Invalid('Aufgabenzeit ungültig.')
        if type(row['hints']) is not list or len(row['hints'])!=3 or any(type(v) is not str or not v.strip() or len(v)>20000 for v in row['hints']):raise Invalid('Drei begrenzte Hilfestufen erforderlich.')
        for key in ('start','setup','solution','criteria','probes'):
            if type(row[key]) is not list or len(row[key])>100:raise Invalid('Begrenzte Aufgabenlisten erwartet: '+key)
        if type(row['terms']) is not list or len(row['terms'])>15:raise Invalid('Begriffe müssen eine begrenzte Liste sein.')
        for term in row['terms']:
            if type(term) is not dict or set(term)!={'term','meaning'} or any(type(v) is not str or not v.strip() or len(v)>2000 for v in term.values()):raise Invalid('Begriff und verständliche Bedeutung erforderlich.')
        if type(row['clarifications']) is not list or len(row['clarifications'])>10:raise Invalid('Maximal zehn vorbereitete Rückfragen je Aufgabe.')
        topics=set()
        for item in row['clarifications']:
            if type(item) is not dict or set(item)!={'id','question','answer'} or any(type(v) is not str or not v.strip() or len(v)>5000 for v in item.values()) or not re.fullmatch('[A-Za-z0-9_-]{1,50}',item['id']) or item['id'] in topics:raise Invalid('Eindeutige Rückfrage mit begrenzter Frage und Antwort erforderlich.')
            if len(item['question'])>2000:raise Invalid('Vorbereitete Rückfrage maximal 2000 Zeichen.')
            topics.add(item['id'])
        for field in ('variants','failures'):
            if type(row[field]) is not list or len(row[field])>5:raise Invalid('Beispielvarianten müssen eine begrenzte Liste sein.')
            labels=set()
            for case in row[field]:
                required={'label','rationale','actions'}|({'outcome'} if field=='failures' else set())
                if type(case) is not dict or set(case)!=required or any(type(case[k]) is not str or not case[k].strip() or len(case[k])>5000 for k in ('label','rationale')) or case['label'] in labels:raise Invalid('Beispielfelder oder doppelte Bezeichnung ungültig.')
                labels.add(case['label'])
                if field=='failures' and case['outcome'] not in ('incomplete','rejected'):raise Invalid('Fehlversuch benötigt incomplete oder rejected.')
                if type(case['actions']) is not list or not 1<=len(case['actions'])<=100:raise Invalid('Beispiel benötigt begrenzte konkrete Aktionen.')
                for step in case['actions']:action_check(step)
        if not legacy and ident!='free' and (not row['terms'] or not row['variants'] or not row['failures']):raise Invalid('Kursformat 2 benötigt Begriffe, geprüfte Variante und ungeeignetes Beispiel je bewerteter Aufgabe.')
        for patch in row['start']:
            if type(patch) is not dict or patch.get('op') not in ('set','remove') or set(patch)!=({'op','path','value'} if patch.get('op')=='set' else {'op','path'}):raise Invalid('Startänderung ungültig.')
            path_check(patch['path'],PATCH_ROOTS)
        for step in row['setup']+row['solution']:action_check(step)
        for probe in row['probes']:
            if type(probe) is not dict or not {'test','args','expected'}<=set(probe) or set(probe)-{'test','args','expected','when'} or probe['test'] not in TESTERS or type(probe['expected']) is not bool or type(probe['args']) is not dict or set(probe['args'])-set(DEFAULTS[probe['test']]):raise Invalid('Ungültige erlaubte/verweigerte Diagnose.')
            if 'when' in probe:
                if type(probe['when']) is dict:expression_check(probe['when'])
                else:path_check(probe['when'],READ_ROOTS)
    if not {'intro','free',*(f'{n:02}' for n in range(1,21))}<=set(records):raise Invalid('Bestehende Kernkennungen dürfen wegen gespeicherter Übungen nicht entfernt werden.')
    for criterion in data['guards']+[c for row in records.values() for c in row['criteria']]:
        if type(criterion) is not dict or set(criterion)!={'label','expr'} or type(criterion['label']) is not str or not criterion['label'].strip():raise Invalid('Prüfkriterium ungültig.')
        expression_check(criterion['expr'])
    for ident,row in records.items():
        try:
            start=make_scenario(row,tariffs)
            if ident=='free':
                if row['criteria'] or row['probes']:raise Invalid('Freie Umgebung hat keine Bewertung.')
                continue
            if not row['probes'] or not any(not p['expected'] for p in row['probes'] if probe_enabled(p,start)) or not any(p['expected'] for p in row['probes']):raise Invalid('Positive und negative Diagnosen erforderlich.')
            start_good=all(c['passed'] for c in state_checks(start,records,data['guards'])) and all(TESTERS[p['test']](start,**p['args'])['allowed']==p['expected'] for p in row['probes'] if probe_enabled(p,start))
            if start_good:raise Invalid('Aufgabe ist bereits fachlich gelöst; eine echte Ausgangsstörung/Konfigurationsaufgabe fehlt.')
            solved=solved_record(row,tariffs)
            result=assess(solved,records,data['guards'])
            if not result['passed']:raise Invalid('Beispiellösung erfüllt nicht: '+'; '.join(c['label'] for c in result['checks'] if not c['passed']))
            for case in row['variants']:
                alternate=solved_record(row,tariffs,case['actions'])
                if not assess(alternate,records,data['guards'])['passed']:raise Invalid('Alternative erfüllt Auftrag nicht: '+case['label'])
            for case in row['failures']:
                rejected=False
                try:wrong=solved_record(row,tariffs,case['actions'])
                except Invalid:rejected=True
                if rejected!=(case['outcome']=='rejected'):raise Invalid('Fehlversuch hat anderen Ablehnungsmodus: '+case['label'])
                if not rejected and assess(wrong,records,data['guards'])['passed']:raise Invalid('Als ungeeignet behauptetes Beispiel besteht: '+case['label'])

        except (Invalid,ValueError,KeyError,TypeError,IndexError) as error:raise Invalid('Kursaufgabe '+ident+': '+str(error)) from error
    return records


def configure_course(data,tariffs):
    records=validate_course_data(data,tariffs)
    import domain
    domain.ACTIVE_TARIFFS=validate_tariffs(tariffs)
    CATALOG.clear();CATALOG.update(records);GUARDS[:]=copy.deepcopy(normalize_course_data(data)['guards'])


def catalog(trainer=False):
    rows=copy.deepcopy(list(CATALOG.values()))
    for row in rows:
        for key in ('start','setup','criteria'):row.pop(key)
        for field in ('variants','failures'):
            for case in row[field]:case.pop('actions')
        if not trainer:
            for key in ('solution','explanation','hints','variants','failures'):row.pop(key)
    return rows


DEFAULT_COURSE_DATA=json.loads(r'''{
  "format": "nordlicht-course/v2",
  "guards": [
    {
      "label": "Vertrauliche Ablage privat",
      "expr": {
        "eq": [
          {
            "path": [
              "resources",
              "storage",
              "public"
            ]
          },
          {
            "literal": false
          }
        ]
      }
    },
    {
      "label": "Keine pauschale öffentliche Administrationsfreigabe",
      "expr": {
        "eq": [
          {
            "unsafe_admin": true
          },
          {
            "literal": []
          }
        ]
      }
    },
    {
      "label": "Nichtöffentliche Dokumente auf keinem Blob-Ziel anonym freigeben",
      "expr": {
        "eq": [
          {
            "unsafe_storage": true
          },
          {
            "literal": []
          }
        ]
      }
    }
  ],
  "tasks": [
    {"id":"intro","title":"Willkommen im IT-Team","sender":"IT-Leitung","message":"Lea kann das Angebot nicht bearbeiten. Bitte kläre Netzwerk, Anmeldung und Gruppenrechte und ermögliche den Vertriebskollegen die Bearbeitung ohne Zugriff auf Personaldaten.","minutes":10,"prerequisite":"Keines","learning":"Identität, Diagnose, Ticket","learn":"Du lernst, Netzwerk, Anmeldung und Datenrechte getrennt zu prüfen.","try_text":"Du probierst einen fehlgeschlagenen Zugriff, eine Gruppenänderung und dieselbe Prüfung nach der Reparatur.","deadline":"Vor Leas erster Angebotsbearbeitung; etwa 10 Minuten, keine Echtzeitsperre.","constraints":"Angebote bearbeiten, keine Personaldaten, Verwaltung oder Zuweisungsrechte. Keine neuen Ressourcen nötig. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Dienst und Vertriebsrolle existieren; Lea fehlt in Vertrieb.","hints":["Welche Gruppe darf Angebote bearbeiten?","Teste Lea auf Angebot A und Personal-B; vergleiche die effektiven Rollen mit Vertrieb. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Füge Lea zu Vertrieb hinzu. Prüfe Angebotsbearbeitung, verweigerte Personaldaten und Auftragszugriff frisch; speichere die Rückmeldung."],"explanation":"Die Vertriebsgruppe besitzt eine Datenrolle auf sales. Eine Verwaltungsrolle allein gibt keinen Dokumentenzugriff. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"membership","group":"Vertrieb","member":"lea","add":true}],"alternatives":"Die Gruppenänderung darf vor oder nach der ersten Diagnose erfolgen. Danach zählen aktuelle erlaubte/verweigerte Tests; Administratorrechte sind kein Ersatz. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_write"},"expected":true},{"test":"access","args":{"user":"lea","document":"payroll","operation":"data_read"},"expected":false},{"test":"application","args":{"user":"lea","operation":"orders_write"},"expected":true},{"test":"application","args":{"user":"u60","operation":"orders_read"},"expected":false}],"start":[{"op":"set","path":["groups","Altprojekt"],"value":[]},{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Lea ist aktiv, MFA-fähig und in Vertrieb","expr":{"all":[{"eq":[{"path":["users","lea","active"]},{"literal":true}]},{"eq":[{"path":["users","lea","mfa"]},{"literal":true}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"lea"}]}]}},{"label":"Lea erhält keine Ressourcenverwaltung oder Zugriffszuweisungen","expr":{"eq":[{"privileged_scopes":{"principal":"lea","rights":["manage","assign"]}},{"literal":[]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"orders-app":{"data_read":["offer"],"data_write":[]},"partner":{"data_read":["offer","payroll","public"],"data_write":["offer","payroll","public"]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]},"lea":{"data_read":["offer"],"data_write":["offer"]}}}}],"function":"Microsoft Entra ID → Gruppenmitgliedschaft; Als Benutzer testen","terms":[{"term":"Gruppe","meaning":"Identitäten mit gemeinsam zugewiesenen Rechten."},{"term":"Datenrolle","meaning":"Erlaubt Dokumentenaktionen unabhängig von Ressourcenverwaltung."}],"variants":[{"label":"Ist-Zugriff zuerst nachweisen","rationale":"Die Anfangsdiagnose dokumentiert die Ursache; nach der Gruppenänderung sind frische Tests nötig.","actions":[{"action":"diagnose","test":"access","args":{"user":"lea","document":"offer","operation":"data_write"}},{"action":"membership","group":"Vertrieb","member":"lea","add":true}]}],"failures":[{"label":"Nur Verwaltung statt Datenzugriff","rationale":"Contributor ersetzt die Vertriebsmitgliedschaft nicht.","actions":[{"action":"role_add","principal":"lea","role":"Contributor","scope":"storage"}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"membership","group":"Vertrieb","member":"lea","add":true},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Leas erster Angebotsbearbeitung; etwa 10 Minuten, keine Echtzeitsperre. Angebote bearbeiten, keine Personaldaten, Verwaltung oder Zuweisungsrechte. Keine neuen Ressourcen nötig."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Lea kann das Angebot nicht bearbeiten. Bitte kläre Netzwerk, Anmeldung und Gruppenrechte und ermögliche den Vertriebskollegen die Bearbeitung ohne Zugriff auf Personaldaten."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Dienst und Vertriebsrolle existieren; Lea fehlt in Vertrieb. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {
      "id": "01",
      "title": "Cloud-Modell für die Büro-Suite",
      "sender": "Geschäftsführung",
      "message": "Wir benötigen eine Büro-Suite für 60 Personen. Wähle eine passende externe SaaS-Lösung und dokumentiere unsere verbleibende Verantwortung für Konten, Zugriffe und Daten.",
      "minutes": 12,
      "prerequisite": "Einstieg",
      "learning": "Cloud-Grundlagen; IaaS/PaaS/SaaS",
      "learn": "Du lernst, fertige Cloud-Software von eigener Server- und Anwendungsverwaltung zu unterscheiden.",
      "try_text": "Du probierst die Modellwahl für einen vorhandenen externen Dienst und erläuterst verbleibende Firmenaufgaben.",
      "deadline": "Vor der Entscheidung über die Büro-Suite; etwa 12 Minuten.",
      "constraints": "60 Personen brauchen eine fertige Büro-Suite. Konten, Freigaben und Daten bleiben Firmenaufgabe.",
      "initial": "Eine externe Büro-SaaS ist vorhanden; die eigene VM betreibt Aufträge, keine fertige Büro-Suite.",
      "hints": [
        "Braucht die Firma fertige Software oder nur Serverkapazität?",
        "Öffne Büro-Suite und vergleiche Anbieterbetrieb mit den VM-Einstellungen.",
        "Dokumentiere office_model = SaaS. Erläutere Identitäten, Freigaben und Daten in der Rückmeldung."
      ],
      "explanation": "SaaS wird vom Anbieter betrieben; das Unternehmen verwaltet weiterhin Identitäten, Freigaben und Daten. IaaS: zusätzlich Betriebssystem; PaaS: Anwendung und Konfiguration.",
      "solution": [
        {
          "action": "decision",
          "key": "office_model",
          "value": "SaaS"
        }
      ],
      "alternatives": "Unterschiedliche Begründungen sind möglich. Bei dieser vorhandenen Büro-Suite ist SaaS die Modellwahl; eine IaaS/PaaS-Beschriftung erzeugt keine fehlende Büroanwendung.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "SaaS als externer Büro-Dienst ausgewählt",
          "expr": {
            "eq": [
              {
                "path": [
                  "decisions",
                  "office_model"
                ]
              },
              {
                "literal": "SaaS"
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Policy & Datenschutz → Entscheidungen; Ressourcen → externer SaaS-Dienst",
      "terms": [
        {
          "term": "IaaS",
          "meaning": "Infrastruktur als Dienst; die Firma betreibt auch Betriebssystem und Anwendung."
        },
        {
          "term": "PaaS",
          "meaning": "Verwaltete Plattform; die Firma betreibt Anwendung und Konfiguration."
        },
        {
          "term": "SaaS",
          "meaning": "Fertige Software als Dienst; die Firma verantwortet weiterhin Nutzung und Daten."
        }
      ],
      "variants": [
        {
          "label": "Anbietergrenze zuerst untersuchen",
          "rationale": "Die Bestandsaufnahme ist frei; die vorhandene Büro-Suite bleibt SaaS.",
          "actions": [
            {
              "action": "diagnose",
              "test": "connection",
              "args": {
                "host": "saas",
                "port": 443
              }
            },
            {
              "action": "decision",
              "key": "office_model",
              "value": "SaaS"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Beschriftung als fertige Büro-Suite",
          "rationale": "Modellwahl allein erzeugt keine Büroanwendung auf der Auftrags-VM.",
          "actions": [
            {
              "action": "decision",
              "key": "office_model",
              "value": "IaaS"
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor der Entscheidung über die Büro-Suite; etwa 12 Minuten. 60 Personen brauchen eine fertige Büro-Suite. Konten, Freigaben und Daten bleiben Firmenaufgabe."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Wir benötigen eine Büro-Suite für 60 Personen. Wähle eine passende externe SaaS-Lösung und dokumentiere unsere verbleibende Verantwortung für Konten, Zugriffe und Daten."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Eine externe Büro-SaaS ist vorhanden; die eigene VM betreibt Aufträge, keine fertige Büro-Suite. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {"id":"02","title":"Projekt sauber organisieren","sender":"IT-Leitung","message":"Lege rg-neuprojekt in einer erlaubten Region mit Abteilung Vertrieb und verantwortlicher Stelle Projektleitung an. Nutze keine zusätzlichen kostenpflichtigen Ressourcen.","minutes":12,"prerequisite":"Cloud-Modelle","learning":"Ressourcenorganisation; Region; Tags","learn":"Du lernst, Ressourcen nach Region, Abteilung und Verantwortung zu organisieren.","try_text":"Du probierst eine Ressourcengruppe mit zulässiger Region und eindeutiger Zuständigkeit.","deadline":"Vor dem ersten Ressourcenauftrag des Vertriebsprojekts; etwa 12 Minuten.","constraints":"rg-neuprojekt, erlaubte Region, Abteilung Vertrieb, Owner Projektleitung. Für diesen Organisationsauftrag keine weiteren Dienste anlegen. Die Bestandsprüfung erkennt zusätzliche Ressourcen auch bei geringer Prognose. Maßgeblich sind die vorbereiteten Firmenregionen Germany West Central und West Europe und die verpflichtenden Tags. Die Policy nicht um weitere Regionen erweitern oder die Tagpflicht ausschalten, um eine Gruppe passend zu machen. Eine engere Regionsauswahl oder zusätzlicher Schutz vor öffentlichem Zugriff ist zulässig; die Projektregion muss auch zur aktuellen engeren Policy passen.","initial":"Tenant, Subscription und bestehende Gruppen sind da; rg-neuprojekt fehlt.","hints":["Welche Verwaltungsgrenze enthält Ressourcen, ohne selbst eine VM zu sein?","Prüfe erlaubte Regionen unter Policy und Tags bestehender Gruppen. Vergleiche mit der Firmenvorgabe dieses Auftrags: Germany West Central oder West Europe, verpflichtende Tags. Die Richtlinie zur Umgehung zu lockern ist keine saubere Projektorganisation.","Lege rg-neuprojekt in Germany West Central oder West Europe mit Vertrieb und Projektleitung an; kontrolliere den Bestand."],"explanation":"Tenant ist das Identitätsverzeichnis, Subscription die Verwaltungs- und Abrechnungsgrenze, Ressourcengruppe ein Container für Ressourcen. Die Firmenvorgabe des Auftrags bleibt unabhängig von nachträglich gelockerten Policy-Einstellungen. Der Prüfer vergleicht Projektregion und aktuelle Policy mit den ursprünglich freigegebenen Regionen und der Tagpflicht. Reihenfolge der Regionsliste ist unerheblich; eine echte Verschärfung bleibt zulässig.","solution":[{"action":"group_create","id":"rg-neuprojekt","region":"germanywestcentral","department":"Vertrieb","owner":"Projektleitung"}],"alternatives":"Beide erlaubten Regionen sind gültig. Name und Zuständigkeit bleiben vorgegeben; zusätzliche Compute-Ressourcen sind keine notwendige Lösung. Die Policy darf auf eine der beiden freigegebenen Regionen eingeschränkt und öffentlicher Zugriff zusätzlich geschützt werden. Die Projektgruppe muss dann auch diese engere Policy erfüllen. Ein rückgängig gemachter Versuch mit einer neu angelegten eigenen Testressource ersetzt keine notwendige Änderung am vorgesehenen Endzustand und erzwingt keinen Klickpfad.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false}],"start":[{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Ressourcengruppe, erlaubte Region und Tags","expr":{"all":[{"contains":[{"path":["policy","regions"]},{"path":["resource_groups","rg-neuprojekt","region"]}]},{"eq":[{"path":["resource_groups","rg-neuprojekt","department"]},{"literal":"Vertrieb"}]},{"eq":[{"path":["resource_groups","rg-neuprojekt","owner"]},{"literal":"Projektleitung"}]},{"contains":[{"literal":["germanywestcentral","westeurope"]},{"path":["resource_groups","rg-neuprojekt","region"]}]}]}},{"label":"Keine zusätzlichen Ressourcen angelegt","expr":{"eq":[{"count":{"path":["resources"]}},{"literal":7}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Vorgegebene Firmenregionen und Pflicht-Tags nicht abgeschwächt","expr":{"all":[{"nonempty":{"path":["policy","regions"]}},{"not":{"some":{"in":{"path":["policy","regions"]},"as":"region","where":{"not":{"contains":[{"literal":["germanywestcentral","westeurope"]},{"var":["region"]}]}}}}},{"eq":[{"path":["policy","require_tags"]},{"literal":true}]}]}}],"function":"Alle Ressourcen → Ressourcengruppe anlegen","terms":[{"term":"Tenant","meaning":"Identitätsverzeichnis der Lernfirma."},{"term":"Subscription","meaning":"Verwaltungs- und Abrechnungsgrenze."},{"term":"Ressourcengruppe","meaning":"Container zur Organisation von Ressourcen."},{"term":"Tag","meaning":"Beschriftung etwa für Abteilung und Zuständigkeit."}],"variants":[{"label":"Erlaubte Region West Europe","rationale":"Beide Standard-Policy-Regionen erfüllen die Gruppenanforderung.","actions":[{"action":"group_create","id":"rg-neuprojekt","region":"westeurope","department":"Vertrieb","owner":"Projektleitung"}]}],"failures":[{"label":"Falsche Zuständigkeit","rationale":"Owner ist nicht die vereinbarte Projektleitung.","actions":[{"action":"group_create","id":"rg-neuprojekt","region":"germanywestcentral","department":"Vertrieb","owner":"Ungeklärt"}],"outcome":"incomplete"},{"label":"Firmenregion per Policy umgangen","rationale":"Die vorbereitete Firmenvorgabe wird für den Organisationsauftrag nicht gelockert; die Gruppe allein genügt nicht.","outcome":"incomplete","actions":[{"action":"policy","changes":{"regions":["eastus"]}},{"action":"group_create","id":"rg-neuprojekt","region":"eastus","department":"Vertrieb","owner":"Projektleitung"}]},{"label":"Zusätzliche Region trotz gültiger Projektregion freigegeben","rationale":"Die vorbereitete Firmenvorgabe wird für den Organisationsauftrag nicht gelockert; die Gruppe allein genügt nicht.","outcome":"incomplete","actions":[{"action":"policy","changes":{"regions":["germanywestcentral","westeurope","eastus"]}},{"action":"group_create","id":"rg-neuprojekt","region":"germanywestcentral","department":"Vertrieb","owner":"Projektleitung"}]},{"label":"Tagpflicht außerhalb der Projektgruppe aufgehoben","rationale":"Die vorbereitete Firmenvorgabe wird für den Organisationsauftrag nicht gelockert; die Gruppe allein genügt nicht.","outcome":"incomplete","actions":[{"action":"policy","changes":{"require_tags":false}},{"action":"group_create","id":"rg-neuprojekt","region":"germanywestcentral","department":"Vertrieb","owner":"Projektleitung"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor dem ersten Ressourcenauftrag des Vertriebsprojekts; etwa 12 Minuten. rg-neuprojekt, erlaubte Region, Abteilung Vertrieb, Owner Projektleitung. Für diesen Organisationsauftrag keine weiteren Dienste anlegen. Die Bestandsprüfung erkennt zusätzliche Ressourcen auch bei geringer Prognose."},{"id":"bestand","question":"Soll ich für das Projekt gleich eine weitere VM oder Ablage anlegen?","answer":"Nein. In diesem Auftrag geht es nur um die Ressourcengruppe mit Region, Tags und Zuständigkeit. Zusätzliche kostenpflichtige Ressourcen sind nicht beauftragt; der bestehende Ressourcenbestand bleibt erhalten."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Tenant, Subscription und bestehende Gruppen sind da; rg-neuprojekt fehlt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {
      "id": "03",
      "title": "Interner Webdienst ohne offene Administration",
      "sender": "Betriebsleitung",
      "message": "Starte den internen Auftragsdienst für beide Standorte. Port 443 muss erreichbar sein, Port 22 aus dem Internet verweigert bleiben. Monatsprognose höchstens 500 Lern-Euro.",
      "minutes": 18,
      "prerequisite": "Ressourcen und Netzwerke",
      "learning": "Compute; interne Webanwendung; Sicherheit",
      "learn": "Du lernst, einen internen Webdienst mit geschützter Administration bereitzustellen.",
      "try_text": "Du probierst Start, Kapazitätskontrolle und Standortverbindungen bei gesperrtem Internetzugriff.",
      "deadline": "Vor Wiederaufnahme der Auftragsbearbeitung an beiden Standorten; etwa 18 Minuten.",
      "constraints": "Intern auf Port 443, keine öffentliche Web-IP oder VM-Administration; höchstens 500 Lern-Euro Monatsprognose.",
      "initial": "Web ist gestoppt; private Netze, DNS und Datenabhängigkeiten sind vorbereitet.",
      "hints": [
        "Wo endet der Pfad zu einer ausgeschalteten VM?",
        "Prüfe DNS/Route, dann Betriebszustand und Port von web sowie Datenbank/Ablage.",
        "Starte web. Prüfe Hauptstandort und Außenstelle auf 443, Internet-Port 22 verweigert und Monatsprognose innerhalb Budget."
      ],
      "explanation": "Der Dienst braucht Betrieb, Netzpfad, Datenbank und Ablage. Eine private Webanwendung benötigt keine öffentliche Administrationsfreigabe.",
      "solution": [
        {
          "action": "power",
          "id": "web",
          "operation": "start"
        }
      ],
      "alternatives": "B2 mit einer Instanz und B1 mit zwei Instanzen tragen die Ausgangslast. Beide müssen dieselben Schutz- und Budgetkriterien erfüllen.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "operation": "orders_read"
          },
          "expected": true
        },
        {
          "test": "application",
          "args": {
            "user": "partner",
            "operation": "orders_write"
          },
          "expected": false
        },
        {
          "test": "connection",
          "args": {
            "source": "branch",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "web",
            "status"
          ],
          "value": "stopped"
        },
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Budget maximal 500 Lern-Euro/Monat",
          "expr": {
            "lte": [
              {
                "monthly": true
              },
              {
                "literal": 500
              }
            ]
          }
        },
        {
          "label": "Interner Dienst ohne öffentliche IP",
          "expr": {
            "eq": [
              {
                "path": [
                  "resources",
                  "web",
                  "public_ip"
                ]
              },
              {
                "literal": ""
              }
            ]
          }
        },
        {
          "label": "Tatsächlich gewählter Auftragsendpunkt bleibt privat",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "target_property": {
                      "host": "auftrag.intern",
                      "name": "public_ip"
                    }
                  },
                  {
                    "literal": ""
                  }
                ]
              },
              {
                "any_of": [
                  {
                    "eq": [
                      {
                        "target_property": {
                          "host": "auftrag.intern",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "VM"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "target_property": {
                          "host": "auftrag.intern",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "App Service"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Alle Ressourcen → VM starten; Virtual Network → Verbindung prüfen",
      "terms": [
        {
          "term": "VM (virtuelle Maschine)",
          "meaning": "Simulierter Server mit Betriebssystem, Rechenkapazität, Datenträger und Netzanschluss; hier keine echte Virtualisierung."
        },
        {
          "term": "Port",
          "meaning": "Nummer eines Dienstzugangs, hier 443."
        },
        {
          "term": "Private IP",
          "meaning": "Adresse im verbundenen privaten Netz ohne eigenen Internet-Endpunkt."
        },
        {
          "term": "Compute-Zuordnung",
          "meaning": "Bereitgestellte Rechenkapazität, auch bei OS-Shutdown berechenbar."
        }
      ],
      "variants": [
        {
          "label": "Zwei kleinere Instanzen",
          "rationale": "B1 mit zwei Instanzen hat im Modell dieselbe CPU-Gesamtkapazität wie eine B2-Instanz.",
          "actions": [
            {
              "action": "configure",
              "id": "web",
              "changes": {
                "size": "B1",
                "instances": 2
              }
            },
            {
              "action": "power",
              "id": "web",
              "operation": "start"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Dienst bleibt aus",
          "rationale": "Netzpfad ersetzt keine laufende Anwendung.",
          "actions": [
            {
              "action": "power",
              "id": "web",
              "operation": "shutdown"
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor Wiederaufnahme der Auftragsbearbeitung an beiden Standorten; etwa 18 Minuten. Intern auf Port 443, keine öffentliche Web-IP oder VM-Administration; höchstens 500 Lern-Euro Monatsprognose."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Starte den internen Auftragsdienst für beide Standorte. Port 443 muss erreichbar sein, Port 22 aus dem Internet verweigert bleiben. Monatsprognose höchstens 500 Lern-Euro."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Web ist gestoppt; private Netze, DNS und Datenabhängigkeiten sind vorbereitet. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {
      "id": "04",
      "title": "DNS-Fehler eingrenzen",
      "sender": "Vertrieb",
      "message": "auftrag.intern ist nicht erreichbar. Finde den ersten Fehler im Pfad und repariere nur die Namenszuordnung. Teste danach den erlaubten und den unerlaubten Pfad.",
      "minutes": 15,
      "prerequisite": "Netzpfad",
      "learning": "DNS; Routing; NSG-Diagnose",
      "learn": "Du lernst, einen Verbindungsfehler vom Namen bis zum Dienst einzugrenzen.",
      "try_text": "Du probierst die Schichtenfolge vom Namen zum Dienst und reparierst den ersten Fehler.",
      "deadline": "Vor dem nächsten Vertriebsabruf; etwa 15 Minuten.",
      "constraints": "Nur die Namenszuordnung reparieren, keine pauschale NSG-Freigabe oder Veröffentlichung. Nur die DNS-Zuordnung darf fachliche Konfiguration ändern; Notizen, Begründung und Diagnosen sind frei.",
      "initial": "auftrag.intern fehlt in DNS; Weblaufzeit und privater Pfad sind intakt.",
      "hints": [
        "Kann ein Server über einen unbekannten Namen erreicht werden?",
        "Vergleiche auftrag.intern mit Ressourcenkennung web; der Namensversuch scheitert zuerst bei DNS.",
        "Setze auftrag.intern auf web oder dessen zugewiesene private IP. Teste erlaubten Standort- und verweigerten Administrationspfad."
      ],
      "explanation": "DNS löst Namen auf. Eine korrekte Route oder NSG kann einen fehlenden DNS-Eintrag nicht ersetzen.",
      "solution": [
        {
          "action": "network",
          "changes": {
            "dns": {
              "auftrag.intern": "web",
              "daten.intern": "db",
              "ablage.intern": "storage",
              "versand.intern": "container"
            }
          }
        }
      ],
      "alternatives": "Ressourcenalias und passende private IP sind zulässige Ziele. Ein Neustart ohne DNS-Eintrag behebt diese Störung nicht.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "remove",
          "path": [
            "network",
            "dns",
            "auftrag.intern"
          ]
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Außer DNS bleibt der fachliche Ausgangsbestand unverändert",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "resources"
                    ]
                  },
                  {
                    "literal": {
                      "web": {
                        "name": "vm-auftrag",
                        "kind": "VM",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.10",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "db": {
                        "name": "db-auftrag",
                        "kind": "Database",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.2.20",
                        "port": 5432,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "data",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "storage": {
                        "name": "stnordlicht",
                        "kind": "Storage",
                        "group": "rg-data",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.2.30",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "data",
                        "public_ip": "198.51.100.30",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "testvm": {
                        "name": "vm-altprojekt",
                        "kind": "VM",
                        "group": "rg-lab",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "D4",
                        "status": "stopped",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.11",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "paas": {
                        "name": "app-auftrag",
                        "kind": "App Service",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "stopped",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.40",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "container": {
                        "name": "ca-versand",
                        "kind": "Container Apps",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.50",
                        "port": 8080,
                        "image": "shipping:broken",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "saas": {
                        "name": "Büro-Suite (externer Anbieter)",
                        "kind": "SaaS",
                        "group": "rg-lab",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 0,
                        "ip": "",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "users"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "name": "Person 01 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u02": {
                        "name": "Person 02 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u03": {
                        "name": "Person 03 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u04": {
                        "name": "Person 04 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u05": {
                        "name": "Person 05 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u06": {
                        "name": "Person 06 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u07": {
                        "name": "Person 07 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u08": {
                        "name": "Person 08 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u09": {
                        "name": "Person 09 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u10": {
                        "name": "Person 10 (fiktiv)",
                        "department": "Geschäftsführung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u11": {
                        "name": "Person 11 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u12": {
                        "name": "Person 12 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u13": {
                        "name": "Person 13 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u14": {
                        "name": "Person 14 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u15": {
                        "name": "Person 15 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u16": {
                        "name": "Person 16 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u17": {
                        "name": "Person 17 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u18": {
                        "name": "Person 18 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u19": {
                        "name": "Person 19 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u20": {
                        "name": "Person 20 (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u21": {
                        "name": "Person 21 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u22": {
                        "name": "Person 22 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u23": {
                        "name": "Person 23 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u24": {
                        "name": "Person 24 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u25": {
                        "name": "Person 25 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u26": {
                        "name": "Person 26 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u27": {
                        "name": "Person 27 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u28": {
                        "name": "Person 28 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u29": {
                        "name": "Person 29 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u30": {
                        "name": "Person 30 (fiktiv)",
                        "department": "Personal",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u31": {
                        "name": "Person 31 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u32": {
                        "name": "Person 32 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u33": {
                        "name": "Person 33 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u34": {
                        "name": "Person 34 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u35": {
                        "name": "Person 35 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u36": {
                        "name": "Person 36 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u37": {
                        "name": "Person 37 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u38": {
                        "name": "Person 38 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u39": {
                        "name": "Person 39 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u40": {
                        "name": "Person 40 (fiktiv)",
                        "department": "Buchhaltung",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u41": {
                        "name": "Person 41 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u42": {
                        "name": "Person 42 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u43": {
                        "name": "Person 43 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u44": {
                        "name": "Person 44 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u45": {
                        "name": "Person 45 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u46": {
                        "name": "Person 46 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u47": {
                        "name": "Person 47 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u48": {
                        "name": "Person 48 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u49": {
                        "name": "Person 49 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u50": {
                        "name": "Person 50 (fiktiv)",
                        "department": "Betrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u51": {
                        "name": "Person 51 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u52": {
                        "name": "Person 52 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u53": {
                        "name": "Person 53 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u54": {
                        "name": "Person 54 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u55": {
                        "name": "Person 55 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u56": {
                        "name": "Person 56 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u57": {
                        "name": "Person 57 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u58": {
                        "name": "Person 58 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u59": {
                        "name": "Person 59 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "u60": {
                        "name": "Person 60 (fiktiv)",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "lea": {
                        "name": "Lea Neumann (fiktiv)",
                        "department": "Vertrieb",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User"
                      },
                      "partner": {
                        "name": "Robin Extern (fiktiv)",
                        "department": "Dienstleister",
                        "active": true,
                        "mfa": true,
                        "guest": true,
                        "expires": 480,
                        "directory_role": "User"
                      },
                      "it": {
                        "name": "IT-Lernrolle",
                        "department": "IT",
                        "active": true,
                        "mfa": true,
                        "guest": false,
                        "expires": 0,
                        "directory_role": "User Administrator"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "IT": [
                        "it"
                      ],
                      "Altprojekt": [
                        "lea"
                      ],
                      "Partner": [
                        "partner"
                      ]
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "roles"
                    ]
                  },
                  {
                    "literal": [
                      {
                        "principal": "IT",
                        "role": "Contributor",
                        "scope": "subscription"
                      },
                      {
                        "principal": "IT",
                        "role": "User Access Administrator",
                        "scope": "subscription"
                      },
                      {
                        "principal": "Vertrieb",
                        "role": "Blob Contributor",
                        "scope": "sales"
                      },
                      {
                        "principal": "Altprojekt",
                        "role": "Blob Reader",
                        "scope": "sales"
                      },
                      {
                        "principal": "partner",
                        "role": "Blob Contributor",
                        "scope": "storage"
                      },
                      {
                        "principal": "lea",
                        "role": "Reader",
                        "scope": "storage"
                      },
                      {
                        "principal": "Vertrieb",
                        "role": "Order Operator",
                        "scope": "orders"
                      },
                      {
                        "principal": "orders-app",
                        "role": "Order Operator",
                        "scope": "orders"
                      },
                      {
                        "principal": "orders-app",
                        "role": "Blob Reader",
                        "scope": "sales"
                      }
                    ]
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "service_principals"
                    ]
                  },
                  {
                    "literal": {
                      "orders-app": {
                        "name": "Dienstidentität der Auftragsanwendung",
                        "active": true
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "application"
                    ]
                  },
                  {
                    "literal": {
                      "name": "Nordlicht Aufträge",
                      "principal": "orders-app"
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "NL-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Arbeitsplatz-Erweiterung",
                        "amount": 120.0,
                        "status": "Neu",
                        "document": "offer",
                        "modified": 0,
                        "version": 1
                      },
                      "NL-1002": {
                        "customer": "Fiktiv: Beispielhandel KG",
                        "subject": "Standortanbindung planen",
                        "amount": 240.0,
                        "status": "In Bearbeitung",
                        "document": "offer",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "order_revision"
                    ]
                  },
                  {
                    "literal": 0
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "name": "Angebot-A.txt",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Angebot A: 120 Lern-Euro; Version 1.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "payroll": {
                        "name": "Personal-B.txt",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Fiktive Personalnotiz B; keine echten Personendaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "public": {
                        "name": "Firmeninfo.txt",
                        "container": "public",
                        "class": "öffentlich",
                        "content": "Nordlicht: 60 fiktive Beschäftigte.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "data_governance"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "owner": "Vertrieb",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "offer",
                        "status": "active"
                      },
                      "payroll": {
                        "owner": "IT",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "payroll",
                        "status": "active"
                      },
                      "public": {
                        "owner": "IT",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "public",
                        "status": "active"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "document_storage"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "kind": "Blob",
                        "host": "storage"
                      },
                      "payroll": {
                        "kind": "Blob",
                        "host": "storage"
                      },
                      "public": {
                        "kind": "Blob",
                        "host": "storage"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "policy"
                    ]
                  },
                  {
                    "literal": {
                      "regions": [
                        "germanywestcentral",
                        "westeurope"
                      ],
                      "require_tags": true,
                      "deny_public": false
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "requests"
                    ]
                  },
                  {
                    "literal": {
                      "active": "",
                      "deployments": {},
                      "company": {},
                      "provider": {}
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "workload"
                    ]
                  },
                  {
                    "literal": 70
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "budget"
                    ]
                  },
                  {
                    "literal": 200.0
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "network",
                      "vnet"
                    ]
                  },
                  {
                    "literal": "10.20.0.0/16"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "network",
                      "subnets"
                    ]
                  },
                  {
                    "literal": {
                      "app": "10.20.1.0/24",
                      "data": "10.20.2.0/24"
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "network",
                      "onprem"
                    ]
                  },
                  {
                    "literal": "10.10.0.0/16"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "network",
                      "vpn"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "network",
                      "rules"
                    ]
                  },
                  {
                    "literal": [
                      {
                        "id": "web-in",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "source": "10.10.0.0/16",
                        "destination": "web",
                        "port": 443,
                        "action": "Allow",
                        "priority": 200
                      },
                      {
                        "id": "storage-in",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "source": "*",
                        "destination": "storage",
                        "port": 443,
                        "action": "Allow",
                        "priority": 210
                      }
                    ]
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 240
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Virtual Network → DNS-Zuordnung; Verbindungspfad",
      "terms": [
        {
          "term": "DNS",
          "meaning": "Ordnet Namen Ressourcen oder zugewiesenen IPs zu."
        },
        {
          "term": "Route",
          "meaning": "Verfügbarer Netzpfad zwischen Quelle und Ziel."
        },
        {
          "term": "NSG",
          "meaning": "Netzwerk-Sicherheitsgruppe für neue Verbindungen nach Regelpriorität."
        }
      ],
      "variants": [
        {
          "label": "DNS auf zugewiesene private IP",
          "rationale": "Der Resolver erkennt die Adresse als dieselbe tatsächliche Ressource.",
          "actions": [
            {
              "action": "network",
              "changes": {
                "dns": {
                  "auftrag.intern": {
                    "$state": [
                      "resources",
                      "web",
                      "ip"
                    ]
                  },
                  "daten.intern": "db",
                  "ablage.intern": "storage",
                  "versand.intern": "container"
                }
              }
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Nur Server starten",
          "rationale": "DNS bleibt die erste Störung.",
          "actions": [
            {
              "action": "power",
              "id": "web",
              "operation": "start"
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor dem nächsten Vertriebsabruf; etwa 15 Minuten. Nur die Namenszuordnung reparieren, keine pauschale NSG-Freigabe oder Veröffentlichung. Nur die DNS-Zuordnung darf fachliche Konfiguration ändern; Notizen, Begründung und Diagnosen sind frei."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "auftrag.intern ist nicht erreichbar. Finde den ersten Fehler im Pfad und repariere nur die Namenszuordnung. Teste danach den erlaubten und den unerlaubten Pfad."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. auftrag.intern fehlt in DNS; Weblaufzeit und privater Pfad sind intakt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {
      "id": "05",
      "title": "Außenstelle wieder anbinden",
      "sender": "Außenstelle",
      "message": "Seit der Verbindungsstörung erreicht unser Standort die Auftragsanwendung nicht. Stelle das VPN wieder her; veröffentliche den Dienst nicht im Internet.",
      "minutes": 15,
      "prerequisite": "Netzpfad",
      "learning": "Hybride Infrastruktur; VPN; On-Premises",
      "learn": "Du lernst, warum private Standorte eine funktionierende Netzverbindung benötigen.",
      "try_text": "Du probierst eine Routenstörung und die erneute Prüfung beider Standorte.",
      "deadline": "Vor der nächsten Auftragsbearbeitung in der Außenstelle; etwa 15 Minuten.",
      "constraints": "VPN und beide Standorte prüfen. Keine öffentliche IP als Ersatz für die private Standortverbindung.",
      "initial": "Das VPN ist unterbrochen; DNS, Dienste und Datenrollen sind vorbereitet.",
      "hints": [
        "Welche gemeinsame Verbindung benötigen die privaten Standorte?",
        "VPN ist der erste Fehler; Datenrollen oder Portfreigaben reparieren diese Route nicht.",
        "Verbinde das Standort-VPN. Prüfe beide Standorte auf auftrag.intern:443, ohne öffentliche IP oder Internet-Administration."
      ],
      "explanation": "Das Standort-VPN verbindet die privaten Netze. Entra ID ersetzt dabei nicht AD DS mit Domänenbeitritt und Gruppenrichtlinien.",
      "solution": [
        {
          "action": "network",
          "changes": {
            "vpn": true
          }
        }
      ],
      "alternatives": "Die Diagnose kann am Hauptstandort oder in der Außenstelle beginnen. Beide müssen danach funktionieren; ein öffentlicher Umweg genügt nicht.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "operation": "orders_read"
          },
          "expected": true
        },
        {
          "test": "application",
          "args": {
            "user": "partner",
            "operation": "orders_write"
          },
          "expected": false
        },
        {
          "test": "connection",
          "args": {
            "source": "branch",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "network",
            "vpn"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Interner Dienst ohne öffentliche IP",
          "expr": {
            "eq": [
              {
                "path": [
                  "resources",
                  "web",
                  "public_ip"
                ]
              },
              {
                "literal": ""
              }
            ]
          }
        },
        {
          "label": "Tatsächlich gewählter Auftragsendpunkt bleibt privat",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "target_property": {
                      "host": "auftrag.intern",
                      "name": "public_ip"
                    }
                  },
                  {
                    "literal": ""
                  }
                ]
              },
              {
                "any_of": [
                  {
                    "eq": [
                      {
                        "target_property": {
                          "host": "auftrag.intern",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "VM"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "target_property": {
                          "host": "auftrag.intern",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "App Service"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Private Standortverbindung tatsächlich wieder verbunden",
          "expr": {
            "eq": [
              {
                "path": [
                  "network",
                  "vpn"
                ]
              },
              {
                "literal": true
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Virtual Network → Standort-VPN",
      "terms": [
        {
          "term": "On-Premises",
          "meaning": "Infrastruktur am eigenen Standort."
        },
        {
          "term": "Standort-VPN",
          "meaning": "Vereinfachte private Verbindung zum VNet."
        },
        {
          "term": "VNet",
          "meaning": "Virtuelles Netz mit privaten Subnetzen."
        }
      ],
      "variants": [
        {
          "label": "Außenstelle zuerst diagnostizieren",
          "rationale": "Der erste Fehler bleibt die private Standortverbindung.",
          "actions": [
            {
              "action": "diagnose",
              "test": "connection",
              "args": {
                "source": "branch",
                "host": "auftrag.intern",
                "port": 443
              }
            },
            {
              "action": "network",
              "changes": {
                "vpn": true
              }
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Öffentlich statt VPN",
          "rationale": "Privater Standortpfad bleibt kaputt; Schutzvorgabe verletzt.",
          "actions": [
            {
              "action": "configure",
              "id": "web",
              "changes": {
                "public_ip": "198.51.100.10"
              }
            },
            {
              "action": "rule_add",
              "rule": {
                "id": "public-detour",
                "direction": "Inbound",
                "protocol": "TCP",
                "source": "Internet",
                "destination": "web",
                "port": 443,
                "action": "Allow",
                "priority": 300
              }
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor der nächsten Auftragsbearbeitung in der Außenstelle; etwa 15 Minuten. VPN und beide Standorte prüfen. Keine öffentliche IP als Ersatz für die private Standortverbindung."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Seit der Verbindungsstörung erreicht unser Standort die Auftragsanwendung nicht. Stelle das VPN wieder her; veröffentliche den Dienst nicht im Internet."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Das VPN ist unterbrochen; DNS, Dienste und Datenrollen sind vorbereitet. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {"id":"06","title":"Leas Eintritt vorbereiten","sender":"Personal","message":"Lea beginnt im Vertrieb. Aktiviere ihr Konto, verlange den simulierten MFA-Nachweis und richte Gruppenrechte für Angebote ein. Personaldaten bleiben gesperrt.","minutes":18,"prerequisite":"Gruppenrechte","learning":"Entra ID; Eintritt; MFA","learn":"Du lernst, Kontoaktivierung, zusätzliche Anmeldung und Gruppenrechte für einen Eintritt vorzubereiten.","try_text":"Du probierst Konto, Lern-MFA und Datenrolle als getrennte Eintrittsvoraussetzungen.","deadline":"Vor Leas erstem Vertriebsarbeitstag; etwa 18 Minuten.","constraints":"Aktives Konto, Lern-MFA und gruppenbasierte Angebotsrechte; Personaldaten und fremde Rechte bleiben geschützt. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Lea ist gesperrt, MFA fehlt und Vertrieb ist noch nicht zugeordnet.","hints":["Reichen Rechte, wenn sich das Konto nicht anmelden darf?","Prüfe Kontostatus/MFA, danach Gruppe und effektive Datenrechte. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Aktiviere Lea und den Lern-MFA-Nachweis; füge sie zu Vertrieb hinzu. Prüfe Angebote, verweigerte Personaldaten und die Anwendung neu."],"explanation":"Anmeldung und Datenfreigabe sind unabhängig. MFA ist ein zweiter Nachweis in der Lernwelt, kein echtes Kennwort und kein echter Code. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"user","id":"lea","changes":{"active":true,"mfa":true}},{"action":"membership","group":"Vertrieb","member":"lea","add":true}],"alternatives":"Gruppenrechte dürfen vor der Aktivierung vorbereitet werden. Erst Anmeldung plus positive/negative Datenprüfungen bestätigen den arbeitsfähigen Zustand. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_write"},"expected":true},{"test":"access","args":{"user":"lea","document":"payroll","operation":"data_read"},"expected":false},{"test":"application","args":{"user":"lea","operation":"orders_write"},"expected":true},{"test":"application","args":{"user":"u60","operation":"orders_read"},"expected":false}],"start":[{"op":"set","path":["groups","Altprojekt"],"value":[]},{"op":"set","path":["users","lea","active"],"value":false},{"op":"set","path":["users","lea","mfa"],"value":false},{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Lea ist aktiv, MFA-fähig und in Vertrieb","expr":{"all":[{"eq":[{"path":["users","lea","active"]},{"literal":true}]},{"eq":[{"path":["users","lea","mfa"]},{"literal":true}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"lea"}]}]}},{"label":"Lea erhält keine Ressourcenverwaltung oder Zugriffszuweisungen","expr":{"eq":[{"privileged_scopes":{"principal":"lea","rights":["manage","assign"]}},{"literal":[]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"orders-app":{"data_read":["offer"],"data_write":[]},"partner":{"data_read":["offer","payroll","public"],"data_write":["offer","payroll","public"]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]},"lea":{"data_read":["offer"],"data_write":["offer"]}}}}],"function":"Microsoft Entra ID → Benutzer, MFA und Gruppen","terms":[{"term":"Identität","meaning":"Darstellung einer Person oder eines Dienstes."},{"term":"MFA","meaning":"Zusätzlicher simulierter Anmeldenachweis; keine echten Codes."},{"term":"Mitgliedschaft","meaning":"Verknüpft eine Identität mit Gruppenrechten."}],"variants":[{"label":"Rechte vor Aktivierung vorbereiten","rationale":"Das gesperrte Konto kann erst nach vollständiger Einrichtung produktiv arbeiten.","actions":[{"action":"membership","group":"Vertrieb","member":"lea","add":true},{"action":"user","id":"lea","changes":{"active":true,"mfa":true}}]}],"failures":[{"label":"Eintritt ohne MFA","rationale":"Aktives Konto und Gruppe ersetzen den Nachweis nicht.","actions":[{"action":"membership","group":"Vertrieb","member":"lea","add":true},{"action":"user","id":"lea","changes":{"active":true,"mfa":false}}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"user","id":"lea","changes":{"active":true,"mfa":true}},{"action":"membership","group":"Vertrieb","member":"lea","add":true},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Leas erstem Vertriebsarbeitstag; etwa 18 Minuten. Aktives Konto, Lern-MFA und gruppenbasierte Angebotsrechte; Personaldaten und fremde Rechte bleiben geschützt."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Lea beginnt im Vertrieb. Aktiviere ihr Konto, verlange den simulierten MFA-Nachweis und richte Gruppenrechte für Angebote ein. Personaldaten bleiben gesperrt."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Lea ist gesperrt, MFA fehlt und Vertrieb ist noch nicht zugeordnet. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {"id":"07","title":"Partner auf ein Angebot begrenzen","sender":"Datenschutz","message":"Robin darf ausschließlich Angebot A lesen, bis Simulationsminute 480. Er darf Personal-B weder lesen noch verändern und keine Rechte weitergeben.","minutes":22,"prerequisite":"Datenrollen","learning":"Gast; minimale Rechte; Ablauf","learn":"Du lernst, einem externen Partner nur den benötigten zeitlich begrenzten Lesezugriff zu geben.","try_text":"Du probierst den Ersatz einer breiten Rolle durch eine minimale zeitliche Lesefreigabe.","deadline":"Gastfreigabe endet bei Simulationsminute 480; etwa 22 Minuten Einrichtung.","constraints":"Robin liest nur A, ändert nichts, sieht keine Personaldaten und weist keine Rechte zu. Breite Datenpfade entfernen. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Blob Contributor auf storage ist zu breit; die Gastlaufzeit ist bereits begrenzt.","hints":["Zieht eine engere Rolle automatisch eine breitere ab?","Prüfe effektive Rollen auf A und Personal-B; suche den direkten Storage-Contributor-Pfad. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Entferne Blob Contributor auf storage und gib Blob Reader auf offer direkt oder über Partner. Prüfe Lesen, Schreiben, Personalzugriff und Weitergabe."],"explanation":"Ein auf Dokument A begrenzter Lesepfad erlaubt weder Schreiben noch Zugriff auf B. Nach Ablauf wird die Gastanmeldung verweigert. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"}],"alternatives":"Direkte Rolle und Partnergruppenrolle auf offer sind gültig. Dokument-Scopes sind hier vereinfacht; der alte breite Pfad muss immer entfallen. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"partner","document":"offer","operation":"data_read"},"expected":true},{"test":"access","args":{"user":"partner","document":"offer","operation":"data_write"},"expected":false},{"test":"access","args":{"user":"partner","document":"payroll","operation":"data_read"},"expected":false},{"test":"access","args":{"user":"partner","document":"payroll","operation":"data_write"},"expected":false},{"test":"access","args":{"user":"partner","document":"offer","operation":"assign"},"expected":false}],"start":[{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Partner hat keine Ressourcen- oder Zuweisungsrechte","expr":{"all":[{"not":{"contains":[{"rights":{"principal":"partner","target":"offer"}},{"literal":"manage"}]}},{"not":{"contains":[{"rights":{"principal":"partner","target":"offer"}},{"literal":"assign"}]}}]}},{"label":"Gastfreigabe endet bei Minute 480","expr":{"all":[{"eq":[{"path":["users","partner","guest"]},{"literal":true}]},{"eq":[{"path":["users","partner","expires"]},{"literal":480}]}]}},{"label":"Partner hat keinerlei Verwaltungs-/Zuweisungsrechte","expr":{"eq":[{"privileged_scopes":{"principal":"partner","rights":["manage","assign"]}},{"literal":[]}]}},{"label":"Partner-Datenrollen gelten ausschließlich zum Lesen von Angebot A","expr":{"all":[{"eq":[{"data_targets":{"principal":"partner","right":"data_read"}},{"literal":["offer"]}]},{"eq":[{"data_targets":{"principal":"partner","right":"data_write"}},{"literal":[]}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"lea":{"data_read":["offer"],"data_write":[]},"orders-app":{"data_read":["offer"],"data_write":[]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]},"partner":{"data_read":["offer"],"data_write":[]}}}}],"function":"Microsoft Entra ID → Gastablauf und dokumentbegrenzte Datenrolle","terms":[{"term":"Gast","meaning":"Externe fiktive Identität mit Ablauf."},{"term":"Scope","meaning":"Geltungsbereich einer Rolle mit möglicher Vererbung."},{"term":"Minimale Rechte","meaning":"Nur die konkret benötigten Aktionen erlauben."}],"variants":[{"label":"Partnergruppe statt Direktrolle","rationale":"Gleicher enger Scope, alter breiter direkter Pfad entfällt.","actions":[{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"Partner","role":"Blob Reader","scope":"offer"}]}],"failures":[{"label":"Enges Recht zum breiten hinzufügen","rationale":"Der alte Schreib-/Personaldatenpfad bleibt additiv bestehen.","actions":[{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Gastfreigabe endet bei Simulationsminute 480; etwa 22 Minuten Einrichtung. Robin liest nur A, ändert nichts, sieht keine Personaldaten und weist keine Rechte zu. Breite Datenpfade entfernen."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Robin darf ausschließlich Angebot A lesen, bis Simulationsminute 480. Er darf Personal-B weder lesen noch verändern und keine Rechte weitergeben."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Blob Contributor auf storage ist zu breit; die Gastlaufzeit ist bereits begrenzt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {"id":"08","title":"Verbliebenen Zugriff finden","sender":"Datenschutz","message":"Leas Angebotszugriff soll enden. Entferne zunächst ihre direkte Angebotsrolle und prüfe erneut: Ein verbliebener Gruppenpfad kann den Zugriff weiterhin erlauben. Entziehe auch diesen Weg gezielt, ohne den Vertriebskollegen den benötigten Zugriff zu nehmen.","minutes":20,"prerequisite":"Vererbung","learning":"Azure RBAC; Gruppen; Entzug","learn":"Du lernst, mehrere gleichzeitig wirksame Zugriffspfade zu erkennen und gezielt zu entziehen.","try_text":"Du probierst additive Rechte und den Nachweis eines verbliebenen Zugriffspfads.","deadline":"Vor weiterer Nutzung der alten Projektfreigabe; etwa 20 Minuten.","constraints":"Alle Angebotslesepfade für Lea entziehen, Betriebszugriffe anderer Abteilungen erhalten. Vertriebszugriffe von u11 und u12 müssen erhalten bleiben. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Ein direkter und ein Altprojekt-Gruppenpfad erlauben A.","hints":["Können mehrere Rollen denselben Zugriff erlauben?","Entferne den direkten Pfad und prüfe erneut; Altprojekt bleibt sichtbar. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Entferne Direktrolle und Altprojekt-Mitgliedschaft. In dieser Ein-Personen-Gruppe darf alternativ ihre verwaiste Datenrolle entfallen; prüfe den Entzug frisch."],"explanation":"Direkte und gruppenbasierte Rollen werden vereinigt und vom Scope vererbt. Das Entfernen einer Rolle beseitigt andere Zugriffspfade nicht. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"role_remove","principal":"lea","role":"Blob Reader","scope":"offer"},{"action":"membership","group":"Altprojekt","member":"lea","add":false}],"alternatives":"Bevorzugt wird nur Leas Mitgliedschaft entfernt. Die Gruppenrolle darf entfallen, wenn die ganze Ein-Personen-Freigabe hinfällig ist; weitere Mitglieder wären zuerst zu prüfen. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_read"},"expected":false},{"test":"access","args":{"user":"u11","document":"offer","operation":"data_write"},"expected":true},{"test":"access","args":{"user":"u12","document":"offer","operation":"data_write"},"expected":true}],"start":[{"op":"set","path":["resources","storage","public"],"value":false},{"op":"set","path":["roles"],"value":[{"principal":"IT","role":"Contributor","scope":"subscription"},{"principal":"IT","role":"User Access Administrator","scope":"subscription"},{"principal":"Vertrieb","role":"Blob Contributor","scope":"sales"},{"principal":"Altprojekt","role":"Blob Reader","scope":"sales"},{"principal":"partner","role":"Blob Contributor","scope":"storage"},{"principal":"lea","role":"Reader","scope":"storage"},{"principal":"Vertrieb","role":"Order Operator","scope":"orders"},{"principal":"orders-app","role":"Order Operator","scope":"orders"},{"principal":"orders-app","role":"Blob Reader","scope":"sales"},{"principal":"lea","role":"Blob Reader","scope":"offer"}]}],"setup":[],"criteria":[{"label":"Kein verbleibender Datenpfad für Lea","expr":{"not":{"contains":[{"rights":{"principal":"lea","target":"offer"}},{"literal":"data_read"}]}}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"orders-app":{"data_read":["offer"],"data_write":[]},"partner":{"data_read":["offer","payroll","public"],"data_write":["offer","payroll","public"]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]}}}}],"function":"Microsoft Entra ID → Rollen und Gruppen entziehen; effektive Pfade prüfen","terms":[{"term":"Vererbung","meaning":"Ein übergeordneter Scope wirkt auf eingeschlossene Ziele."},{"term":"Additive Rechte","meaning":"Mehrere Wege werden vereinigt; ein verbliebener Weg kann weiter erlauben."}],"variants":[{"label":"Verwaiste Gruppenrolle entfernen","rationale":"Nur für die gegebene Ein-Personen-Freigabe, nicht pauschal für Gruppen mit weiterem Bedarf.","actions":[{"action":"role_remove","principal":"lea","role":"Blob Reader","scope":"offer"},{"action":"role_remove","principal":"Altprojekt","role":"Blob Reader","scope":"sales"}]}],"failures":[{"label":"Nur Direktrolle entziehen","rationale":"Altprojekt erlaubt weiterhin Lesen.","actions":[{"action":"role_remove","principal":"lea","role":"Blob Reader","scope":"offer"}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"role_remove","principal":"lea","role":"Blob Reader","scope":"offer"},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor weiterer Nutzung der alten Projektfreigabe; etwa 20 Minuten. Alle Angebotslesepfade für Lea entziehen, Betriebszugriffe anderer Abteilungen erhalten. Vertriebszugriffe von u11 und u12 müssen erhalten bleiben."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Leas Angebotszugriff soll enden. Entferne zunächst ihre direkte Angebotsrolle und prüfe erneut: Ein verbliebener Gruppenpfad kann den Zugriff weiterhin erlauben. Entziehe auch diesen Weg gezielt, ohne den Vertriebskollegen den benötigten Zugriff zu nehmen."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Ein direkter und ein Altprojekt-Gruppenpfad erlauben A. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {"id":"09","title":"Verwalten ist nicht Daten lesen","sender":"IT-Leitung","message":"Lea soll Storage-Einstellungen verwalten und Angebote lesen, aber weder Personaldaten lesen noch Rollenzuweisungen vergeben. Trenne beide Berechtigungsebenen.","minutes":22,"prerequisite":"Azure RBAC","learning":"Verwaltungs- und Datenebene; Contributor","learn":"Du lernst, Ressourcenverwaltung und Zugriff auf gespeicherte Daten getrennt zu vergeben.","try_text":"Du probierst getrennte Verwaltungs-/Datenrechte und kontrollierst das fehlende Zuweisungsrecht.","deadline":"Vor Leas erster administrativer Storage-Änderung; etwa 22 Minuten.","constraints":"Storage verwalten und Angebote lesen; kein Personalzugriff, keine Rollenzuweisung, kein Subscription-Administrator. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Reader auf Storage ist vorhanden, ausreichende Angebots-Datenrechte fehlen.","hints":["Gibt eine Ressourceneinstellung automatisch Dateizugriff?","Vergleiche Contributor und Blob Reader; User Access Administrator wäre hier zu weit. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Weise Contributor auf storage und Blob Reader auf sales oder enger auf offer zu. Prüfe Lesen, Personalverweigerung und fehlendes assign-Recht."],"explanation":"Contributor hat Verwaltungsrechte ohne Rollenzuweisungsrecht. Die Datenrolle wird zusätzlich benötigt; Shared Keys und SAS sind in dieser Simulation deaktiviert. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"role_add","principal":"lea","role":"Contributor","scope":"storage"},{"action":"role_add","principal":"lea","role":"Blob Reader","scope":"sales"}],"alternatives":"sales umfasst Angebote, offer ist enger und ebenfalls gültig. Die Verwaltungsrolle bleibt auf Storage begrenzt. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_read"},"expected":true},{"test":"access","args":{"user":"lea","document":"payroll","operation":"data_read"},"expected":false}],"start":[{"op":"set","path":["groups","Altprojekt"],"value":[]},{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Verwaltung erlaubt, Zuweisungen verweigert","expr":{"all":[{"contains":[{"rights":{"principal":"lea","target":"storage"}},{"literal":"manage"}]},{"not":{"contains":[{"rights":{"principal":"lea","target":"storage"}},{"literal":"assign"}]}}]}},{"label":"Kein Subscription-Verwalter und keine Zuweisungen in anderen Scopes","expr":{"all":[{"not":{"contains":[{"rights":{"principal":"lea","target":"subscription"}},{"literal":"manage"}]}},{"eq":[{"privileged_scopes":{"principal":"lea","rights":["assign"]}},{"literal":[]}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[{"principal":"lea","right":"manage","scope":"storage"}]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"orders-app":{"data_read":["offer"],"data_write":[]},"partner":{"data_read":["offer","payroll","public"],"data_write":["offer","payroll","public"]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]},"lea":{"data_read":["offer"],"data_write":[]}}}}],"function":"Microsoft Entra ID → Contributor und Blob Reader getrennt zuweisen","terms":[{"term":"Verwaltungsebene","meaning":"Aktionen an der Ressourcenkonfiguration."},{"term":"Datenebene","meaning":"Aktionen an gespeicherten Inhalten."},{"term":"Contributor","meaning":"Verwalten ohne Rollenzuweisung oder automatische Blob-Datenrechte."}],"variants":[{"label":"Engerer Dokument-Lesescope","rationale":"Verwaltung auf Storage, Datenlesen enger nur für A.","actions":[{"action":"role_add","principal":"lea","role":"Contributor","scope":"storage"},{"action":"role_add","principal":"lea","role":"Blob Reader","scope":"offer"}]}],"failures":[{"label":"Nur Contributor","rationale":"Verwaltungsrolle gewährt kein Angebotslesen.","actions":[{"action":"role_add","principal":"lea","role":"Contributor","scope":"storage"}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"role_add","principal":"lea","role":"Contributor","scope":"storage"},{"action":"role_add","principal":"lea","role":"Blob Reader","scope":"sales"},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Leas erster administrativer Storage-Änderung; etwa 22 Minuten. Storage verwalten und Angebote lesen; kein Personalzugriff, keine Rollenzuweisung, kein Subscription-Administrator."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Lea soll Storage-Einstellungen verwalten und Angebote lesen, aber weder Personaldaten lesen noch Rollenzuweisungen vergeben. Trenne beide Berechtigungsebenen."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Reader auf Storage ist vorhanden, ausreichende Angebots-Datenrechte fehlen. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {"id":"10","title":"Öffentliche Ablage schließen","sender":"Datenschutz","message":"Die fiktiven vertraulichen Dateien sind öffentlich lesbar. Schließe die Freigabe; Vertriebsmitarbeiter müssen Angebot A weiterhin bearbeiten können.","minutes":15,"prerequisite":"Storage-Rechte","learning":"Storage; öffentliche Freigabe; Datenschutz","learn":"Du lernst, eine öffentliche Datenfreigabe zu schließen und berechtigte Arbeit zu erhalten.","try_text":"Du probierst Absicherung, ohne berechtigten Betrieb abzuschalten.","deadline":"Vor weiterer Nutzung vertraulicher Dateien; etwa 15 Minuten.","constraints":"Anonyme Freigabe schließen, Vertrieb weiter bearbeiten lassen. Netzadresse und Datenfreigabe getrennt behandeln. Neue Dokument-Datenrechte sind nur für die angeforderte Freigabe zulässig. Unbeteiligten Personen oder Dienstidentitäten keine zusätzlichen Datei-Lese-/Schreibrechte geben. Die geforderten weiter benötigten Zugriffe müssen nach dem Entzug oder der Vergabe funktionieren.","initial":"Storage erlaubt anonymes Lesen; Lea fehlt zusätzlich in Vertrieb.","hints":["Ist ein Netz-Endpunkt bereits eine Datenerlaubnis?","Prüfe anonyme Blob-Freigabe und Leas Gruppenpfad; eine andere Region schließt nichts. Prüfe auch unbeabsichtigte Datenfreigaben für andere Personen: weder eine neue direkte Rolle noch eine zusätzliche Gruppenmitgliedschaft darf ihnen weitere Dokumente öffnen.","Deaktiviere anonymes Lesen und ergänze Lea in Vertrieb. Prüfe Bearbeiten/Personalschutz; optional entferne zusätzlich die öffentliche Storage-IP."],"explanation":"Privater Blob-Zugang und passende Datenrollen schützen die Ablage. Eine europäische Region ist allein kein vollständiger Datenschutznachweis. Die zusätzliche Datenrechte-Grenze vergleicht resultierende rollenbedingte Dokumentrechte für Personen und Dienstidentitäten, nicht eine bestimmte Rollenliste. Weniger Rechte bleiben zulässig, soweit die geforderten positiven Zugriffstests weiter bestehen. Anmeldung, Netzpfad und Datenrechte bleiben getrennte Prüfungen.","solution":[{"action":"configure","id":"storage","changes":{"public":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":true}],"alternatives":"Ein geschützter öffentlicher oder ein rein privater Endpunkt sind zulässig. Anonyme vertrauliche Daten bleiben in beiden Fällen verboten. Fachlich gleichwertige direkte oder gruppenbasierte Zuweisungen bleiben innerhalb derselben Datenrechte-Grenze zulässig; die auftragsspezifischen Gruppenanforderungen und positiven/negativen Tests bleiben verbindlich.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_write"},"expected":true},{"test":"access","args":{"user":"lea","document":"payroll","operation":"data_read"},"expected":false},{"test":"application","args":{"user":"lea","operation":"orders_write"},"expected":true},{"test":"application","args":{"user":"u60","operation":"orders_read"},"expected":false}],"start":[{"op":"set","path":["groups","Altprojekt"],"value":[]}],"setup":[],"criteria":[{"label":"Lea ist aktiv, MFA-fähig und in Vertrieb","expr":{"all":[{"eq":[{"path":["users","lea","active"]},{"literal":true}]},{"eq":[{"path":["users","lea","mfa"]},{"literal":true}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"lea"}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Keine unbeauftragten zusätzlichen Dokument-Datenrechte","expr":{"data_access_within":{"orders-app":{"data_read":["offer"],"data_write":[]},"partner":{"data_read":["offer","payroll","public"],"data_write":["offer","payroll","public"]},"u11":{"data_read":["offer"],"data_write":["offer"]},"u12":{"data_read":["offer"],"data_write":["offer"]},"lea":{"data_read":["offer"],"data_write":["offer"]}}}}],"function":"Storage Accounts → Zugang privat; Benutzerzugriff testen","terms":[{"term":"Anonyme Freigabe","meaning":"Lesen ohne Anmeldung."},{"term":"Öffentlicher Endpunkt","meaning":"Netzadresse, die weiterhin NSG- und Datenprüfungen benötigt."}],"variants":[{"label":"Zusätzlich öffentliche IP entfernen","rationale":"Private Standort-/Backendzugriffe bleiben, Außenfläche entfällt.","actions":[{"action":"configure","id":"storage","changes":{"public":false,"public_ip":""}},{"action":"membership","group":"Vertrieb","member":"lea","add":true}]}],"failures":[{"label":"Nur Mitgliedschaft","rationale":"Berechtigte Bearbeitung klappt, anonyme vertrauliche Daten bleiben offen.","actions":[{"action":"membership","group":"Vertrieb","member":"lea","add":true}],"outcome":"incomplete"},{"label":"Unbeteiligtem Kollegen Personal-Datenrecht gegeben","rationale":"Ein erfüllter Zugriffswunsch erlaubt keine zusätzliche Personalfreigabe an u60.","outcome":"incomplete","actions":[{"action":"configure","id":"storage","changes":{"public":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":true},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor weiterer Nutzung vertraulicher Dateien; etwa 15 Minuten. Anonyme Freigabe schließen, Vertrieb weiter bearbeiten lassen. Netzadresse und Datenfreigabe getrennt behandeln."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Die fiktiven vertraulichen Dateien sind öffentlich lesbar. Schließe die Freigabe; Vertriebsmitarbeiter müssen Angebot A weiterhin bearbeiten können."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Storage erlaubt anonymes Lesen; Lea fehlt zusätzlich in Vertrieb. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."}]},
    {
      "id": "11",
      "title": "Archiv und Redundanz auswählen",
      "sender": "Buchhaltung",
      "message": "Wähle für selten gelesene Angebotsbelege eine geeignete Speicherart: Blob oder Dateifreigabe sind bei erfüllten Tests zulässig. Der aktuelle Beleg liegt nur auf dem VM-Datenträger. Hauptstandort, Außenstelle und Auftragsanwendung müssen ihn lesen können; Externe dürfen weder lesen noch schreiben. Nutze Cool und GRS als fiktive Archivvorgabe. Bewahre Dokument und erfolgreiche Sicherungspunkte mindestens sieben Simulationstage auf; Sicherungsintervall höchstens 240 Minuten.",
      "minutes": 15,
      "prerequisite": "Speicherarten",
      "learning": "Speicherartwahl; Objekt-, Datei- und Blockspeicher; Datenrollen; Dokument- und Punktaufbewahrung",
      "learn": "Du lernst, Speicherart und Zugriffsweg passend zum Belegbestand zu wählen.",
      "try_text": "Du probierst echtes Verschieben mit erhaltener Historie, neue Zugriffsprüfungen und getrennte Sicherungs-/Dokumentfristen.",
      "deadline": "Vor Archivfreigabe; etwa 15 Minuten.",
      "constraints": "Beleginhalt und Versionen erhalten; keine anonyme Freigabe. Dateifreigabe nur privat. Speicherprognose aller Blob-/Dateifreigaben zusammen höchstens 2 Lern-Euro/Monat bei vorhandenen Modellbelegungswerten. Fristen und Redundanz sind Lernvorgaben, keine rechtliche Empfehlung. Das vorhandene Angebot einschließlich Historie bleibt unverändert.",
      "initial": "Das Angebot liegt auf dem lokalen Datenträger der laufenden web-VM, ohne passenden Datei-/Datenträgerzugriff für die Standorte. Das ist keine gemeinsame Ablage.",
      "hints": [
        "Ein VM-Datenträger ist keine Netzfreigabe. Welche beiden Dienste erlauben gemeinsames Lesen ohne Anmeldung auf der VM?",
        "Im Storage-Bereich tatsächlichen Ablageort, Protokoll und Datenrollen prüfen. Blob-Rollen gelten nicht automatisch für Files oder Disk. Die Anwendung benötigt eine eigene Leseberechtigung.",
        "Blob: Angebot nach storage verschieben, Cool/GRS und bestehende Vertriebs-/Dienstrollen nutzen. Files: Dateifreigabe anlegen, Cool/GRS, Angebot verschieben und File Reader für Vertrieb sowie orders-app setzen. Breite Partnerrolle entfernen. Dokumentfrist 10080, Backup-Aufbewahrung mindestens 10080, Intervall höchstens 240, echten Punkt erstellen; frische erlaubte/verweigerte Tests."
      ],
      "explanation": "Speicherart und Zielressource bestimmen wirklich den Zugriffsweg. Blob verwendet HTTPS und Blob-Datenrollen, Files im Lernmodell SMB 445 mit eigenen File-Rollen. Ein angehängter Disk-Datensatz ist nur in seiner laufenden VM lokal erreichbar. Beim Verschieben bleiben Inhalt, Versionen und Aufbewahrung bestehen. Redundanz schützt nicht vor jeder inhaltlichen Änderung; ein erfolgreicher Backup-Punkt bleibt erforderlich.",
      "solution": [
        {
          "action": "configure",
          "id": "storage",
          "changes": {
            "tier": "cool",
            "redundancy": "GRS"
          }
        },
        {
          "action": "storage_move",
          "id": "offer",
          "kind": "Blob",
          "host": "storage",
          "reason": "Selten gelesene Belege für beide Standorte und Webanwendung als private Objekte ablegen"
        },
        {
          "action": "role_remove",
          "principal": "partner",
          "role": "Blob Contributor",
          "scope": "storage"
        },
        {
          "action": "backup_config",
          "changes": {
            "interval": 240,
            "retention": 10080,
            "enabled": true
          }
        },
        {
          "action": "data_policy",
          "id": "offer",
          "changes": {
            "owner": "Vertrieb",
            "purpose": "Angebotsarchiv für laufenden Kundenfall",
            "retain_minutes": 10080,
            "hold": false,
            "reason": "Fiktiver Archivauftrag: mindestens sieben Simulationstage erhalten"
          }
        },
        {
          "action": "backup_run"
        }
      ],
      "alternatives": "Blob- und private Files-Ablage sind mit passenden Rollen, erfolgreichem Anwendungs-/Standortzugriff, Cool/GRS, Fristen und Budget gleichwertig. Ein lokaler Disk oder bloße Textentscheidung erfüllt den gemeinsamen Zugriff nicht. Andere geeignete Zielkennungen sind zulässig; geprüft wird das tatsächliche Speicherprofil.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "access",
          "args": {
            "user": "u11",
            "document": "offer"
          },
          "expected": true
        },
        {
          "test": "access",
          "args": {
            "user": "u11",
            "document": "offer",
            "source": "branch"
          },
          "expected": true
        },
        {
          "test": "access",
          "args": {
            "user": "partner",
            "document": "offer"
          },
          "expected": false
        },
        {
          "test": "access",
          "args": {
            "user": "partner",
            "document": "offer",
            "operation": "data_write"
          },
          "expected": false
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "operation": "orders_read"
          },
          "expected": true
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "document_storage",
            "offer"
          ],
          "value": {
            "kind": "Disk",
            "host": "web"
          }
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Geeignete tatsächliche gemeinsame Archivablage, Cool/GRS und geschützter Zugang",
          "expr": {
            "all": [
              {
                "any_of": [
                  {
                    "eq": [
                      {
                        "storage_property": {
                          "document": "offer",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "Blob"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "storage_property": {
                          "document": "offer",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "Files"
                      }
                    ]
                  }
                ]
              },
              {
                "eq": [
                  {
                    "storage_property": {
                      "document": "offer",
                      "name": "tier"
                    }
                  },
                  {
                    "literal": "cool"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "storage_property": {
                      "document": "offer",
                      "name": "redundancy"
                    }
                  },
                  {
                    "literal": "GRS"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "storage_property": {
                      "document": "offer",
                      "name": "anonymous"
                    }
                  },
                  {
                    "literal": false
                  }
                ]
              },
              {
                "any_of": [
                  {
                    "eq": [
                      {
                        "storage_property": {
                          "document": "offer",
                          "name": "kind"
                        }
                      },
                      {
                        "literal": "Blob"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "storage_property": {
                          "document": "offer",
                          "name": "public_ip"
                        }
                      },
                      {
                        "literal": ""
                      }
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Aktiver Archiv-Backupplan, sieben Tage Punktaufbewahrung und erfolgreicher Punkt",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "lte": [
                  {
                    "path": [
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 240
                  }
                ]
              },
              {
                "gte": [
                  {
                    "path": [
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 10080
                  }
                ]
              },
              {
                "nonempty": {
                  "path": [
                    "backup",
                    "points"
                  ]
                }
              }
            ]
          }
        },
        {
          "label": "Dokumentaufbewahrung bis Minute 10080 festgelegt",
          "expr": {
            "gte": [
              {
                "path": [
                  "data_governance",
                  "offer",
                  "retention_until"
                ]
              },
              {
                "literal": 10080
              }
            ]
          }
        },
        {
          "label": "Modellierte Blob-/Files-Speicherkosten höchstens 2 Lern-Euro/Monat",
          "expr": {
            "lte": [
              {
                "storage_monthly": true
              },
              {
                "literal": 2
              }
            ]
          }
        },
        {
          "label": "Weiter benötigter Angebotsinhalt und Historie bleiben unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "offer"
                ]
              },
              {
                "literal": {
                  "name": "Angebot-A.txt",
                  "container": "sales",
                  "class": "vertraulich",
                  "content": "Angebot A: 120 Lern-Euro; Version 1.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Storage → tatsächliche Ablage und Profil; Entra → passende Speicher-Datenrollen; Backup Center und Dokumentfristen",
      "terms": [
        {
          "term": "Blob",
          "meaning": "Objektspeicher für die Archivdokumente."
        },
        {
          "term": "Cool",
          "meaning": "Klasse für seltenen Zugriff mit anderem Lerntarif."
        },
        {
          "term": "GRS",
          "meaning": "Geografische Kopie, kein früherer Datenstand."
        },
        {
          "term": "Backup-Punktaufbewahrung",
          "meaning": "Zeitraum verfügbarer Wiederherstellungspunkte, unabhängig von der Dokumentfrist."
        },
        {
          "term": "Dokumentaufbewahrung",
          "meaning": "Eine begründete Mindestfrist sperrt endgültige Entfernung des Dokuments und seiner abgeleiteten Kopien. Fristablauf allein löscht nicht."
        },
        {
          "term": "Dateifreigabe / Files",
          "meaning": "Gemeinsame Dateiablage; hier SMB/TCP 445 mit eigenen vereinfachten File-Rollen, kein vollständiges AD-/NTFS-Modell."
        },
        {
          "term": "VM-Datenträger / Disk",
          "meaning": "An eine VM gebundener Blockspeicher. Hier lokale Dateiablage ohne automatisch bereitgestellten Netzzugriff."
        },
        {
          "term": "Storage Account und Container",
          "meaning": "Der Speicherdienst enthält logische Blob-Container wie sales. Eine File-Share-Ressource ist hier ein vereinfachter eigener SMB-Endpunkt."
        }
      ],
      "variants": [
        {
          "label": "Private Dateifreigabe statt Blob",
          "rationale": "Gleicher Geschäftsauftrag über SMB mit passenden File-Leserollen für Vertrieb und Dienstidentität.",
          "actions": [
            {
              "action": "create",
              "id": "archivefiles",
              "name": "Archiv-Dateifreigabe",
              "kind": "File Share",
              "group": "rg-data",
              "subnet": "data",
              "ip": "10.20.2.31"
            },
            {
              "action": "configure",
              "id": "archivefiles",
              "changes": {
                "tier": "cool",
                "redundancy": "GRS"
              }
            },
            {
              "action": "storage_move",
              "id": "offer",
              "kind": "Files",
              "host": "archivefiles",
              "reason": "Gemeinsame Dateifreigabe mit SMB-Lesezugriff für Standorte und Dienstidentität"
            },
            {
              "action": "role_add",
              "principal": "Vertrieb",
              "role": "File Reader",
              "scope": "sales"
            },
            {
              "action": "role_add",
              "principal": "orders-app",
              "role": "File Reader",
              "scope": "offer"
            },
            {
              "action": "role_remove",
              "principal": "partner",
              "role": "Blob Contributor",
              "scope": "storage"
            },
            {
              "action": "backup_config",
              "changes": {
                "interval": 240,
                "retention": 10080,
                "enabled": true
              }
            },
            {
              "action": "data_policy",
              "id": "offer",
              "changes": {
                "owner": "Vertrieb",
                "purpose": "Angebotsarchiv für laufenden Kundenfall",
                "retain_minutes": 10080,
                "hold": false,
                "reason": "Fiktiver Archivauftrag: mindestens sieben Simulationstage erhalten"
              }
            },
            {
              "action": "backup_run"
            }
          ]
        },
        {
          "label": "Blob mit engerem Sicherungsintervall",
          "rationale": "Kürzeres Intervall und längere Punktaufbewahrung bei gleichem tatsächlich geeigneten Speicher.",
          "actions": [
            {
              "action": "configure",
              "id": "storage",
              "changes": {
                "tier": "cool",
                "redundancy": "GRS"
              }
            },
            {
              "action": "storage_move",
              "id": "offer",
              "kind": "Blob",
              "host": "storage",
              "reason": "Selten gelesene Belege für beide Standorte und Webanwendung als private Objekte ablegen"
            },
            {
              "action": "role_remove",
              "principal": "partner",
              "role": "Blob Contributor",
              "scope": "storage"
            },
            {
              "action": "backup_config",
              "changes": {
                "interval": 30,
                "retention": 20160,
                "enabled": true
              }
            },
            {
              "action": "data_policy",
              "id": "offer",
              "changes": {
                "owner": "Vertrieb",
                "purpose": "Angebotsarchiv für laufenden Kundenfall",
                "retain_minutes": 10080,
                "hold": false,
                "reason": "Fiktiver Archivauftrag: mindestens sieben Simulationstage erhalten"
              }
            },
            {
              "action": "backup_run"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Nur Blob aufschreiben und Cool/GRS setzen",
          "rationale": "Der Beleg bleibt dabei auf dem lokalen VM-Datenträger; die tatsächliche Ablage ändert sich nicht.",
          "actions": [
            {
              "action": "decision",
              "key": "archive_store",
              "value": "Blob"
            },
            {
              "action": "configure",
              "id": "storage",
              "changes": {
                "tier": "cool",
                "redundancy": "GRS"
              }
            }
          ],
          "outcome": "incomplete"
        },
        {
          "label": "Files ohne eigene Datenrollen",
          "rationale": "Blob-Rollen ersetzen keine File-Share-Datenberechtigungen; Standort und Dienstidentität bleiben ohne Zugriff.",
          "actions": [
            {
              "action": "create",
              "id": "archivefiles",
              "name": "Archiv-Dateifreigabe",
              "kind": "File Share",
              "group": "rg-data",
              "subnet": "data",
              "ip": "10.20.2.31"
            },
            {
              "action": "configure",
              "id": "archivefiles",
              "changes": {
                "tier": "cool",
                "redundancy": "GRS"
              }
            },
            {
              "action": "storage_move",
              "id": "offer",
              "kind": "Files",
              "host": "archivefiles",
              "reason": "Gemeinsame Dateifreigabe mit SMB-Lesezugriff für Standorte und Dienstidentität"
            },
            {
              "action": "role_remove",
              "principal": "partner",
              "role": "Blob Contributor",
              "scope": "storage"
            },
            {
              "action": "backup_config",
              "changes": {
                "interval": 240,
                "retention": 10080,
                "enabled": true
              }
            },
            {
              "action": "data_policy",
              "id": "offer",
              "changes": {
                "owner": "Vertrieb",
                "purpose": "Angebotsarchiv für laufenden Kundenfall",
                "retain_minutes": 10080,
                "hold": false,
                "reason": "Fiktiver Archivauftrag: mindestens sieben Simulationstage erhalten"
              }
            },
            {
              "action": "backup_run"
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor Archivfreigabe; etwa 15 Minuten. Beleginhalt und Versionen erhalten; keine anonyme Freigabe. Dateifreigabe nur privat. Speicherprognose aller Blob-/Dateifreigaben zusammen höchstens 2 Lern-Euro/Monat bei vorhandenen Modellbelegungswerten. Fristen und Redundanz sind Lernvorgaben, keine rechtliche Empfehlung. Das vorhandene Angebot einschließlich Historie bleibt unverändert."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Wähle für selten gelesene Angebotsbelege eine geeignete Speicherart: Blob oder Dateifreigabe sind bei erfüllten Tests zulässig. Der aktuelle Beleg liegt nur auf dem VM-Datenträger. Hauptstandort, Außenstelle und Auftragsanwendung müssen ihn lesen können; Externe dürfen weder lesen noch schreiben. Nutze Cool und GRS als fiktive Archivvorgabe. Bewahre Dokument und erfolgreiche Sicherungspunkte mindestens sieben Simulationstage auf; Sicherungsintervall höchstens 240 Minuten."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Das Angebot liegt auf dem lokalen Datenträger der laufenden web-VM, ohne passenden Datei-/Datenträgerzugriff für die Standorte. Das ist keine gemeinsame Ablage. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {"id":"12","title":"Gelöschtes Angebot wiederherstellen","sender":"Vertrieb","message":"Angebot A wurde bei Simulationsminute 30 gelöscht. Stelle den früheren Inhalt aus dem vorhandenen Punkt zunächst unter offer-restored bereit. Für diesen Zielbestand sind ab der Löschung höchstens zehn Simulationsminuten erlaubt: erfolgreicher Abschluss spätestens bei Minute 40. Alle übrigen Dateien bleiben unverändert. Prüfe vor dem Start Punktfassung, aktuelle Fassung und Ziel. Eine alternative Kopie bedeutet noch keinen vollständigen Anwendungswiederanlauf. Der vorgegebene Punkt heißt rp-0-0 (Minute 0). Sein ursprünglicher Angebotsinhalt und Versionsstand sind verbindlich, auch wenn Sicherungspunkte später ablaufen. Nach der Kopie: u11 darf offer-restored lesen, u60 nicht; das gelöschte Original bleibt für u11 unlesbar.","minutes":20,"prerequisite":"Backup","learning":"Wiederherstellung; Version; RPO/RTO","learn":"Du lernst, frühere Dateidaten wiederherzustellen und die tatsächliche Zeit seit dem festgelegten Ausfall zu prüfen.","try_text":"Du probierst eine zeitgesteuerte Wiederherstellung und den Inhalts-/Versionsvergleich.","deadline":"Ausfall Minute 30; Zielbestand spätestens Minute 40 wiederhergestellt. Etwa 20 Unterrichtsminuten; reale Arbeitszeit läuft unabhängig.","constraints":"Richtigen Punkt nach offer-restored zurückholen. Original bleibt zunächst gelöscht, übrige Dateien unverändert. Backupablage und Ziel brauchen Verfügbarkeit und freien Speicher. Zeit seit Minute 30 zählt einschließlich Warten, Reparatur und neuer Versuche. Die geplante Jobdauer allein erfüllt die Zeitvorgabe nicht. Originalinhalt, Versionen, übrige Dateien sowie bestehende Ablagen/Datenregeln nicht verändern oder endgültig entfernen. Keine anderen Rechte für die Kopie einrichten. Der Prüfer vergleicht mit dem vorgegebenen Ausgangsbestand, nicht mit möglicherweise später veränderten Punktdaten.","initial":"Sicherung bei Minute 0, Löschung bei Minute 30; Übung beginnt bei Minute 30. Der Ausfallbeginn bleibt für diese Aufgabe Minute 30.","hints":["Wo ist der frühere Inhalt noch vorhanden?","Vergleiche in der Vorschau Punktzeit, tatsächliche alte/aktuelle Werte und Zieleffekt. Neuere Arbeit kann trotz Punktalter null anders sein. Das Entfernen einer Datei samt Sicherungskopien ist keine Wiederherstellung. Vergleiche auch Inhalt und Historie des gelöschten Originals mit dem Ausgangsstand.","Wähle Punkt und Ziel offer-restored. Für die Zeitanzeige kannst du Ausfall 30 und RTO-Vorgabe 10 eintragen. Prüfe Vorschau und starte. Der Trainer spult fünf Minuten vor. Vergleiche Inhalt/Version, erhaltene übrige Dateien und tatsächlichen Abschluss spätestens Minute 40; Warten und Fehlversuche zählen mit. Sobald offer-restored existiert, die beiden Kopie-Zugriffstests ausführen; zusätzlich den verweigerten Zugriff auf das Original prüfen."],"explanation":"Ein Punkt enthält tatsächlich frühere Dateidaten. Die Vorschau vergleicht sie mit aktuellen Belegen. Punktalter allein beweist keinen Datenverlust. RPO ist eine Vorgabe zum tolerierten Datenrückstand; RTO eine Vorgabe zur tolerierten Wiederherstellungszeit des betrachteten Ablaufs. Fünf Minuten sind hier die geplante Jobdauer. Erst mit angegebenem Ausfallbeginn und erfasstem erfolgreichem Abschluss kann die Zeit bis zum gewählten Zielbestand gegen eine passende RTO-Vorgabe verglichen werden. Alternative Kopie erhält das Original; In-place-Restore bewahrt die neuere Fassung als Version. Eine Datei allein stellt nicht automatisch die gesamte Anwendung wieder her. In dieser Aufgabe steht der Ausfallbeginn durch den Ausgangszustand bei Minute 30 fest. Der Prüfer vergleicht den erfassten erfolgreichen Abschluss mit Minute 40; deklarierte Eingabewerte oder die geplante Fünf-Minuten-Dauer setzen diese Frist nicht zurück. Späteres Weiterlaufen der Uhr macht einen bereits rechtzeitigen Abschluss nicht verspätet. Fehlt bei einem historischen Job die echte Abschlusszeit, ist der Zeitnachweis offen; ein neuer Restore oder ein gezielter Übungsreset schafft einen neuen prüfbaren Ablauf. Der Prüfmaßstab bleibt der deklarierte Punkt rp-0-0 mit ursprünglichem Dateiinhalt und ursprünglicher Version. Eine gleichzeitige Entfernung von aktueller Datei und Sicherungskopie kann diesen Maßstab nicht ändern. Die Rechteprüfung der Kopie erscheint erst, wenn diese Datei existiert; ihr Ergebnis und ein frischer persönlicher Versuch sind dann erforderlich. Das spätere reguläre Ablaufen des ursprünglichen Sicherungspunkts macht eine bereits rechtzeitig abgeschlossene korrekte Wiederherstellung nicht falsch.","solution":[{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored","outage_minute":30,"rto_limit":10},{"action":"advance","minutes":5}],"alternatives":"Die Zeit kann am Stück oder schrittweise beobachtet werden. Geratener neuer Dateiinhalt ist kein Punktnachweis.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"u11","document":"offer-restored","operation":"data_read"},"expected":true,"when":{"contains":[{"path":["documents"]},{"literal":"offer-restored"}]}},{"test":"access","args":{"user":"u60","document":"offer-restored","operation":"data_read"},"expected":false,"when":{"contains":[{"path":["documents"]},{"literal":"offer-restored"}]}},{"test":"access","args":{"user":"u11","document":"offer","operation":"data_read"},"expected":false}],"start":[{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[{"action":"backup_run"},{"action":"advance","minutes":30},{"action":"file_delete","id":"offer"}],"criteria":[{"label":"Richtiger Punkt und früherer Inhalt am alternativen Ort; Abschluss seit Ausfall Minute 30 spätestens Minute 40","expr":{"all":[{"eq":[{"path":["backup","restore","status"]},{"literal":"success"}]},{"eq":[{"path":["backup","restore","target"]},{"literal":"offer-restored"}]},{"eq":[{"path":["backup","restore","point"]},{"literal":"rp-0-0"}]},{"all":[{"gte":[{"path":["backup","restore","finished_minute"]},{"literal":30}]},{"lte":[{"path":["backup","restore","finished_minute"]},{"literal":40}]}]},{"eq":[{"path":["documents","offer-restored"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"eq":[{"path":["backup","restore","source"]},{"literal":"offer"}]},{"eq":[{"path":["backup","restore","point_minute"]},{"literal":0}]},{"eq":[{"path":["backup","restore","document"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]}}]}]}},{"label":"Gelöschtes Original mit Historie und übrige Dateien bleiben im vorgegebenen Ausgangsstand","expr":{"all":[{"eq":[{"path":["documents","offer"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":2,"deleted":true,"modified":30,"versions":[{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0}]}}]},{"eq":[{"path":["documents","payroll"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"eq":[{"path":["documents","public"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]}}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Vorgegebene Ablagen und Datenregeln von Original, Kopie und übrigen Dateien erhalten","expr":{"all":[{"eq":[{"path":["document_storage","offer"]},{"literal":{"kind":"Blob","host":"storage"}}]},{"eq":[{"path":["data_governance","offer"]},{"literal":{"owner":"Vertrieb","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"offer","status":"active"}}]},{"eq":[{"path":["document_storage","payroll"]},{"literal":{"kind":"Blob","host":"storage"}}]},{"eq":[{"path":["data_governance","payroll"]},{"literal":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"payroll","status":"active"}}]},{"eq":[{"path":["document_storage","public"]},{"literal":{"kind":"Blob","host":"storage"}}]},{"eq":[{"path":["data_governance","public"]},{"literal":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"public","status":"active"}}]},{"eq":[{"path":["document_storage","offer-restored"]},{"literal":{"kind":"Blob","host":"storage"}}]},{"eq":[{"path":["data_governance","offer-restored"]},{"literal":{"owner":"Vertrieb","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"offer","status":"active"}}]}]}}],"function":"Backup Center → Punkt auswählen, alternativ wiederherstellen; Trainer → 5 Minuten vorspulen","terms":[{"term":"Wiederherstellungspunkt","meaning":"Gesicherter Bestand eines früheren Zeitpunkts."},{"term":"RPO","meaning":"Ziel für maximalen Datenverlust als Zeitspanne."},{"term":"RTO","meaning":"Maximal tolerierte Wiederherstellungszeit für einen festgelegten Ablauf. Die geplante Jobdauer allein ist kein Nachweis."}],"variants":[{"label":"Wiederherstellung schrittweise beobachten","rationale":"Identischer Punkt und Zielinhalt; Zeit in mehreren Schritten beobachten.","actions":[{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored","outage_minute":30,"rto_limit":10},{"action":"advance","minutes":3},{"action":"advance","minutes":2}]}],"failures":[{"label":"Inhalt manuell nachschreiben","rationale":"Kein geforderter Punkt-/Dauernachweis, Original unerlaubt verändert.","actions":[{"action":"file_write","id":"offer","content":"Angebot A: 120 Lern-Euro; Version 1."}],"outcome":"incomplete"},{"label":"Ziel fällt während der Wiederherstellung aus","rationale":"Ein vorhandener Punkt genügt nicht: ein gestoppter Zielhost beendet den Job ohne Kopie und ohne erfolgreiches RTO.","outcome":"incomplete","actions":[{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored"},{"action":"fault","id":"document_source","enabled":true},{"action":"advance","minutes":5}]},{"label":"Erst zwanzig Minuten warten","rationale":"Der Job dauert zwar fünf Minuten, endet aber bei Minute 55 und verfehlt die feste Frist Minute 40.","outcome":"incomplete","actions":[{"action":"advance","minutes":20},{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored","outage_minute":30,"rto_limit":10},{"action":"advance","minutes":5}]},{"label":"Personaldatei samt Sicherungskopien entfernt","rationale":"Zwei gemeinsam veränderte Bestände sind kein Nachweis erhaltener übriger Daten.","outcome":"incomplete","actions":[{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored","outage_minute":30,"rto_limit":10},{"action":"advance","minutes":5},{"action":"data_purge","id":"payroll","reason":"Fiktiver unbeauftragter Eingriff"}]},{"label":"Gelöschtes Original umgeschrieben und erneut gelöscht","rationale":"Ein gesetztes Gelöscht-Merkmal allein bewahrt weder ursprünglichen Inhalt noch Historie.","outcome":"incomplete","actions":[{"action":"restore","point":{"$state":["backup","points",0,"id"]},"id":"offer","target":"offer-restored","outage_minute":30,"rto_limit":10},{"action":"advance","minutes":5},{"action":"file_write","id":"offer","content":"Fiktiver unbeauftragter Ersatz"},{"action":"file_delete","id":"offer"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Ausfall Minute 30; Zielbestand spätestens Minute 40 wiederhergestellt. Etwa 20 Unterrichtsminuten; reale Arbeitszeit läuft unabhängig. Richtigen Punkt nach offer-restored zurückholen. Original bleibt zunächst gelöscht, übrige Dateien unverändert. Backupablage und Ziel brauchen Verfügbarkeit und freien Speicher. Zeit seit Minute 30 zählt einschließlich Warten, Reparatur und neuer Versuche. Die geplante Jobdauer allein erfüllt die Zeitvorgabe nicht."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Angebot A wurde bei Simulationsminute 30 gelöscht. Stelle den früheren Inhalt aus dem vorhandenen Punkt zunächst unter offer-restored bereit. Für diesen Zielbestand sind ab der Löschung höchstens zehn Simulationsminuten erlaubt: erfolgreicher Abschluss spätestens bei Minute 40. Alle übrigen Dateien bleiben unverändert. Prüfe vor dem Start Punktfassung, aktuelle Fassung und Ziel. Eine alternative Kopie bedeutet noch keinen vollständigen Anwendungswiederanlauf."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. A wurde 30 Minuten nach dem vorhandenen Punkt gelöscht. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."},{"id":"restore-ziel","question":"Reicht ein gültiger Punkt auch bei ausgefallenem oder vollem Ziel?","answer":"Nein. Backupablage und Speicherziel müssen verfügbar sein, das Ziel braucht freien Platz. Nach einem Abbruch reparieren und bewusst neu starten. Warten und Fehlversuche zählen weiter seit der Löschung bei Minute 30; Erfolg nach Minute 40 verfehlt diese Aufgabe."},{"id":"auswirkung","question":"Sind Punktalter und fünf Minuten Jobdauer schon Nachweise für Datenverlust und RTO?","answer":"Nein. Vergleiche konkrete Daten und Zieleffekt. Ein angegebener Ausfallbeginn und erfasster Abschluss erlauben erst den Zeitvergleich für den gewählten Zielbestand. Eine alternative Datei muss noch geprüft bzw. eingebunden werden."},{"id":"zeitnachweis","question":"Kann ein später eingetragener Ausfallbeginn die Aufgabenfrist verschieben?","answer":"Nein. Für diese Ausgangslage gilt Minute 30 als Ausfallbeginn. Der tatsächliche erfolgreiche Abschluss muss spätestens bei Minute 40 liegen. Die optionalen Eingaben erklären andere Lernfälle, ändern aber diese Aufgabe nicht. Ein fehlender historischer Abschlusszeitstempel bleibt ein offener Nachweis."},{"id":"punkt-und-bestand","question":"Kann ich andere Dateien entfernen oder einen späteren Punkt zum neuen Maßstab machen?","answer":"Nein. Maßgeblich ist der vorgegebene Punkt rp-0-0 von Minute0 und sein ursprünglicher Angebotsinhalt. Originalinhalt/Versionen, andere Dateien, Ablagen und Datenregeln erhalten. Eine spätere automatische Punktbereinigung nimmt einer bereits richtigen, rechtzeitigen Kopie nicht den Erfolg. Kopie für u11 erlaubt und u60 verweigert prüfen; Original bleibt unlesbar."}]},
    {"id":"13","title":"RPO von 60 Minuten nachweisen","sender":"IT-Leitung","message":"Wir dürfen höchstens 60 Minuten Dateiarbeit verlieren. Stelle das Sicherungsintervall auf höchstens 60 Minuten und erzeuge nachweislich einen erfolgreichen Punkt. Ein Plan allein genügt nicht. Angebot-A, Personal-B und Firmeninfo bleiben verfügbar; ihre vorhandenen Ausgangsfassungen müssen im aktuellen Bestand und in einem passenden Punkt noch wiederherstellbar sein. Für diese Übung gilt zusätzlich eine fiktive Mindestaufbewahrung von60Minuten. Neuere Arbeit innerhalb des RPO-Fensters muss noch nicht im letzten Punkt stehen.","minutes":18,"prerequisite":"Sicherungen","learning":"Backup-Plan; Aufbewahrung; RPO","learn":"Du lernst, einen Sicherungsplan und vorhandene erfolgreiche Punkte gegen das Verlustziel zu prüfen.","try_text":"Du probierst einen Sicherungsplan gegen das Verlustziel und beobachtest einen automatischen Lauf.","deadline":"Vor Freigabe des Sicherungskonzepts; RPO höchstens 60 Minuten, etwa 18 Unterrichtsminuten.","constraints":"Aktiver Plan, Intervall höchstens 60 und tatsächlich frischer erfolgreicher Punkt. Geschützte Dateien weder endgültig entfernen noch löschen. Ausgangsfassung erhalten, gegebenenfalls in der Versionshistorie. Mindestens ein höchstens60Minuten alter Punkt mit diesen wiederherstellbaren Fassungen und passendem erfolgreichen Lauf muss existieren. Mindestaufbewahrung60Minuten ist eine eigene Unterrichtsvorgabe, keine allgemeine Azure- oder RPO-Mindestregel.","initial":"Intervall 240, noch kein erfolgreicher Punkt.","hints":["Welche Arbeit könnte zwischen zwei Sicherungen fehlen?","Prüfe erfolgreichen Punkt und Alter gegen die 60-Minuten-Vorgabe; vergleiche zusätzlich tatsächliche Änderungen in der Wiederherstellungsvorschau. Prüfe Punktinhalt und erhaltene Versionen, nicht nur die Zeitangabe oder success-Meldung. Leere oder entfernte Daten werden durch erneutes Sichern nicht wiederherstellbar.","Setze höchstens 60 Minuten, lasse den Trainer bis zum Lauf vorspulen und prüfe Jobstatus, Punktzeit und Alter. Aufbewahrung mindestens60Minuten belassen. Angebot/Personal/Firmeninfo und ihre Ausgangsfassungen erhalten. Ein manueller erfolgreicher Lauf ist ebenfalls zulässig, wenn der aktive Plan bestehen bleibt."],"explanation":"Das Intervall begrenzt den geplanten Verlust; erst ein erfolgreicher vorhandener Punkt belegt Sicherung. Ausfälle müssen in den Sicherungsprotokollen geprüft werden. Das Punktalter ist ein konservativer Vergleich für einen möglichen Ausfall jetzt. Welche Änderungen tatsächlich fehlen würden, zeigt die Datenvergleichsvorschau; ein alter Punkt bei unveränderten Daten bedeutet nicht automatisch verlorene Arbeit. Ein Zeitstempel und eine Erfolgsmeldung allein belegen keine erhaltenen Firmendaten. Der Prüfer sucht einen tatsächlich vorhandenen Punkt im60Minuten-Fenster mit passendem Erfolgslauf und den geschützten Fassungen, auch in dessen Versionshistorie. Aktuelle Dateien dürfen neuere Arbeit enthalten, solange die Ausgangsfassungen erhalten bleiben. Ein solcher neuer Stand muss innerhalb des erlaubten Fensters noch nicht gesichert sein: Das Ziel ist nicht automatisch null Datenverlust. Die gesonderte Mindestaufbewahrung60 ist eine fiktive Firmenvorgabe und nicht die Definition von RPO. Ein fehlgeschlagener Lauf erzeugt keinen neuen Punkt und verjüngt keinen vorhandenen Punkt.","solution":[{"action":"backup_config","changes":{"interval":60,"retention":1440,"enabled":true}},{"action":"advance","minutes":60}],"alternatives":"30 und 60 Minuten sind zulässig. Längere Aufbewahrung ersetzt weder kurzes Intervall noch erfolgreichen Lauf.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false}],"start":[{"op":"set","path":["resources","storage","public"],"value":false}],"setup":[],"criteria":[{"label":"Aktiver Plan, passende Aufbewahrung und tatsächlich erfolgreicher brauchbarer Punkt innerhalb RPO60","expr":{"all":[{"eq":[{"path":["backup","enabled"]},{"literal":true}]},{"lte":[{"path":["backup","interval"]},{"literal":60}]},{"gte":[{"path":["backup","retention"]},{"literal":60}]},{"some":{"in":{"path":["backup","points"]},"as":"point","where":{"all":[{"gte":[{"subtract":[{"path":["minute"]},{"var":["point","minute"]}]},{"literal":0}]},{"lte":[{"subtract":[{"path":["minute"]},{"var":["point","minute"]}]},{"literal":60}]},{"all":[{"eq":[{"var":["point","documents","offer","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"var":["point","documents","offer"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"var":["point","documents","offer","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"var":["point","documents","payroll","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"var":["point","documents","payroll"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"var":["point","documents","payroll","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"var":["point","documents","public","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"var":["point","documents","public"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"var":["point","documents","public","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"some":{"in":{"path":["backup","jobs"]},"as":"job","where":{"all":[{"eq":[{"var":["job","status"]},{"literal":"success"}]},{"eq":[{"var":["job","minute"]},{"var":["point","minute"]}]}]}}}]}}}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Geschützte Firmenfassungen im laufenden Bestand wiederherstellbar und nicht entfernt","expr":{"all":[{"all":[{"all":[{"eq":[{"path":["documents","offer","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"path":["documents","offer"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"path":["documents","offer","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"eq":[{"path":["data_governance","offer","status"]},{"literal":"active"}]}]},{"all":[{"all":[{"eq":[{"path":["documents","payroll","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"path":["documents","payroll"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"path":["documents","payroll","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"eq":[{"path":["data_governance","payroll","status"]},{"literal":"active"}]}]},{"all":[{"all":[{"eq":[{"path":["documents","public","deleted"]},{"literal":false}]},{"any_of":[{"eq":[{"path":["documents","public"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]}}]},{"some":{"in":{"path":["documents","public","versions"]},"as":"protected_version","where":{"eq":[{"var":["protected_version"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"eq":[{"path":["data_governance","public","status"]},{"literal":"active"}]}]}]}}],"function":"Backup Center → Plan; Trainer → Zeit; Sicherungsprotokoll","terms":[{"term":"RPO (Recovery Point Objective)","meaning":"Maximal tolerierter Datenrückstand als Zeitspanne. Hier wird ein möglicher Ausfall jetzt gegen Intervall und Alter eines tatsächlich erfolgreichen Punkts geprüft."},{"term":"Intervall","meaning":"Geplanter Abstand der Versuche."},{"term":"Sicherungsjob","meaning":"Tatsächlicher Versuch mit Erfolg/Fehler."},{"term":"RPO-Nachweis","meaning":"Erfolgreicher Punkt im zulässigen Abstand."},{"term":"Aufbewahrungsdauer","meaning":"Wie lange Sicherungspunkte erhalten bleiben. Hier mindestens60Lernminuten als gesonderte Übungsvorgabe; nicht mit RPO gleichsetzen."}],"variants":[{"label":"RPO mit 30-Minuten-Intervall","rationale":"Engeres Intervall und längere Aufbewahrung sind mit frischem Punkt zulässig.","actions":[{"action":"backup_config","changes":{"interval":30,"retention":2880,"enabled":true}},{"action":"advance","minutes":30}]},{"label":"Aktiver Plan mit zusätzlichem manuellen Lauf","rationale":"Ein tatsächlicher manueller Punkt ist ein gültiger unmittelbarer Nachweis; der ausreichend enge aktive Plan und die Aufbewahrung bleiben bestehen.","actions":[{"action":"backup_config","changes":{"interval":60,"retention":1440,"enabled":true}},{"action":"backup_run"}]}],"failures":[{"label":"Plan ohne Lauf","rationale":"Ohne frischen Punkt kein RPO-Nachweis.","actions":[{"action":"backup_config","changes":{"interval":60,"retention":1440,"enabled":true}}],"outcome":"incomplete"},{"label":"Firmendaten entfernt und leeren Bestand neu gesichert","rationale":"Ein neuer Erfolgslauf macht entfernte Personalinhalte und Versionen nicht wiederherstellbar.","outcome":"incomplete","actions":[{"action":"backup_config","changes":{"interval":60,"retention":1440,"enabled":true}},{"action":"advance","minutes":60},{"action":"data_purge","id":"payroll","reason":"Fiktiver unbeauftragter Eingriff"},{"action":"backup_run"}]},{"label":"Nur eine Minute Aufbewahrung","rationale":"Ein sofort frischer Punkt ersetzt die gesondert vorgegebene Mindestaufbewahrung nicht.","outcome":"incomplete","actions":[{"action":"backup_config","changes":{"interval":60,"retention":1,"enabled":true}},{"action":"backup_run"}]},{"label":"Letzter guter Punkt nach fehlgeschlagenem Lauf zu alt","rationale":"Ein fehlgeschlagener Lauf verjüngt den Punkt nicht; bei121 ist der letzte Punkt von60 schon61Minuten alt.","outcome":"incomplete","actions":[{"action":"backup_config","changes":{"interval":60,"retention":1440,"enabled":true}},{"action":"advance","minutes":60},{"action":"fault","id":"document_source","enabled":true},{"action":"advance","minutes":61}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Freigabe des Sicherungskonzepts; RPO höchstens 60 Minuten, etwa 18 Unterrichtsminuten. Aktiver Plan, Intervall höchstens 60 und tatsächlich frischer erfolgreicher Punkt."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Wir dürfen höchstens 60 Minuten Dateiarbeit verlieren. Stelle das Sicherungsintervall auf höchstens 60 Minuten und erzeuge nachweislich einen erfolgreichen Punkt. Ein Plan allein genügt nicht."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Intervall 240, noch kein erfolgreicher Punkt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."},{"id":"brauchbarer-punkt","question":"Genügt ein frischer Zeitstempel nach dem Entfernen der Dateien?","answer":"Nein. Die vorgegebenen Firmenfassungen müssen im laufenden Bestand und in einem passenden Punkt noch wiederherstellbar sein, gegebenenfalls über Versionen. Neuere ungesicherte Arbeit innerhalb60Minuten bleibt zulässig. Ein manueller Lauf ist erlaubt; der aktive Plan und die gesonderte Mindestaufbewahrung bleiben erforderlich."}]},
    {
      "id": "14",
      "title": "Überlastung beheben",
      "sender": "Betriebsleitung",
      "message": "Bei 150 Lastpunkten gibt es Fehler. Behebe die Kapazitätsgrenze der Webanwendung ohne die Last zu reduzieren. CPU soll höchstens 85% betragen; Monatsprognose höchstens 600 Lern-Euro.",
      "minutes": 20,
      "prerequisite": "Compute und Metriken",
      "learning": "CPU; RAM; Antwortzeit; Skalierung",
      "learn": "Du lernst, eine Überlastung anhand von Messwerten zu erkennen und innerhalb des Budgets zu beheben.",
      "try_text": "Du probierst Kapazitätserweiterung statt Absenken der Anforderung.",
      "deadline": "Während der Lastspitze; etwa 20 Minuten.",
      "constraints": "Last mindestens 150, CPU höchstens 85%, keine Fehler, Monatsprognose höchstens 600 Lern-Euro.",
      "initial": "B2 als Einzelinstanz trägt die Last nicht fehlerfrei.",
      "hints": [
        "Ist der Dienst aus oder nur überlastet?",
        "Vergleiche Last, CPU, Fehlerquote und Tarif vor der Änderung.",
        "Nutze etwa D4 einmal oder B2 zweimal. Behalte Last 150 und prüfe CPU, Fehler, Budget und frische Ticket-Diagnosen."
      ],
      "explanation": "Metriken entstehen aus Last, CPU/RAM, Instanzen und Abhängigkeiten. Eine größere VM oder mehrere geeignete Instanzen können die Last tragen.",
      "solution": [
        {
          "action": "configure",
          "id": "web",
          "changes": {
            "size": "D4"
          }
        }
      ],
      "alternatives": "Größere oder mehrere kleinere Instanzen sind gültig, wenn die Ergebnisse passen. Lastsenkung, Stopp oder Budgetüberschreitung nicht.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "operation": "orders_read"
          },
          "expected": true
        },
        {
          "test": "application",
          "args": {
            "user": "partner",
            "operation": "orders_write"
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "workload"
          ],
          "value": 150
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Last 150, CPU <=85%, keine Fehler, Budget <=600",
          "expr": {
            "all": [
              {
                "gte": [
                  {
                    "path": [
                      "workload"
                    ]
                  },
                  {
                    "literal": 150
                  }
                ]
              },
              {
                "lte": [
                  {
                    "metric": {
                      "resource": "web",
                      "name": "cpu"
                    }
                  },
                  {
                    "literal": 85
                  }
                ]
              },
              {
                "eq": [
                  {
                    "metric": {
                      "resource": "web",
                      "name": "error_rate"
                    }
                  },
                  {
                    "literal": 0
                  }
                ]
              },
              {
                "lte": [
                  {
                    "monthly": true
                  },
                  {
                    "literal": 600
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Azure Monitor → Metriken; Alle Ressourcen → Größe/Instanzen",
      "terms": [
        {
          "term": "CPU-Auslastung",
          "meaning": "Anteil benötigter Rechenkapazität."
        },
        {
          "term": "Vertikal skalieren",
          "meaning": "Leistungsfähigere Größe wählen."
        },
        {
          "term": "Horizontal skalieren",
          "meaning": "Mehrere Instanzen bereitstellen."
        }
      ],
      "variants": [
        {
          "label": "Zwei B2-Instanzen",
          "rationale": "CPU, Fehlerfreiheit und Budget entscheiden unabhängig von der Größe.",
          "actions": [
            {
              "action": "configure",
              "id": "web",
              "changes": {
                "size": "B2",
                "instances": 2
              }
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Anforderung durch Lastsenkung umgehen",
          "rationale": "Niedrige CPU bei unzulässig reduzierter Last genügt nicht.",
          "actions": [
            {
              "action": "workload",
              "value": 20
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Während der Lastspitze; etwa 20 Minuten. Last mindestens 150, CPU höchstens 85%, keine Fehler, Monatsprognose höchstens 600 Lern-Euro."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Bei 150 Lastpunkten gibt es Fehler. Behebe die Kapazitätsgrenze der Webanwendung ohne die Last zu reduzieren. CPU soll höchstens 85% betragen; Monatsprognose höchstens 600 Lern-Euro."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. B2 als Einzelinstanz trägt die Last nicht fehlerfrei. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {
      "id": "15",
      "title": "Alarm mit Ereignis testen",
      "sender": "IT-Leitung",
      "message": "Lege einen CPU-Alarm für web ab 80% über drei Minuten mit Ziel IT an. Erzeuge danach die Last und prüfe den ausgelösten Alarm.",
      "minutes": 18,
      "prerequisite": "Monitoring",
      "learning": "Alarmregel; Fenster; Ereignis",
      "learn": "Du lernst, eine Alarmregel mit einem passenden Messverlauf nachzuweisen.",
      "try_text": "Du probierst Regel, zusammenhängendes Fenster und tatsächlich ausgelöstes Ereignis.",
      "deadline": "Vor Übergabe der Alarmierung; etwa 18 Minuten plus drei Simulationsminuten Testlast.",
      "constraints": "web, CPU ab 80%, drei Minuten, Ziel IT. Danach wieder normale Last 20.",
      "initial": "Noch keine Regel; Last 20 löst nicht aus.",
      "hints": [
        "Beweist eine Regel ohne Testlast bereits ihre Funktion?",
        "Vergleiche Regelinhalt und Ereignistyp. Mindestens80 Prozent müssen drei Minuten ohne Unterbrechung anliegen; zwei Spitzen oder eine gleichnamige Budgetwarnung reichen nicht.",
        "Lege 80/3/IT an, setze Last 160, Trainer spult drei Minuten vor. Prüfe das Ereignis und reduziere wieder auf 20."
      ],
      "explanation": "Drei aufeinanderfolgende kontrollierte Simulationsminuten mit mindestens 80 Prozent CPU lösen den Metrikalarm aus; ein Wert darunter setzt die Folge auf null zurück. Das Ereignis speichert Typ, Ressourcen-/Metrikbezug, Schwelle, Fenster, Ziel, Beginn/Ende und letzten Messwert. Eine Budgetwarnung gleichen Namens ist kein Metriknachweis. Nach dem Test Last auf20 reduzieren. Pro Regel wird im vereinfachten Modell der erste Metrikalarm protokolliert; Auflösung, Quittierung und erneute Alarmepisoden sind nicht nachgebildet.",
      "solution": [
        {
          "action": "alarm_add",
          "rule": {
            "id": "cpu-high",
            "target": "web",
            "metric": "cpu",
            "threshold": 80,
            "window": 3,
            "destination": "IT"
          }
        },
        {
          "action": "workload",
          "value": 160
        },
        {
          "action": "advance",
          "minutes": 3
        },
        {
          "action": "workload",
          "value": 20
        }
      ],
      "alternatives": "Die Regel-ID ist frei. Entscheidend sind Inhalt und Ereignis derselben Regel, nicht ein vorgeschriebener ID-Text.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "workload"
          ],
          "value": 20
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Passende Regel hat einen tatsächlichen Metrikalarm ausgelöst",
          "expr": {
            "some": {
              "in": {
                "path": [
                  "alarms"
                ]
              },
              "as": "alarm",
              "where": {
                "all": [
                  {
                    "eq": [
                      {
                        "var": [
                          "alarm",
                          "metric"
                        ]
                      },
                      {
                        "literal": "cpu"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "var": [
                          "alarm",
                          "target"
                        ]
                      },
                      {
                        "literal": "web"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "var": [
                          "alarm",
                          "threshold"
                        ]
                      },
                      {
                        "literal": 80
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "var": [
                          "alarm",
                          "window"
                        ]
                      },
                      {
                        "literal": 3
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "var": [
                          "alarm",
                          "destination"
                        ]
                      },
                      {
                        "literal": "IT"
                      }
                    ]
                  },
                  {
                    "some": {
                      "in": {
                        "path": [
                          "alerts"
                        ]
                      },
                      "as": "alert",
                      "where": {
                        "all": [
                          {
                            "eq": [
                              {
                                "var": [
                                  "alert",
                                  "rule"
                                ]
                              },
                              {
                                "var": [
                                  "alarm",
                                  "id"
                                ]
                              }
                            ]
                          },
                          {
                            "eq": [
                              {
                                "var": [
                                  "alert",
                                  "kind"
                                ]
                              },
                              {
                                "literal": "metric"
                              }
                            ]
                          }
                        ]
                      }
                    }
                  }
                ]
              }
            }
          }
        },
        {
          "label": "Testlast nach Alarm wieder auf Normalwert 20 reduziert",
          "expr": {
            "eq": [
              {
                "path": [
                  "workload"
                ]
              },
              {
                "literal": 20
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Azure Monitor → Alarm/Last; Trainer → Zeit",
      "terms": [
        {
          "term": "Schwelle",
          "meaning": "Grenzwert zum Zählen der Bedingung."
        },
        {
          "term": "Fenster",
          "meaning": "Hier aufeinanderfolgende Simulationsminuten."
        },
        {
          "term": "Alarmziel",
          "meaning": "Simulierter Empfänger, keine echte Nachricht."
        }
      ],
      "variants": [
        {
          "label": "Eigene Regelkennung",
          "rationale": "Regelinhalt und zugehöriges Ereignis entscheiden statt ID-Text.",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "cpu-labor",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            },
            {
              "action": "workload",
              "value": 160
            },
            {
              "action": "advance",
              "minutes": 3
            },
            {
              "action": "workload",
              "value": 20
            }
          ]
        },
        {
          "label": "Exakt an der 80-Prozent-Schwelle",
          "rationale": "Auch Gleichheit zählt:72 Lastpunkte bei der vorhandenen B2 ergeben80 Prozent CPU.",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "cpu-grenze",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            },
            {
              "action": "workload",
              "value": 72
            },
            {
              "action": "advance",
              "minutes": 3
            },
            {
              "action": "workload",
              "value": 20
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Regel ohne Ereignis",
          "rationale": "Definition allein zeigt kein durchlaufenes Fenster.",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "cpu-only",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            }
          ],
          "outcome": "incomplete"
        },
        {
          "label": "Gleichnamige Budgetwarnung",
          "rationale": "budget-80 als frei gewählte Regel-ID bindet keine Budgetwarnung an die CPU-Metrik. Ohne Testlast bleibt die CPU-Regel ungetestet.",
          "outcome": "incomplete",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "budget-80",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            },
            {
              "action": "budget",
              "value": 0.01
            },
            {
              "action": "advance",
              "minutes": 1
            }
          ]
        },
        {
          "label": "Nur zwei Minuten Testlast",
          "rationale": "Das vollständige Drei-Minuten-Fenster wurde nicht durchlaufen.",
          "outcome": "incomplete",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "cpu-high",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            },
            {
              "action": "workload",
              "value": 72
            },
            {
              "action": "advance",
              "minutes": 2
            },
            {
              "action": "workload",
              "value": 20
            }
          ]
        },
        {
          "label": "Fenster durch Normalwert unterbrochen",
          "rationale": "Zwei hohe Minuten und nach Unterbrechung eine weitere ergeben keine drei aufeinanderfolgenden Minuten.",
          "outcome": "incomplete",
          "actions": [
            {
              "action": "alarm_add",
              "rule": {
                "id": "cpu-high",
                "target": "web",
                "metric": "cpu",
                "threshold": 80,
                "window": 3,
                "destination": "IT"
              }
            },
            {
              "action": "workload",
              "value": 72
            },
            {
              "action": "advance",
              "minutes": 2
            },
            {
              "action": "workload",
              "value": 20
            },
            {
              "action": "advance",
              "minutes": 1
            },
            {
              "action": "workload",
              "value": 72
            },
            {
              "action": "advance",
              "minutes": 1
            },
            {
              "action": "workload",
              "value": 20
            }
          ]
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor Übergabe der Alarmierung; etwa 18 Minuten plus drei Simulationsminuten Testlast. web, CPU ab 80%, drei Minuten, Ziel IT. Danach wieder normale Last 20."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Lege einen CPU-Alarm für web ab 80% über drei Minuten mit Ziel IT an. Erzeuge danach die Last und prüfe den ausgelösten Alarm."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Noch keine Regel; Last 20 löst nicht aus. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        },
        {
          "id": "alarmtyp",
          "question": "Zählt jede Meldung mit derselben Regelkennung als getesteter CPU-Alarm?",
          "answer": "Nein. Der Nachweis muss vom Typ Metrikalarm stammen. Budgetwarnungen und historische Meldungen unbekannten Typs zählen nicht. Das Modell trennt die Typen auch bei gleicher Kennung; unbekannte alte Meldungen bleiben erhalten und werden nicht anhand ihres Texts geraten."
        }
      ]
    },
    {"id":"16","title":"Container-Auslieferung reparieren","sender":"Versand","message":"Die kleine Versand-App ist seit dem Update gestört. Prüfe shipping:1.0, TCP-Port8080, mindestens eine laufende Instanz und die Umgebungsvariablen: DB_HOST muss unsere Firmen-Datenbank db erreichen, DOCUMENT_ID muss Angebot-A (offer) wählen. Ein Schalter Konfiguration vollständig ersetzt diese Werte nicht. Lass die übrige Firma und ihre Rechte unverändert und teste anschließend erlaubte und unerlaubte Verbindungen.","minutes":20,"prerequisite":"Anwendungsabhängigkeiten","learning":"Container Apps; Image; Port; Name/Wert-Konfiguration; Datenabhängigkeiten","learn":"Du lernst, wie ein Container-Image seine Datenbank und sein Dokument über konkrete Umgebungsvariablen findet.","try_text":"Du probierst fehlende oder falsche Konfigurationswerte, Image-/Portreparatur und erneute Dienstprüfung.","deadline":"Vor dem nächsten Versandlauf; etwa 20 Minuten.","constraints":"shipping:1.0, TCP-Port8080, vollständiger Laufzeitstatus und mindestens eine Instanz. DB_HOST muss zu db auflösen; DOCUMENT_ID ist offer. Keine zusätzlichen Rechte oder öffentlichen Administrationszugriffe, keine Änderungen am übrigen Firmenbestand. Keine echte Containerinstallation. Bestehende Cloud-Dateien mit Historien, Aufträge, Ablagen, Datenregeln, übrige Ressourcen, Netze, Konten, Rollen und Sicherungspläne bleiben unverändert. Nur den vorhandenen Versandcontainer und seine Laufzeitwerte bearbeiten. Notizen, Begründungen, Diagnosen und bewusstes Vorspulen samt Kosten-/Sicherungsprotokoll sind zulässig. Es gibt hier keine zusätzliche feste Kostengrenze; eine Budgetwarnung schaltet nichts ab.","initial":"Die Versandressource verwendet ein defektes Image; ihr Datenbankwert DB_HOST fehlt.","hints":["Welche Werte benötigt die Versand-App, um Datenbank und Angebot zu finden? Ein laufender Container und ein gesetzter Statusschalter genügen nicht.","Lies im Containerdetail DB_HOST und DOCUMENT_ID. DB_HOST muss zu db auflösen, DOCUMENT_ID muss offer wählen. Prüfe erst Auflösung und Datenpfade; mehr Instanzen reparieren kein falsches Ziel. Vergleiche nach der Reparatur auch den übrigen Firmenbestand: insbesondere Personaldatei, Aufträge, andere Ressourcen und Datenrollen. Eine funktionierende Versandverbindung allein genügt nicht.","Setze shipping:1.0 und TCP-Port8080 sowie vollständigen Laufzeitstatus. Speichere DB_HOST=daten.intern (alternativ db oder die tatsächlich zu db gehörende private IP) und DOCUMENT_ID=offer. Prüfe versand.intern:8080 sowie die erlaubten und gesperrten übrigen Auftragspfade erneut."],"explanation":"Das Image benötigt den passenden Dienstport und echte Name/Wert-Einstellungen. DB_HOST wird über die tatsächliche DNS-/Adresszuordnung zur Firmen-Datenbank aufgelöst; DOCUMENT_ID wählt den tatsächlichen Dokumentpfad. Fehlende Werte, falsche Ziele, blockierte Datenpfade und fehlende Restkapazität bleiben Störungen. Der Konfigurationsstatus steht zusätzlich für die übrige Laufzeiteinrichtung. Der Simulator führt keine echten Images oder Azure-Revisionen aus. Die Prüfung erhält die übrigen Dateien einschließlich Versionen, Geschäftsvorgänge, anderen Ressourcen, Identitäten und Rechte. Unterschiedliche Reihenfolgen derselben Gruppenmitglieder, Rollen oder Netzregeln sind gleichwertig. Zeitabhängige Protokolle und Lernnotizen bleiben erlaubt; sie ersetzen keine fachliche Reparatur.","solution":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running"}},{"action":"container_config","id":"container","values":{"DB_HOST":"daten.intern","DOCUMENT_ID":"offer"}}],"alternatives":"Eine oder mehrere passende Instanzen sind zulässig, solange alle Schutzbedingungen bleiben. DB_HOST darf einen auf db auflösenden Namen, db selbst oder die aktuelle private DB-Adresse verwenden. Die Dokumentkennung bleibt offer; verschiedene Zielnamen sind kein eigener Klickpfad. Notizen, erneute Diagnosen, bewusstes Vorspulen und eine andere Reihenfolge unveränderter Rollen/Gruppen/Netzregeln sind zulässig. Andere Firmenressourcen oder Daten dürfen dafür nicht verändert werden.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"connection","args":{"source":"hq","host":"versand.intern","port":8080},"expected":true}],"start":[{"op":"set","path":["resources","storage","public"],"value":false},{"op":"set","path":["container_settings","container"],"value":{"DOCUMENT_ID":"offer"}}],"setup":[],"criteria":[{"label":"Gültiges Container-Image, Port und Konfiguration","expr":{"all":[{"eq":[{"path":["resources","container","image"]},{"literal":"shipping:1.0"}]},{"eq":[{"path":["resources","container","port"]},{"literal":8080}]},{"eq":[{"path":["resources","container","configured"]},{"literal":true}]},{"eq":[{"path":["container_settings","container","DOCUMENT_ID"]},{"literal":"offer"}]},{"eq":[{"metric":{"resource":"container","name":"healthy"}},{"literal":true}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Bestehende Cloud-Dateien, Aufträge, Ablagen und Datenregeln bleiben unverändert","expr":{"all":[{"same_records_except_modified":[{"path":["documents"]},{"literal":{"offer":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]},"payroll":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]},"public":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]}}}]},{"same_records_except_modified":[{"path":["orders"]},{"literal":{"NL-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Arbeitsplatz-Erweiterung","amount":120.0,"status":"Neu","document":"offer","modified":0,"version":1},"NL-1002":{"customer":"Fiktiv: Beispielhandel KG","subject":"Standortanbindung planen","amount":240.0,"status":"In Bearbeitung","document":"offer","modified":0,"version":1}}}]},{"eq":[{"path":["document_storage"]},{"literal":{"offer":{"kind":"Blob","host":"storage"},"payroll":{"kind":"Blob","host":"storage"},"public":{"kind":"Blob","host":"storage"}}}]},{"eq":[{"path":["data_governance"]},{"literal":{"offer":{"owner":"Vertrieb","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"offer","status":"active"},"payroll":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"payroll","status":"active"},"public":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"public","status":"active"}}}]}]}},{"label":"Andere Ressourcen und Ressourcengruppen bleiben unverändert","expr":{"all":[{"eq":[{"count":{"path":["resources"]}},{"literal":7}]},{"eq":[{"path":["resources","web"]},{"literal":{"name":"vm-auftrag","kind":"VM","group":"rg-app","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.10","port":443,"image":"orders:1.0","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","db"]},{"literal":{"name":"db-auftrag","kind":"Database","group":"rg-app","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":64,"ip":"10.20.2.20","port":5432,"image":"orders:1.0","instances":1,"subnet":"data","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","storage"]},{"literal":{"name":"stnordlicht","kind":"Storage","group":"rg-data","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":64,"ip":"10.20.2.30","port":443,"image":"orders:1.0","instances":1,"subnet":"data","public_ip":"198.51.100.30","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","testvm"]},{"literal":{"name":"vm-altprojekt","kind":"VM","group":"rg-lab","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"D4","status":"stopped","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.11","port":443,"image":"orders:1.0","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","paas"]},{"literal":{"name":"app-auftrag","kind":"App Service","group":"rg-app","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"stopped","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.40","port":443,"image":"orders:1.0","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","saas"]},{"literal":{"name":"Büro-Suite (externer Anbieter)","kind":"SaaS","group":"rg-lab","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":0,"ip":"","port":443,"image":"orders:1.0","instances":1,"subnet":"","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resource_groups"]},{"literal":{"rg-app":{"region":"germanywestcentral","department":"Betrieb","owner":"IT-Leitung"},"rg-data":{"region":"germanywestcentral","department":"Vertrieb","owner":"IT-Leitung"},"rg-lab":{"region":"germanywestcentral","department":"IT","owner":"IT-Leitung"}}}]}]}},{"label":"Firmenkonten, Gruppen, Datenrollen und Dienstidentitäten bleiben unverändert","expr":{"all":[{"eq":[{"path":["users"]},{"literal":{"u01":{"name":"Person 01 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u02":{"name":"Person 02 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u03":{"name":"Person 03 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u04":{"name":"Person 04 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u05":{"name":"Person 05 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u06":{"name":"Person 06 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u07":{"name":"Person 07 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u08":{"name":"Person 08 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u09":{"name":"Person 09 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u10":{"name":"Person 10 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u11":{"name":"Person 11 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u12":{"name":"Person 12 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u13":{"name":"Person 13 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u14":{"name":"Person 14 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u15":{"name":"Person 15 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u16":{"name":"Person 16 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u17":{"name":"Person 17 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u18":{"name":"Person 18 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u19":{"name":"Person 19 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u20":{"name":"Person 20 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u21":{"name":"Person 21 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u22":{"name":"Person 22 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u23":{"name":"Person 23 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u24":{"name":"Person 24 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u25":{"name":"Person 25 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u26":{"name":"Person 26 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u27":{"name":"Person 27 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u28":{"name":"Person 28 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u29":{"name":"Person 29 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u30":{"name":"Person 30 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u31":{"name":"Person 31 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u32":{"name":"Person 32 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u33":{"name":"Person 33 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u34":{"name":"Person 34 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u35":{"name":"Person 35 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u36":{"name":"Person 36 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u37":{"name":"Person 37 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u38":{"name":"Person 38 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u39":{"name":"Person 39 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u40":{"name":"Person 40 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u41":{"name":"Person 41 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u42":{"name":"Person 42 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u43":{"name":"Person 43 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u44":{"name":"Person 44 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u45":{"name":"Person 45 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u46":{"name":"Person 46 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u47":{"name":"Person 47 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u48":{"name":"Person 48 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u49":{"name":"Person 49 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u50":{"name":"Person 50 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u51":{"name":"Person 51 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u52":{"name":"Person 52 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u53":{"name":"Person 53 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u54":{"name":"Person 54 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u55":{"name":"Person 55 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u56":{"name":"Person 56 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u57":{"name":"Person 57 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u58":{"name":"Person 58 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u59":{"name":"Person 59 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"u60":{"name":"Person 60 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"lea":{"name":"Lea Neumann (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"},"partner":{"name":"Robin Extern (fiktiv)","department":"Dienstleister","active":true,"mfa":true,"guest":true,"expires":480,"directory_role":"User"},"it":{"name":"IT-Lernrolle","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User Administrator"}}}]},{"eq":[{"path":["service_principals"]},{"literal":{"orders-app":{"name":"Dienstidentität der Auftragsanwendung","active":true}}}]},{"eq":[{"count":{"path":["groups"]}},{"literal":4}]},{"all":[{"eq":[{"count":{"path":["groups","Vertrieb"]}},{"literal":2}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"u11"}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"u12"}]}]},{"all":[{"eq":[{"count":{"path":["groups","IT"]}},{"literal":1}]},{"contains":[{"path":["groups","IT"]},{"literal":"it"}]}]},{"all":[{"eq":[{"count":{"path":["groups","Altprojekt"]}},{"literal":1}]},{"contains":[{"path":["groups","Altprojekt"]},{"literal":"lea"}]}]},{"all":[{"eq":[{"count":{"path":["groups","Partner"]}},{"literal":1}]},{"contains":[{"path":["groups","Partner"]},{"literal":"partner"}]}]},{"eq":[{"count":{"path":["roles"]}},{"literal":9}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"IT","role":"Contributor","scope":"subscription"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"IT","role":"User Access Administrator","scope":"subscription"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Vertrieb","role":"Blob Contributor","scope":"sales"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Altprojekt","role":"Blob Reader","scope":"sales"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"partner","role":"Blob Contributor","scope":"storage"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"lea","role":"Reader","scope":"storage"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Vertrieb","role":"Order Operator","scope":"orders"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"orders-app","role":"Order Operator","scope":"orders"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"orders-app","role":"Blob Reader","scope":"sales"}}]}]}},{"label":"Netz- und übrige Firmeneinstellungen bleiben unverändert","expr":{"all":[{"eq":[{"path":["network","vnet"]},{"literal":"10.20.0.0/16"}]},{"eq":[{"path":["network","subnets"]},{"literal":{"app":"10.20.1.0/24","data":"10.20.2.0/24"}}]},{"eq":[{"path":["network","onprem"]},{"literal":"10.10.0.0/16"}]},{"eq":[{"path":["network","vpn"]},{"literal":true}]},{"eq":[{"path":["network","dns"]},{"literal":{"auftrag.intern":"web","daten.intern":"db","ablage.intern":"storage","versand.intern":"container"}}]},{"eq":[{"count":{"path":["network","rules"]}},{"literal":2}]},{"contains":[{"path":["network","rules"]},{"literal":{"id":"web-in","direction":"Inbound","protocol":"TCP","source":"10.10.0.0/16","destination":"web","port":443,"action":"Allow","priority":200}}]},{"contains":[{"path":["network","rules"]},{"literal":{"id":"storage-in","direction":"Inbound","protocol":"TCP","source":"*","destination":"storage","port":443,"action":"Allow","priority":210}}]},{"eq":[{"path":["company"]},{"literal":"Nordlicht Auftragsservice GmbH"}]},{"eq":[{"path":["tenant"]},{"literal":"nordlicht.example (Entra ID)"}]},{"eq":[{"path":["subscription"]},{"literal":"Nordlicht-Lernsubscription"}]},{"eq":[{"path":["locations"]},{"literal":{"Hauptstandort":42,"Außenstelle":10,"Homeoffice":8}}]},{"eq":[{"path":["local_inventory"]},{"literal":[{"name":"AD-01","role":"Lokaler AD-DS-Lernbereich: Konten, Gruppen und Anmeldung; kein echtes Kerberos/GPO","dependency":"LAN"},{"name":"FILE-01","role":"Dateiserver, Abteilungsfreigaben","dependency":"AD-01"},{"name":"ORDER-01","role":"Interne Auftragsanwendung","dependency":"SQL-01 + FILE-01"},{"name":"SQL-01","role":"Auftragsdatenbank","dependency":"LAN"},{"name":"BACKUP-01","role":"Lokale Sicherung","dependency":"FILE-01 + SQL-01"}]}]},{"eq":[{"path":["application"]},{"literal":{"name":"Nordlicht Aufträge","principal":"orders-app"}}]},{"eq":[{"path":["requests"]},{"literal":{"active":"","deployments":{},"company":{},"provider":{}}}]},{"eq":[{"path":["workload"]},{"literal":70}]},{"eq":[{"path":["budget"]},{"literal":200.0}]},{"eq":[{"path":["policy"]},{"literal":{"regions":["germanywestcentral","westeurope"],"require_tags":true,"deny_public":false}}]},{"eq":[{"path":["migration"]},{"literal":{"phase":"inventory","target":"paas","synced":false,"tested":false,"cutover":false,"rollback":false,"cleaned":false,"interrupted":false}}]},{"eq":[{"path":["local_migration"]},{"literal":{"phase":"inventory","strategy":"","reason":"","target":"","documents":{},"orders":{},"governance":{},"source_hash":"","cloud_hash":"","owned_documents":[],"owned_orders":[],"cloud_present":false,"active":false,"interrupted":false,"synced":false,"tested":false,"cleaned":false,"original_dns":"ORDER-01"}}]},{"eq":[{"path":["availability_event"]},{"literal":{"enabled":false,"region":"germanywestcentral","zone":1,"since":0}}]},{"eq":[{"path":["alarms"]},{"literal":[]}]},{"eq":[{"path":["decisions"]},{"literal":{}}]}]}},{"label":"Sicherungspläne und lokaler Betriebsbereich bleiben erhalten","expr":{"all":[{"eq":[{"path":["onprem","enabled"]},{"literal":true}]},{"eq":[{"path":["backup","enabled"]},{"literal":true}]},{"eq":[{"path":["backup","interval"]},{"literal":240}]},{"eq":[{"path":["backup","retention"]},{"literal":1440}]}]}},{"label":"Nur die Konfiguration des vorhandenen Versandcontainers bearbeiten","expr":{"all":[{"eq":[{"count":{"path":["container_settings"]}},{"literal":1}]}]}}],"function":"Alle Ressourcen: Container öffnen, Image/Port/Laufzeitstatus und Name/Wert-Konfiguration getrennt speichern. Virtual Network und Dienstprüfung: tatsächliche Pfade prüfen; abschließend Auftragsdiagnosen erneut ausführen.","terms":[{"term":"Container-Image","meaning":"Versioniertes Paket der simulierten Anwendung."},{"term":"Konfiguration","meaning":"Benannte Laufzeitwerte. Hier DB_HOST für das auflösbare Firmen-Datenbankziel und DOCUMENT_ID für die tatsächliche Dokumentkennung; zusätzlich gibt es einen Status für die übrige Einrichtung."},{"term":"Instanz","meaning":"Bereitgestellte Laufzeitkopie mit Kapazität und Lernkosten."},{"term":"Umgebungsvariable","meaning":"Ein Name/Wert-Paar für ein Programm. Dieses Lernprofil unterstützt DB_HOST und DOCUMENT_ID; keine echten Geheimnisse oder Kennwörter eingeben."}],"variants":[{"label":"Zwei korrekte Containerinstanzen","rationale":"Zwei korrekt konfigurierte Instanzen und die direkte vorhandene DB-Ressourcenkennung sind fachlich zulässig. Mehr Kapazität allein repariert weder Image noch Werte.","actions":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running","instances":2}},{"action":"container_config","id":"container","values":{"DB_HOST":"db","DOCUMENT_ID":"offer"}}]}],"failures":[{"label":"Falsches Image stärker skalieren","rationale":"Mehr Instanzen machen das Paket nicht gesund.","actions":[{"action":"configure","id":"container","changes":{"instances":2}},{"action":"container_config","id":"container","values":{"DB_HOST":"daten.intern","DOCUMENT_ID":"offer"}}],"outcome":"incomplete"},{"label":"Nur den Konfigurationsschalter setzen","rationale":"Der boolesche Laufzeitstatus ersetzt den fehlenden DB_HOST-Wert nicht.","outcome":"incomplete","actions":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running"}},{"action":"container_config","id":"container","values":{"DOCUMENT_ID":"offer"}}]},{"label":"Falsches Datenbankziel","rationale":"Ein auf die Webressource zeigender DB_HOST ist keine Firmen-Datenbank.","outcome":"incomplete","actions":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running"}},{"action":"container_config","id":"container","values":{"DB_HOST":"auftrag.intern","DOCUMENT_ID":"offer"}}]},{"label":"Falsches Geschäfts-Dokument","rationale":"Ein vorhandenes anderes Dokument kann erreichbar sein, erfüllt aber nicht den Auftrag für Angebot-A.","outcome":"incomplete","actions":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running"}},{"action":"container_config","id":"container","values":{"DB_HOST":"db","DOCUMENT_ID":"public"}}]},{"label":"Versand repariert, zusätzliche Personal-Datenrolle vergeben","rationale":"Ein unbeteiligter Kollege darf durch die Containerreparatur keinen neuen Personalzugriff erhalten.","outcome":"incomplete","actions":[{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true,"status":"running"}},{"action":"container_config","id":"container","values":{"DB_HOST":"daten.intern","DOCUMENT_ID":"offer"}},{"action":"role_add","principal":"u60","role":"Blob Reader","scope":"hr","actor":"it"}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor dem nächsten Versandlauf; etwa 20 Minuten. shipping:1.0, TCP-Port8080, vollständiger Laufzeitstatus und mindestens eine Instanz. DB_HOST muss zu db auflösen; DOCUMENT_ID ist offer. Keine zusätzlichen Rechte oder öffentlichen Administrationszugriffe, keine Änderungen am übrigen Firmenbestand. Keine echte Containerinstallation."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Die kleine Versand-App ist seit dem Update gestört. Prüfe shipping:1.0, TCP-Port8080, mindestens eine laufende Instanz und die Umgebungsvariablen: DB_HOST muss unsere Firmen-Datenbank db erreichen, DOCUMENT_ID muss Angebot-A (offer) wählen. Ein Schalter Konfiguration vollständig ersetzt diese Werte nicht. Lass die übrige Firma und ihre Rechte unverändert und teste anschließend erlaubte und unerlaubte Verbindungen."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Nenne Ursache, konkrete Werte und frische erlaubte/verweigerte Diagnosen. Fehlender DB_HOST und kaputtes Image sind getrennte Fehler. Freitext wird von der Lehrkraft besprochen, nicht automatisch verstanden."}]},
    {
      "id": "17",
      "title": "Kosten senken ohne Produktionsausfall",
      "sender": "Buchhaltung",
      "message": "Die gestoppte alte Test-VM verursacht noch Compute-Kosten. Gib ihre Zuordnung frei. Die produktive Auftragsanwendung und alle Daten bleiben verfügbar.",
      "minutes": 18,
      "prerequisite": "VM-Zustände",
      "learning": "Kosten; Stoppen und Deallokieren",
      "learn": "Du lernst, Compute-Kosten zu beenden und verbleibende Datenträgerkosten zu erklären.",
      "try_text": "Du probierst den Unterschied zwischen OS-Shutdown und Deallokierung bei laufender Produktion.",
      "deadline": "Vor dem nächsten längeren Leerlauf; etwa 18 Minuten.",
      "constraints": "Nur Test-Compute freigeben, Produktion/Daten erhalten; Diskkosten bleiben sichtbar. Alle vorhandenen Dokumente, Ablagen und anderen Ressourcen unverändert lassen.",
      "initial": "Test-VM ist gestoppt, aber zugeordnet und berechnet Compute.",
      "hints": [
        "Was bleibt nach OS-Shutdown noch berechnet?",
        "Vergleiche Compute und Disk für testvm; stopped ist keine Freigabe.",
        "Gib testvm frei. Prüfe deren Compute = 0, verbleibende Diskkosten und die erlaubte Produktionsverbindung."
      ],
      "explanation": "Eine im Betriebssystem gestoppte, zugeordnete VM kostet weiter Compute. Deallokieren beendet diese Kosten, Datenträger bleiben berechnet. Budgetwarnungen sind kein Kostendeckel.",
      "solution": [
        {
          "action": "power",
          "id": "testvm",
          "operation": "deallocate"
        }
      ],
      "alternatives": "Vorher kann der Trainer eine weitere Kostenminute messen. Stoppen allein oder Produktionsdaten löschen ist keine Sparlösung.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Test-Compute deallokiert; produktive Daten erhalten",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "resources",
                      "testvm",
                      "status"
                    ]
                  },
                  {
                    "literal": "deallocated"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "resources",
                      "web",
                      "status"
                    ]
                  },
                  {
                    "literal": "running"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "documents",
                      "offer",
                      "deleted"
                    ]
                  },
                  {
                    "literal": false
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Nur Test-Zuordnung geändert, alle Geschäftsdaten und Ablagen erhalten",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "resources"
                    ]
                  },
                  {
                    "literal": {
                      "web": {
                        "name": "vm-auftrag",
                        "kind": "VM",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.10",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "db": {
                        "name": "db-auftrag",
                        "kind": "Database",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.2.20",
                        "port": 5432,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "data",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "storage": {
                        "name": "stnordlicht",
                        "kind": "Storage",
                        "group": "rg-data",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.2.30",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "data",
                        "public_ip": "198.51.100.30",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "testvm": {
                        "name": "vm-altprojekt",
                        "kind": "VM",
                        "group": "rg-lab",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "D4",
                        "status": "deallocated",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.11",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "paas": {
                        "name": "app-auftrag",
                        "kind": "App Service",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "stopped",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.40",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "container": {
                        "name": "ca-versand",
                        "kind": "Container Apps",
                        "group": "rg-app",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 64,
                        "ip": "10.20.1.50",
                        "port": 8080,
                        "image": "shipping:broken",
                        "instances": 1,
                        "subnet": "app",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      },
                      "saas": {
                        "name": "Büro-Suite (externer Anbieter)",
                        "kind": "SaaS",
                        "group": "rg-lab",
                        "region": "germanywestcentral",
                        "department": "IT",
                        "owner": "IT-Leitung",
                        "availability": "single",
                        "size": "B2",
                        "status": "running",
                        "public": false,
                        "locked": false,
                        "disk_gb": 0,
                        "ip": "",
                        "port": 443,
                        "image": "orders:1.0",
                        "instances": 1,
                        "subnet": "",
                        "public_ip": "",
                        "configured": true,
                        "tier": "hot",
                        "redundancy": "LRS",
                        "capacity_gb": 100,
                        "used_gb": 12,
                        "os": "Linux"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "name": "Angebot-A.txt",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Angebot A: 120 Lern-Euro; Version 1.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "payroll": {
                        "name": "Personal-B.txt",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Fiktive Personalnotiz B; keine echten Personendaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "public": {
                        "name": "Firmeninfo.txt",
                        "container": "public",
                        "class": "öffentlich",
                        "content": "Nordlicht: 60 fiktive Beschäftigte.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "document_storage"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "kind": "Blob",
                        "host": "storage"
                      },
                      "payroll": {
                        "kind": "Blob",
                        "host": "storage"
                      },
                      "public": {
                        "kind": "Blob",
                        "host": "storage"
                      }
                    }
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "data_governance"
                    ]
                  },
                  {
                    "literal": {
                      "offer": {
                        "owner": "Vertrieb",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "offer",
                        "status": "active"
                      },
                      "payroll": {
                        "owner": "IT",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "payroll",
                        "status": "active"
                      },
                      "public": {
                        "owner": "IT",
                        "purpose": "Bestandsdaten; Zweck und Frist prüfen",
                        "retention_until": 0,
                        "hold": false,
                        "reason": "Noch keine fachliche Frist festgelegt",
                        "origin": "public",
                        "status": "active"
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Cost Management → Rechenweg; Ressourcen → Zuordnung freigeben",
      "terms": [
        {
          "term": "Shutdown",
          "meaning": "OS aus, Ressourcen bleiben zugeordnet."
        },
        {
          "term": "Deallokieren",
          "meaning": "Compute freigeben, Disk bleibt bestehen."
        },
        {
          "term": "Ist-Kosten",
          "meaning": "Vergangene Kosten verschwinden nicht rückwirkend."
        }
      ],
      "variants": [
        {
          "label": "Kosten vor Freigabe beobachten",
          "rationale": "Eine weitere Minute zeigt noch entstehenden Verbrauch, dann nur Test-Compute freigeben.",
          "actions": [
            {
              "action": "advance",
              "minutes": 1
            },
            {
              "action": "power",
              "id": "testvm",
              "operation": "deallocate"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Nur OS-Shutdown",
          "rationale": "Zuordnung und Compute-Kosten bleiben.",
          "actions": [
            {
              "action": "power",
              "id": "testvm",
              "operation": "shutdown"
            }
          ],
          "outcome": "incomplete"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor dem nächsten längeren Leerlauf; etwa 18 Minuten. Nur Test-Compute freigeben, Produktion/Daten erhalten; Diskkosten bleiben sichtbar. Alle vorhandenen Dokumente, Ablagen und anderen Ressourcen unverändert lassen."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Die gestoppte alte Test-VM verursacht noch Compute-Kosten. Gib ihre Zuordnung frei. Die produktive Auftragsanwendung und alle Daten bleiben verfügbar."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Test-VM ist gestoppt, aber zugeordnet und berechnet Compute. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {
      "id": "18",
      "title": "Auftragsanwendung migrieren",
      "sender": "IT-Leitung",
      "message": "Plane und verschiebe die vorhandene Cloud-Auftragslaufzeit web mit Test, Umschaltung, Nachkontrolle und Rückfall. Der historische Profilname ORDER-01 bezeichnet hier diesen Cloud-Laufzeitauftrag. Der zusätzlich bedienbare lokale Datei-/SQL-Bestand wird durch diesen bisherigen Weg noch nicht in die Cloud übernommen; dieser Cloud-Laufzeitauftrag allein belegt keine lokale Datenübernahme. Für den tatsächlichen lokalen Datei-/Auftragsbestand gibt es zusätzlich den Auftrag umzug.",
      "minutes": 30,
      "prerequisite": "Abhängigkeiten und Backup",
      "learning": "Migration; PaaS; Rückfall; Datenabgleich",
      "learn": "Du lernst, einen Laufzeitumzug mit Datenabgleich, Zieltest und Rückfall abzusichern.",
      "try_text": "Du probierst einen begründeten Laufzeitumzug mit Prüfung, Umschaltung und Rückfallpfad.",
      "deadline": "Vor geplanter Umschaltung; etwa 30 Minuten.",
      "constraints": "ORDER-01 prüfen, Rehost/Replatform begründen, Datenabgleich/Rückfall nachweisen; Quelle erst nach Nachkontrolle freigeben.",
      "initial": "Inventar und PaaS-Ziel vorhanden; Strategie, Abgleich und Zieltest fehlen.",
      "hints": [
        "Welche Betriebsverantwortung soll bei der Firma bleiben?",
        "Vergleiche ORDER-01/AD-01 im Eignungsbericht; prüfe Datenänderungen, Zielpfad und Dienstidentität.",
        "Wähle begründet Rehost oder Replatform. Führe Vorbereitung, Abgleich, Zieltest, Umschaltung, Nachkontrolle und Aufräumen aus; prüfe endgültige Zugriffe frisch."
      ],
      "explanation": "Inventar und Laufzeitprofil begrenzen geeignete Ziele. Rehost belässt OS-/Patchverantwortung beim Unternehmen; Replatform verlagert den Plattformbetrieb. Die Fingerprint-Prüfung erkennt Änderungen an allen Dokumenten und Aufträgen. Auch unmittelbar vor Umschaltung und Aufräumen wird das Ziel erneut geprüft. Datenbank und Ablage bleiben gemeinsame Dienste; simuliert wird der Umzug der Weblaufzeit mit Konsistenzabgleich, keine reale Datenträgerkopie. Beim Rückfall bleibt der App-Service-Plan kostenpflichtig, auch wenn die App gestoppt ist. Bei einem VM-Ziel endet nur die Compute-Zuordnung; der Disk bleibt kostenpflichtig. Der lokale Betriebsbereich ist jetzt tatsächlich bedienbar, sein Datei-/SQL-Bestand ist aber kein automatisch synchronisierter Teil dieses bisherigen Cloud-Laufzeitpfads.",
      "solution": [
        {
          "action": "migration_plan",
          "workload": "ORDER-01",
          "strategy": "replatform",
          "reason": "Linux-Webanwendung ohne Domänenbindung; Plattformbetrieb abgeben, Datenzugriff selbst prüfen."
        },
        {
          "action": "migration",
          "step": "prepare"
        },
        {
          "action": "migration",
          "step": "copy"
        },
        {
          "action": "migration",
          "step": "test"
        },
        {
          "action": "migration",
          "step": "cutover"
        },
        {
          "action": "migration",
          "step": "followup"
        },
        {
          "action": "migration",
          "step": "cleanup"
        }
      ],
      "alternatives": "Beide Laufzeitwege sind geprüft. Retain ist kein Umzug, Büro-SaaS keine Auftragsanwendung. Rückfall startet die Quelle: Ein VM-Ziel wird deallokiert, ein App-Service-Ziel nur gestoppt; Disk beziehungsweise Lern-Plankosten bleiben.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [
        {
          "test": "connection",
          "args": {
            "source": "hq",
            "host": "auftrag.intern",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "connection",
          "args": {
            "source": "internet",
            "host": "web",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "operation": "orders_read"
          },
          "expected": true
        },
        {
          "test": "application",
          "args": {
            "user": "partner",
            "operation": "orders_write"
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Bestand geprüft und ausführbare Strategie begründet",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "decisions",
                      "migration_workload"
                    ]
                  },
                  {
                    "literal": "ORDER-01"
                  }
                ]
              },
              {
                "nonempty": {
                  "path": [
                    "decisions",
                    "migration_reason"
                  ]
                }
              },
              {
                "any_of": [
                  {
                    "all": [
                      {
                        "eq": [
                          {
                            "path": [
                              "decisions",
                              "migration_strategy"
                            ]
                          },
                          {
                            "literal": "rehost"
                          }
                        ]
                      },
                      {
                        "eq": [
                          {
                            "path": [
                              "migration",
                              "target"
                            ]
                          },
                          {
                            "literal": "migrationvm"
                          }
                        ]
                      }
                    ]
                  },
                  {
                    "all": [
                      {
                        "eq": [
                          {
                            "path": [
                              "decisions",
                              "migration_strategy"
                            ]
                          },
                          {
                            "literal": "replatform"
                          }
                        ]
                      },
                      {
                        "eq": [
                          {
                            "path": [
                              "migration",
                              "target"
                            ]
                          },
                          {
                            "literal": "paas"
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Aktueller Datenabgleich und Ziel weiterhin funktionsfähig",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "decisions",
                      "migration_copy_fingerprint"
                    ]
                  },
                  {
                    "migration_fingerprint": true
                  }
                ]
              },
              {
                "migration_target_ready": true
              }
            ]
          }
        },
        {
          "label": "Migration mit Datenabgleich, Prüfung, Umschaltung, Rückfall und Aufräumen",
          "expr": {
            "all": [
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "phase"
                    ]
                  },
                  {
                    "literal": "complete"
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "synced"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "tested"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "cutover"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "rollback"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "path": [
                      "migration",
                      "cleaned"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              },
              {
                "eq": [
                  {
                    "target": "auftrag.intern"
                  },
                  {
                    "path": [
                      "migration",
                      "target"
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "Migration Center → Eignung/Strategie/Rehost oder Replatform/Abgleich/Prüfung/Umschaltung/Nachkontrolle/Aufräumen/Rückfall",
      "terms": [
        {
          "term": "Rehost",
          "meaning": "Umzug auf eigene Ziel-VM mit OS-/Patchbetrieb."
        },
        {
          "term": "Replatform",
          "meaning": "Verwaltete Plattform für die Laufzeit."
        },
        {
          "term": "Rückfall",
          "meaning": "Vorherigen Betrieb gezielt wiederherstellen."
        },
        {
          "term": "Datenabgleich",
          "meaning": "Manifestprüfung, DB und Ablage bleiben hier gemeinsame Dienste."
        }
      ],
      "variants": [
        {
          "label": "Rehost auf eigene VM",
          "rationale": "Eigener OS-Betrieb, aber derselbe vollständige Daten-/Umzugsnachweis.",
          "actions": [
            {
              "action": "migration_plan",
              "workload": "ORDER-01",
              "strategy": "rehost",
              "reason": "VM-Betrieb bewusst beibehalten; Daten und Netz geprüft."
            },
            {
              "action": "migration",
              "step": "prepare"
            },
            {
              "action": "migration",
              "step": "copy"
            },
            {
              "action": "migration",
              "step": "test"
            },
            {
              "action": "migration",
              "step": "cutover"
            },
            {
              "action": "migration",
              "step": "followup"
            },
            {
              "action": "migration",
              "step": "cleanup"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Umschaltung vor Datenprüfung",
          "rationale": "Die Aktion verweigert die unvollständige Reihenfolge.",
          "actions": [
            {
              "action": "migration_plan",
              "workload": "ORDER-01",
              "strategy": "replatform",
              "reason": "Reihenfolge prüfen"
            },
            {
              "action": "migration",
              "step": "prepare"
            },
            {
              "action": "migration",
              "step": "cutover"
            }
          ],
          "outcome": "rejected"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor geplanter Umschaltung; etwa 30 Minuten. ORDER-01 prüfen, Rehost/Replatform begründen, Datenabgleich/Rückfall nachweisen; Quelle erst nach Nachkontrolle freigeben."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Prüfe ORDER-01 und seine Abhängigkeiten. Vergleiche Rehost auf eine eigene Ziel-VM mit Replatform zu App Service; der vorhandene Büro-SaaS-Dienst ersetzt keine Auftragsanwendung. Begründe die Strategie, gleiche Daten ab, teste das Ziel und schalte erst danach um. Halte Rückfall bereit und gib die Quelle erst nach erfolgreicher Nachkontrolle frei."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Inventar und PaaS-Ziel vorhanden; Strategie, Abgleich und Zieltest fehlen. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {"id":"19","title":"Austritt und Datenübergabe","sender":"Personal","message":"Lea verlässt die Firma. Sperre ihr Konto und entferne beide Gruppenpfade. Übergib die Verantwortung für das weiterhin benötigte Angebot an Vertrieb und schütze es für 30 Simulationstage. Entferne den nicht mehr benötigten Austrittsentwurf samt Versionen und modellierten Sicherungskopien. Lea hatte auch eine lokale Anmeldung und lokale Vertriebs-/Auftragsgruppen. Beende diese Zugänge zusätzlich; der Vertrieb und die lokalen Geschäftsdaten bleiben verfügbar. Die übrigen Cloud-Konten, Gruppenmitglieder, Rollen, Geschäftsvorgänge und Dateien bleiben erhalten; Leas alte direkte Reader-Rolle darf zusätzlich entfernt werden.","minutes":22,"prerequisite":"Eintritt und Rechte","learning":"Austritt; Datenminimierung; Aufbewahrung","learn":"Du lernst, Zugänge beim Austritt zu beenden und weiterhin benötigte Daten verantwortlich zu übergeben.","try_text":"Du probierst mehrere Rechteentzüge und dokumentierst getrennt die Datenverantwortung.","deadline":"Vor Leas letztem Arbeitstag; etwa 22 Minuten.","constraints":"Angebot und Auftragsbetrieb erhalten. Verantwortung allein erteilt keine Datenrechte. 30 Tage sind eine fiktive Firmenvorgabe, keine rechtliche Empfehlung. Austrittsentwurf ist nicht mehr erforderlich. Inhalt und Historie des weiter benötigten Angebots nicht verändern. Bei aktivem lokalem Betriebsbereich auch Leas lokales Konto deaktivieren und lokale Gruppenrechte entfernen. Lokale Kollegen, Dienste, Dateien, Aufträge und Sicherungsplan bleiben erhalten. Keine Änderungen an unbeteiligten Cloud-Konten, Gruppen, Rollen, Aufträgen, Dateien oder ihren Ablagen und Datenregeln. Nur Leas eigene Kontoeigenschaften, ihre beiden Mitgliedschaften und optional ihre direkte Reader-Rolle dürfen beim Rechteentzug geändert werden.","initial":"Lea ist aktiv in beiden Gruppen und verantwortet das Angebot. Ein entbehrlicher Austrittsentwurf liegt einschließlich früherer Version und Sicherungspunkt vor.","hints":["Welche Daten werden für den Geschäftsbetrieb noch gebraucht, welche nicht? Kontosperre ersetzt diese Entscheidung nicht.","Im Storage-Bereich Verantwortung und Frist des Angebots setzen. Beim Austrittsentwurf Inhalt, Versionen und Backup vor und nach Entfernung vergleichen. Prüfe die lokale AD-Lernwelt getrennt von Entra: der Cloud-Austritt wird nicht automatisch synchronisiert. Vergleiche auch Cloud-Kollegen und bestehende Aufträge/Dateien mit dem Ausgangsbestand; ein erreichbarer Dienst beweist nicht unveränderte Inhalte.","Lea sperren, Vertrieb/Altprojekt entfernen. Angebot: Vertrieb, 43200 Minuten, Zweck und Begründung. Austrittsentwurf begründet entfernen; danach Datei-/App-Diagnosen frisch ausführen. Zusätzlich lokales Lea-Konto deaktivieren und Lea aus lokalem Vertrieb und Auftragsbearbeitung entfernen; lokale U11-Zugriffe erneut positiv prüfen."],"explanation":"Die fachliche Verantwortung wechselt tatsächlich zum Vertrieb, ohne neue Zugriffsrechte zu erteilen. Eine laufende Aufbewahrung oder Löschsperre verhindert endgültige Entfernung. Nur der entbehrliche Entwurf wird aus dem aktuellen Lernstand einschließlich modellierter Versionen/Sicherungskopien entfernt. Früher exportierte Dateien und technische Datenbanksicherungen liegen außerhalb dieser Funktion. Bei aktiver lokaler Infrastruktur braucht der Austritt expliziten lokalen Konto-/Gruppenentzug; Entra-Aktionen beenden keine eigenständige lokale AD-Anmeldung. Die Abnahme prüft zusätzlich erhaltene Cloud-Geschäftsdaten und fremde Konto-/Gruppen-/Rollenwege. Eine erreichbare, aber inhaltlich beschädigte Anwendung ist keine gültige Datenübergabe. Zeit, Arbeitsnotizen und Diagnosehistorie dürfen sich weiter ändern.","solution":[{"action":"local_account","id":"lea","changes":{"active":false}},{"action":"local_membership","group":"Vertrieb","member":"lea","add":false},{"action":"local_membership","group":"Auftragsbearbeitung","member":"lea","add":false},{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"}],"alternatives":"Direkte Altrollen dürfen zusätzlich entfallen. Eine längere begründete Angebotsfrist ist zulässig; sie lässt sich anschließend nicht verkürzen. Löschen des Angebots und bloße Textentscheidungen erfüllen den Auftrag nicht.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"lea","document":"offer","operation":"data_read"},"expected":false},{"test":"application","args":{"user":"lea","operation":"orders_read"},"expected":false},{"test":"access","args":{"user":"u11","document":"offer","operation":"data_read"},"expected":true},{"test":"application","args":{"user":"u11","operation":"orders_read"},"expected":true},{"test":"local_application","args":{"user":"lea"},"expected":false,"when":["onprem","enabled"]},{"test":"local_file","args":{"user":"lea","document":"angebot-lokal"},"expected":false,"when":["onprem","enabled"]},{"test":"local_application","args":{"user":"u11"},"expected":true,"when":["onprem","enabled"]},{"test":"local_file","args":{"user":"u11","document":"angebot-lokal"},"expected":true,"when":["onprem","enabled"]},{"test":"access","args":{"user":"u12","document":"offer","operation":"data_write"},"expected":true},{"test":"application","args":{"user":"u11","operation":"orders_write"},"expected":true},{"test":"application","args":{"user":"u12","operation":"orders_write"},"expected":true}],"start":[{"op":"set","path":["groups","Vertrieb"],"value":["u11","u12","lea"]},{"op":"set","path":["resources","storage","public"],"value":false},{"op":"set","path":["documents","departure-draft"],"value":{"name":"Austrittsentwurf.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktiver entbehrlicher Austrittsentwurf; nicht weiter erforderlich.","version":1,"deleted":false,"modified":0,"versions":[]}},{"op":"set","path":["data_governance","departure-draft"],"value":{"owner":"lea","purpose":"Entbehrlicher Austrittsentwurf","retention_until":0,"hold":false,"reason":"Auftrag: nicht mehr benötigt","origin":"departure-draft","status":"active"}},{"op":"set","path":["data_governance","offer","owner"],"value":"lea"},{"op":"set","path":["onprem","groups","Vertrieb"],"value":["u11","u12","lea"]},{"op":"set","path":["onprem","groups","Auftragsbearbeitung"],"value":["u11","lea"]}],"setup":[{"action":"file_write","id":"departure-draft","content":"Fiktiver nicht mehr benötigter Entwurf, Version 2."},{"action":"backup_run"}],"criteria":[{"label":"Konto deaktiviert und beide alten Gruppenpfade entfernt","expr":{"all":[{"eq":[{"path":["users","lea","active"]},{"literal":false}]},{"not":{"contains":[{"path":["groups","Vertrieb"]},{"literal":"lea"}]}},{"not":{"contains":[{"path":["groups","Altprojekt"]},{"literal":"lea"}]}}]}},{"label":"Angebotsverantwortung an Vertrieb übergeben und 30 Simulationstage erhalten","expr":{"all":[{"eq":[{"path":["data_governance","offer","owner"]},{"literal":"Vertrieb"}]},{"gte":[{"path":["data_governance","offer","retention_until"]},{"literal":43200}]},{"eq":[{"path":["data_governance","offer","status"]},{"literal":"active"}]},{"eq":[{"path":["documents","offer","deleted"]},{"literal":false}]}]}},{"label":"Entbehrlicher Austrittsentwurf endgültig entfernt","expr":{"eq":[{"path":["data_governance","departure-draft","status"]},{"literal":"purged"}]}},{"label":"Weiter benötigter Angebotsinhalt und Historie bleiben unverändert","expr":{"eq":[{"path":["documents","offer"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]}}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":false},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Cloud-Aufträge, weiter benötigte Dateien, Ablagen und fremde Datenregeln bleiben erhalten","expr":{"all":[{"same_records_except_modified":[{"path":["orders"]},{"literal":{"NL-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Arbeitsplatz-Erweiterung","amount":120.0,"status":"Neu","document":"offer","modified":0,"version":1},"NL-1002":{"customer":"Fiktiv: Beispielhandel KG","subject":"Standortanbindung planen","amount":240.0,"status":"In Bearbeitung","document":"offer","modified":0,"version":1}}}]},{"same_records_except_modified":[{"path":["documents"]},{"literal":{"offer":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]},"payroll":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]},"public":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]},"departure-draft":{"name":"Austrittsentwurf.txt","container":"hr","class":"besonders schutzbedürftig","content":"","version":2,"deleted":true,"modified":0,"versions":[]}}}]},{"eq":[{"path":["document_storage"]},{"literal":{"offer":{"kind":"Blob","host":"storage"},"payroll":{"kind":"Blob","host":"storage"},"public":{"kind":"Blob","host":"storage"},"departure-draft":{"kind":"Blob","host":"storage"}}}]},{"eq":[{"path":["data_governance","payroll"]},{"literal":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"payroll","status":"active"}}]},{"eq":[{"path":["data_governance","public"]},{"literal":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"public","status":"active"}}]}]}},{"label":"Unbeteiligte Cloud-Konten bleiben unverändert","expr":{"all":[{"all":[{"eq":[{"count":{"path":["users"]}},{"literal":63}]},{"eq":[{"path":["users","u01"]},{"literal":{"name":"Person 01 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u02"]},{"literal":{"name":"Person 02 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u03"]},{"literal":{"name":"Person 03 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u04"]},{"literal":{"name":"Person 04 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u05"]},{"literal":{"name":"Person 05 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u06"]},{"literal":{"name":"Person 06 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u07"]},{"literal":{"name":"Person 07 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u08"]},{"literal":{"name":"Person 08 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u09"]},{"literal":{"name":"Person 09 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u10"]},{"literal":{"name":"Person 10 (fiktiv)","department":"Geschäftsführung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u11"]},{"literal":{"name":"Person 11 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u12"]},{"literal":{"name":"Person 12 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u13"]},{"literal":{"name":"Person 13 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u14"]},{"literal":{"name":"Person 14 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u15"]},{"literal":{"name":"Person 15 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u16"]},{"literal":{"name":"Person 16 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u17"]},{"literal":{"name":"Person 17 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u18"]},{"literal":{"name":"Person 18 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u19"]},{"literal":{"name":"Person 19 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]}]},{"all":[{"eq":[{"path":["users","u20"]},{"literal":{"name":"Person 20 (fiktiv)","department":"Vertrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u21"]},{"literal":{"name":"Person 21 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u22"]},{"literal":{"name":"Person 22 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u23"]},{"literal":{"name":"Person 23 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u24"]},{"literal":{"name":"Person 24 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u25"]},{"literal":{"name":"Person 25 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u26"]},{"literal":{"name":"Person 26 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u27"]},{"literal":{"name":"Person 27 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u28"]},{"literal":{"name":"Person 28 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u29"]},{"literal":{"name":"Person 29 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u30"]},{"literal":{"name":"Person 30 (fiktiv)","department":"Personal","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u31"]},{"literal":{"name":"Person 31 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u32"]},{"literal":{"name":"Person 32 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u33"]},{"literal":{"name":"Person 33 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u34"]},{"literal":{"name":"Person 34 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u35"]},{"literal":{"name":"Person 35 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u36"]},{"literal":{"name":"Person 36 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u37"]},{"literal":{"name":"Person 37 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u38"]},{"literal":{"name":"Person 38 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u39"]},{"literal":{"name":"Person 39 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]}]},{"all":[{"eq":[{"path":["users","u40"]},{"literal":{"name":"Person 40 (fiktiv)","department":"Buchhaltung","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u41"]},{"literal":{"name":"Person 41 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u42"]},{"literal":{"name":"Person 42 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u43"]},{"literal":{"name":"Person 43 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u44"]},{"literal":{"name":"Person 44 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u45"]},{"literal":{"name":"Person 45 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u46"]},{"literal":{"name":"Person 46 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u47"]},{"literal":{"name":"Person 47 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u48"]},{"literal":{"name":"Person 48 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u49"]},{"literal":{"name":"Person 49 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u50"]},{"literal":{"name":"Person 50 (fiktiv)","department":"Betrieb","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u51"]},{"literal":{"name":"Person 51 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u52"]},{"literal":{"name":"Person 52 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u53"]},{"literal":{"name":"Person 53 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u54"]},{"literal":{"name":"Person 54 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u55"]},{"literal":{"name":"Person 55 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u56"]},{"literal":{"name":"Person 56 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u57"]},{"literal":{"name":"Person 57 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u58"]},{"literal":{"name":"Person 58 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","u59"]},{"literal":{"name":"Person 59 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]}]},{"all":[{"eq":[{"path":["users","u60"]},{"literal":{"name":"Person 60 (fiktiv)","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User"}}]},{"eq":[{"path":["users","partner"]},{"literal":{"name":"Robin Extern (fiktiv)","department":"Dienstleister","active":true,"mfa":true,"guest":true,"expires":480,"directory_role":"User"}}]},{"eq":[{"path":["users","it"]},{"literal":{"name":"IT-Lernrolle","department":"IT","active":true,"mfa":true,"guest":false,"expires":0,"directory_role":"User Administrator"}}]}]}]}},{"label":"Nur Leas beide Cloud-Gruppenmitgliedschaften entziehen; Kollegen und Gruppen erhalten","expr":{"all":[{"eq":[{"count":{"path":["groups"]}},{"literal":4}]},{"all":[{"eq":[{"count":{"path":["groups","Vertrieb"]}},{"literal":2}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"u11"}]},{"contains":[{"path":["groups","Vertrieb"]},{"literal":"u12"}]}]},{"all":[{"eq":[{"count":{"path":["groups","IT"]}},{"literal":1}]},{"contains":[{"path":["groups","IT"]},{"literal":"it"}]}]},{"all":[{"eq":[{"count":{"path":["groups","Altprojekt"]}},{"literal":0}]}]},{"all":[{"eq":[{"count":{"path":["groups","Partner"]}},{"literal":1}]},{"contains":[{"path":["groups","Partner"]},{"literal":"partner"}]}]}]}},{"label":"Vorhandene Cloud-Rollen erhalten; nur Leas direkte Reader-Rolle optional entfernen","expr":{"all":[{"contains":[{"path":["roles"]},{"literal":{"principal":"IT","role":"Contributor","scope":"subscription"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"IT","role":"User Access Administrator","scope":"subscription"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Vertrieb","role":"Blob Contributor","scope":"sales"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Altprojekt","role":"Blob Reader","scope":"sales"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"partner","role":"Blob Contributor","scope":"storage"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"Vertrieb","role":"Order Operator","scope":"orders"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"orders-app","role":"Order Operator","scope":"orders"}}]},{"contains":[{"path":["roles"]},{"literal":{"principal":"orders-app","role":"Blob Reader","scope":"sales"}}]},{"not":{"some":{"in":{"path":["roles"]},"as":"grant","where":{"not":{"any_of":[{"eq":[{"var":["grant"]},{"literal":{"principal":"IT","role":"Contributor","scope":"subscription"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"IT","role":"User Access Administrator","scope":"subscription"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"Vertrieb","role":"Blob Contributor","scope":"sales"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"Altprojekt","role":"Blob Reader","scope":"sales"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"partner","role":"Blob Contributor","scope":"storage"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"lea","role":"Reader","scope":"storage"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"Vertrieb","role":"Order Operator","scope":"orders"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"orders-app","role":"Order Operator","scope":"orders"}}]},{"eq":[{"var":["grant"]},{"literal":{"principal":"orders-app","role":"Blob Reader","scope":"sales"}}]}]}}}}}]}}],"function":"Entra → Konto/Gruppen; Storage → Datenverantwortung, Frist und gezielte Entfernung","terms":[{"term":"Datenverantwortung","meaning":"Fachlich zuständige Person oder Gruppe; erteilt keine RBAC-Datenrechte."},{"term":"Aufbewahrung","meaning":"Bis zur Frist ist endgültige Entfernung gesperrt. Danach wird geprüft und ausdrücklich entfernt; keine automatische Löschung."},{"term":"Löschsperre","meaning":"Eine fachlich begründete Sperre verhindert Entfernung auch nach Fristablauf."},{"term":"Logisch löschen / endgültig entfernen","meaning":"Logisches Löschen behält Inhalt und Versionen. Endgültige Entfernung leert beides sowie modellierte Sicherungskopien; frühere Exporte bleiben externe Kopien."}],"variants":[{"label":"Direkten Reader zusätzlich entfernen","rationale":"Die gleiche wirksame Übergabe und Datenminimierung mit zusätzlichem Entzug einer alten Verwaltungs-Leserolle.","actions":[{"action":"local_account","id":"lea","changes":{"active":false}},{"action":"local_membership","group":"Vertrieb","member":"lea","add":false},{"action":"local_membership","group":"Auftragsbearbeitung","member":"lea","add":false},{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"},{"action":"role_remove","principal":"lea","role":"Reader","scope":"storage"}]}],"failures":[{"label":"Nur Kontosperre","rationale":"Die Kontosperre allein übergibt keine Datenverantwortung und entfernt weder Gruppen noch entbehrliche Inhalte.","actions":[{"action":"user","id":"lea","changes":{"active":false}}],"outcome":"incomplete"},{"label":"Cloud-Austritt lässt lokale Anmeldung offen","rationale":"Ein funktionierender Entra-Entzug beendet weder das eigenständige lokale Konto noch seine lokalen Gruppenrechte.","outcome":"incomplete","actions":[{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"}]},{"label":"Auftragsinhalt nebenbei verändert","rationale":"Ein erreichbarer Auftragsdienst ersetzt keine unveränderten Geschäftsdaten.","outcome":"incomplete","actions":[{"action":"local_account","id":"lea","changes":{"active":false}},{"action":"local_membership","group":"Vertrieb","member":"lea","add":false},{"action":"local_membership","group":"Auftragsbearbeitung","member":"lea","add":false},{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"},{"action":"order_update","id":"NL-1001","version":1,"changes":{"customer":"Fiktiv: Unbeauftragter Ersatz","amount":0}}]},{"label":"Fremde Personaldatei überschrieben","rationale":"Der Austritt erlaubt keine Veränderung fremder Dateiinhalte oder Historien.","outcome":"incomplete","actions":[{"action":"local_account","id":"lea","changes":{"active":false}},{"action":"local_membership","group":"Vertrieb","member":"lea","add":false},{"action":"local_membership","group":"Auftragsbearbeitung","member":"lea","add":false},{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"},{"action":"file_write","id":"payroll","content":"Fiktiv: Fremder Inhalt ersetzt"}]},{"label":"Vertriebskollegen den Zugang entzogen","rationale":"Der Austritt betrifft Lea; Kollegenkonten und ihre Gruppenwege bleiben erhalten.","outcome":"incomplete","actions":[{"action":"local_account","id":"lea","changes":{"active":false}},{"action":"local_membership","group":"Vertrieb","member":"lea","add":false},{"action":"local_membership","group":"Auftragsbearbeitung","member":"lea","add":false},{"action":"user","id":"lea","changes":{"active":false}},{"action":"membership","group":"Vertrieb","member":"lea","add":false},{"action":"membership","group":"Altprojekt","member":"lea","add":false},{"action":"data_policy","id":"offer","changes":{"owner":"Vertrieb","purpose":"Laufender Kundenauftrag","retain_minutes":43200,"hold":false,"reason":"Fiktiver Firmenauftrag: Angebot 30 Simulationstage erhalten; danach fachlich prüfen"}},{"action":"data_purge","id":"departure-draft","reason":"Nicht mehr benötigter Austrittsentwurf; Datenminimierung nach fiktivem Personalauftrag"},{"action":"user","id":"u12","changes":{"active":false}}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Leas letztem Arbeitstag; etwa 22 Minuten. Angebot und Auftragsbetrieb erhalten. Verantwortung allein erteilt keine Datenrechte. 30 Tage sind eine fiktive Firmenvorgabe, keine rechtliche Empfehlung. Austrittsentwurf ist nicht mehr erforderlich. Inhalt und Historie des weiter benötigten Angebots nicht verändern."},{"id":"daten","question":"Darf ich beim Austritt alle Dateien des Mitarbeiters löschen?","answer":"Nein. Das geschäftlich benötigte Angebot bleibt mit Inhalt und vorhandener Historie erhalten und geht an den Vertrieb mit der vorgegebenen Frist. Nur der entbehrliche Austrittsentwurf darf nach Prüfung von Frist und Haltesperre entfernt werden."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Lea ist aktiv in beiden Gruppen und verantwortet das Angebot. Ein entbehrlicher Austrittsentwurf liegt einschließlich früherer Version und Sicherungspunkt vor. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."},{"id":"lokaler-austritt","question":"Genügt es, Lea in Entra zu deaktivieren?","answer":"Nein. Wenn der lokale Bereich aktiv ist, auch ihr lokales AD-Konto deaktivieren und lokale Vertriebs-/Auftragsmitgliedschaften entfernen. Lokale Kollegen und Firmendaten bleiben verfügbar; es ist kein automatischer Abgleich eingerichtet."},{"id":"bestand-erhalten","question":"Darf ich andere Cloud-Konten, Rollen oder Auftragsdaten beim Austritt vereinfachen?","answer":"Nein. Andere Cloud-Konten, Gruppenmitglieder, Rollen, Geschäftsvorgänge, Dateien, Ablagen und Datenregeln bleiben erhalten. Leas eigene Kontoeigenschaften und die zwei angegebenen Mitgliedschaften ändern; ihre alte direkte Reader-Rolle darf zusätzlich entfallen. Nach dem Entzug auch Kollegen auf erlaubte Datei- und Auftragsbearbeitung prüfen."}]},
    {"id":"20","title":"Abschluss: sichere Firmenarchitektur","sender":"Geschäftsführung","message":"Stabilisiere den Standortzugriff, schütze Daten, begrenze den Partner auf A, repariere Versand, halte einen Sicherungspunkt vor und bleibe unter 500 Lern-Euro pro Monat. Wähle IaaS oder PaaS und begründe die Verantwortung. Die ursprünglichen Inhalte von Angebot-A, Personal-B, Firmeninfo und beiden NL-Aufträgen bleiben erhalten. Mindestens ein vorhandener Dateisicherungspunkt muss diese Belege mit ihren Ausgangsfassungen wiederherstellbar enthalten.","minutes":40,"prerequisite":"Vorherige Themen","learning":"Architektur; Governance; Sicherheit; Kosten","learn":"Du lernst, Netz, Identitäten, Daten, Betrieb und Budget in einer Firmenarchitektur gemeinsam abzusichern.","try_text":"Du probierst Architektur und mehrere zusammenhängende Betriebs-/Schutznachweise.","deadline":"Vor Freigabe des kombinierten Firmenbetriebs; etwa 40 Minuten.","constraints":"Standorte, geschützte Ablage, Partner nur A lesen, Versand, Punkt und Löschschutz; IaaS/PaaS und höchstens 500 Lern-Euro Monatsprognose. Keine benötigten Firmenbelege oder NL-Auftragsinhalte entfernen, überschreiben oder anonymisieren. Zurückgenommene Fehländerungen sind zulässig, wenn aktuelle Inhalte wieder stimmen und ursprüngliche Dateiversionen erhalten sind. Dateisicherung prüft Belege, nicht die Auftragsdatenbank. Neu angelegte private Kopien und passende eigene VM-/App-Service-Ziele bleiben erlaubt.","initial":"VPN, Datenfreigabe, Partner und Container gestört; erfolgreicher Punkt fehlt.","hints":["Welche Fehler teilen Abhängigkeiten, welche brauchen eigene Maßnahmen?","Prüfe Netz, Datenfreigaben, Partner-Scope, Versand und Backup, dann Kosten und tatsächlichen DNS-Dienst. Erreichbarkeit ist kein Inhaltsnachweis: vergleiche die benötigten Belege und Aufträge mit dem Ausgangsbestand und lies auch den Punktinhalt.","Repariere VPN, anonyme Freigabe, Partner, Versand und Backup. Aktiviere Löschschutz, spare Test-Compute und betreibe web/IaaS oder geprüftes paas/PaaS; führe alle Nachweise neu aus. Angebot-A, Personal-B, Firmeninfo und beide ursprünglichen NL-Aufträge erhalten. Falls du einen Beleg verändert hast: Ausgangsversion wiederherstellen und danach einen brauchbaren Dateipunkt erstellen. Ein frischer Punkt mit falschem Inhalt genügt nicht."],"explanation":"Mehrere Architekturwege sind zulässig. Fachlich geprüft werden erreichbare Dienste, verweigerte unerlaubte Zugriffe, vorhandene Sicherung, Löschschutz und Budget gemeinsam. Die Auftragslaufzeit wird anhand ihres Diensttyps und des wirksamen Lernprofils geprüft, nicht anhand eines vorgeschriebenen Ressourcennamens. Eigene VMs/App Services verwenden dieselben Datenpfade und Rechte; DNS-Umschaltung kopiert weder Daten noch Rollen. Der Abschluss prüft zusätzlich die vorgegebenen fachlichen Inhalte aller drei ursprünglichen Cloudbelege und beider NL-Aufträge. Bei Dateien bleibt die ursprüngliche Version entweder aktuell oder in der Historie wiederherstellbar. Eine reparierte Fehländerung darf deshalb einen höheren Versionszähler, weitere Historie und einen neuen Änderungszeitpunkt haben. Ein Dateipunkt muss die richtigen aktuellen Beleginhalte und ursprünglichen Fassungen enthalten; die gewählte VM-/App-Service-Laufzeit oder DNS-Umschaltung ersetzt das nicht. Dieser Cloud-Dateipunkt ist keine Sicherung der Auftragsdatenbank. Es wird keine zusätzliche RPO-/Aufbewahrungsdauer vorgegeben. Eigene Ressourcen und zusätzliche private Kopien sind möglich, solange die ursprünglichen Geschäftsdaten und alle übrigen Auftragskriterien erhalten bleiben.","solution":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"}],"alternatives":"Bestehende VM oder vorbereitete PaaS-Laufzeit sind gültig. PaaS zuerst starten/testen, dann DNS umstellen und Quelle freigeben; Daten-/Schutzkriterien bleiben gleich. Eigene passend konfigurierte VM- oder App-Service-Ressourcen sind ebenfalls zulässig; Modellentscheidung muss zum tatsächlich aufgelösten Diensttyp passen. Büro-SaaS und Kundenanfragen ersetzen die Auftragsanwendung nicht.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"connection","args":{"source":"hq","host":"auftrag.intern","port":443},"expected":true},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false},{"test":"access","args":{"user":"partner","document":"offer","operation":"data_read"},"expected":true},{"test":"access","args":{"user":"partner","document":"offer","operation":"data_write"},"expected":false},{"test":"access","args":{"user":"partner","document":"payroll","operation":"data_read"},"expected":false},{"test":"application","args":{"user":"u11","operation":"orders_read"},"expected":true},{"test":"application","args":{"user":"partner","operation":"orders_write"},"expected":false},{"test":"connection","args":{"source":"branch","host":"auftrag.intern","port":443},"expected":true},{"test":"access","args":{"user":"partner","document":"payroll","operation":"data_write"},"expected":false},{"test":"access","args":{"user":"partner","document":"offer","operation":"assign"},"expected":false}],"start":[{"op":"set","path":["network","vpn"],"value":false}],"setup":[],"criteria":[{"label":"Partner hat keine Ressourcen- oder Zuweisungsrechte","expr":{"all":[{"not":{"contains":[{"rights":{"principal":"partner","target":"offer"}},{"literal":"manage"}]}},{"not":{"contains":[{"rights":{"principal":"partner","target":"offer"}},{"literal":"assign"}]}}]}},{"label":"Gastfreigabe endet bei Minute 480","expr":{"all":[{"eq":[{"path":["users","partner","guest"]},{"literal":true}]},{"eq":[{"path":["users","partner","expires"]},{"literal":480}]}]}},{"label":"Architektur entspricht dem tatsächlich betriebenen Dienst","expr":{"any_of":[{"all":[{"eq":[{"path":["decisions","architecture"]},{"literal":"IaaS"}]},{"eq":[{"target_property":{"host":"auftrag.intern","name":"kind"}},{"literal":"VM"}]}]},{"all":[{"eq":[{"path":["decisions","architecture"]},{"literal":"PaaS"}]},{"eq":[{"target_property":{"host":"auftrag.intern","name":"kind"}},{"literal":"App Service"}]}]}]}},{"label":"Backup, Löschschutz, Container und Budget","expr":{"all":[{"nonempty":{"path":["backup","points"]}},{"eq":[{"path":["resources","storage","locked"]},{"literal":true}]},{"eq":[{"metric":{"resource":"container","name":"healthy"}},{"literal":true}]},{"lte":[{"monthly":true},{"literal":500}]}]}},{"label":"Partner hat keinerlei Verwaltungs-/Zuweisungsrechte","expr":{"eq":[{"privileged_scopes":{"principal":"partner","rights":["manage","assign"]}},{"literal":[]}]}},{"label":"Partner-Datenrollen gelten ausschließlich zum Lesen von Angebot A","expr":{"all":[{"eq":[{"data_targets":{"principal":"partner","right":"data_read"}},{"literal":["offer"]}]},{"eq":[{"data_targets":{"principal":"partner","right":"data_write"}},{"literal":[]}]}]}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Lokale Dienste bleiben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]}]}},{"label":"Keine unangeforderten lokalen Gruppenrechte","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]}]}},{"label":"Lokale Freigaben unverändert","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]}]}},{"label":"Unbeteiligte lokale Dateien und Historien erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]}]}},{"label":"Lokale Geschäftsvorgänge erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"same_records_except_modified":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]}]}},{"label":"Lokale DNS-Zuordnungen erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]}]}},{"label":"Lokales LAN nicht abschalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","lan"]},{"literal":true}]}]}},{"label":"Lokale Konten dem Auftrag entsprechend erhalten","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]}]}},{"label":"Lokaler Sicherungsplan erhalten: enabled","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","enabled"]},{"literal":true}]}]}},{"label":"Lokaler Sicherungsplan erhalten: interval","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","interval"]},{"literal":60}]}]}},{"label":"Lokaler Sicherungsplan erhalten: retention","expr":{"any_of":[{"not":{"path":["onprem","enabled"]}},{"eq":[{"path":["onprem","backup","retention"]},{"literal":1440}]}]}},{"label":"Benötigte ursprüngliche Firmenbelege und Auftragsinhalte bleiben erhalten","expr":{"all":[{"all":[{"eq":[{"path":["documents","offer","name"]},{"literal":"Angebot-A.txt"}]},{"eq":[{"path":["documents","offer","container"]},{"literal":"sales"}]},{"eq":[{"path":["documents","offer","class"]},{"literal":"vertraulich"}]},{"eq":[{"path":["documents","offer","content"]},{"literal":"Angebot A: 120 Lern-Euro; Version 1."}]},{"eq":[{"path":["documents","offer","deleted"]},{"literal":false}]},{"gte":[{"path":["documents","offer","version"]},{"literal":1}]},{"any_of":[{"eq":[{"path":["documents","offer","version"]},{"literal":1}]},{"some":{"in":{"path":["documents","offer","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"path":["documents","payroll","name"]},{"literal":"Personal-B.txt"}]},{"eq":[{"path":["documents","payroll","container"]},{"literal":"hr"}]},{"eq":[{"path":["documents","payroll","class"]},{"literal":"besonders schutzbedürftig"}]},{"eq":[{"path":["documents","payroll","content"]},{"literal":"Fiktive Personalnotiz B; keine echten Personendaten."}]},{"eq":[{"path":["documents","payroll","deleted"]},{"literal":false}]},{"gte":[{"path":["documents","payroll","version"]},{"literal":1}]},{"any_of":[{"eq":[{"path":["documents","payroll","version"]},{"literal":1}]},{"some":{"in":{"path":["documents","payroll","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"path":["documents","public","name"]},{"literal":"Firmeninfo.txt"}]},{"eq":[{"path":["documents","public","container"]},{"literal":"public"}]},{"eq":[{"path":["documents","public","class"]},{"literal":"öffentlich"}]},{"eq":[{"path":["documents","public","content"]},{"literal":"Nordlicht: 60 fiktive Beschäftigte."}]},{"eq":[{"path":["documents","public","deleted"]},{"literal":false}]},{"gte":[{"path":["documents","public","version"]},{"literal":1}]},{"any_of":[{"eq":[{"path":["documents","public","version"]},{"literal":1}]},{"some":{"in":{"path":["documents","public","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"eq":[{"path":["data_governance","offer","status"]},{"literal":"active"}]},{"eq":[{"path":["data_governance","payroll","status"]},{"literal":"active"}]},{"eq":[{"path":["data_governance","public","status"]},{"literal":"active"}]},{"all":[{"eq":[{"path":["orders","NL-1001","customer"]},{"literal":"Fiktiv: Hafenwerk GmbH"}]},{"eq":[{"path":["orders","NL-1001","subject"]},{"literal":"Arbeitsplatz-Erweiterung"}]},{"eq":[{"path":["orders","NL-1001","amount"]},{"literal":120.0}]},{"eq":[{"path":["orders","NL-1001","status"]},{"literal":"Neu"}]},{"eq":[{"path":["orders","NL-1001","document"]},{"literal":"offer"}]},{"gte":[{"path":["orders","NL-1001","version"]},{"literal":1}]}]},{"all":[{"eq":[{"path":["orders","NL-1002","customer"]},{"literal":"Fiktiv: Beispielhandel KG"}]},{"eq":[{"path":["orders","NL-1002","subject"]},{"literal":"Standortanbindung planen"}]},{"eq":[{"path":["orders","NL-1002","amount"]},{"literal":240.0}]},{"eq":[{"path":["orders","NL-1002","status"]},{"literal":"In Bearbeitung"}]},{"eq":[{"path":["orders","NL-1002","document"]},{"literal":"offer"}]},{"gte":[{"path":["orders","NL-1002","version"]},{"literal":1}]}]}]}},{"label":"Vorhandener Dateipunkt enthält die benötigten ursprünglichen Firmenbelege","expr":{"some":{"in":{"path":["backup","points"]},"as":"point","where":{"all":[{"gte":[{"var":["point","minute"]},{"literal":0}]},{"lte":[{"var":["point","minute"]},{"path":["minute"]}]},{"all":[{"eq":[{"var":["point","documents","offer","name"]},{"literal":"Angebot-A.txt"}]},{"eq":[{"var":["point","documents","offer","container"]},{"literal":"sales"}]},{"eq":[{"var":["point","documents","offer","class"]},{"literal":"vertraulich"}]},{"eq":[{"var":["point","documents","offer","content"]},{"literal":"Angebot A: 120 Lern-Euro; Version 1."}]},{"eq":[{"var":["point","documents","offer","deleted"]},{"literal":false}]},{"gte":[{"var":["point","documents","offer","version"]},{"literal":1}]},{"any_of":[{"eq":[{"var":["point","documents","offer","version"]},{"literal":1}]},{"some":{"in":{"var":["point","documents","offer","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"var":["point","documents","payroll","name"]},{"literal":"Personal-B.txt"}]},{"eq":[{"var":["point","documents","payroll","container"]},{"literal":"hr"}]},{"eq":[{"var":["point","documents","payroll","class"]},{"literal":"besonders schutzbedürftig"}]},{"eq":[{"var":["point","documents","payroll","content"]},{"literal":"Fiktive Personalnotiz B; keine echten Personendaten."}]},{"eq":[{"var":["point","documents","payroll","deleted"]},{"literal":false}]},{"gte":[{"var":["point","documents","payroll","version"]},{"literal":1}]},{"any_of":[{"eq":[{"var":["point","documents","payroll","version"]},{"literal":1}]},{"some":{"in":{"var":["point","documents","payroll","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0}}]}}}]}]},{"all":[{"eq":[{"var":["point","documents","public","name"]},{"literal":"Firmeninfo.txt"}]},{"eq":[{"var":["point","documents","public","container"]},{"literal":"public"}]},{"eq":[{"var":["point","documents","public","class"]},{"literal":"öffentlich"}]},{"eq":[{"var":["point","documents","public","content"]},{"literal":"Nordlicht: 60 fiktive Beschäftigte."}]},{"eq":[{"var":["point","documents","public","deleted"]},{"literal":false}]},{"gte":[{"var":["point","documents","public","version"]},{"literal":1}]},{"any_of":[{"eq":[{"var":["point","documents","public","version"]},{"literal":1}]},{"some":{"in":{"var":["point","documents","public","versions"]},"as":"original_version","where":{"eq":[{"var":["original_version"]},{"literal":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0}}]}}}]}]}]}}}}],"function":"Virtual Network, Storage, Entra ID, Container, Backup und Cost Management kombiniert","terms":[{"term":"Architektur","meaning":"Aufteilung von Laufzeit, Daten, Netz und Verantwortung."},{"term":"Governance","meaning":"Verbindliche Regeln und Zuständigkeiten."},{"term":"Nachweis","meaning":"Aktuelle erlaubte und verweigerte Tests."}],"variants":[{"label":"PaaS-Auftragslaufzeit","rationale":"Ziel starten/testen, dann DNS umstellen und Quelle freigeben.","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"configure","id":"paas","changes":{"status":"running"}},{"action":"diagnose","test":"connection","args":{"source":"hq","host":"paas","port":443}},{"action":"network","changes":{"dns":{"auftrag.intern":"paas","daten.intern":"db","ablage.intern":"storage","versand.intern":"container"}}},{"action":"power","id":"web","operation":"deallocate"},{"action":"decision","key":"architecture","value":"PaaS"}]},{"label":"Eigene VM für Aufträge","rationale":"Neue Laufzeit mit demselben Auftragsprofil, Dienstidentität und Firmen-Datenbestand. Erst Ziel prüfen, dann DNS umstellen; Rollen, Schutz und Budget gelten unverändert.","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"create","id":"eigenevm","name":"Eigene Auftragslaufzeit","kind":"VM","group":"rg-app","ip":"10.20.1.61","subnet":"app"},{"action":"configure","id":"eigenevm","changes":{"image":"orders:1.0","port":443,"configured":true,"size":"B2"}},{"action":"diagnose","test":"connection","args":{"source":"hq","host":"eigenevm","port":443}},{"action":"network","changes":{"dns":{"auftrag.intern":"eigenevm","daten.intern":"db","ablage.intern":"storage","versand.intern":"container"}}},{"action":"power","id":"web","operation":"deallocate"},{"action":"decision","key":"architecture","value":"IaaS"}]},{"label":"Eigene App Service für Aufträge","rationale":"Neue Laufzeit mit demselben Auftragsprofil, Dienstidentität und Firmen-Datenbestand. Erst Ziel prüfen, dann DNS umstellen; Rollen, Schutz und Budget gelten unverändert.","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"create","id":"eigeneapp","name":"Eigene Auftragslaufzeit","kind":"App Service","group":"rg-app","ip":"10.20.1.61","subnet":"app"},{"action":"configure","id":"eigeneapp","changes":{"image":"orders:1.0","port":443,"configured":true,"size":"B2"}},{"action":"diagnose","test":"connection","args":{"source":"hq","host":"eigeneapp","port":443}},{"action":"network","changes":{"dns":{"auftrag.intern":"eigeneapp","daten.intern":"db","ablage.intern":"storage","versand.intern":"container"}}},{"action":"power","id":"web","operation":"deallocate"},{"action":"decision","key":"architecture","value":"PaaS"}]}],"failures":[{"label":"Nur VPN reparieren","rationale":"Datenfreigabe, Partner, Versand und Backup bleiben fehlerhaft.","actions":[{"action":"network","changes":{"vpn":true}}],"outcome":"incomplete"},{"label":"Personalbestand entfernt und frisch gesichert","rationale":"Ein frischer Punkt macht endgültig entfernte benötigte Personalinhalte nicht wiederherstellbar.","outcome":"incomplete","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"data_purge","id":"payroll","reason":"Fiktiver unbeauftragter Eingriff"},{"action":"backup_run"}]},{"label":"Angebot überschrieben und frisch gesichert","rationale":"Ein erreichbarer Dienst und eine noch vorhandene Ausgangsversion ersetzen den korrekten aktuellen Beleginhalt nicht.","outcome":"incomplete","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"file_write","id":"offer","content":"Fiktiver beschädigter Originalbeleg"},{"action":"backup_run"}]},{"label":"Bestehenden Auftrag inhaltlich geändert","rationale":"Die lesbare Auftragsanwendung muss die benötigten Geschäftsangaben behalten.","outcome":"incomplete","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"backup_run"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"order_update","id":"NL-1001","version":1,"changes":{"amount":0}}]},{"label":"Nur beschädigter Dateipunkt trotz repariertem aktuellen Beleg","rationale":"Nach Wiederherstellung des aktuellen Inhalts braucht die Firma zusätzlich einen brauchbaren vorhandenen Dateipunkt.","outcome":"incomplete","actions":[{"action":"network","changes":{"vpn":true}},{"action":"configure","id":"storage","changes":{"public":false,"locked":true}},{"action":"role_remove","principal":"partner","role":"Blob Contributor","scope":"storage"},{"action":"role_add","principal":"partner","role":"Blob Reader","scope":"offer"},{"action":"configure","id":"container","changes":{"image":"shipping:1.0","port":8080,"configured":true}},{"action":"power","id":"testvm","operation":"deallocate"},{"action":"decision","key":"architecture","value":"IaaS"},{"action":"file_write","id":"offer","content":"Fiktiver beschädigter Zwischenstand"},{"action":"backup_run"},{"action":"version_restore","id":"offer","version":1}]}],"clarifications":[{"id":"rahmen","question":"Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?","answer":"Vor Freigabe des kombinierten Firmenbetriebs; etwa 40 Minuten. Standorte, geschützte Ablage, Partner nur A lesen, Versand, Punkt und Löschschutz; IaaS/PaaS und höchstens 500 Lern-Euro Monatsprognose."},{"id":"bedarf","question":"Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?","answer":"Stabilisiere den Standortzugriff, schütze Daten, begrenze den Partner auf A, repariere Versand, halte einen Sicherungspunkt vor und bleibe unter 500 Lern-Euro pro Monat. Wähle IaaS oder PaaS und begründe die Verantwortung."},{"id":"rueckmeldung","question":"Welche Rückmeldung erwarten Sie zum Abschluss?","answer":"Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. VPN, Datenfreigabe, Partner und Container gestört; erfolgreicher Punkt fehlt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."},{"id":"firmeninhalt","question":"Reichen erreichbare Dienste und ein frischer Sicherungspunkt?","answer":"Nein. Benötigte Originalbelege und NL-Auftragsinhalte müssen erhalten sein. Ein Punkt mit beschädigtem Inhalt genügt nicht. Reparierte Dateiinhalte mit erhaltener Ausgangsversion sind zulässig; anschließend brauchbaren Dateipunkt erstellen. Die Dateisicherung enthält keine Auftragsdatenbank."}]},
    {
      "id": "free",
      "title": "Freie Übungsumgebung",
      "sender": "IT-Leitung",
      "message": "Erkunde, ändere und teste die Firma ohne Aufgabenbewertung. Eigene Spielstände lassen sich unabhängig exportieren und zurücksetzen.",
      "minutes": 0,
      "prerequisite": "Keines",
      "learning": "Alle Themen",
      "learn": "Du lernst, eigene Vermutungen durch begrenzte Änderungen und erneute Prüfungen zu untersuchen.",
      "try_text": "Du probierst eigene Hypothesen und beobachtest Netz, Daten, Identitäten, Kosten und Uhr.",
      "deadline": "Kein Abgabetermin, Trainer legt Dauer fest.",
      "constraints": "Nur fiktive Daten/Lernpreise, bewusst testen; keine Abschlussbewertung.",
      "initial": "Teilweise eingerichtete Firma mit Altlasten, ohne festen Einzelauftrag.",
      "hints": [
        "Formuliere eine prüfbare Vermutung und erwartete erlaubte/verweigerte Fälle.",
        "Ändere begrenzt eine Einstellung und vergleiche Pfad, Rechte oder Kosten.",
        "Notiere Hypothese, Änderung und Ergebnis; exportiere vor Umbauten und nutze gezielte Trainer-Störungen."
      ],
      "explanation": "Die freie Umgebung hat keine automatische Abschlussbewertung.",
      "solution": [],
      "alternatives": "Kein vorgeschriebener Weg und kein Abschluss-Haken; Beobachtungen und Protokolle werden besprochen.",
      "attachment": "Firmeninventar und Diagnoseprotokoll im Portal",
      "probes": [],
      "start": [],
      "setup": [],
      "criteria": [],
      "function": "Alle Portalbereiche ohne automatische Bewertung",
      "terms": [
        {
          "term": "Hypothese",
          "meaning": "Überprüfbare Vermutung über Ursache/Wirkung."
        },
        {
          "term": "Sandbox",
          "meaning": "Freier Übungsraum ohne Abschlussnote."
        }
      ],
      "variants": [],
      "failures": [],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Kein Abgabetermin, Trainer legt Dauer fest. Nur fiktive Daten/Lernpreise, bewusst testen; keine Abschlussbewertung."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Erkunde, ändere und teste die Firma ohne Aufgabenbewertung. Eigene Spielstände lassen sich unabhängig exportieren und zurücksetzen."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Teilweise eingerichtete Firma mit Altlasten, ohne festen Einzelauftrag. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    },
    {
      "id": "lokal",
      "title": "Lokalen Betrieb trotz Cloud-VPN-Ausfall wiederherstellen",
      "sender": "IT-Leitung · lokaler Betrieb",
      "message": "Im Hauptstandort läuft der lokale Auftragsdienst nicht, das lokale Angebot wurde gelöscht und Lea kommt nicht an die Freigabe. Das Cloud-VPN ist separat ausgefallen. Repariere AD-Konto, lokale Gruppe und ORDER-01, stelle das Angebot aus einem lokalen Punkt wieder her und prüfe erlaubte und verweigerte Zugriffe. Ändere dafür keine Cloud-Identitäten oder Cloud-Ressourcen.",
      "minutes": 25,
      "prerequisite": "Standort, lokale Dienste, Gruppenmitgliedschaft und Sicherungspunkt",
      "learning": "Lokale AD-/Datei-/SQL-/Anwendungs-/Backup-Abhängigkeiten von Entra und Cloud-Verbindung unterscheiden.",
      "learn": "Du lernst, warum lokale Anmeldung und Freigabe nicht durch eine Azure-Rolle entstehen.",
      "try_text": "Du probierst lokale Dienstreparatur, Gruppenrechte und eine echte lokale Dateiwiederherstellung.",
      "deadline": "Vor Wiederaufnahme der lokalen Auftragsbearbeitung; etwa 25 Minuten.",
      "constraints": "Lea benötigt lokale Angebotsrechte, aber keine Personal- oder IT-Administrationsrechte. Cloud-Konten, Gruppen, Rollen und Ressourcen bleiben unverändert. VPN bleibt unterbrochen: der lokale LAN-Betrieb muss unabhängig funktionieren. Lokale Aufträge und die Personaldatei unverändert erhalten. Nur fiktive Daten und lokale Dienste, kein Cloud-Deployment und keine zusätzlichen Cloud-Kosten.",
      "initial": "Lokale ORDER-01-Laufzeit gestoppt, Leas lokales Konto deaktiviert, Angebot gelöscht, lokaler Anfangspunkt vorhanden; Cloud-VPN unterbrochen.",
      "hints": [
        "Unterscheide LAN-Pfad, lokale AD-Anmeldung, Gruppe und Anwendungsabhängigkeiten. Die Cloud-Störung ist ein anderes Problem.",
        "Prüfe ORDER-01, AD-01, SQL-01 und FILE-01; die lokalen Dienste haben eigene Konten/Freigaben und eine eigene Sicherung.",
        "Starte ORDER-01, aktiviere Leas lokales Konto und füge sie zur lokalen Gruppe Vertrieb hinzu. Stelle angebot-lokal aus dem Anfangspunkt wieder her, spule fünf Minuten vor und prüfe Lea/Personal/Partner und den noch blockierten Cloud-Pfad."
      ],
      "explanation": "Das lokale LAN benötigt kein Cloud-VPN. AD-01 prüft eigene aktive Konten und Gruppen; FILE-01 prüft Freigaben. ORDER-01 benötigt SQL-01 sowie svc-orders mit passenden lokalen Gruppen und lesbaren Anhängen. BACKUP-01 hält tatsächliche lokale Datei-/Auftragspunkte. Eine Entra-Mitgliedschaft oder Azure-Rolle ersetzt keine dieser lokalen Bedingungen.",
      "solution": [
        {
          "action": "local_service",
          "id": "ORDER-01",
          "changes": {
            "status": "running"
          }
        },
        {
          "action": "local_account",
          "id": "lea",
          "changes": {
            "active": true
          }
        },
        {
          "action": "local_membership",
          "group": "Vertrieb",
          "member": "lea",
          "add": true
        },
        {
          "action": "local_restore",
          "scope": "file",
          "id": "angebot-lokal",
          "target": "angebot-lokal",
          "point": {
            "$state": [
              "onprem",
              "backup",
              "points",
              0,
              "id"
            ]
          }
        },
        {
          "action": "advance",
          "minutes": 5
        }
      ],
      "alternatives": "Erst eine alternative lokale Dateikopie prüfen und danach das Original wiederherstellen; oder die unabhängigen Konto-/Dienstreparaturen umordnen. Keine pauschalen lokalen IT-Rechte, keine Entra-Änderung als Ersatz.",
      "attachment": "Lokales Inventar mit tatsächlichen Dienstzuständen und lokalem Anfangssicherungspunkt.",
      "probes": [
        {
          "test": "local_application",
          "args": {
            "user": "lea",
            "source": "hq"
          },
          "expected": true
        },
        {
          "test": "local_file",
          "args": {
            "user": "lea",
            "document": "angebot-lokal",
            "operation": "data_read"
          },
          "expected": true
        },
        {
          "test": "local_file",
          "args": {
            "user": "lea",
            "document": "personal-lokal"
          },
          "expected": false
        },
        {
          "test": "local_file",
          "args": {
            "user": "partner",
            "document": "angebot-lokal"
          },
          "expected": false
        },
        {
          "test": "local_connection",
          "args": {
            "source": "cloud",
            "host": "auftrag.lan",
            "port": 443
          },
          "expected": false
        },
        {
          "test": "local_connection",
          "args": {
            "source": "hq",
            "host": "auftrag.lan",
            "port": 443
          },
          "expected": true
        },
        {
          "test": "application",
          "args": {
            "user": "u11",
            "source": "hq"
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "network",
            "vpn"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public_ip"
          ],
          "value": ""
        },
        {
          "op": "set",
          "path": [
            "onprem",
            "services",
            "ORDER-01",
            "status"
          ],
          "value": "stopped"
        },
        {
          "op": "set",
          "path": [
            "onprem",
            "accounts",
            "lea",
            "active"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "onprem",
            "documents",
            "angebot-lokal",
            "deleted"
          ],
          "value": true
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Lokaler Dienst gestartet",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "services",
                  "ORDER-01",
                  "status"
                ]
              },
              {
                "literal": "running"
              }
            ]
          }
        },
        {
          "label": "Lokales Konto aktiv",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "accounts",
                  "lea",
                  "active"
                ]
              },
              {
                "literal": true
              }
            ]
          }
        },
        {
          "label": "Lokale IT-Gruppe bleibt begrenzt",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "groups",
                  "IT"
                ]
              },
              {
                "literal": [
                  "it"
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigabe-ACLs unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "shares"
                ]
              },
              {
                "literal": {
                  "sales": {
                    "read": [
                      "Vertrieb",
                      "Anwendung",
                      "IT",
                      "Sicherung"
                    ],
                    "write": [
                      "Vertrieb",
                      "IT"
                    ]
                  },
                  "hr": {
                    "read": [
                      "Personal",
                      "IT",
                      "Sicherung"
                    ],
                    "write": [
                      "Personal",
                      "IT"
                    ]
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Lokales Angebot wieder vorhanden",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "documents",
                  "angebot-lokal",
                  "deleted"
                ]
              },
              {
                "literal": false
              }
            ]
          }
        },
        {
          "label": "Richtiger Angebotsinhalt",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "documents",
                  "angebot-lokal",
                  "content"
                ]
              },
              {
                "literal": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR."
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Personaldatei unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "documents",
                  "personal-lokal"
                ]
              },
              {
                "literal": {
                  "name": "Lokale Personalübersicht",
                  "container": "hr",
                  "class": "besonders schutzbedürftig",
                  "content": "Ausschließlich fiktive lokale Personaldaten.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Lokale Aufträge erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "orders"
                ]
              },
              {
                "literal": {
                  "LP-1001": {
                    "customer": "Fiktiv: Hafenwerk GmbH",
                    "subject": "Lokaler Wartungsauftrag",
                    "amount": 4800.0,
                    "status": "Neu",
                    "document": "angebot-lokal",
                    "modified": 0,
                    "version": 1
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Lokale Wiederherstellung erfolgreich",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "backup",
                  "restore",
                  "status"
                ]
              },
              {
                "literal": "success"
              }
            ]
          }
        },
        {
          "label": "Cloud-VPN nicht als Abkürzung repariert",
          "expr": {
            "eq": [
              {
                "path": [
                  "network",
                  "vpn"
                ]
              },
              {
                "literal": false
              }
            ]
          }
        },
        {
          "label": "Cloud-Konten unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "users"
                ]
              },
              {
                "literal": {
                  "u01": {
                    "name": "Person 01 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u02": {
                    "name": "Person 02 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u03": {
                    "name": "Person 03 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u04": {
                    "name": "Person 04 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u05": {
                    "name": "Person 05 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u06": {
                    "name": "Person 06 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u07": {
                    "name": "Person 07 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u08": {
                    "name": "Person 08 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u09": {
                    "name": "Person 09 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u10": {
                    "name": "Person 10 (fiktiv)",
                    "department": "Geschäftsführung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u11": {
                    "name": "Person 11 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u12": {
                    "name": "Person 12 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u13": {
                    "name": "Person 13 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u14": {
                    "name": "Person 14 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u15": {
                    "name": "Person 15 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u16": {
                    "name": "Person 16 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u17": {
                    "name": "Person 17 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u18": {
                    "name": "Person 18 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u19": {
                    "name": "Person 19 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u20": {
                    "name": "Person 20 (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u21": {
                    "name": "Person 21 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u22": {
                    "name": "Person 22 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u23": {
                    "name": "Person 23 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u24": {
                    "name": "Person 24 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u25": {
                    "name": "Person 25 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u26": {
                    "name": "Person 26 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u27": {
                    "name": "Person 27 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u28": {
                    "name": "Person 28 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u29": {
                    "name": "Person 29 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u30": {
                    "name": "Person 30 (fiktiv)",
                    "department": "Personal",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u31": {
                    "name": "Person 31 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u32": {
                    "name": "Person 32 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u33": {
                    "name": "Person 33 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u34": {
                    "name": "Person 34 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u35": {
                    "name": "Person 35 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u36": {
                    "name": "Person 36 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u37": {
                    "name": "Person 37 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u38": {
                    "name": "Person 38 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u39": {
                    "name": "Person 39 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u40": {
                    "name": "Person 40 (fiktiv)",
                    "department": "Buchhaltung",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u41": {
                    "name": "Person 41 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u42": {
                    "name": "Person 42 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u43": {
                    "name": "Person 43 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u44": {
                    "name": "Person 44 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u45": {
                    "name": "Person 45 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u46": {
                    "name": "Person 46 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u47": {
                    "name": "Person 47 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u48": {
                    "name": "Person 48 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u49": {
                    "name": "Person 49 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u50": {
                    "name": "Person 50 (fiktiv)",
                    "department": "Betrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u51": {
                    "name": "Person 51 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u52": {
                    "name": "Person 52 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u53": {
                    "name": "Person 53 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u54": {
                    "name": "Person 54 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u55": {
                    "name": "Person 55 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u56": {
                    "name": "Person 56 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u57": {
                    "name": "Person 57 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u58": {
                    "name": "Person 58 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u59": {
                    "name": "Person 59 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "u60": {
                    "name": "Person 60 (fiktiv)",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "lea": {
                    "name": "Lea Neumann (fiktiv)",
                    "department": "Vertrieb",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User"
                  },
                  "partner": {
                    "name": "Robin Extern (fiktiv)",
                    "department": "Dienstleister",
                    "active": true,
                    "mfa": true,
                    "guest": true,
                    "expires": 480,
                    "directory_role": "User"
                  },
                  "it": {
                    "name": "IT-Lernrolle",
                    "department": "IT",
                    "active": true,
                    "mfa": true,
                    "guest": false,
                    "expires": 0,
                    "directory_role": "User Administrator"
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Cloud-Gruppen unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "groups"
                ]
              },
              {
                "literal": {
                  "Vertrieb": [
                    "u11",
                    "u12"
                  ],
                  "IT": [
                    "it"
                  ],
                  "Altprojekt": [
                    "lea"
                  ],
                  "Partner": [
                    "partner"
                  ]
                }
              }
            ]
          }
        },
        {
          "label": "Cloud-Rollen unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "roles"
                ]
              },
              {
                "literal": [
                  {
                    "principal": "IT",
                    "role": "Contributor",
                    "scope": "subscription"
                  },
                  {
                    "principal": "IT",
                    "role": "User Access Administrator",
                    "scope": "subscription"
                  },
                  {
                    "principal": "Vertrieb",
                    "role": "Blob Contributor",
                    "scope": "sales"
                  },
                  {
                    "principal": "Altprojekt",
                    "role": "Blob Reader",
                    "scope": "sales"
                  },
                  {
                    "principal": "partner",
                    "role": "Blob Contributor",
                    "scope": "storage"
                  },
                  {
                    "principal": "lea",
                    "role": "Reader",
                    "scope": "storage"
                  },
                  {
                    "principal": "Vertrieb",
                    "role": "Order Operator",
                    "scope": "orders"
                  },
                  {
                    "principal": "orders-app",
                    "role": "Order Operator",
                    "scope": "orders"
                  },
                  {
                    "principal": "orders-app",
                    "role": "Blob Reader",
                    "scope": "sales"
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine Cloud-Ressource verändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "resources"
                ]
              },
              {
                "literal": {
                  "web": {
                    "name": "vm-auftrag",
                    "kind": "VM",
                    "group": "rg-app",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "running",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.1.10",
                    "port": 443,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "app",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "db": {
                    "name": "db-auftrag",
                    "kind": "Database",
                    "group": "rg-app",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "running",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.2.20",
                    "port": 5432,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "data",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "storage": {
                    "name": "stnordlicht",
                    "kind": "Storage",
                    "group": "rg-data",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "running",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.2.30",
                    "port": 443,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "data",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "testvm": {
                    "name": "vm-altprojekt",
                    "kind": "VM",
                    "group": "rg-lab",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "D4",
                    "status": "stopped",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.1.11",
                    "port": 443,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "app",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "paas": {
                    "name": "app-auftrag",
                    "kind": "App Service",
                    "group": "rg-app",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "stopped",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.1.40",
                    "port": 443,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "app",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "container": {
                    "name": "ca-versand",
                    "kind": "Container Apps",
                    "group": "rg-app",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "running",
                    "public": false,
                    "locked": false,
                    "disk_gb": 64,
                    "ip": "10.20.1.50",
                    "port": 8080,
                    "image": "shipping:broken",
                    "instances": 1,
                    "subnet": "app",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  },
                  "saas": {
                    "name": "Büro-Suite (externer Anbieter)",
                    "kind": "SaaS",
                    "group": "rg-lab",
                    "region": "germanywestcentral",
                    "department": "IT",
                    "owner": "IT-Leitung",
                    "availability": "single",
                    "size": "B2",
                    "status": "running",
                    "public": false,
                    "locked": false,
                    "disk_gb": 0,
                    "ip": "",
                    "port": 443,
                    "image": "orders:1.0",
                    "instances": 1,
                    "subnet": "",
                    "public_ip": "",
                    "configured": true,
                    "tier": "hot",
                    "redundancy": "LRS",
                    "capacity_gb": 100,
                    "used_gb": 12,
                    "os": "Linux"
                  }
                }
              }
            ]
          }
        }
      ],
      "function": "Lokale Infrastruktur: Dienste, lokale AD-Konten/Gruppen, Freigaben, Aufträge, Backup und gemeinsame Uhr",
      "terms": [
        {
          "term": "AD DS im Lernmodell",
          "meaning": "Lokale Konten und Gruppen mit eigener Anmeldung; hier keine echte Windows-Domäne oder GPO."
        },
        {
          "term": "SMB-Dateidienst",
          "meaning": "FILE-01 prüft lokale Freigabegruppen am modellierten TCP-Port 445; kein echtes Netzlaufwerk."
        },
        {
          "term": "Lokale Sicherung",
          "meaning": "Ein tatsächlicher Punkt enthält Dateien und strukturierte lokale Aufträge. Er ist vom Cloud-Backup getrennt."
        }
      ],
      "variants": [
        {
          "label": "Erst alternative Kopie prüfen",
          "rationale": "Punktinhalt erst getrennt lesen; danach das Original für die Anwendung wiederherstellen.",
          "actions": [
            {
              "action": "local_service",
              "id": "ORDER-01",
              "changes": {
                "status": "running"
              }
            },
            {
              "action": "local_account",
              "id": "lea",
              "changes": {
                "active": true
              }
            },
            {
              "action": "local_membership",
              "group": "Vertrieb",
              "member": "lea",
              "add": true
            },
            {
              "action": "local_restore",
              "scope": "file",
              "id": "angebot-lokal",
              "target": "angebot-pruefkopie",
              "point": {
                "$state": [
                  "onprem",
                  "backup",
                  "points",
                  0,
                  "id"
                ]
              }
            },
            {
              "action": "advance",
              "minutes": 5
            },
            {
              "action": "local_read",
              "id": "angebot-pruefkopie",
              "user": "u11"
            },
            {
              "action": "local_restore",
              "scope": "file",
              "id": "angebot-lokal",
              "target": "angebot-lokal",
              "point": {
                "$state": [
                  "onprem",
                  "backup",
                  "points",
                  0,
                  "id"
                ]
              }
            },
            {
              "action": "advance",
              "minutes": 5
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Nur Entra-Gruppe statt lokalem Konto",
          "rationale": "Cloud-Mitgliedschaft repariert keine lokale Anmeldung/Freigabe und verletzt den Auftrag.",
          "outcome": "incomplete",
          "actions": [
            {
              "action": "local_service",
              "id": "ORDER-01",
              "changes": {
                "status": "running"
              }
            },
            {
              "action": "membership",
              "group": "Vertrieb",
              "member": "lea",
              "add": true
            },
            {
              "action": "local_restore",
              "scope": "file",
              "id": "angebot-lokal",
              "target": "angebot-lokal",
              "point": {
                "$state": [
                  "onprem",
                  "backup",
                  "points",
                  0,
                  "id"
                ]
              }
            },
            {
              "action": "advance",
              "minutes": 5
            }
          ]
        },
        {
          "label": "Pauschale lokale IT-Rechte",
          "rationale": "Lokale Personalrechte und Administrationsrechte sind nicht beauftragt.",
          "outcome": "incomplete",
          "actions": [
            {
              "action": "local_service",
              "id": "ORDER-01",
              "changes": {
                "status": "running"
              }
            },
            {
              "action": "local_account",
              "id": "lea",
              "changes": {
                "active": true
              }
            },
            {
              "action": "local_membership",
              "group": "IT",
              "member": "lea",
              "add": true
            },
            {
              "action": "local_restore",
              "scope": "file",
              "id": "angebot-lokal",
              "target": "angebot-lokal",
              "point": {
                "$state": [
                  "onprem",
                  "backup",
                  "points",
                  0,
                  "id"
                ]
              }
            },
            {
              "action": "advance",
              "minutes": 5
            }
          ]
        }
      ],
      "clarifications": [
        {
          "id": "vpn",
          "question": "Soll ich zuerst das Cloud-VPN reparieren?",
          "answer": "Nein. Prüfe den lokalen LAN-Betrieb und die lokalen Dienst-/Kontobedingungen. Das VPN bleibt in diesem Auftrag aus; die Cloud-Verbindung ist ein getrennter Fehler."
        },
        {
          "id": "entra",
          "question": "Genügt Leas Entra-Gruppe für die lokale Freigabe?",
          "answer": "Nein. Der lokale AD-Lernbereich hat eigene aktive Konten, Gruppen und Freigaberechte. Es ist kein automatischer Abgleich eingerichtet."
        },
        {
          "id": "daten",
          "question": "Kopiert dieser Auftrag lokale Daten bereits in die Cloud?",
          "answer": "Nein. Diese lokale Reparatur verändert den lokalen Bestand. Der zusätzliche Auftrag umzug übernimmt tatsächliche lokale Datei-/Auftragsdaten; der historische Auftrag 18 bleibt eine Cloud-Laufzeitmigration."
        }
      ]
    },
    {
      "id": "umzug",
      "title": "Lokale Aufträge tatsächlich in die Cloud übernehmen",
      "sender": "Geschäftsführung · IT-Leitung",
      "message": "Übernimm die lokale Auftragsanwendung samt LP-1001 und ihrem tatsächlichen Angebotsinhalt in die Cloud. Wähle IaaS oder PaaS, prüfe die getrennte Kopie vor Umschaltung, kontrolliere den Zugriff über den bisherigen Programmeinstieg und stoppe erst danach die lokale ORDER-Laufzeit. Die übrige Cloudfirma und lokale Personaldatei bleiben erhalten.",
      "minutes": 35,
      "prerequisite": "Lokale Dienste, Entra-/Datenrollen, VPN/NSG und Rückfall",
      "learning": "Echte getrennte Datenkopie, Prüfung, Umschaltung und Rückfall mit aktuellen Cloud-Änderungen nachvollziehen.",
      "learn": "Du lernst, dass ein Kopiermanifest noch keine übertragenen Auftragsdaten ist.",
      "try_text": "Du probierst Übernahme, positive/negative Zugriffe, Nachkontrolle und geordnetes Stilllegen der bisherigen Laufzeit.",
      "deadline": "Vor der nächsten Nutzung im Hauptstandort; etwa 35 Minuten.",
      "constraints": "LP-1001 und sein Anhang müssen inhaltlich erhalten in der Cloud vorhanden und über den bisherigen Programmeinstieg erreichbar sein. Daten nicht vor erfolgreichem Test umschalten. Keine bestehende Cloud-Datei oder Cloud-Aufträge überschreiben, keine lokalen Personaldaten übertragen, keine zusätzlichen Administratoren oder öffentlichen Administrationsregeln. AD- und Entra-Konten bleiben getrennt; keine automatische Identitätskonvertierung. Nachkontrolle vor Stop von ORDER-01. Rückfall muss aktuelle Cloud-Änderungen zurückbringen können.",
      "initial": "Lokaler Betrieb mit eigenständigen Datei-/Auftragsdaten ist aktiv; der bisherige Cloudbestand enthält LP-1001 nicht. Die Migrationsidentität besitzt anfangs keine Datenrollen. Ein neues Ziel muss vorbereitet und erreichbar konfiguriert werden.",
      "hints": [
        "Prüfe lokale Daten und Abhängigkeiten; begründe IaaS oder PaaS im Bereich Migration. Halte lokale und vorhandene Cloud-Daten auseinander.",
        "Lokale IT-Konsolenrechte und Cloud-Verwaltungsrechte ersetzen keine Datenrollen. Die Kopierquelle benötigt Cloud-zu-LAN-VPN, lokale Freigaben für AD/FILE/SQL und zulässige NSG-Pfade.",
        "Bereite das Ziel vor, erlaube internes HTTPS, kopiere tatsächliche Daten und teste. Erst dann umschalten, über den lokalen Programmeinstieg nachprüfen und ORDER-01 stoppen. Neue Quelldaten benötigen neue Kopie und Test."
      ],
      "explanation": "Der Kopierschritt hält eigene Datei-/Auftragsdatensätze, ohne bestehende Cloud-Daten zu ändern. Test und Cutover vergleichen erneut die Quelle und prüfen reale Zielpfade, Rollen und Inhalte. Die Umschaltung setzt den lokalen Programmeinstieg auf das Cloudziel und friert die alten Quelldaten ein. Nach Rückfall werden aktuelle Cloud-Fassungen lokal übernommen; die aufbewahrte Cloudkopie bleibt schreibgeschützt. Die restlichen lokalen AD-/Datei-/SQL-/Backupdienste bleiben für andere Aufgaben erhalten.",
      "solution": [
        {
          "action": "role_add",
          "principal": "it",
          "role": "Blob Contributor",
          "scope": "sales"
        },
        {
          "action": "role_add",
          "principal": "it",
          "role": "Order Operator",
          "scope": "orders"
        },
        {
          "action": "local_service",
          "id": "AD-01",
          "changes": {
            "allow_cloud": true
          }
        },
        {
          "action": "local_service",
          "id": "FILE-01",
          "changes": {
            "allow_cloud": true
          }
        },
        {
          "action": "local_service",
          "id": "SQL-01",
          "changes": {
            "allow_cloud": true
          }
        },
        {
          "action": "local_migration",
          "step": "prepare",
          "strategy": "replatform",
          "reason": "Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."
        },
        {
          "action": "configure",
          "id": "localpaas",
          "changes": {
            "configured": true,
            "status": "running"
          }
        },
        {
          "action": "rule_add",
          "rule": {
            "id": "local-migration-https",
            "direction": "Inbound",
            "protocol": "TCP",
            "source": "10.10.0.0/16",
            "destination": "localpaas",
            "port": 443,
            "action": "Allow",
            "priority": 220
          }
        },
        {
          "action": "local_migration",
          "step": "copy"
        },
        {
          "action": "local_migration",
          "step": "test"
        },
        {
          "action": "local_migration",
          "step": "cutover"
        },
        {
          "action": "local_migration",
          "step": "followup"
        },
        {
          "action": "local_migration",
          "step": "cleanup"
        }
      ],
      "alternatives": "Rehost nutzt eine eigene VM mit Compute- und Disk-Kosten; Replatform nutzt einen eigenen App-Service-Lernplan mit verbleibenden Plankosten beim Stop. Dies ist eine Portierung der fiktiven Webanwendung, keine binäre VM-/SQL- oder AD-Migration. Retain ist eine begründete Planungsalternative ohne Migrationsabschluss; die Büro-SaaS ersetzt keine Auftragsanwendung.",
      "attachment": "LP-1001 mit tatsächlichem lokalem Dateiinhalt; Plan und Kopierbestand sind im Migration Center lesbar.",
      "probes": [
        {
          "test": "local_application",
          "args": {
            "user": "u11",
            "source": "hq"
          },
          "expected": true
        },
        {
          "test": "local_application",
          "args": {
            "user": "partner",
            "source": "hq"
          },
          "expected": false
        },
        {
          "test": "local_connection",
          "args": {
            "source": "internet",
            "host": "auftrag.lan",
            "port": 22
          },
          "expected": false
        },
        {
          "test": "local_file",
          "args": {
            "user": "u11",
            "document": "personal-lokal"
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        },
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public_ip"
          ],
          "value": ""
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Übernahme mit Nachkontrolle abgeschlossen",
          "expr": {
            "eq": [
              {
                "path": [
                  "local_migration",
                  "phase"
                ]
              },
              {
                "literal": "complete"
              }
            ]
          }
        },
        {
          "label": "Programmeinstieg nutzt das gewählte Cloudziel",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "dns",
                  "auftrag.lan"
                ]
              },
              {
                "path": [
                  "local_migration",
                  "target"
                ]
              }
            ]
          }
        },
        {
          "label": "Umschaltung aktiv",
          "expr": {
            "eq": [
              {
                "path": [
                  "local_migration",
                  "active"
                ]
              },
              {
                "literal": true
              }
            ]
          }
        },
        {
          "label": "Kopie enthält genau die lokalen Aufträge",
          "expr": {
            "eq": [
              {
                "path": [
                  "local_migration",
                  "orders"
                ]
              },
              {
                "literal": {
                  "LP-1001": {
                    "customer": "Fiktiv: Hafenwerk GmbH",
                    "subject": "Lokaler Wartungsauftrag",
                    "amount": 4800.0,
                    "status": "Neu",
                    "document": "angebot-lokal",
                    "modified": 0,
                    "version": 1
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Lokale ursprüngliche Aufträge erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "orders"
                ]
              },
              {
                "literal": {
                  "LP-1001": {
                    "customer": "Fiktiv: Hafenwerk GmbH",
                    "subject": "Lokaler Wartungsauftrag",
                    "amount": 4800.0,
                    "status": "Neu",
                    "document": "angebot-lokal",
                    "modified": 0,
                    "version": 1
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Übernommener Auftrag inhaltlich erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "orders",
                  "LP-1001"
                ]
              },
              {
                "literal": {
                  "customer": "Fiktiv: Hafenwerk GmbH",
                  "subject": "Lokaler Wartungsauftrag",
                  "amount": 4800.0,
                  "status": "Neu",
                  "document": "angebot-lokal",
                  "modified": 0,
                  "version": 1
                }
              }
            ]
          }
        },
        {
          "label": "Dateiinhalt und Historie tatsächlich übertragen",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "angebot-lokal"
                ]
              },
              {
                "literal": {
                  "name": "Angebot des lokalen Betriebs",
                  "container": "sales",
                  "class": "vertraulich",
                  "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Lokale Personaldatei unverändert",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "documents",
                  "personal-lokal"
                ]
              },
              {
                "literal": {
                  "name": "Lokale Personalübersicht",
                  "container": "hr",
                  "class": "besonders schutzbedürftig",
                  "content": "Ausschließlich fiktive lokale Personaldaten.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Keine Personaldatei übertragen",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "personal-lokal"
                ]
              },
              {
                "literal": null
              }
            ]
          }
        },
        {
          "label": "Alte ORDER-Laufzeit nach Nachkontrolle gestoppt",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "services",
                  "ORDER-01",
                  "status"
                ]
              },
              {
                "literal": "stopped"
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen Administratoren",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Keine automatische AD-/Entra-Konvertierung",
          "expr": {
            "eq": [
              {
                "path": [
                  "onprem",
                  "accounts"
                ]
              },
              {
                "literal": {
                  "u01": {
                    "active": true
                  },
                  "u02": {
                    "active": true
                  },
                  "u03": {
                    "active": true
                  },
                  "u04": {
                    "active": true
                  },
                  "u05": {
                    "active": true
                  },
                  "u06": {
                    "active": true
                  },
                  "u07": {
                    "active": true
                  },
                  "u08": {
                    "active": true
                  },
                  "u09": {
                    "active": true
                  },
                  "u10": {
                    "active": true
                  },
                  "u11": {
                    "active": true
                  },
                  "u12": {
                    "active": true
                  },
                  "u13": {
                    "active": true
                  },
                  "u14": {
                    "active": true
                  },
                  "u15": {
                    "active": true
                  },
                  "u16": {
                    "active": true
                  },
                  "u17": {
                    "active": true
                  },
                  "u18": {
                    "active": true
                  },
                  "u19": {
                    "active": true
                  },
                  "u20": {
                    "active": true
                  },
                  "u21": {
                    "active": true
                  },
                  "u22": {
                    "active": true
                  },
                  "u23": {
                    "active": true
                  },
                  "u24": {
                    "active": true
                  },
                  "u25": {
                    "active": true
                  },
                  "u26": {
                    "active": true
                  },
                  "u27": {
                    "active": true
                  },
                  "u28": {
                    "active": true
                  },
                  "u29": {
                    "active": true
                  },
                  "u30": {
                    "active": true
                  },
                  "u31": {
                    "active": true
                  },
                  "u32": {
                    "active": true
                  },
                  "u33": {
                    "active": true
                  },
                  "u34": {
                    "active": true
                  },
                  "u35": {
                    "active": true
                  },
                  "u36": {
                    "active": true
                  },
                  "u37": {
                    "active": true
                  },
                  "u38": {
                    "active": true
                  },
                  "u39": {
                    "active": true
                  },
                  "u40": {
                    "active": true
                  },
                  "u41": {
                    "active": true
                  },
                  "u42": {
                    "active": true
                  },
                  "u43": {
                    "active": true
                  },
                  "u44": {
                    "active": true
                  },
                  "u45": {
                    "active": true
                  },
                  "u46": {
                    "active": true
                  },
                  "u47": {
                    "active": true
                  },
                  "u48": {
                    "active": true
                  },
                  "u49": {
                    "active": true
                  },
                  "u50": {
                    "active": true
                  },
                  "u51": {
                    "active": true
                  },
                  "u52": {
                    "active": true
                  },
                  "u53": {
                    "active": true
                  },
                  "u54": {
                    "active": true
                  },
                  "u55": {
                    "active": true
                  },
                  "u56": {
                    "active": true
                  },
                  "u57": {
                    "active": true
                  },
                  "u58": {
                    "active": true
                  },
                  "u59": {
                    "active": true
                  },
                  "u60": {
                    "active": true
                  },
                  "lea": {
                    "active": true
                  },
                  "it": {
                    "active": true
                  },
                  "svc-orders": {
                    "active": true
                  },
                  "svc-backup": {
                    "active": true
                  }
                }
              }
            ]
          }
        },
        {
          "label": "Bestehender Cloudauftrag NL-1001 erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "orders",
                  "NL-1001"
                ]
              },
              {
                "literal": {
                  "customer": "Fiktiv: Hafenwerk GmbH",
                  "subject": "Arbeitsplatz-Erweiterung",
                  "amount": 120.0,
                  "status": "Neu",
                  "document": "offer",
                  "modified": 0,
                  "version": 1
                }
              }
            ]
          }
        },
        {
          "label": "Bestehender Cloudauftrag NL-1002 erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "orders",
                  "NL-1002"
                ]
              },
              {
                "literal": {
                  "customer": "Fiktiv: Beispielhandel KG",
                  "subject": "Standortanbindung planen",
                  "amount": 240.0,
                  "status": "In Bearbeitung",
                  "document": "offer",
                  "modified": 0,
                  "version": 1
                }
              }
            ]
          }
        },
        {
          "label": "Bestehende Clouddatei offer erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "offer"
                ]
              },
              {
                "literal": {
                  "name": "Angebot-A.txt",
                  "container": "sales",
                  "class": "vertraulich",
                  "content": "Angebot A: 120 Lern-Euro; Version 1.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Bestehende Clouddatei payroll erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "payroll"
                ]
              },
              {
                "literal": {
                  "name": "Personal-B.txt",
                  "container": "hr",
                  "class": "besonders schutzbedürftig",
                  "content": "Fiktive Personalnotiz B; keine echten Personendaten.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        },
        {
          "label": "Bestehende Clouddatei public erhalten",
          "expr": {
            "eq": [
              {
                "path": [
                  "documents",
                  "public"
                ]
              },
              {
                "literal": {
                  "name": "Firmeninfo.txt",
                  "container": "public",
                  "class": "öffentlich",
                  "content": "Nordlicht: 60 fiktive Beschäftigte.",
                  "version": 1,
                  "deleted": false,
                  "modified": 0,
                  "versions": []
                }
              }
            ]
          }
        }
      ],
      "function": "Lokale Infrastruktur: Dienste, lokale AD-Konten/Gruppen, Freigaben, Aufträge, Backup und gemeinsame Uhr",
      "terms": [
        {
          "term": "Datenübernahme",
          "meaning": "Dateiinhalte, Versionen und Auftragsdatensätze werden tatsächlich in einen getrennten Kopierbestand übernommen."
        },
        {
          "term": "Cutover",
          "meaning": "Bewusste Umschaltung des bisherigen Programmeinstiegs nach erfolgreichem Zieltest."
        },
        {
          "term": "Rückfall",
          "meaning": "Aktuelle Cloud-Fassungen zurück in den eingefrorenen lokalen Bestand übernehmen; keine Rückkehr zu einer veralteten Kopie."
        }
      ],
      "variants": [
        {
          "label": "Eigene IaaS-VM",
          "rationale": "Gleiche fachliche Datenübernahme mit einer selbst verwalteten VM statt App-Service-Lernplan.",
          "actions": [
            {
              "action": "role_add",
              "principal": "it",
              "role": "Blob Contributor",
              "scope": "sales"
            },
            {
              "action": "role_add",
              "principal": "it",
              "role": "Order Operator",
              "scope": "orders"
            },
            {
              "action": "local_service",
              "id": "AD-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "FILE-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "SQL-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_migration",
              "step": "prepare",
              "strategy": "rehost",
              "reason": "Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."
            },
            {
              "action": "configure",
              "id": "localvm",
              "changes": {
                "configured": true,
                "status": "running"
              }
            },
            {
              "action": "rule_add",
              "rule": {
                "id": "local-migration-https",
                "direction": "Inbound",
                "protocol": "TCP",
                "source": "10.10.0.0/16",
                "destination": "localvm",
                "port": 443,
                "action": "Allow",
                "priority": 220
              }
            },
            {
              "action": "local_migration",
              "step": "copy"
            },
            {
              "action": "local_migration",
              "step": "test"
            },
            {
              "action": "local_migration",
              "step": "cutover"
            },
            {
              "action": "local_migration",
              "step": "followup"
            },
            {
              "action": "local_migration",
              "step": "cleanup"
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Umschalten ohne Zieltest",
          "rationale": "Eine echte Kopie allein beweist noch keinen funktionsfähigen Zielbetrieb.",
          "outcome": "rejected",
          "actions": [
            {
              "action": "role_add",
              "principal": "it",
              "role": "Blob Contributor",
              "scope": "sales"
            },
            {
              "action": "role_add",
              "principal": "it",
              "role": "Order Operator",
              "scope": "orders"
            },
            {
              "action": "local_service",
              "id": "AD-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "FILE-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "SQL-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_migration",
              "step": "prepare",
              "strategy": "replatform",
              "reason": "Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."
            },
            {
              "action": "configure",
              "id": "localpaas",
              "changes": {
                "configured": true,
                "status": "running"
              }
            },
            {
              "action": "rule_add",
              "rule": {
                "id": "local-migration-https",
                "direction": "Inbound",
                "protocol": "TCP",
                "source": "10.10.0.0/16",
                "destination": "localpaas",
                "port": 443,
                "action": "Allow",
                "priority": 220
              }
            },
            {
              "action": "local_migration",
              "step": "copy"
            },
            {
              "action": "local_migration",
              "step": "cutover"
            }
          ]
        },
        {
          "label": "Quelldaten nach Kopie geändert",
          "rationale": "Der Zieltest muss neuere Quelldaten erkennen und eine neue Kopie verlangen.",
          "outcome": "rejected",
          "actions": [
            {
              "action": "role_add",
              "principal": "it",
              "role": "Blob Contributor",
              "scope": "sales"
            },
            {
              "action": "role_add",
              "principal": "it",
              "role": "Order Operator",
              "scope": "orders"
            },
            {
              "action": "local_service",
              "id": "AD-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "FILE-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "SQL-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_migration",
              "step": "prepare",
              "strategy": "replatform",
              "reason": "Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."
            },
            {
              "action": "configure",
              "id": "localpaas",
              "changes": {
                "configured": true,
                "status": "running"
              }
            },
            {
              "action": "rule_add",
              "rule": {
                "id": "local-migration-https",
                "direction": "Inbound",
                "protocol": "TCP",
                "source": "10.10.0.0/16",
                "destination": "localpaas",
                "port": 443,
                "action": "Allow",
                "priority": 220
              }
            },
            {
              "action": "local_migration",
              "step": "copy"
            },
            {
              "action": "local_write",
              "id": "angebot-lokal",
              "user": "u11",
              "content": "Neue lokale Fassung"
            },
            {
              "action": "local_migration",
              "step": "test"
            }
          ]
        },
        {
          "label": "Unterbrochene Übernahme",
          "rationale": "Eine pausierte Migration darf nicht still weiterlaufen.",
          "outcome": "rejected",
          "actions": [
            {
              "action": "role_add",
              "principal": "it",
              "role": "Blob Contributor",
              "scope": "sales"
            },
            {
              "action": "role_add",
              "principal": "it",
              "role": "Order Operator",
              "scope": "orders"
            },
            {
              "action": "local_service",
              "id": "AD-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "FILE-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_service",
              "id": "SQL-01",
              "changes": {
                "allow_cloud": true
              }
            },
            {
              "action": "local_migration",
              "step": "prepare",
              "strategy": "replatform",
              "reason": "Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."
            },
            {
              "action": "configure",
              "id": "localpaas",
              "changes": {
                "configured": true,
                "status": "running"
              }
            },
            {
              "action": "rule_add",
              "rule": {
                "id": "local-migration-https",
                "direction": "Inbound",
                "protocol": "TCP",
                "source": "10.10.0.0/16",
                "destination": "localpaas",
                "port": 443,
                "action": "Allow",
                "priority": 220
              }
            },
            {
              "action": "local_migration",
              "step": "pause"
            },
            {
              "action": "local_migration",
              "step": "copy"
            }
          ]
        }
      ],
      "clarifications": [
        {
          "id": "identitaet",
          "question": "Wandelt der Umzug lokale AD-Konten automatisch in Entra-Konten um?",
          "answer": "Nein. Der Cloudbetrieb verwendet vorhandene Entra-Konten und separat geprüfte Rollen. Der lokale AD-Bestand bleibt unverändert."
        },
        {
          "id": "daten",
          "question": "Reicht das bisherige Cloud-Migrationsprofil?",
          "answer": "Nein. Dieser Auftrag verlangt die tatsächlich vorhandenen lokalen Datei-/Auftragsdaten. Die bisherige Aufgabe 18 verschiebt eine schon vorhandene Cloud-Weblaufzeit."
        },
        {
          "id": "rueckfall",
          "question": "Gehen nach der Umschaltung bearbeitete Aufträge beim Rückfall verloren?",
          "answer": "Der Rückfall liest aktuelle Cloud-Aufträge und zugehörige Dateien. Fehlen Quelle, Leserechte oder lokales Schreibziel, wird er ohne Datenänderung abgewiesen."
        }
      ]
    },
    {"id":"bereinigung","title":"Lokale und Cloud-Geschäftskopien gemeinsam bereinigen","sender":"Datenschutzkoordination · Vertrieb","message":"Der abgeschlossene fiktive Vorgang LP-1001 wird nach der Firmenfrist nicht weiter benötigt. Sein Beleg liegt noch lokal, in einem lokalen Auszug, im Migrationsbestand und in Cloud-Kopien. Prüfe die Herkunft und die Frist, hebe die vorgegebene Löschsperre begründet auf und bereinige anschließend den gesamten Vorgang. Der übrige Cloudbetrieb und lokale Personalbestand bleiben erforderlich.","minutes":25,"prerequisite":"Aufbewahrung, Löschsperre, Datenherkunft und Migrationskopien","learning":"Herkunft, Frist und Löschsperre über operative Kopien und modellierte Sicherungen hinweg prüfen.","learn":"Du lernst, warum das Entfernen nur einer sichtbaren Cloud-Datei keine vollständige Bereinigung des Vorgangs ist.","try_text":"Du probierst eine gemeinsame Datenregel, bewusstes Abwarten der Restfrist und überprüfbare Entfernung aller bekannten Modellkopien.","deadline":"Nach Ablauf der fiktiven Firmenfrist bei Minute 15, etwa 25 Minuten Bearbeitung.","constraints":"Die laufende Frist darf nicht verkürzt werden. Löschsperre nur mit begründeter Entscheidung aufheben. Inhalte und Versionen von angebot-lokal, lokaler-auszug und cloud-auszug sowie die zugehörigen LP-Auftragsfelder aus den aktuellen lokalen/Cloud-/Migrations- und modellierten Sicherungsbeständen entfernen. Alte technische Datenbanksicherungen, bereits exportierte Dateien und Freitext sind getrennt. Bestehende Clouddateien und NL-Aufträge sowie lokale Personaldatei bleiben unverändert. Keine pauschalen neuen Rechte.","initial":"Migration ist abgeschlossen. Der lokale und der Cloud-Auszug teilen die bekannte Beleg-Herkunft. Fiktive Frist bis Minute 15 und Löschsperre sind aktiv; aktuelle Minute 10. Tatsächliche Inhalte liegen außerdem in Punkten und Migrationskopie.","hints":["Öffne Datenbereinigung. Prüfe alle zugeordneten Dokumente und Aufträge, nicht nur den sichtbaren Speicherort.","Die strengste Frist und jede aktive Löschsperre wirken gemeinsam. Verantwortung ist keine Zugriffsrolle. Datenregel ändern benötigt Rechte in allen betroffenen Bereichen.","Begründe die Freigabe, behalte fünf weitere Simulationsminuten bei und spule fünf Minuten vor. Bestätige dann die gezielte Geschäftsbereinigung und prüfe den erhaltenen Betrieb sowie den verweigerten Zugriff auf entfernte Belege."],"explanation":"Bekannte Herkunft verbindet lokale Auszüge, Migration und Cloud-Wiederherstellungen. Der gezielte Geschäftsschritt leert Beleginhalte und Historien, anonymisiert die zugehörigen Auftrags-Nutzfelder, bereinigt modellierte Punkte und entfernt passende Restorejobs. Stabile Kennungen bleiben als nicht wieder beschreibbare Tombstones erhalten. Rückfall oder alte Punkte dürfen diese bekannten Nutzdaten nicht zurückbringen. Technische DB-Backups, frühere Exporte und frei eingegebene Notizen sind ausdrücklich außerhalb dieser Funktion.","solution":[{"action":"business_policy","area":"cloud","id":"cloud-auszug","changes":{"owner":"Vertrieb","purpose":"Abgeschlossener fiktiver Vorgang; nach Firmenfrist nicht weiter benötigt","retain_minutes":5,"hold":false,"reason":"Fiktive fachliche Vorgabe; zugehörige Aufträge und Kopien gemeinsam betrachten"}},{"action":"advance","minutes":5},{"action":"business_purge","area":"cloud","id":"cloud-auszug","reason":"Fiktiver abgeschlossener Vorgang nach abgelaufener Firmenfrist nicht weiter benötigt"}],"alternatives":"Die Datenregel und Bereinigung können von der lokalen Herkunft oder einer verbundenen Cloud-Kopie ausgehen. Beide Wege prüfen dieselben Fristen/Sperren und Rechte. Eine einzelne unverbundene Datei oder Logik-Löschung ist kein Ersatz. Ältere ungeklärte lokale Kopien benötigen vor der Bereinigung eine ausdrückliche Herkunftsentscheidung.","attachment":"Kopienübersicht mit lokalem Auszug, Cloud-Auszug, Migrationsbestand und tatsächlichen Sicherungspunkten.","probes":[{"test":"local_application","args":{"user":"u11"},"expected":true},{"test":"access","args":{"user":"u11","document":"angebot-lokal"},"expected":false},{"test":"access","args":{"user":"u11","document":"offer"},"expected":true},{"test":"local_file","args":{"user":"u21","document":"personal-lokal"},"expected":true}],"start":[{"op":"set","path":["resources","storage","public"],"value":false},{"op":"set","path":["resources","storage","public_ip"],"value":""}],"setup":[{"action":"local_write","id":"angebot-lokal","user":"u11","content":"Fiktiver vertraulicher Vorgang zur späteren Bereinigung."},{"action":"local_restore","scope":"file","point":{"$state":["onprem","backup","points",0,"id"]},"id":"angebot-lokal","target":"lokaler-auszug"},{"action":"advance","minutes":5},{"action":"local_backup_run"},{"action":"role_add","principal":"it","role":"Blob Contributor","scope":"sales"},{"action":"role_add","principal":"it","role":"Order Operator","scope":"orders"},{"action":"local_service","id":"AD-01","changes":{"allow_cloud":true}},{"action":"local_service","id":"FILE-01","changes":{"allow_cloud":true}},{"action":"local_service","id":"SQL-01","changes":{"allow_cloud":true}},{"action":"local_migration","step":"prepare","strategy":"replatform","reason":"Fiktive Auftrags-Webanwendung und tatsächlich vorhandene Datei-/SQL-Daten übernehmen. Entra-Zugriff gesondert prüfen; Rückfallkopie behalten."},{"action":"configure","id":"localpaas","changes":{"configured":true,"status":"running"}},{"action":"rule_add","rule":{"id":"local-migration-https","direction":"Inbound","protocol":"TCP","source":"10.10.0.0/16","destination":"localpaas","port":443,"action":"Allow","priority":220}},{"action":"local_migration","step":"copy"},{"action":"local_migration","step":"test"},{"action":"local_migration","step":"cutover"},{"action":"local_migration","step":"followup"},{"action":"local_migration","step":"cleanup"},{"action":"local_order_update","id":"LP-1001","version":1,"changes":{"customer":"Fiktiv: Abgeschlossener Kunde","subject":"Nicht mehr benötigter Vorgang","amount":600,"status":"Erledigt"}},{"action":"business_policy","area":"cloud","id":"angebot-lokal","changes":{"owner":"Vertrieb","purpose":"Abgeschlossener fiktiver Vorgang; nach Firmenfrist nicht weiter benötigt","retain_minutes":10,"hold":true,"reason":"Fiktive fachliche Vorgabe; zugehörige Aufträge und Kopien gemeinsam betrachten"}},{"action":"backup_run"},{"action":"restore","point":{"$state":["backup","points",-1,"id"]},"id":"angebot-lokal","target":"cloud-auszug"},{"action":"advance","minutes":5}],"criteria":[{"label":"Gemeinsame Herkunft endgültig entfernt","expr":{"eq":[{"path":["onprem","data_governance","angebot-lokal","status"]},{"literal":"purged"}]}},{"label":"Cloud-Herkunft entfernt","expr":{"eq":[{"path":["data_governance","angebot-lokal","status"]},{"literal":"purged"}]}},{"label":"Migrationskopie ohne Nutzinhalt","expr":{"eq":[{"path":["local_migration","documents","angebot-lokal","content"]},{"literal":""}]}},{"label":"Cloudauftrag ohne frühere Nutzfelder","expr":{"eq":[{"path":["orders","LP-1001","customer"]},{"literal":"[Entfernt]"}]}},{"label":"Lokaler Auftrag ohne frühere Nutzfelder","expr":{"eq":[{"path":["onprem","orders","LP-1001","customer"]},{"literal":"[Entfernt]"}]}},{"label":"Kopierauftrag ohne Nutzfelder","expr":{"eq":[{"path":["local_migration","orders","LP-1001","subject"]},{"literal":"[Entfernt]"}]}},{"label":"Alte Cloud-Restorekopie entfernt","expr":{"eq":[{"path":["documents","cloud-auszug","content"]},{"literal":""}]}},{"label":"Lokaler Auszug entfernt","expr":{"eq":[{"path":["onprem","documents","lokaler-auszug","content"]},{"literal":""}]}},{"label":"Keine zusätzlichen Administratoren","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Bestehender Cloudauftrag erhalten","expr":{"eq":[{"path":["orders","NL-1001","amount"]},{"literal":120.0}]}},{"label":"Andere Clouddatei erhalten","expr":{"eq":[{"path":["documents","offer","content"]},{"literal":"Angebot A: 120 Lern-Euro; Version 1."}]}},{"label":"Lokale Personaldatei erhalten","expr":{"eq":[{"path":["onprem","documents","personal-lokal","content"]},{"literal":"Ausschließlich fiktive lokale Personaldaten."}]}},{"label":"Lokale und Cloud-Frist nicht verkürzt","expr":{"eq":[{"path":["onprem","data_governance","angebot-lokal","retention_until"]},{"literal":15}]}}],"function":"Lokale Infrastruktur: Dienste, lokale AD-Konten/Gruppen, Freigaben, Aufträge, Backup und gemeinsame Uhr","terms":[{"term":"Herkunftsgruppe","meaning":"Bekannte Ableitungen eines Belegs teilen die fachliche Aufbewahrung; gleiche Textinhalte allein beweisen keine Herkunft."},{"term":"Löschsperre","meaning":"Zusätzliche begründete Sperre, die auch nach Ablauf der Frist entfernt werden muss."},{"term":"Tombstone","meaning":"Verbleibende Kennung mit leerem Beleg und neutralisierten Auftrags-Nutzfeldern; kein neu beschreibbarer alter Geschäftsvorgang."}],"variants":[{"label":"Von der lokalen Herkunft bereinigen","rationale":"Gleiche bekannte Kopiengruppe und Auftragsdaten, gemeinsame Regeln statt örtlich begrenztem Entfernen.","actions":[{"action":"business_policy","area":"local","id":"lokaler-auszug","changes":{"owner":"Vertrieb","purpose":"Abgeschlossener fiktiver Vorgang; nach Firmenfrist nicht weiter benötigt","retain_minutes":5,"hold":false,"reason":"Fiktive fachliche Vorgabe; zugehörige Aufträge und Kopien gemeinsam betrachten"}},{"action":"advance","minutes":5},{"action":"business_purge","area":"local","id":"angebot-lokal","reason":"Lokale Herkunft einschließlich aller bekannten Cloud- und Modellkopien fachlich freigegeben"}]}],"failures":[{"label":"Löschsperre übergehen","rationale":"Eine abgelaufene Frist allein hebt keine Löschsperre auf.","outcome":"rejected","actions":[{"action":"advance","minutes":5},{"action":"business_purge","area":"cloud","id":"cloud-auszug","reason":"Trotz Sperre"}]},{"label":"Vor Ablauf entfernen","rationale":"Eine aufgehobene Sperre verkürzt die laufende Frist nicht.","outcome":"rejected","actions":[{"action":"business_policy","area":"local","id":"angebot-lokal","changes":{"owner":"Vertrieb","purpose":"Abgeschlossener fiktiver Vorgang; nach Firmenfrist nicht weiter benötigt","retain_minutes":5,"hold":false,"reason":"Fiktive fachliche Vorgabe; zugehörige Aufträge und Kopien gemeinsam betrachten"}},{"action":"business_purge","area":"local","id":"angebot-lokal","reason":"Zu früh"}]},{"label":"Cloud-Kopie als Umweg entfernen","rationale":"Der alte Dateischritt darf bekannte lokale und Migrationskopien nicht übergehen.","outcome":"rejected","actions":[{"action":"data_purge","id":"cloud-auszug","reason":"Nur sichtbare Kopie"}]}],"clarifications":[{"id":"kopien","question":"Reicht es, den Cloud-Auszug zu entfernen?","answer":"Nein. Die bekannte Gruppe enthält lokale und Migrationskopien. Benutze die gemeinsame Datenbereinigung mit Vorschau der betroffenen Belege und Aufträge."},{"id":"backups","question":"Verschwinden dabei auch früher exportierte Dateien und technische Datenbanksicherungen?","answer":"Nein. Bereinigt werden die bekannten operativen Modellbestände und modellierten Punkte der aktiven Übung. Technische DB-Sicherungen, alte Exporte und Freitext bleiben getrennte Arbeitsaufträge."}]},
    {
      "id": "modelle",
      "title": "Eine Kundenanforderung, drei Cloud-Modelle",
      "sender": "Vertriebsleitung",
      "message": "Zwei Beschäftigte brauchen eine Kundenanfrage-Anwendung. u11 erfasst und bearbeitet Anfragen; u12 liest ausschließlich. Externe dürfen keine Anfragen sehen. Stelle denselben Dienst wahlweise über eine VM (IaaS), App Service (PaaS) oder einen externen SaaS-Anbieter bereit. Erfasse ANF-001 für Fiktiv: Hafenwerk GmbH mit Betreff Rückruf zum Cloud-Arbeitsplatz und bearbeite sie bis Erledigt.",
      "minutes": 30,
      "prerequisite": "Einstieg, Ressourcen und effektive Zugriffe",
      "learning": "IaaS/PaaS/SaaS vergleichen; Verantwortungen; Anwendungsrollen; Datenbestand; Lernkosten",
      "learn": "Du lernst, dieselbe Kundenanforderung mit unterschiedlicher Betriebsverantwortung über drei Cloud-Modelle zu lösen.",
      "try_text": "Du probierst Bereitstellung, Anwendung und erlaubte/verweigerte Zugriffe. In einem zweiten Durchlauf kannst du ein anderes Modell wählen.",
      "deadline": "Vor der nächsten Vertriebsbesprechung; etwa 30 Minuten je erstem Lösungsweg.",
      "constraints": "u11: Operator, u12: Reader, Externe ausgeschlossen, Lern-MFA erforderlich. Nur ausgewählte Modellablage zählt. Zusätzliche Anfrage-Laufzeiten/Lizenzen zusammen höchstens 80 Lern-Euro/Prognosemonat; vorhandene gemeinsame Datenbank bleibt außerhalb dieses Zusatzbudgets. Keine öffentlich offene VM-Administration. Daten bleiben beim Modellwechsel erhalten, werden aber nicht automatisch zum SaaS-Anbieter kopiert.",
      "initial": "Die bestehende Auftragsanwendung bleibt bestehen; für die neue Kundenanfrage-Anforderung ist noch kein Modell bereitgestellt.",
      "hints": [
        "Vergleiche zuerst die Verantwortung für Betriebssystem, Anwendung, Daten und Konten. Welchen Betrieb will die Firma selbst übernehmen?",
        "Im Bereich IaaS/PaaS/SaaS einen Dienst bereitstellen und auswählen. VM: Patches, App und Start; PaaS: App und Start; SaaS: Lizenzen und Mitglieder. Prüfe danach die Anwendung als Benutzer.",
        "VM/App Service: requests:1.0 konfigurieren und starten; bei VM zusätzlich Patches bestätigen. u11 Operator und u12 Reader zuweisen, Dienst auswählen, ANF-001 mit vorgegebenen Texten anlegen und mit aktueller Version auf Erledigt setzen. Die Ticket-Diagnosen einschließlich u12-Schreibverbot, externem Verbot und fehlender MFA frisch prüfen."
      ],
      "explanation": "Alle drei Modelle führen dieselbe Erfassung und Bearbeitung aus. IaaS verlangt zusätzlich Betriebssystempflege, PaaS überlässt diese der Plattform, SaaS liefert die fertige Anwendung samt eigenem Anbieterdatenbestand. Konten, Rollen, Daten und fachliche Anbieterprüfung bleiben Aufgaben der Firma. Firmen-Datenbankausfall betrifft IaaS/PaaS, nicht den SaaS-Datenspeicher. Die vorhandene Büro-Suite ist dafür ungeeignet; hier gibt es einen ausdrücklich fiktiven Anbieter für Kundenanfragen.",
      "solution": [
        {
          "action": "request_deploy",
          "model": "IaaS",
          "reason": "Fiktive Anforderung: Kundenanfragen mit begrenzten Rollen und vertretbarem Betrieb bereitstellen"
        },
        {
          "action": "request_config",
          "model": "IaaS",
          "changes": {
            "app_version": "requests:1.0",
            "patched": true
          }
        },
        {
          "action": "power",
          "id": "requestvm",
          "operation": "start"
        },
        {
          "action": "request_grant",
          "model": "IaaS",
          "user": "u11",
          "role": "Operator"
        },
        {
          "action": "request_grant",
          "model": "IaaS",
          "user": "u12",
          "role": "Reader"
        },
        {
          "action": "request_select",
          "model": "IaaS"
        },
        {
          "action": "request_create",
          "id": "ANF-001",
          "user": "u11",
          "changes": {
            "customer": "Fiktiv: Hafenwerk GmbH",
            "subject": "Rückruf zum Cloud-Arbeitsplatz",
            "status": "Neu"
          }
        },
        {
          "action": "request_update",
          "id": "ANF-001",
          "version": 1,
          "user": "u11",
          "changes": {
            "status": "Erledigt"
          }
        }
      ],
      "alternatives": "IaaS, PaaS und SaaS sind bei erfüllten Kriterien gleichwertig. Zwei vollständige alternative Aktionsfolgen sind geprüft. Nicht benötigte Bereitstellungen bleiben kostenpflichtig, bis sie freigegeben oder abbestellt werden. Anbieter- und Firmenablage bleiben getrennt; kein vorgetäuschter automatischer Datenumzug.",
      "attachment": "Vergleichstabelle mit Firmen-/Anbieteraufgaben und Zusatzkosten im Bereich IaaS/PaaS/SaaS",
      "probes": [
        {
          "test": "request",
          "args": {
            "user": "u11",
            "operation": "request_read"
          },
          "expected": true
        },
        {
          "test": "request",
          "args": {
            "user": "u11",
            "source": "branch",
            "operation": "request_write"
          },
          "expected": true
        },
        {
          "test": "request",
          "args": {
            "user": "u12",
            "operation": "request_read"
          },
          "expected": true
        },
        {
          "test": "request",
          "args": {
            "user": "u12",
            "operation": "request_write"
          },
          "expected": false
        },
        {
          "test": "request",
          "args": {
            "user": "partner",
            "operation": "request_read"
          },
          "expected": false
        },
        {
          "test": "request",
          "args": {
            "user": "partner",
            "operation": "request_write"
          },
          "expected": false
        },
        {
          "test": "request",
          "args": {
            "user": "u11",
            "mfa": false
          },
          "expected": false
        },
        {
          "test": "connection",
          "args": {
            "host": "anfrage.intern",
            "source": "internet",
            "port": 22
          },
          "expected": false
        }
      ],
      "start": [
        {
          "op": "set",
          "path": [
            "resources",
            "storage",
            "public"
          ],
          "value": false
        }
      ],
      "setup": [],
      "criteria": [
        {
          "label": "Aktives Modell enthält die tatsächlich erfasste und bearbeitete Kundenanfrage",
          "expr": {
            "any_of": [
              {
                "all": [
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "active"
                        ]
                      },
                      {
                        "literal": "IaaS"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "customer"
                        ]
                      },
                      {
                        "literal": "Fiktiv: Hafenwerk GmbH"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "subject"
                        ]
                      },
                      {
                        "literal": "Rückruf zum Cloud-Arbeitsplatz"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "status"
                        ]
                      },
                      {
                        "literal": "Erledigt"
                      }
                    ]
                  },
                  {
                    "gte": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "version"
                        ]
                      },
                      {
                        "literal": 2
                      }
                    ]
                  }
                ]
              },
              {
                "all": [
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "active"
                        ]
                      },
                      {
                        "literal": "PaaS"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "customer"
                        ]
                      },
                      {
                        "literal": "Fiktiv: Hafenwerk GmbH"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "subject"
                        ]
                      },
                      {
                        "literal": "Rückruf zum Cloud-Arbeitsplatz"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "status"
                        ]
                      },
                      {
                        "literal": "Erledigt"
                      }
                    ]
                  },
                  {
                    "gte": [
                      {
                        "path": [
                          "requests",
                          "company",
                          "ANF-001",
                          "version"
                        ]
                      },
                      {
                        "literal": 2
                      }
                    ]
                  }
                ]
              },
              {
                "all": [
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "active"
                        ]
                      },
                      {
                        "literal": "SaaS"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "provider",
                          "ANF-001",
                          "customer"
                        ]
                      },
                      {
                        "literal": "Fiktiv: Hafenwerk GmbH"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "provider",
                          "ANF-001",
                          "subject"
                        ]
                      },
                      {
                        "literal": "Rückruf zum Cloud-Arbeitsplatz"
                      }
                    ]
                  },
                  {
                    "eq": [
                      {
                        "path": [
                          "requests",
                          "provider",
                          "ANF-001",
                          "status"
                        ]
                      },
                      {
                        "literal": "Erledigt"
                      }
                    ]
                  },
                  {
                    "gte": [
                      {
                        "path": [
                          "requests",
                          "provider",
                          "ANF-001",
                          "version"
                        ]
                      },
                      {
                        "literal": 2
                      }
                    ]
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Zusatzbudget aller Anfrage-Bereitstellungen höchstens 80 Lern-Euro/Monat",
          "expr": {
            "lte": [
              {
                "request_monthly": true
              },
              {
                "literal": 80
              }
            ]
          }
        },
        {
          "label": "Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte",
          "expr": {
            "eq": [
              {
                "unexpected_admin": {
                  "trusted": [
                    "it"
                  ],
                  "allow": []
                }
              },
              {
                "literal": []
              }
            ]
          }
        },
        {
          "label": "Lokale Dienste bleiben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "services"
                    ]
                  },
                  {
                    "literal": {
                      "AD-01": {
                        "offset": 20,
                        "status": "running",
                        "port": 389,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "FILE-01": {
                        "offset": 21,
                        "status": "running",
                        "port": 445,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "ORDER-01": {
                        "offset": 22,
                        "status": "running",
                        "port": 443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "SQL-01": {
                        "offset": 23,
                        "status": "running",
                        "port": 1433,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      },
                      "BACKUP-01": {
                        "offset": 24,
                        "status": "running",
                        "port": 9443,
                        "configured": true,
                        "allow_cloud": false,
                        "capacity_gb": 100,
                        "used_gb": 12
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Keine unangeforderten lokalen Gruppenrechte",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "groups"
                    ]
                  },
                  {
                    "literal": {
                      "IT": [
                        "it"
                      ],
                      "Vertrieb": [
                        "u11",
                        "u12"
                      ],
                      "Personal": [
                        "u21"
                      ],
                      "Anwendung": [
                        "svc-orders"
                      ],
                      "Auftragsbearbeitung": [
                        "u11"
                      ],
                      "Datenbankanwendung": [
                        "svc-orders"
                      ],
                      "Sicherung": [
                        "svc-backup"
                      ]
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Freigaben unverändert",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "shares"
                    ]
                  },
                  {
                    "literal": {
                      "sales": {
                        "read": [
                          "Vertrieb",
                          "Anwendung",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Vertrieb",
                          "IT"
                        ]
                      },
                      "hr": {
                        "read": [
                          "Personal",
                          "IT",
                          "Sicherung"
                        ],
                        "write": [
                          "Personal",
                          "IT"
                        ]
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Unbeteiligte lokale Dateien und Historien erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "documents"
                    ]
                  },
                  {
                    "literal": {
                      "angebot-lokal": {
                        "name": "Angebot des lokalen Betriebs",
                        "container": "sales",
                        "class": "vertraulich",
                        "content": "Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      },
                      "personal-lokal": {
                        "name": "Lokale Personalübersicht",
                        "container": "hr",
                        "class": "besonders schutzbedürftig",
                        "content": "Ausschließlich fiktive lokale Personaldaten.",
                        "version": 1,
                        "deleted": false,
                        "modified": 0,
                        "versions": []
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Geschäftsvorgänge erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "same_records_except_modified": [
                  {
                    "path": [
                      "onprem",
                      "orders"
                    ]
                  },
                  {
                    "literal": {
                      "LP-1001": {
                        "customer": "Fiktiv: Hafenwerk GmbH",
                        "subject": "Lokaler Wartungsauftrag",
                        "amount": 4800.0,
                        "status": "Neu",
                        "document": "angebot-lokal",
                        "modified": 0,
                        "version": 1
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale DNS-Zuordnungen erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "dns"
                    ]
                  },
                  {
                    "literal": {
                      "ad.lan": "AD-01",
                      "dateien.lan": "FILE-01",
                      "auftrag.lan": "ORDER-01",
                      "sql.lan": "SQL-01",
                      "sicherung.lan": "BACKUP-01"
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokales LAN nicht abschalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "lan"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokale Konten dem Auftrag entsprechend erhalten",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "accounts"
                    ]
                  },
                  {
                    "literal": {
                      "u01": {
                        "active": true
                      },
                      "u02": {
                        "active": true
                      },
                      "u03": {
                        "active": true
                      },
                      "u04": {
                        "active": true
                      },
                      "u05": {
                        "active": true
                      },
                      "u06": {
                        "active": true
                      },
                      "u07": {
                        "active": true
                      },
                      "u08": {
                        "active": true
                      },
                      "u09": {
                        "active": true
                      },
                      "u10": {
                        "active": true
                      },
                      "u11": {
                        "active": true
                      },
                      "u12": {
                        "active": true
                      },
                      "u13": {
                        "active": true
                      },
                      "u14": {
                        "active": true
                      },
                      "u15": {
                        "active": true
                      },
                      "u16": {
                        "active": true
                      },
                      "u17": {
                        "active": true
                      },
                      "u18": {
                        "active": true
                      },
                      "u19": {
                        "active": true
                      },
                      "u20": {
                        "active": true
                      },
                      "u21": {
                        "active": true
                      },
                      "u22": {
                        "active": true
                      },
                      "u23": {
                        "active": true
                      },
                      "u24": {
                        "active": true
                      },
                      "u25": {
                        "active": true
                      },
                      "u26": {
                        "active": true
                      },
                      "u27": {
                        "active": true
                      },
                      "u28": {
                        "active": true
                      },
                      "u29": {
                        "active": true
                      },
                      "u30": {
                        "active": true
                      },
                      "u31": {
                        "active": true
                      },
                      "u32": {
                        "active": true
                      },
                      "u33": {
                        "active": true
                      },
                      "u34": {
                        "active": true
                      },
                      "u35": {
                        "active": true
                      },
                      "u36": {
                        "active": true
                      },
                      "u37": {
                        "active": true
                      },
                      "u38": {
                        "active": true
                      },
                      "u39": {
                        "active": true
                      },
                      "u40": {
                        "active": true
                      },
                      "u41": {
                        "active": true
                      },
                      "u42": {
                        "active": true
                      },
                      "u43": {
                        "active": true
                      },
                      "u44": {
                        "active": true
                      },
                      "u45": {
                        "active": true
                      },
                      "u46": {
                        "active": true
                      },
                      "u47": {
                        "active": true
                      },
                      "u48": {
                        "active": true
                      },
                      "u49": {
                        "active": true
                      },
                      "u50": {
                        "active": true
                      },
                      "u51": {
                        "active": true
                      },
                      "u52": {
                        "active": true
                      },
                      "u53": {
                        "active": true
                      },
                      "u54": {
                        "active": true
                      },
                      "u55": {
                        "active": true
                      },
                      "u56": {
                        "active": true
                      },
                      "u57": {
                        "active": true
                      },
                      "u58": {
                        "active": true
                      },
                      "u59": {
                        "active": true
                      },
                      "u60": {
                        "active": true
                      },
                      "lea": {
                        "active": true
                      },
                      "it": {
                        "active": true
                      },
                      "svc-orders": {
                        "active": true
                      },
                      "svc-backup": {
                        "active": true
                      }
                    }
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: enabled",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "enabled"
                    ]
                  },
                  {
                    "literal": true
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: interval",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "interval"
                    ]
                  },
                  {
                    "literal": 60
                  }
                ]
              }
            ]
          }
        },
        {
          "label": "Lokaler Sicherungsplan erhalten: retention",
          "expr": {
            "any_of": [
              {
                "not": {
                  "path": [
                    "onprem",
                    "enabled"
                  ]
                }
              },
              {
                "eq": [
                  {
                    "path": [
                      "onprem",
                      "backup",
                      "retention"
                    ]
                  },
                  {
                    "literal": 1440
                  }
                ]
              }
            ]
          }
        }
      ],
      "function": "IaaS/PaaS/SaaS → Modell bereitstellen, einrichten, Rollen prüfen, echte Kundenanfrage erfassen/bearbeiten",
      "terms": [
        {
          "term": "IaaS",
          "meaning": "Die Firma betreibt in diesem Lernfall VM-Betriebssystem/Patches und Anfrageanwendung selbst."
        },
        {
          "term": "PaaS",
          "meaning": "Der Anbieter betreibt Plattform und Betriebssystem; die Firma konfiguriert und betreibt ihre Anfrageanwendung."
        },
        {
          "term": "SaaS",
          "meaning": "Fertige externe Anfrageanwendung mit Lizenzen und getrenntem Anbieterbestand. Keine VM-NIC oder Betriebssystemverwaltung durch die Firma."
        },
        {
          "term": "Anwendungsrolle",
          "meaning": "Reader darf Anfragen lesen, Operator auch erstellen/ändern. Ressourcenverwaltung allein gewährt keinen Anwendungszugriff."
        }
      ],
      "variants": [
        {
          "label": "PaaS: App Service",
          "rationale": "Gleiche Geschäftsfunktion und Rechte; keine eigene Betriebssystempflege.",
          "actions": [
            {
              "action": "request_deploy",
              "model": "PaaS",
              "reason": "Fiktive Anforderung: Kundenanfragen mit begrenzten Rollen und vertretbarem Betrieb bereitstellen"
            },
            {
              "action": "request_config",
              "model": "PaaS",
              "changes": {
                "app_version": "requests:1.0"
              }
            },
            {
              "action": "power",
              "id": "requestpaas",
              "operation": "start"
            },
            {
              "action": "request_grant",
              "model": "PaaS",
              "user": "u11",
              "role": "Operator"
            },
            {
              "action": "request_grant",
              "model": "PaaS",
              "user": "u12",
              "role": "Reader"
            },
            {
              "action": "request_select",
              "model": "PaaS"
            },
            {
              "action": "request_create",
              "id": "ANF-001",
              "user": "u11",
              "changes": {
                "customer": "Fiktiv: Hafenwerk GmbH",
                "subject": "Rückruf zum Cloud-Arbeitsplatz",
                "status": "Neu"
              }
            },
            {
              "action": "request_update",
              "id": "ANF-001",
              "version": 1,
              "user": "u11",
              "changes": {
                "status": "Erledigt"
              }
            }
          ]
        },
        {
          "label": "SaaS: externer Anfrageanbieter",
          "rationale": "Gleiche Geschäftsfunktion mit eigener Anbieterablage und zwei Benutzerlizenzen; Firmen-VPN und Firmen-DB sind keine Laufzeitabhängigkeit.",
          "actions": [
            {
              "action": "request_deploy",
              "model": "SaaS",
              "reason": "Fiktive Anforderung: Kundenanfragen mit begrenzten Rollen und vertretbarem Betrieb bereitstellen"
            },
            {
              "action": "request_grant",
              "model": "SaaS",
              "user": "u11",
              "role": "Operator"
            },
            {
              "action": "request_grant",
              "model": "SaaS",
              "user": "u12",
              "role": "Reader"
            },
            {
              "action": "request_select",
              "model": "SaaS"
            },
            {
              "action": "request_create",
              "id": "ANF-001",
              "user": "u11",
              "changes": {
                "customer": "Fiktiv: Hafenwerk GmbH",
                "subject": "Rückruf zum Cloud-Arbeitsplatz",
                "status": "Neu"
              }
            },
            {
              "action": "request_update",
              "id": "ANF-001",
              "version": 1,
              "user": "u11",
              "changes": {
                "status": "Erledigt"
              }
            }
          ]
        }
      ],
      "failures": [
        {
          "label": "Nur das Modell beschriften",
          "rationale": "Eine Textentscheidung erstellt weder Dienst, Rollen noch Kundenanfrage.",
          "actions": [
            {
              "action": "decision",
              "key": "request_model",
              "value": "SaaS"
            }
          ],
          "outcome": "incomplete"
        },
        {
          "label": "SaaS wie eine VM patchen",
          "rationale": "Betriebssystempflege des externen Dienstes ist keine Kundeneinstellung.",
          "actions": [
            {
              "action": "request_deploy",
              "model": "SaaS",
              "reason": "Fiktiver Anfrageauftrag"
            },
            {
              "action": "request_config",
              "model": "SaaS",
              "changes": {
                "patched": true
              }
            }
          ],
          "outcome": "rejected"
        }
      ],
      "clarifications": [
        {
          "id": "rahmen",
          "question": "Welche Frist und Grenzen muss ich bei diesem Auftrag einhalten?",
          "answer": "Vor der nächsten Vertriebsbesprechung; etwa 30 Minuten je erstem Lösungsweg. u11: Operator, u12: Reader, Externe ausgeschlossen, Lern-MFA erforderlich. Nur ausgewählte Modellablage zählt. Zusätzliche Anfrage-Laufzeiten/Lizenzen zusammen höchstens 80 Lern-Euro/Prognosemonat; vorhandene gemeinsame Datenbank bleibt außerhalb dieses Zusatzbudgets. Keine öffentlich offene VM-Administration. Daten bleiben beim Modellwechsel erhalten, werden aber nicht automatisch zum SaaS-Anbieter kopiert."
        },
        {
          "id": "bedarf",
          "question": "Welchen konkreten Bedarf soll meine Arbeit für Sie erfüllen?",
          "answer": "Zwei Beschäftigte brauchen eine Kundenanfrage-Anwendung. u11 erfasst und bearbeitet Anfragen; u12 liest ausschließlich. Externe dürfen keine Anfragen sehen. Stelle denselben Dienst wahlweise über eine VM (IaaS), App Service (PaaS) oder einen externen SaaS-Anbieter bereit. Erfasse ANF-001 für Fiktiv: Hafenwerk GmbH mit Betreff Rückruf zum Cloud-Arbeitsplatz und bearbeite sie bis Erledigt."
        },
        {
          "id": "rueckmeldung",
          "question": "Welche Rückmeldung erwarten Sie zum Abschluss?",
          "answer": "Bitte nennen Sie Ursache, Änderungen und tatsächlich erlaubte und verweigerte Tests. Die bestehende Auftragsanwendung bleibt bestehen; für die neue Kundenanfrage-Anforderung ist noch kein Modell bereitgestellt. Ihre Begründung besprechen wir mit der Lehrkraft; Freitext wird nicht automatisch verstanden."
        }
      ]
    }
  ]
}
''')
DEFAULT_COURSE_DATA['tasks'].append(json.loads(r'''{"id":"verfuegbarkeit","title":"Eine Lernzone fällt aus – der Auftrag muss weiterlaufen","sender":"IT-Leitung · Betriebsübung","message":"Im Wartungsfenster ist Lernzone1 in germanywestcentral ausgefallen. Der bestehende Web-Auftragsdienst, seine Datenbank und die Angebotsablage müssen am Standort weiter funktionieren. Belasse alle drei in dieser Region und die bestehende Weblaufzeit im Einsatz. Halte höchstens600 Lern-Euro Monatsprognose ein, öffne keine zusätzlichen externen Zugriffe und erstelle eine erfolgreiche Sicherung. Eine allein verteilte Weboberfläche genügt nicht.","minutes":35,"prerequisite":"Ressourcen konfigurieren, Netzpfad und Benutzerzugriff prüfen; Grundlagen zu Backup und Lernkosten.","learning":"Cloud-Architektur; Verfügbarkeit; Storage-Redundanz; Abhängigkeiten; Kosten","learn":"Du lernst, warum mehrere verteilte Instanzen und eine verfügbare Datenablage gemeinsam benötigt werden.","try_text":"Du probierst verbleibende Kapazität während eines gezielten Lernzonenausfalls aus und prüfst erlaubte sowie verweigerte Zugriffe.","deadline":"Während des kontrollierten Wartungsausfalls; keine echte Azure-SLA.","constraints":"web, db und storage bleiben in germanywestcentral; Auftrags-DNS bleibt web. Budget höchstens600 Lern-Euro/Monat. Zone1 bleibt zur Abnahme ausgefallen. Kein zusätzlicher öffentlicher Zugriff und keine Rechteerweiterung. Andere Geschäftsdaten, lokale Dienste und nicht betroffene Ressourcen bleiben unverändert; keine Rollenänderungen.","initial":"Vorbereitete Firma; der Trainer hat den Ausfall der Lernzone1 gesetzt. Einzelstandorte und die primäre LRS-Ablage sind betroffen.","hints":["Prüfe zuerst, welche Instanz und welche Datenabhängigkeit vom Ausfall betroffen ist. Ein erfolgreicher VPN-Schalter genügt nicht.","Verteile mehrere Instanzen von web und db über die Lernzonen. Prüfe anschließend die tatsächliche Angebotsablage; GRS ist hier keine automatische Umschaltung.","Zum Beispiel web und db jeweils B2 mit zwei verteilten Instanzen, storage mit ZRS und privater Blob-Freigabe. Erstelle einen Sicherungspunkt und prüfe u11 erlaubt, Partner und Internet-Administration verweigert. Die Auswahl einer Zone allein erzeugt keine zweite VM."],"explanation":"Verteilte Instanzen behalten nach Zonenausfall nur ihre verbleibende Kapazität. Auch Datenbank und Dokumentablage sind Abhängigkeiten. ZRS hält im begrenzten Modell die Ablage verfügbar; es ersetzt keine frühere Sicherung und keine Benutzerrechte. Eine einzelne Instanz kann nicht über mehrere Zonen gleichzeitig überleben.","solution":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"db","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"storage","changes":{"redundancy":"ZRS","public":false}},{"action":"backup_run"}],"alternatives":"Zwei B2-Instanzen oder drei kleinere B1-Instanzen pro Laufzeit sind mögliche Lösungswege, sofern Restkapazität, Zugriffe, Region und Budget passen.","attachment":"Firmeninventar und Diagnoseprotokoll im Portal","probes":[{"test":"application","args":{"user":"u11","source":"hq"},"expected":true},{"test":"application","args":{"user":"partner","source":"hq"},"expected":false},{"test":"connection","args":{"source":"internet","host":"web","port":22},"expected":false}],"start":[],"setup":[{"action":"availability_event","region":"germanywestcentral","zone":1,"enabled":true}],"criteria":[{"label":"Vorgegebener Zonenausfall und bestehende Region/Laufzeit bleiben erhalten","expr":{"all":[{"eq":[{"path":["availability_event","enabled"]},{"literal":true}]},{"eq":[{"path":["availability_event","region"]},{"literal":"germanywestcentral"}]},{"eq":[{"path":["availability_event","zone"]},{"literal":1}]},{"eq":[{"path":["network","dns","auftrag.intern"]},{"literal":"web"}]},{"eq":[{"path":["resources","web","region"]},{"literal":"germanywestcentral"}]},{"eq":[{"path":["resources","db","region"]},{"literal":"germanywestcentral"}]},{"eq":[{"path":["resources","storage","region"]},{"literal":"germanywestcentral"}]}]}},{"label":"Monatsprognose bleibt höchstens600 Lern-Euro","expr":{"lte":[{"monthly":true},{"literal":600}]}},{"label":"Während der Übung erfolgreicher Sicherungslauf protokolliert","expr":{"some":{"in":{"path":["backup","jobs"]},"as":"job","where":{"eq":[{"var":["job","status"]},{"literal":"success"}]}}}},{"label":"Keine zusätzlichen pauschalen oder auftragsfremden Verwaltungsrechte","expr":{"eq":[{"unexpected_admin":{"trusted":["it"],"allow":[]}},{"literal":[]}]}},{"label":"Geschäftsdaten, lokale Umgebung, Rechte und übrige Ressourcen bleiben erhalten","expr":{"all":[{"eq":[{"path":["documents"]},{"literal":{"offer":{"name":"Angebot-A.txt","container":"sales","class":"vertraulich","content":"Angebot A: 120 Lern-Euro; Version 1.","version":1,"deleted":false,"modified":0,"versions":[]},"payroll":{"name":"Personal-B.txt","container":"hr","class":"besonders schutzbedürftig","content":"Fiktive Personalnotiz B; keine echten Personendaten.","version":1,"deleted":false,"modified":0,"versions":[]},"public":{"name":"Firmeninfo.txt","container":"public","class":"öffentlich","content":"Nordlicht: 60 fiktive Beschäftigte.","version":1,"deleted":false,"modified":0,"versions":[]}}}]},{"eq":[{"path":["orders"]},{"literal":{"NL-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Arbeitsplatz-Erweiterung","amount":120.0,"status":"Neu","document":"offer","modified":0,"version":1},"NL-1002":{"customer":"Fiktiv: Beispielhandel KG","subject":"Standortanbindung planen","amount":240.0,"status":"In Bearbeitung","document":"offer","modified":0,"version":1}}}]},{"eq":[{"path":["document_storage"]},{"literal":{"offer":{"kind":"Blob","host":"storage"},"payroll":{"kind":"Blob","host":"storage"},"public":{"kind":"Blob","host":"storage"}}}]},{"eq":[{"path":["data_governance"]},{"literal":{"offer":{"owner":"Vertrieb","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"offer","status":"active"},"payroll":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"payroll","status":"active"},"public":{"owner":"IT","purpose":"Bestandsdaten; Zweck und Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"public","status":"active"}}}]},{"eq":[{"path":["roles"]},{"literal":[{"principal":"IT","role":"Contributor","scope":"subscription"},{"principal":"IT","role":"User Access Administrator","scope":"subscription"},{"principal":"Vertrieb","role":"Blob Contributor","scope":"sales"},{"principal":"Altprojekt","role":"Blob Reader","scope":"sales"},{"principal":"partner","role":"Blob Contributor","scope":"storage"},{"principal":"lea","role":"Reader","scope":"storage"},{"principal":"Vertrieb","role":"Order Operator","scope":"orders"},{"principal":"orders-app","role":"Order Operator","scope":"orders"},{"principal":"orders-app","role":"Blob Reader","scope":"sales"}]}]},{"eq":[{"path":["resources","testvm"]},{"literal":{"name":"vm-altprojekt","kind":"VM","group":"rg-lab","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"D4","status":"stopped","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.11","port":443,"image":"orders:1.0","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","paas"]},{"literal":{"name":"app-auftrag","kind":"App Service","group":"rg-app","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"stopped","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.40","port":443,"image":"orders:1.0","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","container"]},{"literal":{"name":"ca-versand","kind":"Container Apps","group":"rg-app","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":64,"ip":"10.20.1.50","port":8080,"image":"shipping:broken","instances":1,"subnet":"app","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["resources","saas"]},{"literal":{"name":"Büro-Suite (externer Anbieter)","kind":"SaaS","group":"rg-lab","region":"germanywestcentral","department":"IT","owner":"IT-Leitung","availability":"single","size":"B2","status":"running","public":false,"locked":false,"disk_gb":0,"ip":"","port":443,"image":"orders:1.0","instances":1,"subnet":"","public_ip":"","configured":true,"tier":"hot","redundancy":"LRS","capacity_gb":100,"used_gb":12,"os":"Linux"}}]},{"eq":[{"path":["onprem","enabled"]},{"literal":true}]},{"eq":[{"path":["onprem","lan"]},{"literal":true}]},{"eq":[{"path":["onprem","services"]},{"literal":{"AD-01":{"offset":20,"status":"running","port":389,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"FILE-01":{"offset":21,"status":"running","port":445,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"ORDER-01":{"offset":22,"status":"running","port":443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"SQL-01":{"offset":23,"status":"running","port":1433,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12},"BACKUP-01":{"offset":24,"status":"running","port":9443,"configured":true,"allow_cloud":false,"capacity_gb":100,"used_gb":12}}}]},{"eq":[{"path":["onprem","accounts"]},{"literal":{"u01":{"active":true},"u02":{"active":true},"u03":{"active":true},"u04":{"active":true},"u05":{"active":true},"u06":{"active":true},"u07":{"active":true},"u08":{"active":true},"u09":{"active":true},"u10":{"active":true},"u11":{"active":true},"u12":{"active":true},"u13":{"active":true},"u14":{"active":true},"u15":{"active":true},"u16":{"active":true},"u17":{"active":true},"u18":{"active":true},"u19":{"active":true},"u20":{"active":true},"u21":{"active":true},"u22":{"active":true},"u23":{"active":true},"u24":{"active":true},"u25":{"active":true},"u26":{"active":true},"u27":{"active":true},"u28":{"active":true},"u29":{"active":true},"u30":{"active":true},"u31":{"active":true},"u32":{"active":true},"u33":{"active":true},"u34":{"active":true},"u35":{"active":true},"u36":{"active":true},"u37":{"active":true},"u38":{"active":true},"u39":{"active":true},"u40":{"active":true},"u41":{"active":true},"u42":{"active":true},"u43":{"active":true},"u44":{"active":true},"u45":{"active":true},"u46":{"active":true},"u47":{"active":true},"u48":{"active":true},"u49":{"active":true},"u50":{"active":true},"u51":{"active":true},"u52":{"active":true},"u53":{"active":true},"u54":{"active":true},"u55":{"active":true},"u56":{"active":true},"u57":{"active":true},"u58":{"active":true},"u59":{"active":true},"u60":{"active":true},"lea":{"active":true},"it":{"active":true},"svc-orders":{"active":true},"svc-backup":{"active":true}}}]},{"eq":[{"path":["onprem","groups"]},{"literal":{"IT":["it"],"Vertrieb":["u11","u12"],"Personal":["u21"],"Anwendung":["svc-orders"],"Auftragsbearbeitung":["u11"],"Datenbankanwendung":["svc-orders"],"Sicherung":["svc-backup"]}}]},{"eq":[{"path":["onprem","shares"]},{"literal":{"sales":{"read":["Vertrieb","Anwendung","IT","Sicherung"],"write":["Vertrieb","IT"]},"hr":{"read":["Personal","IT","Sicherung"],"write":["Personal","IT"]}}}]},{"eq":[{"path":["onprem","documents"]},{"literal":{"angebot-lokal":{"name":"Angebot des lokalen Betriebs","container":"sales","class":"vertraulich","content":"Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.","version":1,"deleted":false,"modified":0,"versions":[]},"personal-lokal":{"name":"Lokale Personalübersicht","container":"hr","class":"besonders schutzbedürftig","content":"Ausschließlich fiktive lokale Personaldaten.","version":1,"deleted":false,"modified":0,"versions":[]}}}]},{"eq":[{"path":["onprem","orders"]},{"literal":{"LP-1001":{"customer":"Fiktiv: Hafenwerk GmbH","subject":"Lokaler Wartungsauftrag","amount":4800.0,"status":"Neu","document":"angebot-lokal","modified":0,"version":1}}}]},{"eq":[{"path":["onprem","dns"]},{"literal":{"ad.lan":"AD-01","dateien.lan":"FILE-01","auftrag.lan":"ORDER-01","sql.lan":"SQL-01","sicherung.lan":"BACKUP-01"}}]},{"eq":[{"path":["onprem","data_governance"]},{"literal":{"angebot-lokal":{"owner":"Vertrieb","purpose":"Lokale Bestandsdaten; fachliche Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"angebot-lokal","status":"active"},"personal-lokal":{"owner":"IT","purpose":"Lokale Bestandsdaten; fachliche Frist prüfen","retention_until":0,"hold":false,"reason":"Noch keine fachliche Frist festgelegt","origin":"personal-lokal","status":"active"}}}]}]}}],"function":"Trainerbereich: Lernzonenausfall; Alle Ressourcen: Verteilung/Instanzen; Storage Accounts: ZRS; Auftragsanwendung/Virtual Network: Tests; Backup Center: Sicherung; Cost Management: Monatsprognose.","terms":[{"term":"Verfügbarkeitszone","meaning":"Getrennter Ausfallbereich innerhalb einer Region. Hier drei logische Lernzonen; keine echte Standort- oder SKU-Zusage."},{"term":"Replikat","meaning":"Zusätzliche Laufzeitinstanz. Im Lernmodell werden verteilte Instanzen abwechselnd Zone1,2,3 zugeordnet; ein Ressourceneintrag fasst das logische Deployment zusammen."},{"term":"ZRS","meaning":"Zonenredundanter Speicher. Das Modell hält seinen logischen Datenbestand bei einem einzelnen Lernzonenausfall verfügbar; Löschen und Überschreiben werden dadurch nicht rückgängig."},{"term":"GRS","meaning":"Georedundante Kopie. Dieses Lernprofil führt keine automatische Regionsumschaltung oder asynchrone Kopierhistorie aus."}],"variants":[{"label":"Drei kleinere Instanzen je Laufzeit","rationale":"Zwei B1-Instanzen verbleiben nach dem Verlust einer Zone und reichen für die vorgegebene Last.","actions":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":3,"size":"B1"}},{"action":"configure","id":"db","changes":{"availability":"zones","instances":3,"size":"B1"}},{"action":"configure","id":"storage","changes":{"redundancy":"ZRS","public":false}},{"action":"backup_run"}]}],"failures":[{"label":"Nur die Weboberfläche verteilt","rationale":"Datenbank und Dokumentablage bleiben ausgefallen.","outcome":"incomplete","actions":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":2,"size":"B2"}}]},{"label":"Eine Instanz mit Zonen-Häkchen","rationale":"Eine einzelne Instanz in Zone1 bleibt vom Ausfall betroffen.","outcome":"incomplete","actions":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":1}},{"action":"configure","id":"db","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"storage","changes":{"redundancy":"ZRS","public":false}}]},{"label":"GRS ist keine automatische Zonen-Umschaltung","rationale":"Das primäre Modellzentrum bleibt ausgefallen; eine teurere Geokopie ist keine automatische Umschaltung.","outcome":"incomplete","actions":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"db","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"storage","changes":{"redundancy":"GRS"}}]},{"label":"Ausfall zum Prüfen einfach ausgeschaltet","rationale":"Das vorgegebene Wartungsereignis muss bei der Abnahme noch aktiv sein.","outcome":"incomplete","actions":[{"action":"configure","id":"web","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"db","changes":{"availability":"zones","instances":2,"size":"B2"}},{"action":"configure","id":"storage","changes":{"redundancy":"ZRS","public":false}},{"action":"availability_event","region":"germanywestcentral","zone":1,"enabled":false},{"action":"backup_run"}]}],"clarifications":[{"id":"zone","question":"Ist ein Häkchen Zonen bei einer einzigen Instanz ausreichend?","answer":"Nein. Eine einzelne Instanz liegt in genau einem Ausfallbereich. Prüfe tatsächliche verbleibende Instanzen und alle Datenabhängigkeiten."}]}'''))

# The standard management/data lesson now requires explicit evidence on both planes.
for _task in DEFAULT_COURSE_DATA['tasks']:
    if _task['id']=='09':
        _task['message']+=' Prüfe Ressourcen ansehen, Storage verwalten und die verweigerte Rollenvergabe separat vom Dateizugriff.'
        _task['hints'][1]+=' Nutze im Identitätsbereich Verwaltungsrechte getrennt testen für storage: Ansehen und Verwalten sollen erlaubt, Rollen zuweisen soll verweigert sein.'
        _task['explanation']+=' Die Verwaltungsdiagnose verwendet Anmeldung und wirksame Rollen im gewählten Geltungsbereich. Ein unterbrochener Datei-VPN-Pfad entfernt kein Rollenvergabe- oder Verwaltungsrecht. Umgekehrt öffnet ein Verwaltungsrecht keine Datei.'
        _task['probes'] += [dict(test='management',args=dict(user='lea',target='storage',operation=operation),expected=expected) for operation,expected in [('read',True),('manage',True),('assign',False)]]

GUARDS=copy.deepcopy(DEFAULT_COURSE_DATA['guards'])
CATALOG=validate_course_data(DEFAULT_COURSE_DATA)
