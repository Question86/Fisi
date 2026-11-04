"""Deterministic teaching model. No cloud APIs, wall-clock simulation or random metrics."""
import copy
import hashlib
import ipaddress
import json
import math

VERSION = 17
BASE_TARIFFS = {'format':'nordlicht-tariffs/v1','label':'Nordlicht-Lernpreise 1','currency':'EUR','month_hours':730,
    'sizes':{'B1':{'cpu':1,'ram':2,'compute_hour':.04},'B2':{'cpu':2,'ram':4,'compute_hour':.08},'D4':{'cpu':4,'ram':16,'compute_hour':.20}},
    'vm_disk_gb_hour':.0001,'storage_gb_hour':{'hot':.00008,'cool':.00004},
    'redundancy_multiplier':{'LRS':1.0,'ZRS':1.5,'GRS':2.0},'saas_hour':.015,'traffic_load_hour':.00001}
ACTIVE_TARIFFS = copy.deepcopy(BASE_TARIFFS)

ROLES = {'Reader': {'read'}, 'Contributor': {'read', 'manage'},
         'User Access Administrator': {'read', 'assign'},
         'File Reader': {'data_read'}, 'File Contributor': {'data_read','data_write'},
         'Disk Reader': {'data_read'}, 'Disk Contributor': {'data_read','data_write'},
         'Blob Reader': {'data_read'}, 'Blob Contributor': {'data_read', 'data_write'},
         'Request Operator': {'request_read','request_write'},
         'Order Reader': {'orders_read'}, 'Order Operator': {'orders_read', 'orders_write'}}
STORAGE_TYPES={'Blob':'Storage','Files':'File Share','Disk':'VM'}
STORAGE_DATA_ROLES={kind:{prefix+' Reader',prefix+' Contributor'} for kind,prefix in [('Blob','Blob'),('Files','File'),('Disk','Disk')]}
RESOURCE_FIELDS = {'name', 'region', 'department', 'owner', 'availability', 'size', 'status',
                   'public', 'locked', 'disk_gb', 'ip', 'port', 'image', 'instances', 'configured',
                   'tier', 'redundancy', 'capacity_gb', 'used_gb', 'kind', 'group', 'os', 'subnet', 'public_ip'}


class Invalid(ValueError):
    pass



def validate_tariffs(data):
    if type(data) is not dict or set(data)!=set(BASE_TARIFFS) or data['format']!='nordlicht-tariffs/v1' or data['currency']!='EUR':raise Invalid('Unbekanntes Tarifformat oder Tarif-Felder.')
    if type(data['label']) is not str or not data['label'].strip() or len(data['label'])>120:raise Invalid('Tarifbezeichnung erforderlich (max. 120 Zeichen).')
    number(data['month_hours'],1,1000,True)
    sizes=data['sizes']
    if type(sizes) is not dict or not {'B1','B2','D4'}<=set(sizes) or not 3<=len(sizes)<=20:raise Invalid('Tarife benötigen B1, B2, D4 und höchstens 20 Größen.')
    for key,row in sizes.items():
        if type(key) is not str or not key or len(key)>20 or not key.replace('-','').isalnum() or type(row) is not dict or set(row)!={'cpu','ram','compute_hour'}:raise Invalid('Ungültige Größen-/Tariffelder.')
        number(row['cpu'],1,128,True);number(row['ram'],1,1024,True);number(row['compute_hour'],0,1000)
    for field,keys in [('storage_gb_hour',{'hot','cool'}),('redundancy_multiplier',{'LRS','GRS'})]:
        if type(data[field]) is not dict or (set(data[field])!=keys and not (field=='redundancy_multiplier' and set(data[field])==keys|{'ZRS'})):raise Invalid('Tarifstufen unvollständig: '+field)
        for rate in data[field].values():number(rate,0,1000)
    for field in ('vm_disk_gb_hour','saas_hour','traffic_load_hour'):number(data[field],0,1000)
    return copy.deepcopy(data)


def monthly(s):return sum(row['total'] for row in hourly(s))*s['tariffs']['month_hours']


def tariff_description(s):
    t=s['tariffs'];sizes='; '.join(f"{key}: {row['cpu']} CPU/{row['ram']} GB RAM, {row['compute_hour']:g} EUR/h" for key,row in t['sizes'].items())
    return f"Fiktive Lernpreise · {t['label']} · {sizes}; VM-Disk {t['vm_disk_gb_hour']:g} EUR/GB·h; Storage Hot/Cool {t['storage_gb_hour']['hot']:g}/{t['storage_gb_hour']['cool']:g} EUR/GB·h; Redundanz {', '.join(key+' ×'+format(value,'g') for key,value in t['redundancy_multiplier'].items())}; Büro-SaaS {t['saas_hour']:g} EUR/h; Anfrage-SaaS {t['saas_hour']:g} EUR/Lizenz·h; Traffic {t['traffic_load_hour']:g} EUR/Lastpunkt·h; Prognosemonat {t['month_hours']} h."

def resource(name, kind, group, **kw):
    r = dict(name=name, kind=kind, group=group, region='germanywestcentral', department='IT',
             owner='IT-Leitung', availability='single', size='B2', status='running', public=False,
             locked=False, disk_gb=64, ip='10.20.1.10', port=443, image='orders:1.0', instances=1,
             subnet='' if kind=='SaaS' else 'app', public_ip='', configured=True, tier='hot', redundancy='LRS', capacity_gb=100, used_gb=12, os='Linux')
    if kind=='File Share':r.update(port=445,disk_gb=0)
    r.update(kw)
    return r


def require_resource_policy(s,r):
    """Check a proposed resource only; do not rewrite older noncompliant snapshots."""
    tags=all(type(r[key]) is str and bool(r[key].strip()) for key in ('owner','department'))
    if type(r['region']) is not str or r['region'] not in s['policy']['regions'] or (s['policy']['require_tags'] and not tags) or (s['policy']['deny_public'] and (r['public'] or r['public_ip'])):
        raise Invalid('Azure-Policy-Lernregel verweigert Region, Tags oder öffentlichen Zugang.')


REQUEST_MODELS={
 'IaaS':dict(resource='requestvm',kind='VM',company='Betriebssystem/Patches, Anwendung, Datenbankzugriff, Daten, Konten und Freigaben',provider='Hardware und Virtualisierung'),
 'PaaS':dict(resource='requestpaas',kind='App Service',company='Anwendung, Konfiguration, Datenbankzugriff, Daten, Konten und Freigaben',provider='Hardware, Betriebssystem/Patches und Plattform'),
 'SaaS':dict(resource='requestsaas',kind='SaaS',company='Fachliche Eignung, Lizenzen, Konten, Rollen, Daten und Anbieterprüfung',provider='Fertige Anwendung, Betriebssystem, Plattform und Infrastruktur')}


def data_record(owner='IT', purpose='Bestandsdaten; Zweck und Frist prüfen', origin=''):
    return dict(owner=owner,purpose=purpose,retention_until=0,hold=False,reason='Noch keine fachliche Frist festgelegt',origin=origin,status='active')


LOCAL_ACTION_FIELDS={
 'local_initialize':(set(),{'actor'}),'local_service':({'id','changes'},{'actor'}),'local_account':({'id','changes'},{'actor'}),
 'local_membership':({'group','member','add'},{'actor'}),'local_network':({'changes'},{'actor'}),'local_acl':({'share','changes'},{'actor'}),
 'local_open':(set(),{'user','source'}),'local_read':({'id'},{'user','source'}),'local_write':({'id','content'},{'user','source'}),'local_delete':({'id'},{'user','source'}),
 'local_order_create':({'id','changes'},{'user','source'}),'local_order_update':({'id','version','changes'},{'user','source'}),
 'local_backup_run':(set(),{'actor'}),'local_backup_config':({'changes'},{'actor'}),'local_restore':({'point','scope'},{'id','target','actor','outage_minute','rpo_limit','rto_limit'})}

def local_seed(users, enabled=True, minute=0):
    accounts={key:dict(active=True) for key,u in users.items() if type(u) is dict and not u.get('guest',True)}
    accounts.update({'svc-orders':dict(active=True),'svc-backup':dict(active=True)})
    groups={'IT':['it'] if 'it' in accounts else [],'Vertrieb':[u for u in ('u11','u12') if u in accounts],'Personal':['u21'] if 'u21' in accounts else [],'Anwendung':['svc-orders'],'Auftragsbearbeitung':['u11'] if 'u11' in accounts else [],'Datenbankanwendung':['svc-orders'],'Sicherung':['svc-backup']}
    documents={
        'angebot-lokal':dict(name='Angebot des lokalen Betriebs',container='sales',**{'class':'vertraulich'},content='Fiktives lokales Angebot LP-1001: Hafenwerk GmbH, 4800 EUR.',version=1,deleted=False,modified=minute,versions=[]),
        'personal-lokal':dict(name='Lokale Personalübersicht',container='hr',**{'class':'besonders schutzbedürftig'},content='Ausschließlich fiktive lokale Personaldaten.',version=1,deleted=False,modified=minute,versions=[])}
    orders={'LP-1001':dict(customer='Fiktiv: Hafenwerk GmbH',subject='Lokaler Wartungsauftrag',amount=4800.0,status='Neu',document='angebot-lokal',modified=minute,version=1)}
    services={key:dict(offset=20+i,status='running',port=port,configured=True,allow_cloud=False,capacity_gb=100,used_gb=12) for i,(key,port) in enumerate([('AD-01',389),('FILE-01',445),('ORDER-01',443),('SQL-01',1433),('BACKUP-01',9443)])}
    return dict(data_governance={key:local_rule(None,key) for key in documents} if enabled else {},lineage_pending=[],enabled=enabled,lan=True,services=services if enabled else {},accounts=accounts if enabled else {},groups=groups if enabled else {},shares={'sales':dict(read=['Vertrieb','Anwendung','IT','Sicherung'],write=['Vertrieb','IT']),'hr':dict(read=['Personal','IT','Sicherung'],write=['Personal','IT'])} if enabled else {},dns={'ad.lan':'AD-01','dateien.lan':'FILE-01','auftrag.lan':'ORDER-01','sql.lan':'SQL-01','sicherung.lan':'BACKUP-01'} if enabled else {},documents=documents if enabled else {},orders=orders if enabled else {},backup=dict(enabled=True,interval=60,retention=1440,last=minute,points=[dict(id='local-initial-'+str(minute),minute=minute,documents=copy.deepcopy(documents),orders=copy.deepcopy(orders))] if enabled else [],jobs=[],restore=None))


def local_connection(s, source='hq', host='auftrag.lan', port=443, protocol='TCP'):
    if type(source) is not str or type(host) is not str or type(port) is not int or not 1<=port<=65535 or protocol!='TCP':raise Invalid('Lokale Verbindungsparameter ungültig.')
    p=s['onprem'];path=[]
    if s['local_migration']['active'] and host=='auftrag.lan':
        source={'home':str(ipaddress.ip_network(s['network']['onprem']).network_address+12)}.get(source,source)
        return connection(s,source,s['local_migration']['target'],port,protocol)
    def result(allowed,reason):return dict(allowed=allowed,path=path+[reason],first_error=None if allowed else reason)
    if not p['enabled']:return result(False,'Lokale Infrastruktur ist für diesen alten Stand noch nicht eingerichtet.')
    net=ipaddress.ip_network(s['network']['onprem']);cloud=ipaddress.ip_network(s['network']['vnet']);target=p['dns'].get(host,host)
    target=next((key for key,v in p['services'].items() if str(net.network_address+v['offset'])==target),target)
    if target not in p['services']:return result(False,'DNS: lokaler Dienst nicht auflösbar.')
    r=p['services'][target];path.append('DNS: '+host+' → '+str(net.network_address+r['offset'])+' ('+target+')')
    address={'hq':str(net.network_address+10),'branch':str(net.network_address+11),'home':str(net.network_address+12),'cloud':str(cloud.network_address+10),'internet':'203.0.113.10'}.get(source,source)
    if source in p['services']:address=str(net.network_address+p['services'][source]['offset'])
    elif source in s['resources']:address=s['resources'][source]['ip']
    try:origin=ipaddress.IPv4Address(address)
    except (ValueError,TypeError):raise Invalid('Lokale Quelle benötigt Standort, Dienst oder IPv4-Adresse.')
    if not p['lan']:return result(False,'Route: lokales LAN unterbrochen.')
    if origin in net:path.append('Route: lokales Firmennetz; kein Cloud-VPN erforderlich.')
    elif origin in cloud:
        if not s['network']['vpn']:return result(False,'Route: Cloud-zu-LAN-VPN unterbrochen.')
        allowed,reason=nsg(s,str(origin),str(net.network_address+r['offset']),port,'Outbound',protocol,destination_ip=str(net.network_address+r['offset']))
        path.append(reason)
        if not allowed:return result(False,'NSG Outbound blockiert den lokalen Dienst.')
        if not r['allow_cloud']:return result(False,'Lokale Dienstfreigabe: Cloud-Quellen nicht erlaubt.')
        path.append('Route: VNet → VPN → lokales LAN; Dienstfreigabe erlaubt.')
    else:return result(False,'Route: kein öffentlicher lokaler Dienst.')
    if r['status']!='running' or not r['configured'] or port!=r['port'] or protocol!='TCP':return result(False,'Dienst: gestoppt, falscher Port oder fehlende lokale Konfiguration.')
    return result(True,'Lokaler TCP-Dienst erreichbar.')


def local_login(s,user,source='hq'):
    if type(user) is not str:raise Invalid('Lokaler Benutzer benötigt eine Kennung.')
    p=s['onprem'];net=local_connection(s,source,'ad.lan',389)
    if not net['allowed'] or p['dns'].get('ad.lan')!='AD-01':return False,'Lokale AD-Anmeldung verweigert: AD-01 oder sein Netzpfad fehlt.'
    if user not in p['accounts'] or not p['accounts'][user]['active']:return False,'Lokale AD-Anmeldung verweigert: Konto fehlt oder ist deaktiviert.'
    return True,'Lokale AD-Lernanmeldung erlaubt; kein automatischer Entra-Abgleich und kein echter Kerberos-/MFA-Vorgang.'


def local_access(s,user='u11',document='angebot-lokal',operation='data_read',source='hq'):
    if type(document) is not str or operation not in ('data_read','data_write'):raise Invalid('Lokales Dokument/Zugriffsart ungültig.')
    p=s['onprem'];net=local_connection(s,source,'dateien.lan',445);signed,why=local_login(s,user,source);groups=[key for key,members in p['groups'].items() if user in members];rights=set();grants=[]
    if document in p['documents']:
        d=p['documents'][document];acl=p['shares'].get(d['container'],{})
        for name,right in [('read','data_read'),('write','data_write')]:
            for group in groups:
                if group in acl.get(name,[]):rights.add(right);grants.append(dict(principal=group,role='Lokales '+name,scope=d['container']))
    allowed=net['allowed'] and p['dns'].get('dateien.lan')=='FILE-01' and signed and operation in rights and document in p['documents'] and not p['documents'][document]['deleted']
    if operation=='data_write' and p['services'].get('FILE-01',{}).get('used_gb',0)>=p['services'].get('FILE-01',{}).get('capacity_gb',0):allowed=False
    return dict(allowed=bool(allowed),network=net,authentication=why,rights=sorted(rights),grants=grants,reason='Lokaler Dateizugriff erlaubt.' if allowed else 'Lokaler Dateizugriff verweigert: Netz, AD, Freigabe, Dateistatus oder Schreibkapazität prüfen.')


def local_application_access(s,user='u11',source='hq',operation='orders_read'):
    if s['local_migration']['active']:return local_cloud_access(s,user,source,operation)
    p=s['onprem'];net=local_connection(s,source,'auftrag.lan',443);signed,why=local_login(s,user,source);groups=[key for key,members in p['groups'].items() if user in members];rights=[]
    if any(g in groups for g in ('Vertrieb','IT')):rights.append('orders_read')
    if any(g in groups for g in ('Auftragsbearbeitung','IT')):rights.append('orders_write')
    database=local_connection(s,'ORDER-01','sql.lan',1433) if p['enabled'] else dict(allowed=False)
    service,_=local_login(s,'svc-orders','ORDER-01') if p['enabled'] else (False,'')
    backend=service and 'svc-orders' in p['groups'].get('Datenbankanwendung',[]) and database['allowed'] and p['dns'].get('sql.lan')=='SQL-01'
    allowed=net['allowed'] and p['dns'].get('auftrag.lan')=='ORDER-01' and signed and operation in rights and backend
    for row in p['orders'].values():
        if p['data_governance'][row['document']]['status']=='purged':continue
        if not local_access(s,'svc-orders',row['document'],source='ORDER-01')['allowed']:allowed=False
    return dict(allowed=bool(allowed),network=net,authentication=why,rights=rights,grants=[dict(principal=g,role='Lokale Anwendung',scope='ORDER-01') for g in groups if g in ('Vertrieb','IT','Auftragsbearbeitung')],reason='Lokale Auftragsanwendung erlaubt.' if allowed else 'Lokale Anwendung verweigert: ORDER/AD, Anwendungsgruppe, SQL-/Dienstidentität oder FILE-Anhang prüfen.')


def local_backup_problem(s, restore_scope=None):
    p=s['onprem']
    if not local_connection(s,'BACKUP-01','BACKUP-01',9443)['allowed']:return 'BACKUP-01 oder lokales LAN nicht verfügbar.'
    if not local_login(s,'svc-backup','BACKUP-01')[0] or 'svc-backup' not in p['groups'].get('Sicherung',[]):return 'Lokales Sicherungskonto oder AD-Freigabe fehlt.'
    if not local_connection(s,'BACKUP-01','FILE-01',445)['allowed'] or (restore_scope!='file' and not local_connection(s,'BACKUP-01','SQL-01',1433)['allowed']):return 'Lokale Datei- oder SQL-Quelle nicht verfügbar.'
    return ''


def local_snapshot(s):
    p=s['onprem'];b=p['backup'];problem=local_backup_problem(s)
    if not problem and p['services']['BACKUP-01']['used_gb']>=p['services']['BACKUP-01']['capacity_gb']:problem='Lokale Backupablage voll.'
    b['jobs'].append(dict(minute=s['minute'],status='failed' if problem else 'success',reason=problem or 'Lokale Dateien und Aufträge gesichert.'));b['jobs']=b['jobs'][-100:];b['last']=s['minute']
    if not problem:
        b['points'].append(dict(id='local-'+str(s['minute'])+'-'+str(s['seq']),minute=s['minute'],documents=copy.deepcopy(p['documents']),orders=copy.deepcopy(p['orders'])));b['points']=b['points'][-100:]
    event(s,'local_backup',problem or 'Lokaler Dateibestand und SQL-Aufträge gesichert.')


def advance_local(s):
    p=s['onprem'];b=p['backup']
    if not p['enabled']:return
    if b['enabled'] and s['minute']-b['last']>=b['interval']:local_snapshot(s)
    b['points']=[point for point in b['points'] if s['minute']-point['minute']<=b['retention']]
    job=b['restore']
    if not job or job['status']!='running':return
    problem=local_backup_problem(s,job['scope'])
    if not problem and p['services']['FILE-01']['used_gb']>=p['services']['FILE-01']['capacity_gb']:problem='Lokales Dateiziel voll.'
    if not problem and job['scope']=='file' and job['target'] in p['documents'] and job['target']!=job['source']:problem='Lokales alternatives Ziel belegt.'
    if problem:job.update(status='failed',reason=problem,finished_minute=s['minute']);event(s,'local_restore',problem);return
    if s['minute']<job['due']:return
    b['points'].append(dict(id='before-local-restore-'+str(s['minute'])+'-'+str(s['seq']),minute=s['minute'],documents=copy.deepcopy(p['documents']),orders=copy.deepcopy(p['orders'])));b['points']=b['points'][-100:]
    if job['scope']=='application':p['documents']=copy.deepcopy(job['documents']);p['orders']=copy.deepcopy(job['orders'])
    else:
        restored=copy.deepcopy(job['documents'][job['source']]);target=job['target']
        if target in p['documents']:
            current=p['documents'][target];restored['versions']=copy.deepcopy(current['versions'])+[{k:copy.deepcopy(v) for k,v in current.items() if k!='versions'}];restored.update(version=current['version']+1,modified=s['minute'])
        p['documents'][target]=restored
        p['data_governance'][target]=copy.deepcopy(p['data_governance'][job['source']])
        if job['source'] in p['lineage_pending'] and target not in p['lineage_pending']:p['lineage_pending'].append(target)
    job.update(status='success',finished_minute=s['minute']);event(s,'local_restore','Lokaler Bestand aus gewähltem Punkt wiederhergestellt; vorheriger Bestand als Punkt erhalten.')


def local_action(s,action,p):
    if action not in LOCAL_ACTION_FIELDS:raise Invalid('Lokale Aktion unbekannt.')
    required,optional=LOCAL_ACTION_FIELDS[action]
    if not required<=set(p) or set(p)-required-optional:raise Invalid('Lokale Aktionsfelder fehlen oder sind unbekannt.')
    for key in ('id','user','actor','source','member','group','share','point','scope','target','content'):
        if key in p and (type(p[key]) is not str or (key!='content' and not p[key].strip()) or len(p[key])>(10000 if key=='content' else 120)):raise Invalid('Lokales Textfeld ungültig: '+key)
    if 'version' in p and (type(p['version']) is not int or p['version']<1):raise Invalid('Lokale Auftragsversion ungültig.')
    local=s['onprem'];user=p.get('user','u11');source=p.get('source','hq')
    if action=='local_initialize':
        if local['enabled']:raise Invalid('Lokale Infrastruktur existiert bereits; vorhandene Daten werden nicht ersetzt.')
        if p.get('actor','it')!='it' or 'it' not in s['users']:raise Invalid('Einrichtung nur über die IT-Lernkonsole.')
        s['onprem']=local_seed(s['users'],True,s['minute']);return 'Lokale fiktive Infrastruktur eingerichtet.'
    if not local['enabled']:raise Invalid('Lokale Infrastruktur für diesen alten Stand zuerst ausdrücklich einrichten.')
    migration=s['local_migration']
    if migration['active']:
        if action in ('local_write','local_delete') and p['id'] in migration['documents']:raise Invalid('Lokale Quellanhänge sind nach Umschaltung eingefroren; aktuelle Cloud-Datei bearbeiten.')
        if action=='local_restore' and (p.get('scope')=='application' or p.get('id') in migration['documents'] or p.get('target') in migration['documents']):raise Invalid('Restore der eingefrorenen Quelle erst nach Rückfall ausführen; unabhängige lokale Dateien bleiben separat nutzbar.')
        if action in ('local_order_create','local_order_update'):
            if type(p['changes']) is not dict:raise Invalid('Cloud-Auftragsänderungen müssen ein Objekt sein.')
            if action=='local_order_update' and p['id'] not in migration['owned_orders']:raise Invalid('Kein Auftrag dieser migrierten Anwendung.')
            if p['changes'].get('document',s['orders'].get(p['id'],{}).get('document','')) not in migration['owned_documents']:raise Invalid('Migrierte Anwendung benötigt einen ihrer übernommenen Anhänge.')
            probe=local_cloud_state(s);probe,result=act(probe,'order_create' if action=='local_order_create' else 'order_update',**p)
            probe['network']['dns']['auftrag.intern']=s['network']['dns']['auftrag.intern']
            if action=='local_order_create':probe['local_migration']['owned_orders'].append(p['id'])
            s.clear();s.update(probe);return result

    if action in ('local_open','local_read','local_write','local_delete','local_order_create','local_order_update'):
        if action in ('local_open','local_order_create','local_order_update'):
            auth=local_application_access(s,user,source,'orders_read' if action=='local_open' else 'orders_write')
            if action=='local_open':return dict(kind='local_orders',authorization=auth,orders=[dict(row,id=key) for key,row in (s['orders'].items() if migration['active'] else local['orders'].items()) if not migration['active'] or key in migration['owned_orders']] if auth['allowed'] else [])
            if not auth['allowed']:raise Invalid(auth['reason'])
            key=p['id'];changes=p['changes']
            if type(changes) is not dict or set(changes)-{'customer','subject','amount','status','document'}:raise Invalid('Lokale Auftragsfelder ungültig.')
            if action=='local_order_create':
                if key in local['orders']:raise Invalid('Lokale Auftragskennung bereits vorhanden.')
                row=dict(customer='',subject='',amount=0.0,status='Neu',document='angebot-lokal',version=1,modified=s['minute'])
            else:
                if key not in local['orders'] or p.get('version')!=local['orders'][key]['version']:raise Invalid('Lokaler Auftrag inzwischen geändert; neue Version laden.')
                row=dict(local['orders'][key],version=local['orders'][key]['version']+1,modified=s['minute'])
            row.update(changes)
            if not local_access(s,'svc-orders',row['document'],source='ORDER-01')['allowed']:raise Invalid('Lokale Anwendung kann den neuen Dateianhang nicht lesen.')
            local['orders'][key]=row;return 'Lokaler SQL-Auftrag gespeichert.'
        key=p['id']
        if action in ('local_write','local_delete') and local['data_governance'].get(key,{}).get('status')=='purged':raise Invalid('Endgültig entfernte lokale Kennung kann nicht wieder beschrieben werden.')
        auth=local_access(s,user,key,'data_read' if action=='local_read' else 'data_write',source)
        if action=='local_read':return dict(kind='local_file',authorization=auth,document=copy.deepcopy(local['documents'][key]) if auth['allowed'] else None)
        if not auth['allowed']:raise Invalid(auth['reason'])
        row=local['documents'][key];row['versions'].append({k:copy.deepcopy(v) for k,v in row.items() if k!='versions'});row.update(version=row['version']+1,modified=s['minute'])
        if action=='local_delete':row['deleted']=True
        else:row.update(content=p['content'],deleted=False)
        return 'Lokale Datei mit Historie gespeichert.'
    actor=p.get('actor','it')
    if actor not in local['groups'].get('IT',[]) or not local['accounts'].get(actor,{}).get('active'):raise Invalid('Lokale IT-Konsolenberechtigung erforderlich; Azure-Rollen verleihen sie nicht.')
    if action=='local_service':
        if p['id'] not in local['services'] or type(p['changes']) is not dict or set(p['changes'])-{'status','configured','port','allow_cloud','capacity_gb','used_gb'}:raise Invalid('Lokale Dienstkonfiguration ungültig.')
        local['services'][p['id']].update(p['changes'])
    elif action=='local_account':
        if p['id'] not in local['accounts'] or type(p['changes']) is not dict or set(p['changes'])!={'active'}:raise Invalid('Bestehendes lokales Konto mit active wählen; kein automatischer Entra-Import.')
        local['accounts'][p['id']].update(p['changes'])
    elif action=='local_membership':
        if p['group'] not in local['groups'] or p['member'] not in local['accounts'] or type(p['add']) is not bool:raise Invalid('Lokale Gruppe/Mitglied ungültig.')
        members=local['groups'][p['group']]
        if p['add'] and p['member'] not in members:members.append(p['member'])
        if not p['add'] and p['member'] in members:members.remove(p['member'])
    elif action=='local_network':
        if type(p['changes']) is not dict or set(p['changes'])-{'lan','dns'}:raise Invalid('Lokale Netzfelder ungültig.')
        local.update(p['changes'])
    elif action=='local_acl':
        if p['share'] not in local['shares'] or type(p['changes']) is not dict or set(p['changes'])!={'read','write'}:raise Invalid('Lokale Freigabe benötigt read/write-Gruppen.')
        local['shares'][p['share']]=p['changes']
    elif action=='local_backup_config':
        if type(p['changes']) is not dict or set(p['changes'])-{'enabled','interval','retention'}:raise Invalid('Lokale Sicherungsfelder ungültig.')
        local['backup'].update(p['changes'])
    elif action=='local_backup_run':local_snapshot(s)
    elif action=='local_restore':
        b=local['backup'];scope=p['scope'];target=p.get('target','');key=p.get('id','');point=next((row for row in b['points'] if row['id']==p['point']),None)
        if scope=='file' and (key not in local['data_governance'] or local['data_governance'][key]['status']=='purged'):raise Invalid('Entfernte oder ungeklärte lokale Daten dürfen nicht wiederhergestellt werden.')
        if scope not in ('file','application') or point is None:raise Invalid('Lokalen vorhandenen Punkt und file/application wählen.')
        if b['restore'] and b['restore']['status']=='running':raise Invalid('Lokaler Wiederherstellungsjob läuft bereits.')
        if scope=='file' and (key not in point['documents'] or not target.strip() or target in ('__proto__','constructor','prototype') or len(target)>120 or (target in local['documents'] and target!=key)):raise Invalid('Lokale Quelle oder freies alternatives Ziel ungültig.')
        problem=local_backup_problem(s,scope)
        if problem or local['services']['FILE-01']['used_gb']>=local['services']['FILE-01']['capacity_gb']:raise Invalid(problem or 'Lokales Wiederherstellungsziel voll.')
        b['restore']=dict(scope=scope,source=key,target=target,point=point['id'],point_minute=point['minute'],status='running',started=s['minute'],due=s['minute']+5,documents=copy.deepcopy(point['documents']),orders=copy.deepcopy(point['orders']),reason='')
        b['restore'].update(recovery_context(s,p))
    else:raise Invalid('Lokale Aktion nicht unterstützt.')
    return 'Lokale Konfiguration gespeichert; Entra-/Cloud-Bestand bleibt getrennt.'


def validate_local(s):
    p=s['onprem'];services={'AD-01','FILE-01','ORDER-01','SQL-01','BACKUP-01'}
    if not p['enabled']:
        if any(p[key] for key in ('services','accounts','groups','shares','dns','documents','orders')) or p['backup']['points'] or p['backup']['restore']:raise Invalid('Deaktivierter lokaler Bereich darf keinen versteckten Geschäftsbestand enthalten.')
        return
    net=ipaddress.IPv4Network(s['network']['onprem'])
    if net.num_addresses<32 or set(p['services'])!=services:raise Invalid('Lokales Netz benötigt Platz für fünf Dienste und Clients.')
    offsets=[]
    for r in p['services'].values():
        if r['status'] not in ('running','stopped') or not 1<=r['offset']<net.num_addresses-1 or not 1<=r['port']<=65535 or not 1<=r['capacity_gb']<=10000 or not 0<=r['used_gb']<=10000:raise Invalid('Lokale Dienstwerte ungültig.')
        offsets.append(r['offset'])
    if len(set(offsets))!=len(offsets) or any(v in (10,11,12) for v in offsets):raise Invalid('Lokale Dienstadressen kollidieren.')
    if any(key not in s['users'] and key not in ('svc-orders','svc-backup') for key in p['accounts']):raise Invalid('Lokales Konto benötigt fiktive Firmenidentität oder Dienstkonto.')
    for members in p['groups'].values():
        if len(members)!=len(set(members)) or any(u not in p['accounts'] for u in members):raise Invalid('Lokales Gruppenmitglied fehlt oder ist doppelt.')
    if set(p['shares'])!={'sales','hr'} or any(set(acl)!= {'read','write'} or any(group not in p['groups'] for permission in acl.values() for group in permission) for acl in p['shares'].values()):raise Invalid('Lokale Freigabegruppen ungültig.')
    if any(target not in services and not (host=='auftrag.lan' and s['local_migration']['active'] and target==s['local_migration']['target']) for host,target in p['dns'].items()):raise Invalid('Lokales DNS darf nur vorhandene lokale Dienste zuordnen.')
    def stores(documents,orders):
        for d in documents.values():
            if d['container'] not in p['shares'] or d['class'] not in ('öffentlich','intern','vertraulich','besonders schutzbedürftig') or d['version']<1:raise Invalid('Lokales Dokument benötigt gültige Freigabe/Version.')
        for key,row in orders.items():
            if not key.strip() or row['document'] not in documents or not row['customer'].strip() or not row['subject'].strip() or row['status'] not in ('Neu','In Bearbeitung','Erledigt') or row['version']<1 or not 0<=row['amount']<=1000000:raise Invalid('Lokaler SQL-Auftrag oder Dokumentbezug ungültig.')
    stores(p['documents'],p['orders']);b=p['backup']
    if not 1<=b['interval']<=1440 or not 1<=b['retention']<=43200 or len(b['points'])>100 or len(b['jobs'])>100:raise Invalid('Lokale Sicherungsgrenzen ungültig.')
    ids=[]
    for point in b['points']:stores(point['documents'],point['orders']);ids.append(point['id'])
    if len(set(ids))!=len(ids):raise Invalid('Lokale Sicherungspunktkennung doppelt.')
    for job in b['jobs']:
        if job['status'] not in ('success','failed'):raise Invalid('Lokales Sicherungsergebnis ungültig.')
    job=b['restore']
    if job:
        stores(job['documents'],job['orders'])
        if job['scope'] not in ('file','application') or job['status'] not in ('running','failed','success') or job['due']!=job['started']+5 or (job['status']=='failed' and not job['reason'].strip()):raise Invalid('Lokale Wiederherstellung ungültig.')
        if job['scope']=='file' and (job['source'] not in job['documents'] or not job['target'].strip() or len(job['target'])>120 or job['target'] in ('__proto__','constructor','prototype')):raise Invalid('Lokaler Wiederherstellungspfad ungültig.')



def local_rule(s,key):
    return data_record('Vertrieb' if key=='angebot-lokal' else 'IT','Lokale Bestandsdaten; fachliche Frist prüfen',key)


def local_migration_source_rules(s):
    documents,_=local_migration_source(s)
    return {key:copy.deepcopy(s['onprem']['data_governance'][key]) for key in documents}


def local_migration_source_hash(s):
    return business_hash(*local_migration_source(s),local_migration_source_rules(s))


def business_related(s,area,ident):
    if area not in ('local','cloud') or type(ident) is not str:raise Invalid('Lokalen oder Cloud-Datenbereich und Kennung wählen.')
    p=s['onprem'];m=s['local_migration'];local=p['data_governance'];cloud=s['data_governance'];sets=dict(local=set(),cloud=set(),stage=set())
    rules=local if area=='local' else cloud
    if ident not in rules:raise Invalid('Datenkennung ohne aktuelle Herkunftsregel.')
    origin=rules[ident]['origin'];sets[area]={key for key,rule in rules.items() if rule['origin']==origin}
    while True:
        before=tuple(frozenset(sets[k]) for k in ('local','cloud','stage'))
        local_origins={local[key]['origin'] for key in sets['local']}
        for key in sets['cloud'] & set(m['owned_documents']):
            if key in local:local_origins.add(local[key]['origin'])
        sets['local'].update(key for key,rule in local.items() if rule['origin'] in local_origins)
        sets['stage'].update(key for key,rule in m['governance'].items() if rule['origin'] in local_origins)
        cloud_origins={cloud[key]['origin'] for key in sets['cloud']}
        if m['cloud_present']:
            cloud_origins.update(cloud[key]['origin'] for key in m['owned_documents'] if key in cloud and key in local and local[key]['origin'] in local_origins)
        sets['cloud'].update(key for key,rule in cloud.items() if rule['origin'] in cloud_origins)
        if before==tuple(frozenset(sets[k]) for k in ('local','cloud','stage')):return sets


def business_rules(s,related):
    return [rules[key] for name,rules in [('local',s['onprem']['data_governance']),('cloud',s['data_governance']),('stage',s['local_migration']['governance'])] for key in related[name]]


def require_business_management(s,actor,related):
    if related['local'] or related['stage']:
        p=s['onprem']
        if not p['enabled'] or not p['accounts'].get(actor,{}).get('active') or actor not in p['groups'].get('IT',[]):raise Invalid('Aktive lokale IT-Konsolenberechtigung für lokalen Bestand oder Kopierbestand erforderlich.')
    targets={s['document_storage'][key]['host'] for key in related['cloud']}
    if related['stage']:targets.add('storage')
    if any(row['document'] in related['cloud'] for row in s['orders'].values()):targets.add('db')
    for target in targets:require_management(s,actor,target)


def refresh_business_migration(s,invalidate=False):
    m=s['local_migration']
    if m['source_hash']:m['source_hash']=business_hash(m['documents'],m['orders'],m['governance'])
    if m['cloud_present']:m['cloud_hash']=local_migration_cloud_hash(s)
    if invalidate and not m['active'] and m['phase'] in ('copied','tested'):m.update(phase='copied',synced=False,tested=False)


def business_policy(s,area,ident,changes,actor='it'):
    related=business_related(s,area,ident);require_business_management(s,actor,related);rules=business_rules(s,related)
    if not any(rule['status']=='active' for rule in rules):raise Invalid('Endgültig entfernte Daten können nicht wieder aktiviert werden.')
    if type(changes) is not dict or set(changes)!={'owner','purpose','retain_minutes','hold','reason'}:raise Invalid('Verantwortung, Zweck, Dauer, Löschsperre und Begründung gemeinsam angeben.')
    if changes['owner'] not in set(s['users'])|set(s['groups']) or type(changes['purpose']) is not str or not changes['purpose'].strip() or len(changes['purpose'])>500 or type(changes['reason']) is not str or not changes['reason'].strip() or len(changes['reason'])>2000 or type(changes['hold']) is not bool:raise Invalid('Gültige Verantwortung und begründete Datenregel erforderlich.')
    until=s['minute']+number(changes['retain_minutes'],0,43200,True)
    if until<max(rule['retention_until'] for rule in rules):raise Invalid('Keine laufende Frist einer lokalen, Cloud- oder Migrationskopie verkürzen.')
    for rule in rules:rule.update(owner=changes['owner'],purpose=changes['purpose'],retention_until=until,hold=changes['hold'],reason=changes['reason'])
    refresh_business_migration(s,True)
    return dict(area=area,id=ident,retention_until=until,hold=changes['hold'],copies={key:sorted(value) for key,value in related.items()})


def erase_business_document(row):
    row.update(name='[Entfernt]',content='',versions=[],deleted=True)


def erase_business_orders(records,documents):
    affected=set()
    for key,row in records.items():
        if row['document'] in documents:row.update(customer='[Entfernt]',subject='[Entfernt]',amount=0.0,status='Erledigt');affected.add(key)
    return affected


def business_purge(s,area,ident,reason,actor='it'):
    related=business_related(s,area,ident);require_business_management(s,actor,related);rules=business_rules(s,related);p=s['onprem'];m=s['local_migration']
    if type(reason) is not str or not reason.strip() or len(reason)>2000:raise Invalid('Endgültige Bereinigung des Geschäftsvorgangs begründen.')
    if not any(rule['status']=='active' for rule in rules):raise Invalid('Geschäftsdaten sind bereits entfernt.')
    if (related['local'] or related['stage']) and p['lineage_pending']:raise Invalid('Ungeklärte ältere lokale Kopien zuerst ausdrücklich zuordnen oder als eigenständige Daten bestätigen; unbekannte Ableitungen dürfen nicht übersehen werden.')
    if any(rule['hold'] for rule in rules):raise Invalid('Eine lokale, Cloud- oder Kopier-Löschsperre ist noch aktiv.')
    if any(s['minute']<rule['retention_until'] for rule in rules):raise Invalid('Mindestens eine Aufbewahrungsfrist läuft noch.')
    for rule in rules:rule['status']='purged'
    pending=s['backup']['restore']
    if pending and (pending['source'] in related['cloud'] or pending['target'] in related['cloud']):s['backup']['restore']=None
    pending=p['backup']['restore']
    if pending and (pending['source'] in related['local'] or pending['target'] in related['local'] or set(pending['documents']) & related['local']):p['backup']['restore']=None
    order_ids=set()
    stores=[(s['documents'],s['orders'],related['cloud']),(p['documents'],p['orders'],related['local']),(m['documents'],m['orders'],related['stage'])]
    stores += [(point['documents'],{},related['cloud']) for point in s['backup']['points']]
    stores += [(point['documents'],point['orders'],related['local']) for point in p['backup']['points']]
    for documents,orders,keys in stores:
        for key in keys & set(documents):erase_business_document(documents[key])
        order_ids.update(erase_business_orders(orders,keys))
    if any(row['document'] in related['cloud'] for row in s['orders'].values()):s['order_revision']+=1
    # The bounded audit stores prior payloads in change parameters, not an external audit service.
    for entry in s['events']:
        parameters=entry.get('parameters',{});action=entry.get('message');key=parameters.get('id')
        keys=related['local'] if action in ('local_write','local_delete','local_order_create','local_order_update') else related['cloud']
        if action in ('file_write','local_write') and key in keys:parameters['content']='[Im aktuellen Lernstand entfernt]'
        if action in ('order_create','order_update','local_order_create','local_order_update') and key in order_ids:parameters['changes']={}
    refresh_business_migration(s,True)
    result=dict(area=area,id=ident,status='purged',documents={key:sorted(value) for key,value in related.items()},orders=sorted(order_ids),reason=reason)
    event(s,'business_purge','Geschäftsinhalte aus lokalem, Cloud- und Kopierbestand sowie modellierten Punkten entfernt; technische Backups, alte Exporte und Freitext bleiben getrennt.',parameters=dict(area=area,id=ident))
    return result


def local_lineage(s,ident,source,reason,actor='it'):
    p=s['onprem'];rules=p['data_governance']
    if ident not in rules or source not in rules or type(reason) is not str or not reason.strip() or len(reason)>2000:raise Invalid('Vorhandene lokale Kennungen und Herkunftsentscheidung begründen.')
    a=business_related(s,'local',ident);b=business_related(s,'local',source);related={key:a[key]|b[key] for key in a};require_business_management(s,actor,related)
    all_rules=business_rules(s,related)
    if any(s['onprem']['data_governance'][key]['status']=='purged' for key in related['local']) or any(s['local_migration']['governance'][key]['status']=='purged' for key in related['stage']):raise Invalid('Bereits entfernte lokale Herkunft nicht neu verknüpfen.')
    until=max(rule['retention_until'] for rule in all_rules);hold=any(rule['hold'] for rule in all_rules);origin=rules[source]['origin'];canonical=rules[source]
    for key in related['local']:rules[key]=dict(canonical,origin=origin,retention_until=until,hold=hold)
    for key in related['stage']:s['local_migration']['governance'][key]=dict(canonical,origin=origin,retention_until=until,hold=hold)
    if related['cloud']:
        # Cloud origins/statuses stay authoritative, including historical partial purge.
        # The explicit local bridge joins their handling without reactivating a Cloud tombstone.
        for key in related['cloud']:s['data_governance'][key].update(owner=canonical['owner'],purpose=canonical['purpose'],reason=canonical['reason'],retention_until=until,hold=hold)
    p['lineage_pending']=[key for key in p['lineage_pending'] if key not in related['local']]
    refresh_business_migration(s,True)
    event(s,'lineage_review','Lokale Datenherkunft ausdrücklich geprüft.',parameters=dict(id=ident,source=source,reason=reason))
    return dict(origin=origin,local_documents=sorted(related['local']),retention_until=until,hold=hold)


def initialize_business_governance(s):
    p=s['onprem'];m=s['local_migration'];m['governance']={};keys=set(p['documents'])|set(m['documents'])
    for point in p['backup']['points']:keys.update(point['documents'])
    if p['backup']['restore']:keys.update(p['backup']['restore']['documents'])
    p['data_governance']={key:local_rule(s,key) for key in keys};p['lineage_pending']=sorted(keys-{'angebot-lokal','personal-lokal'})
    # Recorded restore edges are provenance. Text similarity is never used to infer lineage.
    edges=[];pending_edge=None
    for entry in s['events']:
        if entry.get('kind')=='change' and entry.get('message')=='local_restore':pending_edge=entry.get('parameters',{})
        elif entry.get('kind')=='local_restore':
            if pending_edge and entry.get('message','').startswith('Lokaler Bestand aus gewähltem Punkt wiederhergestellt'):edges.append(pending_edge)
            pending_edge=None
    job=p['backup']['restore']
    if job and job['scope']=='file' and job['status']=='success':edges.append(dict(scope='file',id=job['source'],target=job['target']))
    for edge in edges:
        source=edge.get('id');target=edge.get('target')
        if edge.get('scope')=='file' and source in p['data_governance'] and target in p['data_governance']:
            p['data_governance'][target]=copy.deepcopy(p['data_governance'][source])
            if source not in p['lineage_pending'] and target in p['lineage_pending']:p['lineage_pending'].remove(target)
    if m['cloud_present']:
        for key in m['owned_documents']:
            if key not in p['data_governance'] or key not in s['data_governance']:continue
            related=business_related(s,'local',key);linked=[s['data_governance'][key] for key in related['cloud']]
            if linked:
                until=max(rule['retention_until'] for rule in linked);hold=any(rule['hold'] or rule['status']=='purged' for rule in linked)
                canonical=linked[0]
                for key in related['local']:p['data_governance'][key].update(owner=canonical['owner'],purpose=canonical['purpose'],reason=canonical['reason'],retention_until=until,hold=hold)
                if len({(rule['owner'],rule['purpose']) for rule in linked})>1:
                    p['lineage_pending']=sorted(set(p['lineage_pending'])|related['local'])
    m['governance']={key:copy.deepcopy(p['data_governance'][key]) for key in m['documents']}
    if m['source_hash']:m['source_hash']=business_hash(m['documents'],m['orders'],m['governance'])
    if not m['active'] and m['phase']=='tested':m.update(phase='copied',tested=False,synced=False)


def validate_business_governance(s):
    p=s['onprem'];rules=p['data_governance'];m=s['local_migration']
    if not set(p['documents'])<=set(rules) or len(p['lineage_pending'])!=len(set(p['lineage_pending'])) or not set(p['lineage_pending'])<=set(rules):raise Invalid('Lokale Herkunftsregeln oder offene Prüfkennungen fehlen.')
    for key,rule in rules.items():
        if rule['owner'] not in set(s['users'])|set(s['groups']) or rule['origin'] not in rules or rule!=rules[rule['origin']]:raise Invalid('Lokale Verantwortung/Herkunftsgruppe ungültig.')
        if not rule['purpose'].strip() or len(rule['purpose'])>500 or not rule['reason'].strip() or len(rule['reason'])>2000 or not 0<=rule['retention_until']<=10000000 or rule['status'] not in ('active','purged'):raise Invalid('Lokale Aufbewahrungsregel ungültig.')
        if rule['status']=='purged':
            for docs,orders in [(p['documents'],p['orders']),*[(point['documents'],point['orders']) for point in p['backup']['points']]]:
                if key in docs and (docs[key]['content'] or docs[key]['versions'] or not docs[key]['deleted']):raise Invalid('Entfernte lokale Daten dürfen keine wiederherstellbaren Inhalte besitzen.')
                if any(row['document']==key and (row['customer']!='[Entfernt]' or row['subject']!='[Entfernt]' or row['amount']!=0) for row in orders.values()):raise Invalid('Entfernter lokaler Geschäftsvorgang enthält noch Auftragsdaten.')
    if set(m['governance'])!=set(m['documents']):raise Invalid('Kopierbestand benötigt genaue Herkunftsregeln.')
    for key,rule in m['governance'].items():
        if key not in rules or rule!=rules[key]:raise Invalid('Migrationskopie muss aktuelle lokale Aufbewahrung beibehalten.')
        if rule['status']=='purged' and (m['documents'][key]['content'] or m['documents'][key]['versions'] or not m['documents'][key]['deleted'] or any(row['document']==key and (row['customer']!='[Entfernt]' or row['subject']!='[Entfernt]' or row['amount']!=0) for row in m['orders'].values())):raise Invalid('Entfernter Kopierbestand enthält Geschäftsinhalte.')


def business_summaries(s):
    result=[];seen=set()
    for area,rules in [('local',s['onprem']['data_governance']),('cloud',s['data_governance'])]:
        for ident,rule in rules.items():
            related=business_related(s,area,ident);signature=(frozenset(related['local']),frozenset(related['cloud']))
            if signature in seen:continue
            seen.add(signature);all_rules=business_rules(s,related)
            result.append(dict(area=area,id=ident,owner=rule['owner'],purpose=rule['purpose'],reason=rule['reason'],retention_until=max(r['retention_until'] for r in all_rules),hold=any(r['hold'] for r in all_rules),purged=all(r['status']=='purged' for r in all_rules),copies={key:sorted(value) for key,value in related.items()},orders=dict(local=[key for key,row in s['onprem']['orders'].items() if row['document'] in related['local']],cloud=[key for key,row in s['orders'].items() if row['document'] in related['cloud']]),lineage_pending=sorted(related['local']&set(s['onprem']['lineage_pending']))))
    return result


def local_migration_seed():
    return dict(phase='inventory',strategy='',reason='',target='',documents={},orders={},governance={},source_hash='',cloud_hash='',owned_documents=[],owned_orders=[],cloud_present=False,active=False,interrupted=False,synced=False,tested=False,cleaned=False,original_dns='ORDER-01')


def business_hash(documents,orders,governance=None):
    payload=dict(documents=documents,orders=orders)
    if governance is not None:payload['governance']=governance
    return hashlib.sha256(json.dumps(payload,ensure_ascii=True,sort_keys=True).encode('utf-8')).hexdigest()


def local_migration_source(s):
    orders=copy.deepcopy(s['onprem']['orders']);keys={row['document'] for row in orders.values()}
    return {key:copy.deepcopy(s['onprem']['documents'][key]) for key in keys},orders


def local_cloud_state(s):
    probe=copy.deepcopy(s);probe['network']['dns']['auftrag.intern']=s['local_migration']['target'];return probe


def local_cloud_access(s,user='u11',source='hq',operation='orders_read'):
    m=s['local_migration'];probe=local_cloud_state(s)
    source={'home':str(ipaddress.ip_network(s['network']['onprem']).network_address+12)}.get(source,source)
    result=application_access(probe,user,source,operation)
    if s['onprem']['dns'].get('auftrag.lan')!=m['target']:
        result.update(allowed=False,reason='Lokaler Programmeinstieg zeigt nicht auf das gewählte Cloudziel.')
    return result


def local_migration_preview(s):
    probe=local_cloud_state(s);m=s['local_migration']
    for key,row in m['documents'].items():
        probe['documents'][key]=copy.deepcopy(row)
        if key not in s['documents']:
            probe['document_storage'][key]=dict(kind='Blob',host='storage')
        policy=m['governance'][key]
        if key in s['data_governance'] and s['data_governance'][key]['status']=='purged' and policy['status']!='purged':raise Invalid('Bereits entfernte Cloudherkunft nicht durch lokale Altinhalte wieder aktivieren; gemeinsamen Bestand bereinigen.')
        same=[ident for ident,rule in m['governance'].items() if rule['origin']==policy['origin']]
        canonical=next((s['data_governance'][ident]['origin'] for ident in same if ident in s['data_governance']),min(same))
        probe['data_governance'][key]=dict(policy,origin=canonical)
    probe['orders'].update(copy.deepcopy(m['orders']))
    return probe


def local_migration_cloud_hash(s):
    m=s['local_migration']
    if any(key not in s['documents'] for key in m['owned_documents']) or any(key not in s['orders'] for key in m['owned_orders']):raise Invalid('Zur Migration gehörender Cloudbestand fehlt; keine stillschweigende Datenersetzung.')
    return business_hash({key:s['documents'][key] for key in m['owned_documents']},{key:s['orders'][key] for key in m['owned_orders']})


def local_migration_actor(s,actor):
    p=s['onprem']
    if not p['enabled'] or not p['accounts'].get(actor,{}).get('active') or actor not in p['groups'].get('IT',[]):raise Invalid('Lokaler aktiver IT-Auftrag erforderlich; Entra-Rollen genügen nicht.')
    for target in ('rg-app','db','storage'):require_management(s,actor,target)


def local_migration_source_ready(s,actor,cloud=False,rollback=False):
    m=s['local_migration'];origin=m['target'] if cloud else 'hq'
    if not local_login(s,actor,origin)[0]:raise Invalid('Lokale AD-Quelle oder Anmeldung nicht verfügbar.')
    if not local_connection(s,origin,'sql.lan',1433)['allowed'] or s['onprem']['dns'].get('sql.lan')!='SQL-01':raise Invalid('Lokale SQL-Quelle über den gewählten Pfad nicht verfügbar.')
    docs,orders=local_migration_source(s)
    if not orders:raise Invalid('Keine lokalen Auftragsdaten zur Migration vorhanden.')
    for key in docs:
        if s['onprem']['data_governance'][key]['status']=='purged':continue
        if not local_access(s,actor,key,source=origin)['allowed']:raise Invalid('Lokaler Dateianhang nicht lesbar: '+key)
    if rollback and any(s['onprem']['services'][key]['used_gb']>=s['onprem']['services'][key]['capacity_gb'] for key in ('FILE-01','SQL-01')):raise Invalid('Lokales Rückfallziel hat keine freie Kapazität.')
    return docs,orders


def local_migration_target_check(s,actor,user='u11',write=True,check_user=True):
    m=s['local_migration'];probe=local_cloud_state(s);target=m['target']
    if target not in s['resources'] or s['resources'][target]['kind']!=('VM' if m['strategy']=='rehost' else 'App Service'):raise Invalid('Migrationsziel fehlt oder hat den falschen Ressourcentyp.')
    require_management(s,actor,target)
    if not connection(probe,host=target)['allowed'] or connection(probe,source='internet',host=target,port=22)['allowed']:raise Invalid('Cloudziel ist nicht funktionsfähig oder öffentlich administrierbar.')
    if check_user and not application_access(probe,user)['allowed']:raise Invalid('Testbenutzer besitzt keinen funktionierenden Cloud-Anwendungszugriff.')
    if write and 'orders_write' not in effective(probe,actor,'orders')[0]:raise Invalid('Die Migrationsidentität benötigt eine explizite Auftrags-Datenrolle.')
    for key in m['documents']:
        if m['governance'][key]['status']=='purged':continue
        if key not in probe['documents'] or not document_available(probe,key,for_write=write) or not document_network(probe,key,source=target)['allowed']:raise Invalid('Cloud-Dateiziel fehlt, ist voll oder nicht erreichbar.')
        if write and 'data_write' not in effective(probe,actor,key)[0]:raise Invalid('Explizite Daten-Schreibrolle am Cloud-Dateiziel fehlt.')
        if (check_user and not access(probe,user,key,source=target)['allowed']) or 'data_read' not in effective(probe,probe['application']['principal'],key)[0]:raise Invalid('Testbenutzer oder Dienstidentität kann den übernommenen Anhang nicht lesen.')
    if unsafe_storage(probe):raise Invalid('Vertrauliche Dateien dürfen auf keinem Blob-Ziel anonym freigegeben sein.')


def local_migration_action(s,p):
    step=p.get('step');actor=p.get('actor','it');m=s['local_migration']
    allowed={'step','actor'}|({'strategy','reason'} if step=='prepare' else {'user'} if step in ('test','followup') else set())
    if type(step) is not str or set(p)-allowed or any(type(v) is not str for v in p.values()):raise Invalid('Migrationsschritt oder Parameter ungültig.')
    local_migration_actor(s,actor)
    if step=='prepare':
        if m['phase'] not in ('inventory','prepared','rolled_back') or m['active']:raise Invalid('Vor neuem Plan laufende Migration zurückrollen.')
        strategy=p.get('strategy');reason=p.get('reason','')
        if strategy not in ('rehost','replatform') or not reason.strip() or len(reason)>2000:raise Invalid('Rehost oder Replatform und fachliche Begründung wählen.')
        if not local_application_access(s,actor)['allowed']:raise Invalid('Die lokale Quellanwendung mit ihren Abhängigkeiten muss vor der Vorbereitung funktionieren.')
        if m['cloud_present'] and local_migration_cloud_hash(s)!=m['cloud_hash']:raise Invalid('Zurückbehaltener Cloudbestand wurde geändert; zuerst Datenkonflikt klären.')
        target='localvm' if strategy=='rehost' else 'localpaas'
        if target in s['resources'] and target!=m['target']:raise Invalid('Zielkennung ist bereits belegt; keine fremde Ressource überschreiben.')
        if target not in s['resources']:
            source=s['resources']['web'];kind='VM' if strategy=='rehost' else 'App Service'
            group=s['resource_groups']['rg-app']
            candidate=resource('Lokale Aufträge · '+strategy,kind,'rg-app',region=group['region'],owner=group['owner'],department=group['department'],subnet=source['subnet'],ip=next_private_ip(s,source['subnet']),configured=False,status='stopped',disk_gb=64 if strategy=='rehost' else 0)
            require_resource_policy(s,candidate)
            s['resources'][target]=candidate
        if s['resources'][target]['kind']!=('VM' if strategy=='rehost' else 'App Service'):raise Invalid('Vorhandenes Ziel passt nicht zur Strategie.')
        require_resource_policy(s,s['resources'][target])
        m.update(phase='prepared',strategy=strategy,reason=reason,target=target,synced=False,tested=False,interrupted=False,cleaned=False)
    elif step in ('pause','resume'):
        if m['phase'] in ('inventory','rolled_back'):raise Invalid('Keine laufende Migration.')
        m['interrupted']=step=='pause'
        if not m['active']:m.update(phase='prepared' if not m['source_hash'] else 'copied',synced=False,tested=False)
    elif step=='copy':
        if m['active'] or m['phase'] not in ('prepared','copied','tested') or m['interrupted']:raise Invalid('Kopie benötigt vorbereitete, nicht unterbrochene Migration.')
        docs,orders=local_migration_source_ready(s,actor,cloud=True)
        if any(len(key)>50 for key in orders):raise Invalid('Lokale Auftragskennung überschreitet das Cloud-Lernformat (50 Zeichen).')
        if any(key in s['documents'] and key not in m['owned_documents'] for key in docs) or any(key in s['orders'] and key not in m['owned_orders'] for key in orders):raise Invalid('Cloud-Kennungskollision: vorhandene fremde Geschäftsdaten werden nicht überschrieben.')
        if m['cloud_present'] and local_migration_cloud_hash(s)!=m['cloud_hash']:raise Invalid('Cloudkopie wurde seit dem Rückfall geändert.')
        m.update(documents=docs,orders=orders,governance=local_migration_source_rules(s),source_hash=local_migration_source_hash(s),phase='copied',synced=True,tested=False)
        preview=local_migration_preview(s);local_migration_target_check(preview,actor,check_user=False)
    elif step in ('test','cutover'):
        if m['phase']!=('copied' if step=='test' else 'tested') or not m['synced'] or m['interrupted']:raise Invalid('Erst vollständig kopieren und vor Umschaltung erfolgreich testen.')
        docs,orders=local_migration_source_ready(s,actor,cloud=True)
        if local_migration_source_hash(s)!=m['source_hash']:raise Invalid('Lokaler Datenstand seit der Kopie geändert; erneut kopieren und testen.')
        if m['cloud_present'] and local_migration_cloud_hash(s)!=m['cloud_hash']:raise Invalid('Cloud-Zielbestand seit der Kopie geändert; Datenkonflikt klären.')
        if any(key in s['documents'] and key not in m['owned_documents'] for key in m['documents']) or any(key in s['orders'] and key not in m['owned_orders'] for key in m['orders']):raise Invalid('Neue Cloud-Kennungskollision seit Kopie; keine fremden Daten überschreiben.')
        preview=local_migration_preview(s);local_migration_target_check(preview,actor,p.get('user','u11'))
        if step=='test':m.update(phase='tested',tested=True)
        else:
            if s['onprem']['backup']['restore'] and s['onprem']['backup']['restore']['status']=='running':raise Invalid('Lokalen Restore vor Umschaltung abschließen.')
            for key in m['documents']:
                s['documents'][key]=preview['documents'][key];s['document_storage'][key]=preview['document_storage'][key];s['data_governance'][key]=preview['data_governance'][key]
            s['orders'].update(copy.deepcopy(m['orders']));s['order_revision']+=1
            m['owned_documents']=sorted(set(m['owned_documents'])|set(m['documents']));m['owned_orders']=sorted(set(m['owned_orders'])|set(m['orders']))
            m.update(original_dns=s['onprem']['dns'].get('auftrag.lan','ORDER-01'),phase='cutover',active=True,cloud_present=True)
            s['onprem']['dns']['auftrag.lan']=m['target'];m['cloud_hash']=local_migration_cloud_hash(s)
    elif step in ('followup','cleanup'):
        if m['phase']!=('cutover' if step=='followup' else 'verified') or not m['active'] or m['interrupted']:raise Invalid('Nachkontrolle und Aufräumen benötigen aktive geprüfte Umschaltung.')
        if s['onprem']['dns'].get('auftrag.lan')!=m['target']:raise Invalid('Programmeinstieg zeigt nicht auf das Cloudziel.')
        local_migration_target_check(s,actor,p.get('user','u11'))
        if step=='followup':m['phase']='verified'
        else:s['onprem']['services']['ORDER-01']['status']='stopped';m.update(phase='complete',cleaned=True)
        m['cloud_hash']=local_migration_cloud_hash(s)
    elif step=='rollback':
        if m['phase'] in ('inventory','rolled_back'):raise Invalid('Keine rückfallfähige Migration vorhanden.')
        if m['active']:
            pending=s['backup']['restore']
            if pending and pending['status']=='running' and pending['target'] in m['owned_documents']:raise Invalid('Cloud-Dateiwiederherstellung vor Rückfall abschließen, damit keine spätere Änderung der Rückfallkopie entsteht.')
            local_migration_source_ready(s,actor,rollback=True)
            docs,orders=local_migration_source(s)
            if local_migration_source_hash(s)!=m['source_hash']:raise Invalid('Lokale eingefrorene Quelle hat abweichende Geschäftsdaten; kein Überschreiben.')
            current_docs={key:copy.deepcopy(s['documents'][key]) for key in m['owned_documents']};current_orders={key:copy.deepcopy(s['orders'][key]) for key in m['owned_orders']}
            if any(row['document'] not in current_docs for row in current_orders.values()):raise Invalid('Cloudauftrag verwendet fremden Anhang; Bezug vor Rückfall klären.')
            for key in current_docs:
                if s['data_governance'][key]['status']=='purged':continue
                if not document_available(s,key) or not document_network(s,key,source=m['target'])['allowed'] or 'data_read' not in effective(s,actor,key)[0]:raise Invalid('Aktuelle Cloud-Datei nicht lesbar; Rückfall würde Daten verlieren.')
            if not connection(s,source=m['target'],host='db',port=s['resources']['db']['port'])['allowed'] or 'orders_read' not in effective(s,actor,'orders')[0]:raise Invalid('Aktuelle Cloud-Datenbank für Rückfall nicht lesbar.')
            s['onprem']['documents'].update(current_docs);s['onprem']['orders'].update(current_orders)
            s['onprem']['dns']['auftrag.lan']=m['original_dns'];s['onprem']['services']['ORDER-01']['status']='running'
            m['cloud_hash']=local_migration_cloud_hash(s)
        s['resources'][m['target']]['status']='deallocated' if m['strategy']=='rehost' else 'stopped'
        m.update(phase='rolled_back',active=False,synced=False,tested=False,cleaned=False,interrupted=False)
    else:raise Invalid('Unbekannter lokaler Migrationsschritt.')
    event(s,'local_migration','Lokale Datenmigration: '+step+' → '+m['phase'])
    return dict(phase=m['phase'],documents=len(m['documents']),orders=len(m['orders']),active=m['active'],note='Kopie enthält echte Modellinhalte. AD wird nicht automatisch zu Entra. Rückfall übernimmt aktuelle Cloud-Fassungen; zurückbehaltene Cloudkopien sind danach schreibgeschützt.')


def validate_local_migration(s):
    m=s['local_migration'];phases={'inventory','prepared','copied','tested','cutover','verified','complete','rolled_back'}
    if m['phase'] not in phases or m['strategy'] not in ('','rehost','replatform') or m['target'] not in ('','localvm','localpaas') or m['original_dns']!='ORDER-01':raise Invalid('Lokaler Migrationszustand ungültig.')
    for field in ('source_hash','cloud_hash'):
        if m[field] and (len(m[field])!=64 or any(c not in '0123456789abcdef' for c in m[field])):raise Invalid('Lokaler Datenabgleich benötigt SHA-256.')
    if m['phase']!='inventory' and (not m['reason'].strip() or m['target'] not in s['resources'] or m['strategy'] not in ('rehost','replatform')):raise Invalid('Lokale Migration benötigt begründeten Plan und vorhandenes Ziel.')
    if m['active']!=(m['phase'] in ('cutover','verified','complete')) or (m['active'] and (not m['cloud_present'] or s['onprem']['dns'].get('auftrag.lan')!=m['target'])):raise Invalid('Lokale Umschaltung und Programmeinstieg widersprechen sich.')
    if m['cleaned']!=(m['phase']=='complete'):raise Invalid('Aufräumzustand widersprüchlich.')
    if m['source_hash'] and m['source_hash']!=business_hash(m['documents'],m['orders'],m['governance']):raise Invalid('Abgleich und tatsächlicher Kopierbestand widersprechen sich.')
    if m['active'] and (not m['tested'] or local_migration_source_hash(s)!=m['source_hash']):raise Invalid('Aktive Übernahme benötigt getestete Kopie und eingefrorene Quelle.')
    if any(row['document'] not in m['documents'] for row in m['orders'].values()):raise Invalid('Migrationskopie enthält unvollständige Dateibezüge.')
    for field,root in [('owned_documents','documents'),('owned_orders','orders')]:
        if len(m[field])!=len(set(m[field])) or (m['cloud_present'] and any(key not in s[root] for key in m[field])):raise Invalid('Zugeordnete Cloud-Geschäftsdaten fehlen oder sind doppelt.')
    for row in m['documents'].values():
        if row['container'] not in ('sales','hr','public') or row['version']<1:raise Invalid('Migrationsdokument ungültig.')
    for row in m['orders'].values():
        if not row['customer'].strip() or not row['subject'].strip() or row['status'] not in ('Neu','In Bearbeitung','Erledigt') or row['version']<1 or not 0<=row['amount']<=1000000:raise Invalid('Migrationsauftrag ungültig.')


def fresh(tariffs=None):
    departments = ['Geschäftsführung', 'Vertrieb', 'Personal', 'Buchhaltung', 'Betrieb', 'IT']
    users = {f'u{i:02}': dict(name=f'Person {i:02} (fiktiv)', department=departments[(i-1)//10],
             active=True, mfa=True, guest=False, expires=0, directory_role='User') for i in range(1, 61)}
    users['lea'] = dict(name='Lea Neumann (fiktiv)', department='Vertrieb', active=True,
                        mfa=True, guest=False, expires=0, directory_role='User')
    users['partner'] = dict(name='Robin Extern (fiktiv)', department='Dienstleister', active=True,
                            mfa=True, guest=True, expires=480, directory_role='User')
    users['it'] = dict(name='IT-Lernrolle', department='IT', active=True, mfa=True, guest=False,
                      expires=0, directory_role='User Administrator')
    return dict(schema=VERSION, tariffs=validate_tariffs(ACTIVE_TARIFFS if tariffs is None else tariffs), minute=0, seq=0, name='Lernende Person', company='Nordlicht Auftragsservice GmbH',
        tenant='nordlicht.example (Entra ID)', subscription='Nordlicht-Lernsubscription',
        locations={'Hauptstandort': 42, 'Außenstelle': 10, 'Homeoffice': 8},
        groups={'Vertrieb': ['u11', 'u12'], 'IT': ['it'], 'Altprojekt': ['lea'], 'Partner': ['partner']}, users=users,
        resource_groups={'rg-app': {'region': 'germanywestcentral', 'department': 'Betrieb', 'owner': 'IT-Leitung'},
                         'rg-data': {'region': 'germanywestcentral', 'department': 'Vertrieb', 'owner': 'IT-Leitung'},
                         'rg-lab': {'region': 'germanywestcentral', 'department': 'IT', 'owner': 'IT-Leitung'}},
        resources={'web': resource('vm-auftrag', 'VM', 'rg-app'),
                   'db': resource('db-auftrag', 'Database', 'rg-app', ip='10.20.2.20', subnet='data', port=5432),
                   'storage': resource('stnordlicht', 'Storage', 'rg-data', ip='10.20.2.30', subnet='data', public=True, public_ip='198.51.100.30'),
                   'testvm': resource('vm-altprojekt', 'VM', 'rg-lab', size='D4', status='stopped', ip='10.20.1.11'),
                   'paas': resource('app-auftrag', 'App Service', 'rg-app', ip='10.20.1.40', status='stopped'),
                   'container': resource('ca-versand', 'Container Apps', 'rg-app', ip='10.20.1.50', port=8080, image='shipping:broken'),
                   'saas': resource('Büro-Suite (externer Anbieter)', 'SaaS', 'rg-lab', ip='', disk_gb=0)},
        local_inventory=[{'name': 'AD-01', 'role': 'Lokaler AD-DS-Lernbereich: Konten, Gruppen und Anmeldung; kein echtes Kerberos/GPO', 'dependency': 'LAN'},
                         {'name': 'FILE-01', 'role': 'Dateiserver, Abteilungsfreigaben', 'dependency': 'AD-01'},
                         {'name': 'ORDER-01', 'role': 'Interne Auftragsanwendung', 'dependency': 'SQL-01 + FILE-01'},
                         {'name': 'SQL-01', 'role': 'Auftragsdatenbank', 'dependency': 'LAN'},
                         {'name': 'BACKUP-01', 'role': 'Lokale Sicherung', 'dependency': 'FILE-01 + SQL-01'}],
        network={'vnet': '10.20.0.0/16', 'subnets': {'app':'10.20.1.0/24','data':'10.20.2.0/24'}, 'onprem': '10.10.0.0/16', 'vpn': True,
                 'dns': {'auftrag.intern': 'web', 'daten.intern': 'db', 'ablage.intern': 'storage', 'versand.intern': 'container'},
                 'rules': [{'id': 'web-in', 'direction': 'Inbound', 'protocol': 'TCP', 'source': '10.10.0.0/16', 'destination': 'web', 'port': 443, 'action': 'Allow', 'priority': 200},
                           {'id': 'storage-in', 'direction': 'Inbound', 'protocol': 'TCP', 'source': '*', 'destination': 'storage', 'port': 443, 'action': 'Allow', 'priority': 210}]},
        roles=[{'principal': 'IT', 'role': 'Contributor', 'scope': 'subscription'},
               {'principal': 'IT', 'role': 'User Access Administrator', 'scope': 'subscription'},
               {'principal': 'Vertrieb', 'role': 'Blob Contributor', 'scope': 'sales'},
               {'principal': 'Altprojekt', 'role': 'Blob Reader', 'scope': 'sales'},
               {'principal': 'partner', 'role': 'Blob Contributor', 'scope': 'storage'},
               {'principal': 'lea', 'role': 'Reader', 'scope': 'storage'},
               {'principal': 'Vertrieb', 'role': 'Order Operator', 'scope': 'orders'},
               {'principal': 'orders-app', 'role': 'Order Operator', 'scope': 'orders'},
               {'principal': 'orders-app', 'role': 'Blob Reader', 'scope': 'sales'}],
        service_principals={'orders-app': {'name': 'Dienstidentität der Auftragsanwendung', 'active': True}},
        application={'name': 'Nordlicht Aufträge', 'principal': 'orders-app'},
        requests=dict(active='',deployments={},company={},provider={}),
        order_revision=0,
        orders={'NL-1001': {'customer': 'Fiktiv: Hafenwerk GmbH', 'subject': 'Arbeitsplatz-Erweiterung', 'amount': 120.0,
                           'status': 'Neu', 'document': 'offer', 'modified': 0, 'version': 1},
                'NL-1002': {'customer': 'Fiktiv: Beispielhandel KG', 'subject': 'Standortanbindung planen', 'amount': 240.0,
                           'status': 'In Bearbeitung', 'document': 'offer', 'modified': 0, 'version': 1}},
        documents={'offer': {'name': 'Angebot-A.txt', 'container': 'sales', 'class': 'vertraulich', 'content': 'Angebot A: 120 Lern-Euro; Version 1.', 'version': 1, 'deleted': False, 'modified': 0, 'versions': []},
                   'payroll': {'name': 'Personal-B.txt', 'container': 'hr', 'class': 'besonders schutzbedürftig', 'content': 'Fiktive Personalnotiz B; keine echten Personendaten.', 'version': 1, 'deleted': False, 'modified': 0, 'versions': []},
                   'public': {'name': 'Firmeninfo.txt', 'container': 'public', 'class': 'öffentlich', 'content': 'Nordlicht: 60 fiktive Beschäftigte.', 'version': 1, 'deleted': False, 'modified': 0, 'versions': []}},
        document_storage={key:dict(kind='Blob',host='storage') for key in ('offer','payroll','public')},
        data_governance={key:data_record('Vertrieb' if key=='offer' else 'IT',origin=key) for key in ('offer','payroll','public')},
        backup={'interval': 240, 'retention': 1440, 'enabled': True, 'last': 0, 'points': [], 'jobs': [], 'restore': None},
        workload=70, container_settings={'container':{'DB_HOST':'daten.intern','DOCUMENT_ID':'offer'}}, availability_event=dict(enabled=False,region='germanywestcentral',zone=1,since=0), faults={}, alarms=[], alerts=[], metrics=[], cost=0.0, cost_ledger=[], budget=200.0,
        policy={'regions': ['germanywestcentral', 'westeurope'], 'require_tags': True, 'deny_public': False},
        migration={'phase': 'inventory', 'target': 'paas', 'synced': False, 'tested': False, 'cutover': False, 'rollback': False, 'cleaned': False, 'interrupted': False},
        local_migration=local_migration_seed(), onprem=local_seed(users), decisions={}, notes='', replies={}, diagnostics=[], events=[], hints=[], completed={}, task='intro', task_status='active')


def event(s, kind, message, **data):
    s['events'].append(dict(minute=s['minute'], kind=kind, message=message, **data))
    s['events'] = s['events'][-500:]


def scopes(s, target):
    if target == 'orders':
        return ['orders', 'db', s['resources']['db']['group'], 'subscription']
    if target in s['documents']:
        d = s['documents'][target]
        host=s['document_storage'][target]['host']
        return [target, d['container'], host, s['resources'][host]['group'], 'subscription']
    if target in s['resources']:
        return [target, s['resources'][target]['group'], 'subscription']
    if target in s['resource_groups']:
        return [target, 'subscription']
    return [target, 'subscription']



def record_signin(s,user='u11',mfa=True,source='hq',target='Identität',authorized=None):
    if type(user) is not str or not user.strip() or len(user)>120 or type(mfa) is not bool or type(source) is not str or not source.strip() or len(source)>120:raise Invalid('Anmeldeprüfung benötigt begrenzten Benutzer, Standort und booleschen MFA-Nachweis.')
    signed,reason=login(s,user,mfa)
    detail=dict(user=user,source=source,target=target,mfa=mfa,authenticated=signed,reason=reason,access='not_checked' if authorized is None else 'allowed' if authorized else 'denied')
    event(s,'signin',('Anmeldung erlaubt: ' if signed else 'Anmeldung verweigert: ')+user+' · '+target,detail=detail)
    return detail


def effective(s, user, target):
    identities = {user} | {g for g, members in s['groups'].items() if user in members}
    grants = [r for r in s['roles'] if r['principal'] in identities and r['scope'] in scopes(s, target)]
    if target in s['documents']:
        data_roles=set().union(*STORAGE_DATA_ROLES.values());accepted=STORAGE_DATA_ROLES[s['document_storage'][target]['kind']]
        grants=[r for r in grants if r['role'] not in data_roles or r['role'] in accepted]
    rights = set().union(*(ROLES[r['role']] for r in grants)) if grants else set()
    return rights, grants


def login(s, user, mfa=True):
    u = s['users'].get(user)
    if not u or not u['active']:
        return False, 'Anmeldung verweigert: Konto fehlt oder ist deaktiviert.'
    if u['guest'] and u['expires'] <= s['minute']:
        return False, 'Anmeldung verweigert: Gastfreigabe abgelaufen.'
    if not u['mfa'] or not mfa:
        return False, 'Anmeldung verweigert: simulierter MFA-Nachweis erforderlich.'
    return True, 'Anmeldung mit simuliertem MFA-Nachweis erlaubt.'


def match_address(value, ip, local_networks):
    if value in ('*', 'Any', 'Internet'):
        return value != 'Internet' or not any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in local_networks)
    if value == 'VirtualNetwork':
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in local_networks)
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False


def nsg(s, source, target, port, direction='Inbound', protocol='TCP', destination_ip=None):
    nets = [s['network']['vnet'], s['network']['onprem']]
    for r in sorted(s['network']['rules'], key=lambda r: r['priority']):
        dest = r['destination']
        if r['direction'] == direction and r['protocol'] in ('*', protocol) and match_address(s['resources'].get(r['source'],{}).get('ip',r['source']), source, nets) and (dest in ('*', target) or match_address(dest, destination_ip or s['resources'][target]['ip'], nets)) and r['port'] in (0, port):
            return r['action'] == 'Allow', f"NSG {r['id']} (Priorität {r['priority']}): {r['action']}"
    if direction == 'Outbound':
        return True, 'Standard AllowVnetOutBound/AllowInternetOutBound (65000/65001)'
    if match_address('VirtualNetwork', source, nets):
        return True, 'Standard AllowVnetInBound (65000), vereinfachtes verbundenes Netz'
    return False, 'Standard DenyAllInBound (65500)'



def unsafe_admin_rules(s):
    """Find TCP administration access from outside the modeled trusted private nets."""
    trusted=[ipaddress.ip_network(s['network'][key]) for key in ('vnet','onprem')]
    unsafe=[]
    for rule in s['network']['rules']:
        if rule['direction']!='Inbound' or rule['action']!='Allow' or rule['protocol'] not in ('TCP','*') or rule['port'] not in (0,22,3389):continue
        origin=s['resources'].get(rule['source'],{}).get('ip',rule['source'])
        if origin=='VirtualNetwork':continue
        try:
            network=ipaddress.ip_network(origin,strict=False)
            if any(network.version==private.version and network.subnet_of(private) for private in trusted):continue
        except ValueError:pass
        targets=[key for key,r in s['resources'].items() if r['kind']=='VM']
        if any(rule['destination'] in ('*','Any',target) or match_address(rule['destination'],s['resources'][target]['ip'],[s['network']['vnet'],s['network']['onprem']]) for target in targets):unsafe.append(rule['id'])
    return unsafe


def require_management(s, actor, target):
    if type(actor) is not str or not login(s,actor)[0] or 'manage' not in effective(s,actor,target)[0]:
        raise Invalid('Ressourcenverwaltung verweigert: aktive Anmeldung, simulierter MFA-Nachweis und Contributor im passenden Scope erforderlich.')


def application_backend_ready(s):
    principal=s['application']['principal']
    return s['service_principals'][principal]['active'] and 'orders_read' in effective(s,principal,'orders')[0] and 'data_read' in effective(s,principal,'offer')[0]


def unsafe_storage(s):
    return sorted(key for key,d in s['documents'].items() if not d['deleted'] and d['class']!='öffentlich' and s['document_storage'][key]['kind']=='Blob' and s['resources'][s['document_storage'][key]['host']]['public'])


def resource_availability(s,ident):
    r=s['resources'][ident];incident=s['availability_event'];external=r['kind']=='SaaS';storage=r['kind'] in ('Storage','File Share');count=1 if storage or external else r['instances']
    zones=[1,2,3] if storage and r['redundancy']=='ZRS' else [1]*count if storage or r['availability']=='single' else [1+i%3 for i in range(count)]
    affected=incident['enabled'] and incident['region']==r['region'] and not external
    surviving=(1 if r['redundancy']=='ZRS' else int(incident['zone']!=1)) if storage and affected else sum(zone!=incident['zone'] for zone in zones) if affected else count
    online=surviving if r['status']=='running' else 0
    reason='Externer Anbieter; eigener Providerzustand statt Firmen-Lernzonen.' if external else 'Kein passender Lernzonenausfall.' if not affected else 'ZRS-Modell hält Datenzugriff bei einer ausgefallenen Lernzone verfügbar.' if storage and r['redundancy']=='ZRS' else 'Primärer Modellstandort ausgefallen; LRS/GRS schaltet hier nicht automatisch um.' if storage else f'Lernzone {incident["zone"]} ausgefallen: {surviving}/{count} Instanzen verbleiben.'
    if r['status']!='running':reason+=' Ressource ist gestoppt/freigegeben.'
    return dict(online=online,provisioned=count,placement=zones,affected=affected,reason=reason)


def resource_online(s,ident):return resource_availability(s,ident)['online']>0


def document_available(s, document, for_write=False):
    place=s['document_storage'][document];r=s['resources'][place['host']]
    if not resource_online(s,place['host']):return False
    if place['kind']=='Disk':return r['disk_gb']>0 and (not for_write or r['used_gb']<r['disk_gb'])
    return r['configured'] and (not for_write or r['used_gb']<r['capacity_gb'])


def document_profile(s, document):
    place=s['document_storage'][document];r=s['resources'][place['host']]
    return dict(kind=place['kind'],host=place['host'],region=r['region'],tier=r['tier'] if place['kind']!='Disk' else 'attached',redundancy=r['redundancy'] if place['kind']!='Disk' else 'single-disk',anonymous=place['kind']=='Blob' and r['public'],public_ip=r['public_ip'],available=document_available(s,document))


def document_network(s, document, source='hq'):
    place=s['document_storage'][document];host=place['host'];r=s['resources'][host]
    if place['kind']=='Disk':
        allowed=source in (host,r['ip']) and document_available(s,document)
        return dict(allowed=allowed,path=[f'Datenträger an VM {host}; lokaler Dateisystemzugriff erforderlich.','Lokaler Zugriff verfügbar.' if allowed else 'Kein Netzfreigabedienst oder VM/Datenträger nicht verfügbar.'],first_error=None if allowed else 'Lokaler Datenträger')
    endpoint='ablage.intern' if place==dict(kind='Blob',host='storage') else host
    if endpoint=='ablage.intern' and resolve_target(s,endpoint)!=host:return dict(allowed=False,path=['DNS: Ablage zeigt nicht auf den tatsächlichen Blob-Speicher.'],first_error='DNS')
    return connection(s,source,endpoint,445 if place['kind']=='Files' else 443)


def storage_monthly(s):
    return sum(row['storage'] for row in hourly(s))*s['tariffs']['month_hours']


METRIC_KINDS={'VM','App Service','Container Apps'}


def validate_container_values(values):
    if type(values) is not dict or set(values)-{'DB_HOST','DOCUMENT_ID'} or any(type(value) is not str or len(value)>120 for value in values.values()):raise Invalid('Container-Konfiguration: nur DB_HOST und DOCUMENT_ID als Text bis120 Zeichen. Keine Kennwörter, Geheimnisse oder ausführbaren Werte; unbekannte Variablen sind nicht unterstützt.')


def container_context(s,target):
    values=s['container_settings'][target];host=values.get('DB_HOST','');document=values.get('DOCUMENT_ID','');reason=''
    if not host:reason='Container-Konfiguration DB_HOST fehlt.'
    elif resolve_target(s,host)!='db':reason='Container-Konfiguration DB_HOST löst nicht zur modellierten Firmen-Datenbank db auf.'
    elif not document:reason='Container-Konfiguration DOCUMENT_ID fehlt.'
    elif document not in s['documents'] or s['documents'][document]['deleted'] or s['data_governance'][document]['status']=='purged':reason='Container-Konfiguration DOCUMENT_ID verweist auf kein vorhandenes aktives Dokument.'
    else:
        result=connection(s,source=target,host=host,port=s['resources']['db']['port'])
        if not result['allowed']:reason='Container-Konfiguration DB_HOST: '+' → '.join(result['path'])
    return dict(db_host=host,document=document,reason=reason)


def runtime_profile(s,target):
    r=s['resources'].get(target)
    if r is None:return 'none'
    if r['kind']=='Container Apps':return 'shipping'
    if r['kind'] in ('VM','App Service'):
        return 'requests' if any(d['resource']==target for d in s['requests']['deployments'].values()) else 'orders'
    return 'none'


def order_runtime(s,target):return runtime_profile(s,target)=='orders'


def metrics(s, target='web'):
    r=s['resources'].get(target) if type(target) is str else None
    supported=r is not None and r['kind'] in METRIC_KINDS
    container=r is not None and r['kind']=='Container Apps';context=None
    reason='Keine auflösbare Auftragslaufzeit.' if r is None else 'Für diesen Diensttyp ist kein CPU-/RAM-Kapazitätsmodell vorhanden.' if not supported else ''
    if supported:
        if not resource_online(s,target):reason=resource_availability(s,target)['reason']+' Keine verfügbare Laufzeitinstanz.'
        elif not r['configured']:reason='Laufzeitkonfiguration fehlt; keine Leistungsmodellmessung.'
        elif r['kind']=='Container Apps' and (r['image']!='shipping:1.0' or r['port']!=8080):reason='Container-Image oder Dienstport fehlerhaft.'
        elif order_runtime(s,target) and (r['image']!='orders:1.0' or r['port']!=443):reason='Auftrags-Image oder Dienstport fehlerhaft.'
        if not reason and container:
            context=container_context(s,target);reason=context['reason']
        document=context['document'] if context is not None else 'offer'
        if not reason and (r['kind']=='Container Apps' or order_runtime(s,target)):
            db=s['resources']['db']
            if db['kind']!='Database':reason='Firmen-Datenbank db besitzt kein Datenbank-Dienstprofil; ein anderer Ressourcentyp ersetzt keinen Datenbestand.'
            elif not resource_online(s,'db') or not db['configured']:reason='Abhängigkeit Datenbank nicht verfügbar.'
            elif not nsg(s,r['ip'],'db',db['port'],'Outbound')[0] or not nsg(s,r['ip'],'db',db['port'])[0]:reason='Netzpfad zur Datenbank blockiert.'
            elif not document_available(s,document,for_write=True):reason='Dokumentablage nicht verfügbar oder voll.'
            elif not document_network(s,document,source=target)['allowed']:reason='Netzpfad zur Dokumentablage blockiert.'
            elif r['kind']!='Container Apps' and not application_backend_ready(s):reason='Anwendungsidentität oder Datenrolle fehlt.'
    available=supported and not reason
    if not available:return dict(cpu=0,memory=0,response_ms=0,error_rate=100,healthy=False,available=False,supported=supported,reason=reason)
    size=s['tariffs']['sizes'][r['size']];online=resource_availability(s,target)['online'];capacity=size['cpu']*45*online;cpu=min(100,round(s['workload']/capacity*100))
    return dict(cpu=cpu,memory=min(100,round(s['workload']/(size['ram']*online*20)*100)),response_ms=round(100+cpu*3+max(0,s['workload']-capacity)*20),error_rate=min(100,round(max(0,s['workload']-capacity)/max(1,s['workload'])*100)),healthy=True,available=True,supported=True,reason='Deterministisches Dienst-/Kapazitätsmodell; keine echte Hosttelemetrie.')


def metric_sample(s):
    target=resolve_target(s);m=metrics(s,target)
    return dict(minute=s['minute'],target=target or '',**{k:v for k,v in m.items() if k!='supported'})


def validate_metric_sample(row,minute):
    base={'minute','cpu','memory','response_ms','error_rate','healthy'};extra={'target','available','reason'}
    if type(row) is not dict or not base<=set(row) or set(row)-base-extra or (set(row)&extra and not extra<=set(row)):raise Invalid('Metrikpunkt benötigt vollständige Werte und zusammengehörigen Quellenkontext.')
    number(row['minute'],0,minute,True)
    for k in ('cpu','memory','error_rate'):number(row[k],0,100,True)
    number(row['response_ms'],0,100000,True)
    if type(row['healthy']) is not bool:raise Invalid('Metrikzustand benötigt booleschen Wert.')
    if extra<=set(row):
        if type(row['target']) is not str or len(row['target'])>120 or type(row['reason']) is not str or not row['reason'].strip() or len(row['reason'])>2000 or type(row['available']) is not bool or row['available']!=row['healthy']:raise Invalid('Metrikquellenkontext ungültig.')
        if row['available'] and not row['target']:raise Invalid('Verfügbarer Metrikpunkt benötigt eine Quelle.')
        if not row['available'] and any(row[k]!=0 for k in ('cpu','memory','response_ms')):raise Invalid('Nicht verfügbare Modellwerte dürfen keine Leistungswerte vortäuschen.')
    # Exact old values remain valid, but absence of context is never filled from current DNS.


def resolve_target(s, host='auftrag.intern'):
    value=s['network']['dns'].get(host,host)
    if value in s['resources']:return value
    return next((key for key,r in s['resources'].items() if value and value in (r['ip'],r['public_ip'])),None)


def connection(s, source='hq', host='auftrag.intern', port=443, protocol='TCP'):
    path=[]
    resolved=s['network']['dns'].get(host,host)
    target=resolve_target(s,host)
    if target is None:return dict(allowed=False,path=['DNS: Name oder zugeordnete Adresse nicht auflösbar.'],first_error='DNS')
    r=s['resources'][target]
    if target=='db' and r['kind']!='Database':return dict(allowed=False,path=['Dienstprofil: Firmen-Datenbank db ist kein Database-Lernservice. Ein anderer Typ übernimmt nicht automatisch SQL-/Auftragsdaten.'],first_error='Datenbankprofil')
    if r['kind']=='SaaS':
        ready=r['status']=='running' and r['configured'] and port==443 and protocol=='TCP'
        return dict(allowed=ready,path=[f'DNS: {host} → externer SaaS-Anbieter','Externer HTTPS-Dienst: Anbieter betreibt Infrastruktur.']+([] if ready else ['Anbieterdienst nicht verfügbar oder kein HTTPS/TCP-Port 443.']),first_error=None if ready else 'SaaS-Dienst')
    cloud_target=resolve_target(s) or 'web'
    cloud_ip=s['resources'].get(cloud_target,s['resources']['web'])['ip']
    ip={'hq':'10.10.1.5','branch':'10.10.2.5','internet':'203.0.113.10','cloud':cloud_ip}.get(source,s['resources'].get(source,{}).get('ip',source))
    try:origin=ipaddress.IPv4Address(ip)
    except ValueError as e:raise Invalid('IPv4-Quelladresse oder private Ressourcenkennung erwartet.') from e
    from_onprem=origin in ipaddress.ip_network(s['network']['onprem'])
    from_cloud=origin in ipaddress.ip_network(s['network']['vnet'])
    named=resolved==target
    destination=(r['ip'] if from_onprem or from_cloud else r['public_ip']) if named else resolved
    path.append(f'DNS: {host} → {destination or "kein öffentlicher Endpunkt"} ({target})')
    public_path=bool(r['public_ip'] and destination==r['public_ip'])
    if not public_path and not (from_onprem or from_cloud):return dict(allowed=False,path=path+['Route: private Adresse ist aus dem Internet nicht erreichbar; öffentliche IP zuweisen.'],first_error='Route')
    if not public_path and from_onprem and not s['network']['vpn']:return dict(allowed=False,path=path+['Route: Standort-VPN unterbrochen.'],first_error='VPN')
    if public_path:
        path.append(f'Route: öffentlicher Lern-Endpunkt {r["public_ip"]} → private Adresse {r["ip"]}')
        inbound_source='203.0.113.10' if from_onprem or from_cloud else ip
        if inbound_source!=ip:path.append('Lernannahme: Internetabgang wird als externer Client 203.0.113.10 geprüft; kein vollständiges NAT-Modell.')
    else:
        inbound_source=ip
        path.append(('Route: Standort-VPN → ' if from_onprem else 'Route: VNet → ')+f'Subnetz {r["subnet"]} ({s["network"]["subnets"][r["subnet"]]})')
    if from_cloud:
        allowed,reason=nsg(s,ip,target,port,'Outbound',protocol,destination_ip=destination)
        path.append(reason)
        if not allowed:return dict(allowed=False,path=path,first_error='NSG Outbound')
    allowed,reason=nsg(s,inbound_source,target,port,'Inbound',protocol)
    path.append(reason)
    if not allowed:return dict(allowed=False,path=path,first_error='NSG Inbound')
    if not resource_online(s,target):return dict(allowed=False,path=path+[resource_availability(s,target)['reason']],first_error='Verfügbarkeit')
    if r['status'] != 'running' or r['port'] != port or not r['configured'] or protocol != 'TCP':
        return dict(allowed=False, path=path + ['Dienst: gestoppt, falscher Port oder fehlende Konfiguration.'], first_error='Dienst')
    document='offer'
    if r['kind']=='Container Apps':
        context=container_context(s,target)
        if context['reason']:return dict(allowed=False,path=path+[context['reason']],first_error='Container-Konfiguration')
        document=context['document'];path.append('Container-Konfiguration: DB_HOST='+context['db_host']+' → db; DOCUMENT_ID='+document+'. Dienstprüfung ist noch keine Benutzer-Datenfreigabe.')
    if r['kind']=='Container Apps' or order_runtime(s,target):
        for dep in ('db',):
            dep_r = s['resources'][dep]
            ok_out, why_out = nsg(s, r['ip'], dep, dep_r['port'], 'Outbound')
            ok_in, why_in = nsg(s, r['ip'], dep, dep_r['port'])
            path.extend([f'Abhängigkeit {dep}: {why_out}', why_in])
            if not ok_out or not ok_in or not resource_online(s,dep):
                return dict(allowed=False, path=path, first_error=f'Abhängigkeit {dep}')
        data_path=document_network(s,document,source=target);path.extend(data_path['path'])
        if not data_path['allowed']:return dict(allowed=False,path=path,first_error='Abhängigkeit '+s['document_storage'][document]['host'])
        if order_runtime(s,target) and not application_backend_ready(s):
            return dict(allowed=False,path=path+['Anwendung: Dienstidentität oder explizite Datenrolle für Datenbank/Ablage fehlt.'],first_error='Anwendungsidentität')
        m = metrics(s, target)
        if not m['healthy'] or m['error_rate'] > 0:
            return dict(allowed=False, path=path + ['Anwendung: '+m['reason'] if not m['available'] else 'Anwendung: Restkapazität reicht für die aktuelle Last nicht aus.'], first_error='Anwendung')
    return dict(allowed=True, path=path + ['Dienst: erreichbar; Anmeldung und Datenrechte separat prüfen.'], first_error=None)


def management_access(s,user='u11',target='web',operation='read',mfa=True):
    """Test the same modeled sign-in and scoped rights as management actions, without a data path."""
    if type(user) is not str or not user.strip() or len(user)>120 or type(target) is not str or not target.strip() or len(target)>120 or type(mfa) is not bool or operation not in ('read','manage','assign'):
        raise Invalid('Verwaltungsprüfung benötigt Benutzer, Geltungsbereich, read/manage/assign und booleschen Lern-MFA-Nachweis.')
    known={'subscription','sales','hr','public','orders','requests'}|set(s['resources'])|set(s['documents'])|set(s['resource_groups'])
    if target not in known:raise Invalid('Unbekannter Geltungsbereich für Verwaltungsprüfung.')
    if operation!='assign' and target not in ({'subscription'}|set(s['resources'])|set(s['resource_groups'])):raise Invalid('Ansehen/Verwalten benötigt Subscription, Ressourcengruppe oder Ressource. Container-/Dokument-/Anwendungsbereiche sind hier nur für Rollenvergabe unterstützt.')
    signed,why=login(s,user,mfa);rights,grants=effective(s,user,target)
    allowed=bool(signed and operation in rights)
    reason=why if not signed else 'Passendes Verwaltungsrecht vorhanden.' if operation in rights else 'Die wirksamen Rollen enthalten dieses Verwaltungsrecht nicht.'
    return dict(kind='management',allowed=allowed,authenticated=signed,authentication=why,user=user,target=target,operation=operation,rights=sorted(rights),grants=copy.deepcopy(grants),reason=reason+' Datei-Netzpfad und Dateidatenrechte sind eigene Prüfungen; diese Diagnose führt keine Verwaltungsänderung aus.')


def access(s, user='lea', document='offer', operation='data_read', mfa=True, source='hq'):
    if document not in s['documents']:
        raise Invalid('Dokument nicht vorhanden.')
    if operation=='assign':return management_access(s,user,document,'assign',mfa)
    d = s['documents'][document]
    net = document_network(s,document,source)
    rights, grants = effective(s, user, document)
    signed, why = login(s, user, mfa)
    place=s['document_storage'][document]
    public = place['kind']=='Blob' and s['resources'][place['host']]['public'] and operation == 'data_read'
    allowed = not d['deleted'] and net['allowed'] and ((signed and operation in rights) or public)
    return dict(allowed=allowed, network=net, authentication=why, grants=grants, rights=sorted(rights),
                reason=('Öffentlicher Blob-Lesezugriff; Anmeldung umgangen.' if public else
                        f"{operation}: {'erlaubt' if allowed else 'verweigert'}; Netzwerk, Anmeldung und Datenrolle werden getrennt geprüft."))


def application_access(s, user='u11', source='hq', operation='orders_read', mfa=True):
    """Check network, human sign-in, application role and backend identity separately."""
    if operation not in ('orders_read', 'orders_write'): raise Invalid('Auftragsoperation nicht unterstützt.')
    net = connection(s, source=source)
    signed, why = login(s, user, mfa)
    rights, grants = effective(s, user, 'orders')
    runtime=resolve_target(s);supported=order_runtime(s,runtime)
    backend = s['application']['principal']
    identity = s['service_principals'][backend]
    backend_rights, _ = effective(s, backend, 'orders')
    backend_storage, _ = effective(s, backend, 'offer')
    if not net['allowed']: reason = f"Verbindung verweigert ({net['first_error']}): {net['path'][-1]}"
    elif not supported:reason='DNS-Ziel stellt im Lernmodell keine Auftragslaufzeit bereit; Büro-SaaS, Storage und beliebige andere Dienste ersetzen diese Anwendung nicht.'
    elif not signed: reason = why
    elif operation not in rights: reason = 'Anmeldung erfolgreich, aber die passende Auftrags-Datenrolle fehlt.'
    elif not identity['active']: reason = 'Dienstidentität der Anwendung ist deaktiviert.'
    elif operation not in backend_rights: reason = 'Dienstidentität besitzt keine passende Datenbank-Datenrolle.'
    elif 'data_read' not in backend_storage: reason = 'Dienstidentität kann die zugehörige Angebotsablage nicht lesen.'
    else: reason = 'Netzpfad, Anmeldung, Auftragsrolle und Dienstidentität erlauben die Operation.'
    allowed = supported and net['allowed'] and signed and operation in rights and identity['active'] and operation in backend_rights and 'data_read' in backend_storage
    return dict(allowed=bool(allowed),network=net,authentication=why,grants=grants,rights=sorted(rights),reason=reason)


def order_application(s, user='u11', source='hq', mfa=True):
    authorization = application_access(s,user,source,'orders_read',mfa)
    rows=[]
    if authorization['allowed']:
        for ident, order in s['orders'].items():
            d=s['documents'][order['document']]
            human_access=access(s,user,order['document'],mfa=mfa,source=resolve_target(s) or 'web')
            service_access='data_read' in effective(s,s['application']['principal'],order['document'])[0]
            attachment_allowed=human_access['allowed'] and service_access
            rows.append(dict(id=ident,**copy.deepcopy(order),attachment=dict(allowed=attachment_allowed,
                name=d['name'],content=d['content'] if attachment_allowed else '',
                reason=human_access['reason'] if service_access else 'Datenrolle der Dienstidentität fehlt.')))
    return dict(authorization=authorization,orders=rows)



def request_rows(s):
    return s['requests']['provider' if s['requests']['active']=='SaaS' else 'company']


def request_access(s,user='u11',source='hq',operation='request_read',mfa=True):
    if operation not in ('request_read','request_write'):raise Invalid('Anfrageoperation nicht unterstützt.')
    state=s['requests'];model=state['active'];deployment=state['deployments'].get(model)
    net=dict(allowed=False,path=['Anfrageannahme noch nicht bereitgestellt/ausgewählt.'],first_error='Bereitstellung')
    signed,why=login(s,user,mfa);rights=set();grants=[];reason=net['path'][0]
    if deployment:
        target=deployment['resource'];net=connection(s,source,'anfrage.intern',443)
        if resolve_target(s,'anfrage.intern')!=target:net=dict(allowed=False,path=['DNS zeigt nicht auf die ausgewählte Anfragebereitstellung.'],first_error='DNS')
        role=deployment['members'].get(user)
        rights={'request_read','request_write'} if role=='Operator' else {'request_read'} if role=='Reader' else set()
        if role:grants=[dict(principal=user,role='Anfrage '+role,scope=target)]
        if not net['allowed']:reason='Netzpfad: '+str(net['first_error'])
        elif model=='SaaS' and len(deployment['members'])>deployment['seats']:reason='SaaS: nicht genügend Benutzerlizenzen.'
        elif model!='SaaS' and not deployment['patched']:reason='IaaS: Betriebssystem-Patches fehlen.'
        elif model!='SaaS' and deployment['app_version']!='requests:1.0':reason='Unternehmensanwendung: falsche oder fehlende Version.'
        elif model!='SaaS' and metrics(s,target)['error_rate']>20:reason='Kapazität: simulierte Fehlerrate über 20 Prozent.'
        elif model!='SaaS' and (resolve_target(s,'daten.intern')!='db' or not connection(s,target,'daten.intern',s['resources']['db']['port'])['allowed']):reason='Firmen-Datenbankpfad nicht verfügbar.'
        elif model!='SaaS' and (not s['service_principals'].get('requests-app',{}).get('active') or operation not in effective(s,'requests-app','requests')[0]):reason='Dienstidentität oder Datenbank-Datenrolle fehlt.'
        elif not signed:reason=why
        elif operation not in rights:reason='Anmeldung allein genügt nicht: passende Anwendungsrolle fehlt.'
        else:reason='Erlaubt: ausgewählter Dienst, Netzpfad, Anmeldung und Anwendungsrolle geprüft.'
    return dict(allowed=reason.startswith('Erlaubt:'),network=net,authentication=why,grants=grants,rights=sorted(rights),reason=reason)


def request_application(s,**auth):
    authorization=request_access(s,operation='request_read',**auth)
    return dict(authorization=authorization,model=s['requests']['active'],requests=[dict(id=key,**row) for key,row in request_rows(s).items()] if authorization['allowed'] else [])


def request_monthly(s):
    owned={d['resource'] for d in s['requests']['deployments'].values()}
    return sum(row['total'] for row in hourly(s) if row['resource'] in owned)*s['tariffs']['month_hours']


def migration_fingerprint(s):
    return hashlib.sha256(json.dumps(dict(documents=s['documents'],document_storage=s['document_storage'],orders=s['orders']),ensure_ascii=True,sort_keys=True).encode('utf-8')).hexdigest()


def migration_assessment(s, workload='ORDER-01'):
    inventory=next((r for r in s['local_inventory'] if r['name']==workload),None)
    if inventory is None:raise Invalid('Inventarsystem unbekannt.')
    is_order=workload=='ORDER-01'
    source=s['resources']['web'];source_ok=connection(s,host='web')['allowed']
    common=[dict(label='Auftragsanwendung als ausführbarer Modellumfang ausgewählt',passed=is_order),
            dict(label='Quell-VM und ihre Daten-/Identitätsabhängigkeiten erreichbar',passed=source_ok),
            dict(label='Angebotsdaten vorhanden',passed=not s['documents']['offer']['deleted'])]
    options=[]
    for strategy,title,target,responsibility in [
        ('rehost','Rehost · eigene Ziel-VM (IaaS)','migrationvm','Unternehmen: Betriebssystem, Updates, Anwendung, Daten, Zugriffe und Backup. Anbieter: physische Infrastruktur.'),
        ('replatform','Replatform · App Service (PaaS)','paas','Anbieter: Betriebssystem und Plattform. Unternehmen: Anwendung, Konfiguration, Daten, Identitäten und Sicherungskonzept.'),
        ('replace','Replace · vorhandener SaaS-Dienst','saas','Anbieter: Laufzeit und fertige Anwendung. Unternehmen: fachliche Eignung, Daten, Berechtigungen und Vertragsprüfung.'),
        ('retain','Retain · Bestand weiterbetreiben','web','Unternehmen betreibt und sichert den bisherigen Dienst weiter; keine Cloud-Umschaltung.')]:
        checks=copy.deepcopy(common)
        if strategy in ('rehost','replatform'):checks.append(dict(label='Lernumzug nutzt gemeinsame Blob-/Files-Ablage; lokale Datenträgerkopie wird nicht modelliert',passed=s['document_storage']['offer']['kind'] in ('Blob','Files')))
        if strategy=='replatform':
            checks.append(dict(label='Lernprofil: Linux-Webanwendung ohne Windows-/Domänenbindung',passed=source['os']=='Linux'))
            checks.append(dict(label='Vorbereitetes Ziel ist App Service',passed=s['resources']['paas']['kind']=='App Service'))
        elif strategy=='rehost':checks.append(dict(label='Quelllaufzeit ist eine VM',passed=source['kind']=='VM'))
        elif strategy=='replace':checks.append(dict(label='Vorhandene Büro-SaaS bietet Aufträge und Dokumentintegration',passed=False))
        else:checks=[dict(label='Bestand bewusst beibehalten; kein technischer Migrationsablauf',passed=True)]
        supported=is_order and strategy in ('rehost','replatform')
        options.append(dict(strategy=strategy,title=title,target=target,checks=checks,
                            suitable=all(c['passed'] for c in checks),executable=supported,
                            responsibility=responsibility,
                            consequence=('Zusätzliche VM mit eigener Compute-/Disk-Abrechnung; Quelle bleibt bis zur Nachkontrolle bestehen.' if strategy=='rehost' else
                                         'Plattformbetrieb entfällt für die Lernfirma; Zielkonfiguration und Datenzugriff bleiben ihre Aufgabe.' if strategy=='replatform' else
                                         'Der vorhandene externe Büro-Dienst ersetzt die Auftragsfunktion nicht; kein Scheinimport in eine SaaS-VM.' if strategy=='replace' else
                                         'Kein Umzug, kein Migrationsabschluss; bestehende Kosten und Verantwortungen bleiben.')))
    return dict(workload=workload,inventory=copy.deepcopy(inventory),options=options,
                boundary='Eignung ist ein vereinfachtes Lernprofil, keine Azure-Migrate-Kompatibilitätsprüfung. Technischer Ablauf nur für ORDER-01; Datenbank und Ablage bleiben gemeinsame Dienste. Lokaler AD-/Datei-/SQL-/Backup-Betrieb ist im eigenen Bereich bedienbar; dieser bestehende Cloud-Laufzeitpfad kopiert seinen lokalen Datenbestand jedoch noch nicht und konvertiert keine Domäne automatisch zu Entra oder App Service.')


def migration_choice(s, require_ready=True):
    d=s['decisions'];strategy=d.get('migration_strategy')
    if not d.get('migration_reason','').strip():raise Invalid('Migrationsentscheidung und Begründung fehlen.')
    assessment=migration_assessment(s,d.get('migration_workload','ORDER-01'))
    option=next((o for o in assessment['options'] if o['strategy']==strategy),None)
    if option is None or not option['executable']:raise Invalid('Für diese Auswahl ist kein technischer Migrationsablauf modelliert.')
    if require_ready and not option['suitable']:
        raise Invalid('Eignungsprüfung nicht bestanden: '+'; '.join(c['label'] for c in option['checks'] if not c['passed']))
    return option


def migration_target_ready(s):
    target=s['migration']['target']
    return target in s['resources'] and connection(s,host=target,port=443)['allowed'] and not connection(s,source='internet',host=target,port=22)['allowed']


def upgrade_snapshot(raw):
    """Convert only exact known versions; persistence must preserve the original first."""
    if type(raw) is not dict or type(raw.get('schema')) is not int:raise Invalid('Unbekanntes Speicherformat.')
    if raw['schema']==VERSION:return validate(copy.deepcopy(raw))
    if raw['schema'] not in (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16):raise Invalid('Nicht unterstützte Speicherformat-Version; Original bleibt erhalten.')
    # A claimed old format cannot contain the newly introduced diagnostic language.
    for item in raw.get('diagnostics',[]) if type(raw.get('diagnostics')) is list else []:
        if type(item) is dict and (item.get('test')=='management' or (type(item.get('result')) is dict and item['result'].get('kind')=='management')):raise Invalid('Altes Format enthält eine erst ab Schema17 unterstützte Verwaltungsdiagnose.')
    for item in raw.get('events',[]) if type(raw.get('events')) is list else []:
        if type(item) is dict and item.get('kind')=='diagnostic' and type(item.get('detail')) is dict and item['detail'].get('kind')=='management':raise Invalid('Altes Format enthält ein erst ab Schema17 unterstütztes Diagnoseereignis.')
    if raw['schema']==16:
        upgraded=copy.deepcopy(raw);upgraded['schema']=VERSION
        if type(upgraded.get('seq')) is not int:raise Invalid('Alte Änderungsnummer ungültig.')
        upgraded['seq']+=1;validate(upgraded)
        event(upgraded,'save_migration','Speicherformat 16 → 17: Verwaltungsdiagnosen ergänzt; bisherige Rollen, Containerwerte und historische Nachweise unverändert erhalten.')
        return validate(upgraded)
    old_version=raw['schema'];seed=fresh();added=({'service_principals','application','order_revision','orders'} if old_version==1 else set())|({'tariffs'} if old_version<4 else set())|({'data_governance'} if old_version<5 else set())|({'requests'} if old_version<6 else set())|({'document_storage'} if old_version<7 else set())|({'onprem'} if old_version<8 else set())|({'local_migration'} if old_version<9 else set())|({'faults'} if old_version<14 else set())|({'availability_event'} if old_version<15 else set())|{'container_settings'}
    if set(raw)!=set(seed)-added:raise Invalid('Altes Speicherformat enthält fehlende oder unbekannte Felder.')
    upgraded=copy.deepcopy(raw)
    for key in added:upgraded[key]=copy.deepcopy(BASE_TARIFFS if key=='tariffs' else seed[key])
    if type(upgraded.get('resources')) is not dict or any(type(r) is not dict for r in upgraded['resources'].values()):raise Invalid('Alte Ressourcen ungültig.')
    upgraded['container_settings']={key:dict(DB_HOST='db',DOCUMENT_ID='offer') for key,r in upgraded['resources'].items() if r.get('kind')=='Container Apps'}
    if type(upgraded.get('documents')) is not dict:raise Invalid('Alte Dokumente ungültig.')
    if type(upgraded.get('users')) is not dict:raise Invalid('Alte Konten ungültig.')
    if old_version<8:upgraded['onprem']=local_seed(upgraded['users'],False,upgraded.get('minute',0))
    if old_version<7:upgraded['document_storage']={key:dict(kind='Blob',host='storage') for key in upgraded['documents']}
    if old_version<5:upgraded['data_governance']={key:data_record('Vertrieb' if doc.get('container')=='sales' else 'IT',origin=key) for key,doc in upgraded['documents'].items() if type(doc) is dict}
    if old_version==1:
        if type(upgraded['roles']) is not list:raise Invalid('Alte Rollenzuweisungen ungültig.')
        upgraded['roles'].extend(copy.deepcopy(seed['roles'][-3:]))
        if type(upgraded['migration']) is dict and 'copied_version' in upgraded['migration']:upgraded['migration']['copied_order_revision']=0
    if old_version<3:
        net=upgraded['network']
        if type(net) is not dict or set(net)!={'vnet','subnet','onprem','vpn','dns','rules'}:raise Invalid('Alte Netzwerkfelder ungültig.')
        net['subnets']={'legacy':net.pop('subnet')}
        if type(upgraded['resources']) is not dict:raise Invalid('Alte Ressourcen ungültig.')
        public_index=10
        for ident,r in sorted(upgraded['resources'].items()):
            if type(r) is not dict or set(r)!=RESOURCE_FIELDS-{'subnet','public_ip'}:raise Invalid('Alte Ressourcenfelder fehlen oder sind unbekannt.')
            r['subnet']='' if r['kind']=='SaaS' else 'legacy';r['public_ip']=''
            if r['public'] and r['kind']!='SaaS':
                if public_index>254:raise Invalid('Zu viele öffentliche Endpunkte für den Lernadresspool.')
                r['public_ip']=f'198.51.100.{public_index}';public_index+=1
    if old_version<10:initialize_business_governance(upgraded)
    if old_version<12:
        if type(upgraded.get('alerts')) is not list:raise Invalid('Alte Warnungen ungültig.')
        for alert in upgraded['alerts']:
            if type(alert) is not dict or set(alert)!={'minute','rule','message'}:raise Invalid('Alte Warnung enthält fehlende oder unbekannte Felder.')
            alert.update(kind='legacy',detail={})
    upgraded['schema']=VERSION
    if type(upgraded['seq']) is not int:raise Invalid('Alte Änderungsnummer ungültig.')
    upgraded['seq']+=1
    validate(upgraded)
    event(upgraded,'save_migration',f'Speicherformat {old_version} → {VERSION}: Geschäftsinhalte und Datenregeln erhalten. Frühere Konfigurationen und Historien bleiben erhalten. Neue Trainerstörungen erfassen nur eigene Änderungen; für ältere Störungen wird kein ursprünglicher Wert geraten.')
    return validate(upgraded)


def next_private_ip(s, subnet, preferred=None):
    if subnet not in s['network']['subnets']:raise Invalid('Zielsubnetz fehlt.')
    net=ipaddress.ip_network(s['network']['subnets'][subnet]);used={r['ip'] for r in s['resources'].values()}
    if preferred and ipaddress.ip_address(preferred) in net and preferred not in used:return preferred
    for offset in range(4,min(net.num_addresses-1,len(used)+5)):
        address=str(net.network_address+offset)
        if address not in used:return address
    raise Invalid('Im Zielsubnetz ist keine nutzbare private Adresse frei.')


def hourly(s):
    rows = [];t=s['tariffs']
    for key, r in s['resources'].items():
        compute = t['sizes'][r['size']]['compute_hour'] * r['instances'] if r['kind']=='App Service' or (r['status'] != 'deallocated' and r['kind'] in ('VM', 'Container Apps', 'Database')) else 0
        disk = r['disk_gb'] * t['vm_disk_gb_hour'] if r['kind'] == 'VM' else 0
        storage = r['used_gb'] * t['storage_gb_hour'][r['tier']] * t['redundancy_multiplier'][r['redundancy']] if r['kind'] in ('Storage','File Share') else 0
        seats=s['requests']['deployments'].get('SaaS',{}).get('seats',1) if key=='requestsaas' else 1
        service = t['saas_hour']*seats if r['kind'] == 'SaaS' else 0
        traffic = s['workload'] * t['traffic_load_hour'] if (order_runtime(s,key) or (runtime_profile(s,key)=='requests' and r['kind'] in ('VM','App Service'))) and r['status'] == 'running' else 0
        rows.append(dict(resource=key, department=r['department'], compute=compute, disk=disk, storage=storage, traffic=traffic, service=service, total=compute + disk + storage + traffic + service))
    return rows


RECOVERY_CONTEXT={'outage_minute','rpo_limit','rto_limit'}


def recovery_context(s,values):
    result={}
    for key in RECOVERY_CONTEXT:
        value=values.get(key)
        if value is not None:result[key]=number(value,0,s['minute'] if key=='outage_minute' else 43200,True)
    return result


def validate_recovery_job(job,minute):
    if job is None:return
    start=job.get('started',job.get('started_minute'))
    if start is not None and (type(start) is not int or not 0<=start<=minute):raise Invalid('Wiederherstellungsbeginn ungültig.')
    for key in RECOVERY_CONTEXT:
        if key not in job:continue
        limit=start if key=='outage_minute' else 43200
        if limit is None or type(job[key]) is not int or not 0<=job[key]<=limit:raise Invalid('Erfasster Ausfallbeginn oder Wiederherstellungsziel ungültig.')
    if 'finished_minute' in job:
        finish=job['finished_minute']
        if type(finish) is not int or not 0<=finish<=minute or (start is not None and finish<start) or job['status']=='running':raise Invalid('Wiederherstellungsabschluss widerspricht Uhr oder Status.')


def recovery_timing(job,minute):
    if job is None:return None
    start=job.get('started',job.get('started_minute'));finish=job.get('finished_minute');outage=job.get('outage_minute');point=job['point_minute'];success=job['status']=='success'
    planned=job.get('duration',job['due']-job.get('started',job['due']-5))
    rpo=None if outage is None else max(0,outage-point)
    recovered=None if not success or finish is None or outage is None else finish-outage
    return dict(status=job['status'],point_minute=point,started_minute=start,finished_minute=finish,outage_minute=outage,planned_minutes=planned,
        point_age_at_start=(start-point if start is not None else job.get('rpo')),attempt_minutes=(finish-start if start is not None and finish is not None else minute-start if start is not None and job['status']=='running' else None),
        rpo_minutes=rpo,rpo_limit=job.get('rpo_limit'),rpo_within_limit=None if rpo is None or 'rpo_limit' not in job else rpo<=job['rpo_limit'],
        recovery_minutes=recovered,rto_limit=job.get('rto_limit'),rto_within_limit=None if recovered is None or 'rto_limit' not in job else recovered<=job['rto_limit'],
        elapsed_since_outage=None if outage is None else (finish if success and finish is not None else minute)-outage,
        point_after_outage=outage is not None and point>outage,completion_recorded=finish is not None,
        reason=job.get('failure_reason',job.get('reason','')),
        boundary='Zeiten bis zum gewählten Ziel-Datenbestand. Alternative Kopie bedeutet noch keinen vollständigen Anwendungswiederanlauf. Historische fehlende Zeitstempel werden nicht erfunden.')


def recovery_record(row,kind):
    if row is None:return None
    fields=('name','container','class','content','deleted','version','modified') if kind=='document' else ('customer','subject','amount','status','document','version','modified')
    summary={key:copy.deepcopy(row[key]) for key in fields}
    if kind=='document':summary['history_count']=len(row['versions'])
    return summary


def recovery_changes(current,point,kind):
    rows=[]
    for key in sorted(set(current)|set(point)):
        before=current.get(key);saved=point.get(key)
        if before==saved:continue
        fields=sorted(set(before or {})|set(saved or {}));changed=[field for field in fields if before is None or saved is None or before.get(field)!=saved.get(field)]
        rows.append(dict(kind=kind,id=key,change='new_since_point' if saved is None else 'missing_now' if before is None else 'changed',fields=changed,current=recovery_record(before,kind),point=recovery_record(saved,kind)))
    return rows


def restore_preview(s,area,point,scope='file',id=None,target=None,actor='it',outage_minute=None,rpo_limit=None,rto_limit=None):
    if area not in ('cloud','local') or scope not in ('file','application') or (area=='cloud' and scope!='file'):raise Invalid('Cloud-Datei, lokale Datei oder lokalen Gesamtbestand wählen.')
    for value in (point,actor):
        if type(value) is not str or not value.strip() or len(value)>120:raise Invalid('Vorhandenen Punkt und gültige Lernidentität wählen.')
    if area=='local' and not s['onprem']['enabled']:raise Invalid('Lokaler Datenbereich ist nicht eingerichtet.')
    b=s['backup'] if area=='cloud' else s['onprem']['backup'];saved=next((row for row in b['points'] if row['id']==point),None)
    if saved is None:raise Invalid('Der gewählte vorhandene Wiederherstellungspunkt fehlt.')
    docs=s['documents'] if area=='cloud' else s['onprem']['documents'];orders={} if area=='cloud' else s['onprem']['orders']
    parameters=dict(point=point,actor=actor);action='restore' if area=='cloud' else 'local_restore'
    if area=='local':parameters['scope']=scope
    if scope=='file':
        if type(id) is not str or id not in set(docs)|set(saved['documents']):raise Invalid('Vorhandenes Dokument im aktuellen Bestand oder gewählten Punkt wählen.')
        target=id+'-restored' if target is None else target
        if type(target) is not str or not target.strip() or len(target)>120:raise Invalid('Gültiges Dateiziel wählen.')
        parameters.update(id=id,target=target)
    context=recovery_context(s,dict(outage_minute=outage_minute,rpo_limit=rpo_limit,rto_limit=rto_limit));parameters.update(context)
    changes=recovery_changes(docs,saved['documents'],'document')
    if area=='local':changes+=recovery_changes(orders,saved['orders'],'order')
    effects=[];blocked='';projection=None
    try:
        projection,_=act(s,action,**parameters)
        projection,_=act(projection,'advance',minutes=5)
        job=projection['backup']['restore'] if area=='cloud' else projection['onprem']['backup']['restore']
        if not job or job['status']!='success':raise Invalid((job or {}).get('failure_reason',(job or {}).get('reason','Wiederherstellung wäre nicht erfolgreich.')))
        after_docs=projection['documents'] if area=='cloud' else projection['onprem']['documents']
        if scope=='file':
            effects=[dict(kind='document',id=target,current=recovery_record(docs.get(target),'document'),expected=recovery_record(after_docs[target],'document'),effect='replace_active_preserve_history' if target==id and target in docs else 'create_copy_keep_original')]
        else:
            for row in recovery_changes(docs,after_docs,'document')+recovery_changes(orders,projection['onprem']['orders'],'order'):
                effects.append(dict(kind=row['kind'],id=row['id'],current=row['current'],expected=row['point'],effect='remove_from_active_store' if row['point'] is None else 'restore_active_store'))
    except Invalid as error:blocked=str(error)
    start=s['minute'];outage=context.get('outage_minute');gap=None if outage is None else max(0,outage-saved['minute']);projected_recovery=None if outage is None or blocked else start+5-outage
    return dict(kind='restore_preview',area=area,scope=scope,point=point,point_minute=saved['minute'],snapshot_minute=start,point_age_minutes=start-saved['minute'],source=id if scope=='file' else '',target=target if scope=='file' else '',
        can_start=not blocked,blocked_reason=blocked,action=action,parameters=parameters,changes=changes,effects=effects,
        planned_minutes=5,expected_finish_minute=None if blocked else start+5,outage_minute=outage,rpo_minutes=gap,rpo_limit=context.get('rpo_limit'),rpo_within_limit=None if gap is None or 'rpo_limit' not in context else gap<=context['rpo_limit'],
        projected_recovery_minutes=projected_recovery,rto_limit=context.get('rto_limit'),projected_rto_within_limit=None if projected_recovery is None or 'rto_limit' not in context else projected_recovery<=context['rto_limit'],point_after_outage=outage is not None and saved['minute']>outage,
        preservation='Original bleibt unverändert; Punktfassung wird separat angelegt.' if scope=='file' and target!=id else 'Neuere aktuelle Fassung bleibt zusätzlich als Version erhalten.' if scope=='file' else 'Aktiver lokaler Datei-/Auftragsbestand wird ersetzt; vorheriger Gesamtbestand wird als zusätzlicher Modellpunkt erhalten.',
        not_covered=['Cloud-Aufträge, Laufzeiten, Identitäten und Netzkonfiguration werden durch den Cloud-Dateipunkt nicht zurückgesetzt.'] if area=='cloud' else ['Aktuelle Datenregeln und Cloud-Geschäftsdaten werden nicht durch den lokalen Punkt zurückgesetzt.'],
        assumptions='Reine Vorschau derselben Modelllogik auf einer Kopie. Fünf Minuten ohne weitere Änderungen/Störungen angenommen; echte Uhr, Kosten, Revision und Daten bleiben unverändert. Quelle/Ziel werden beim tatsächlichen Start erneut geprüft. RPO-Vergleich benötigt angegebenen Ausfallbeginn; Punktalter allein ist kein konkreter Datenverlust. RTO bezieht sich auf den gewählten Zielbestand, nicht automatisch auf den gesamten Geschäftsdienst.')


FAULT_TITLES={'vpn':'VPN unterbrochen','service':'Aktiver Cloud-Auftragsdienst gestoppt','storage':'Backupablage storage voll','container':'Container-Image fehlerhaft','data':'Vertriebs-Datenrolle fehlt','migration':'Cloud-Laufzeitmigration unterbrochen','nsg':'NSG zum aktiven Auftragsziel','document_source':'Beleg-Speicher ausgefallen','request_provider':'Anfrage-SaaS-Anbieter ausgefallen'}
FAULT_ROLE=dict(principal='Vertrieb',role='Blob Contributor',scope='sales')


def fault_value(s,p):
    k,t=p['kind'],p['target']
    if k=='status':return s['resources'][t]['status']
    if k=='usage':return s['resources'][t]['used_gb']
    if k=='image':return s['resources'][t]['image']
    if k=='vpn':return s['network']['vpn']
    if k=='migration':return s['migration']['interrupted']
    if k=='role':return [i for i,r in enumerate(s['roles']) if r==FAULT_ROLE]
    return next((copy.deepcopy(r) for r in s['network']['rules'] if r['id']==t),None)


def fault_equal(p,a,b):return len(a)==len(b) if p['kind']=='role' else a==b


def fault_write(s,p,value):
    k,t=p['kind'],p['target']
    if k=='status':s['resources'][t]['status']=value
    elif k=='usage':s['resources'][t]['used_gb']=value
    elif k=='image':s['resources'][t]['image']=value
    elif k=='vpn':s['network']['vpn']=value
    elif k=='migration':s['migration']['interrupted']=value
    elif k=='role':
        s['roles']=[r for r in s['roles'] if r!=FAULT_ROLE]
        for index in value:s['roles'].insert(min(index,len(s['roles'])),copy.deepcopy(FAULT_ROLE))
    else:
        s['network']['rules']=[r for r in s['network']['rules'] if r['id']!=t]
        if value is not None:s['network']['rules'].append(copy.deepcopy(value))


def fault_patch(s,ident):
    if ident in ('service','nsg'):
        target=resolve_target(s)
        if target not in s['resources'] or s['resources'][target]['kind'] not in METRIC_KINDS:raise Invalid('Auftrags-DNS muss für diese Störung auf eine modellierte Laufzeit zeigen.')
    elif ident=='document_source':target=s['document_storage']['offer']['host']
    elif ident=='request_provider':
        if 'SaaS' not in s['requests']['deployments']:raise Invalid('Anfrage-SaaS-Anbieter zuerst abonnieren.')
        target=s['requests']['deployments']['SaaS']['resource']
    elif ident=='storage':target='storage'
    elif ident=='container':target='container'
    else:target=''
    kind='status' if ident in ('service','document_source','request_provider') else 'usage' if ident=='storage' else 'image' if ident=='container' else 'role' if ident=='data' else ident
    if ident=='nsg':
        port=s['resources'][target]['port'];nets=[s['network']['vnet'],s['network']['onprem']]
        relevant=[r['priority'] for r in s['network']['rules'] if r['direction']=='Inbound' and r['protocol'] in ('TCP','*') and r['port'] in (0,port) and (r['destination'] in ('*',target) or match_address(r['destination'],s['resources'][target]['ip'],nets))]
        used={r['priority'] for r in s['network']['rules'] if r['direction']=='Inbound'}
        priority=next((n for n in range(100,min(relevant,default=4097)) if n not in used),None)
        if priority is None:raise Invalid('Keine freie vorrangige NSG-Priorität für die gezielte Störung. Bestehende Regeln werden nicht überschrieben; Regel im Netzwerkbereich gezielt bearbeiten.')
        ids={r['id'] for r in s['network']['rules']};name=next('trainer-fault-'+str(n) for n in range(1,len(ids)+2) if 'trainer-fault-'+str(n) not in ids)
        return dict(kind='nsg',target=name,before=None,injected=dict(id=name,direction='Inbound',protocol='TCP',source='*',destination=target,port=port,action='Deny',priority=priority))
    p=dict(kind=kind,target=target,before=None,injected=None);before=fault_value(s,p)
    injected=('stopped' if before=='running' else before) if kind=='status' else max(before,s['resources'][target]['capacity_gb']) if kind=='usage' else 'shipping:broken' if kind=='image' else False if kind=='vpn' else True if kind=='migration' else []
    p.update(before=copy.deepcopy(before),injected=injected);return p


def resource_faults(s,ident):
    return [key for key,r in s['faults'].items() if (r['patch']['kind'] in ('status','usage','image') and r['patch']['target']==ident) or (r['patch']['kind']=='nsg' and r['patch']['injected']['destination']==ident)]


def require_unowned_resource(s,ident):
    faults=resource_faults(s,ident)
    if faults:raise Invalid('Aufgezeichnete Trainerstörung '+', '.join(faults)+' bindet diese Ressource. Die Lehrkraft muss sie zuerst gezielt zurücknehmen oder die aktuelle Bearbeitung ausdrücklich beibehalten. Danach übrige Abhängigkeiten prüfen.')


def validate_faults(s):
    if type(s['faults']) is not dict or set(s['faults'])-set(FAULT_TITLES):raise Invalid('Unbekannte aufgezeichnete Trainerstörung.')
    owned=set()
    for ident,record in s['faults'].items():
        if type(record) is not dict or set(record)!={'minute','patch'}:raise Invalid('Störungsaufzeichnung benötigt Minute und begrenzte Änderung.')
        number(record['minute'],0,s['minute'],True);p=record['patch']
        if type(p) is not dict or set(p)!={'kind','target','before','injected'} or type(p['target']) is not str or len(p['target'])>120:raise Invalid('Störungsänderung enthält unbekannte Felder.')
        expected='status' if ident in ('service','document_source','request_provider') else 'usage' if ident=='storage' else 'image' if ident=='container' else 'role' if ident=='data' else ident
        if p['kind']!=expected or (p['kind'],p['target']) in owned:raise Invalid('Störungstyp oder überlappender Änderungsbesitz ungültig.')
        owned.add((p['kind'],p['target']));before,after=p['before'],p['injected'];kind=p['kind']
        if kind in ('status','usage','image') and p['target'] not in s['resources']:raise Invalid('Aufgezeichnetes Störungsziel fehlt; Störung vor Ressourcenentfernung abschließen.')
        if kind=='status':
            if before not in ('running','stopped','deallocated') or after!=('stopped' if before=='running' else before):raise Invalid('Störungszustand ungültig.')
            if ident=='service' and s['resources'][p['target']]['kind'] not in METRIC_KINDS:raise Invalid('Unpassendes Laufzeitziel.')
            if ident=='request_provider' and s['resources'][p['target']]['kind']!='SaaS':raise Invalid('Unpassender Anbieter.')
        elif kind=='usage':
            if p['target']!='storage':raise Invalid('Speicherstörung ist auf Backupablage storage begrenzt.')
            number(before,0,10000,True);number(after,before,10000,True)
        elif kind=='image':
            if p['target']!='container' or type(before) is not str or not before or len(before)>20000 or after!='shipping:broken':raise Invalid('Containerstörung ungültig.')
        elif kind in ('vpn','migration'):
            if p['target'] or type(before) is not bool or type(after) is not bool or after!=(kind=='migration'):raise Invalid('Boolesche Störung ungültig.')
        elif kind=='role':
            if p['target'] or type(before) is not list or len(before)>100000 or any(type(i) is not int or not 0<=i<=100000 for i in before) or before!=sorted(set(before)) or after!=[]:raise Invalid('Vertriebsrollen-Aufzeichnung ungültig.')
        else:
            r=after
            if before is not None or type(r) is not dict or set(r)!={'id','direction','protocol','source','destination','port','action','priority'} or r['id']!=p['target'] or r['direction']!='Inbound' or r['protocol']!='TCP' or r['source']!='*' or r['action']!='Deny' or any(type(r[k]) is not str for k in ('id','direction','protocol','source','destination','action')) or r['destination'] not in s['resources']:raise Invalid('Eigene NSG-Störregel ungültig.')
            number(r['priority'],100,4096,True);number(r['port'],1,65535,True)


def trainer_fault(s,ident,enabled,resolution='restore'):
    if type(ident) is not str or ident not in FAULT_TITLES or type(enabled) is not bool or resolution not in ('restore','keep'):raise Invalid('Störung, boolescher Zustand und Rücknahmeart erforderlich.')
    existing=s['faults'].get(ident)
    if enabled:
        if existing:return dict(kind='trainer_fault',changed=False,message='Bereits aufgezeichnet. Der ursprüngliche Stand und zwischenzeitliche Bearbeitungen bleiben erhalten.')
        p=fault_patch(s,ident)
        if any((r['patch']['kind'],r['patch']['target'])==(p['kind'],p['target']) for r in s['faults'].values()):raise Invalid('Dieser Wert wird bereits von einer anderen Trainerstörung gesteuert. Zuerst diese Störung abschließen.')
        s['faults'][ident]=dict(minute=s['minute'],patch=p);fault_write(s,p,p['injected'])
        return dict(kind='trainer_fault',changed=True,message='Störung mit ursprünglichem Wert und betroffenem Bereich aufgezeichnet. Reparieren und anschließend die Funktion neu prüfen.')
    if not existing:return dict(kind='trainer_fault',changed=False,message='Keine aufgezeichnete Störung dieses Typs. Bestehende Konfiguration und Rechte wurden nicht repariert oder erweitert.')
    p=existing['patch'];current=fault_value(s,p)
    if resolution=='restore':
        if fault_equal(p,current,p['injected']):fault_write(s,p,p['before'])
        elif not fault_equal(p,current,p['before']):raise Invalid('Wert wurde zwischenzeitlich bearbeitet. Aktuelle Bearbeitung prüfen und ausdrücklich beibehalten; automatische Rücknahme würde sie überschreiben.')
    del s['faults'][ident]
    return dict(kind='trainer_fault',changed=True,message='Aufzeichnung abgeschlossen; aktuelle Bearbeitung bewusst beibehalten. Das ist kein Reparaturnachweis. Funktion erneut prüfen.' if resolution=='keep' else 'Nur die aufgezeichnete Änderung zurückgenommen beziehungsweise bereits erfolgte Reparatur beibehalten. Zeit, Kosten, Daten und fremde Änderungen bleiben erhalten. Funktion erneut prüfen.')


def fault_text(p,value):
    if p['kind']=='role':return str(len(value))+' passende Vertriebszuordnungen'
    if p['kind']=='nsg':return 'Keine eigene Störregel' if value is None else str(value['id'])+' · '+str(value['action'])+' '+str(value['destination'])+':'+str(value['port'])+' · Priorität '+str(value['priority'])
    if p['kind']=='usage':return str(value)+' GB'
    if p['kind']=='status':return {'running':'Gestartet','stopped':'Gestoppt','deallocated':'Zuordnung freigegeben'}[value]
    return str(value)


def fault_summaries(s):
    rows=[]
    for ident,r in s['faults'].items():
        p=r['patch'];current=fault_value(s,p);rows.append(dict(id=ident,title=FAULT_TITLES[ident],minute=r['minute'],target=p['target'] or ('Vertriebs-Datenrolle' if p['kind']=='role' else 'Standortverbindung' if p['kind']=='vpn' else 'Cloud-Laufzeitmigration'),before=fault_text(p,p['before']),injected=fault_text(p,p['injected']),current=fault_text(p,current),conflict=not fault_equal(p,current,p['before']) and not fault_equal(p,current,p['injected'])))
    return rows



def snapshot_backup(s):
    b = s['backup']
    if not resource_online(s,'storage') or s['resources']['storage']['used_gb']>=s['resources']['storage']['capacity_gb']:
        b['jobs'].append(dict(minute=s['minute'], status='failed', reason='Storage nicht verfügbar'))
        return
    unavailable=next((key for key in s['documents'] if s['data_governance'][key]['status']!='purged' and not document_available(s,key)),None)
    if unavailable:
        b['jobs'].append(dict(minute=s['minute'],status='failed',reason='Dokumentquelle nicht verfügbar: '+unavailable));return
    b['points'].append(dict(id=f"rp-{s['minute']}-{len(b['jobs'])}", minute=s['minute'], documents=copy.deepcopy(s['documents'])))
    b['jobs'].append(dict(minute=s['minute'], status='success', reason='Dateibestand gesichert'))
    b['last'] = s['minute']
    event(s, 'backup', 'Wiederherstellungspunkt erfolgreich erstellt.')


def restore_problem(s,pending):
    repository=s['resources']['storage']
    if not resource_online(s,'storage') or not repository['configured']:return 'Backupablage storage ist nicht verfügbar oder nicht konfiguriert.'
    source=pending['source'];target=pending['target']
    if source not in s['documents'] or s['data_governance'][source]['status']=='purged':return 'Ursprungsdokument oder seine gültige Aufbewahrungsregel fehlt.'
    if target in s['documents'] and target!=source:return 'Alternativer Wiederherstellungsort ist inzwischen belegt.'
    place=s['document_storage'][source]
    if not document_available(s,source,for_write=True):return 'Ziel '+place['host']+' ist nicht verfügbar, nicht konfiguriert oder hat keinen freien Speicher.'
    return ''


def advance(s, minutes):
    for _ in range(minutes):
        s['minute'] += 1
        for row in hourly(s):
            amount = row['total'] / 60
            s['cost'] += amount
            ledger = next((x for x in s['cost_ledger'] if x['resource'] == row['resource'] and x['department'] == row['department']), None)
            if ledger is None:
                ledger = dict(resource=row['resource'], department=row['department'], amount=0.0)
                s['cost_ledger'].append(ledger)
            ledger['amount'] += amount
        b = s['backup']
        if b['enabled'] and s['minute'] - b['last'] >= b['interval']:
            snapshot_backup(s)
            b['last'] = s['minute']
        b['points'] = [p for p in b['points'] if s['minute'] - p['minute'] <= b['retention']]
        b['jobs'] = b['jobs'][-100:]
        pending = b['restore']
        if pending and pending['status']=='running':
            problem=restore_problem(s,pending)
            if problem:
                pending.update(status='failed',failure_reason=problem,finished_minute=s['minute'])
                event(s,'restore','Wiederherstellung fehlgeschlagen: '+problem)
            elif s['minute']>=pending['due']:
                restored=copy.deepcopy(pending['document'])
                if pending['target'] in s['documents']:
                    current=s['documents'][pending['target']]
                    restored['versions']=copy.deepcopy(current['versions'])+[{k:copy.deepcopy(v) for k,v in current.items() if k!='versions'}]
                    restored['version']=current['version']+1;restored['modified']=s['minute']
                s['documents'][pending['target']] = restored
                s['data_governance'][pending['target']]=copy.deepcopy(s['data_governance'][pending['source']])
                s['document_storage'][pending['target']]=copy.deepcopy(s['document_storage'][pending['source']])
                pending.update(status='success',finished_minute=s['minute'])
                event(s, 'restore', f"Wiederherstellung nach {pending['duration']} Simulationsminuten abgeschlossen.")
        advance_local(s)
        for rule in s['alarms']:
            m = metrics(s, rule['target'])
            rule['streak'] = rule['streak'] + 1 if m['supported'] and (m['available'] or rule['metric']=='error_rate') and m[rule['metric']] >= rule['threshold'] else 0
            if rule['streak'] >= rule['window'] and not any(a['kind']=='metric' and a['rule']==rule['id'] for a in s['alerts']):
                s['alerts'].append(dict(kind='metric',minute=s['minute'],rule=rule['id'],message=f"{rule['target']}: {rule['metric']} >= {rule['threshold']} für {rule['window']} min; Ziel {rule['destination']}",detail=dict(target=rule['target'],metric=rule['metric'],threshold=rule['threshold'],window=rule['window'],destination=rule['destination'],start_minute=s['minute']-rule['window']+1,end_minute=s['minute'],value=m[rule['metric']])))
        for threshold in (80, 100):
            tag = f'budget-{threshold}'
            if s['cost'] >= s['budget'] * threshold / 100 and not any(a['kind']=='budget' and a['rule']==tag for a in s['alerts']):
                s['alerts'].append(dict(kind='budget',minute=s['minute'],rule=tag,message=f'Budget {threshold}% erreicht. Kein automatisches Abschalten.',detail=dict(threshold=threshold,budget=s['budget'],cost=s['cost'])))
        s['metrics'].append(metric_sample(s))
        s['metrics'] = s['metrics'][-120:]


def validate_alert(row,minute):
    if type(row) is not dict or set(row)!={'kind','minute','rule','message','detail'} or row['kind'] not in ('metric','budget','legacy'):raise Invalid('Warnung benötigt bekannten Typ und begrenzte Felder.')
    number(row['minute'],0,minute,True)
    if any(type(row[k]) is not str or not row[k].strip() or len(row[k])>2000 for k in ('rule','message')) or type(row['detail']) is not dict:raise Invalid('Warnung benötigt Kennung, Meldung und typisierte Details.')
    d=row['detail']
    if row['kind']=='legacy':
        if d:raise Invalid('Historische Warnung enthält keinen erfundenen Typnachweis.')
    elif row['kind']=='metric':
        if set(d)!={'target','metric','threshold','window','destination','start_minute','end_minute','value'} or d['metric'] not in ('cpu','memory','response_ms','error_rate'):raise Invalid('Metriknachweisfelder ungültig.')
        if any(type(d[k]) is not str or not d[k].strip() or len(d[k])>120 for k in ('target','destination')):raise Invalid('Metrikziel oder Empfänger ungültig.')
        number(d['threshold'],0,100000);number(d['window'],1,1440,True);number(d['start_minute'],1,minute,True);number(d['end_minute'],1,minute,True);number(d['value'],0,100000)
        if d['end_minute']!=row['minute'] or d['end_minute']-d['start_minute']+1!=d['window'] or d['value']<d['threshold']:raise Invalid('Metriknachweis passt nicht zu Zeitfenster oder Schwelle.')
    else:
        if set(d)!={'threshold','budget','cost'} or type(d['threshold']) is not int or d['threshold'] not in (80,100) or row['rule']!='budget-'+str(d['threshold']):raise Invalid('Budgetnachweisfelder ungültig.')
        number(d['budget'],.01,100000);number(d['cost'],0,float('inf'))
        if d['cost']<d['budget']*d['threshold']/100:raise Invalid('Budgetnachweis erreicht die behauptete Schwelle nicht.')


def number(value, low, high, integer=False):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high or (integer and type(value) is not int):
        raise Invalid(f'Zahl muss zwischen {low} und {high} liegen.')
    return value


def _validate_snapshot_shape(s):
    """Validate consumed nested types before any semantic lookup or persistent write."""
    def fail(path, expected):
        raise Invalid(f'Spielstandfeld {path}: {expected} erwartet. Der bisherige Stand bleibt erhalten.')

    def scalar(value, sample, path):
        expected = type(sample)
        if expected is float:
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0: fail(path, 'endliche nichtnegative Zahl')
        elif type(value) is not expected:
            fail(path, {str:'Text', bool:'Wahrheitswert', int:'Ganzzahl'}.get(expected, expected.__name__))
        elif expected is int and value < 0:
            fail(path, 'nichtnegative Ganzzahl')

    def obj(value, fields, path, optional=()):
        if type(value) is not dict: fail(path, 'Objekt')
        if set(value)-set(fields) or set(fields)-set(optional)-set(value): fail(path, 'vollständiges Objekt mit erlaubten Feldern')
        for key, sample in fields.items():
            if key not in value: continue
            if callable(sample): sample(value[key], path+'.'+key)
            else: scalar(value[key], sample, path+'.'+key)

    def mapping(check):
        def run(value, path):
            if type(value) is not dict or any(type(k) is not str for k in value): fail(path, 'Zuordnung mit Textschlüsseln')
            for key, item in value.items(): check(item, path+'.'+key)
        return run

    def sequence(check):
        def run(value, path):
            if type(value) is not list: fail(path, 'Liste')
            for index, item in enumerate(value): check(item, f'{path}[{index}]')
        return run

    text=lambda value,path:scalar(value,'',path)
    integer=lambda value,path:scalar(value,0,path)
    role=lambda value,path:obj(value,dict(principal='',role='',scope=''),path)
    point_document_fields=dict(name='',container='',**{'class':''},content='',version=0,deleted=False,modified=0)
    def document(value,path):
        obj(value,dict(point_document_fields,versions=sequence(lambda v,p:obj(v,point_document_fields,p))),path)
    documents=mapping(document)
    def nullable_text(value,path):
        if value is not None: text(value,path)
    def connection_result(value,path):
        obj(value,dict(allowed=False,path=sequence(text),first_error=nullable_text),path)
    def access_result(value,path):
        obj(value,dict(allowed=False,network=connection_result,authentication='',grants=sequence(role),rights=sequence(text),reason=''),path)
    def management_result(value,path):
        obj(value,dict(kind='',allowed=False,authenticated=False,authentication='',user='',target='',operation='',rights=sequence(text),grants=sequence(role),reason=''),path)
        if value['kind']!='management' or value['operation'] not in ('read','manage','assign'):fail(path,'Verwaltungsdiagnose mit read/manage/assign')
    def diagnostic(value,path):
        obj(value,dict(seq=0,minute=0,test='',args=lambda v,p:None,result=lambda v,p:None),path)
        if value['test'] in ('connection','local_connection'):
            fields=dict(source='',host='',port=0,protocol='')
            obj(value['args'],fields,path+'.args',optional=fields)
            connection_result(value['result'],path+'.result')
        elif value['test']=='management':
            fields=dict(user='',target='',operation='',mfa=False)
            obj(value['args'],fields,path+'.args',optional=fields)
            management_result(value['result'],path+'.result')
        elif value['test'] in ('access','local_file'):
            fields=dict(user='',document='',operation='',mfa=False,source='')
            if value['test']=='local_file':fields.pop('mfa')
            obj(value['args'],fields,path+'.args',optional=fields)
            if value['test']=='access' and type(value['result']) is dict and value['result'].get('kind')=='management':
                if value['args'].get('operation')!='assign':fail(path+'.result','Verwaltungsergebnis nur für ältere assign-Prüfung')
                management_result(value['result'],path+'.result')
            else:access_result(value['result'],path+'.result')
        elif value['test'] in ('application','request','local_application'):
            fields=dict(user='',source='',operation='',mfa=False)
            if value['test']=='local_application':fields.pop('mfa')
            obj(value['args'],fields,path+'.args',optional=fields)
            access_result(value['result'],path+'.result')
        else: fail(path+'.test','connection, access, application oder request')
    def restore(value,path):
        if value is not None:
            obj(value,dict(status='',due=0,duration=0,point='',source='',target='',point_minute=0,rpo=0,document=document,failure_reason='',started_minute=0,finished_minute=0,outage_minute=0,rpo_limit=0,rto_limit=0),path,optional=('failure_reason','started_minute','finished_minute','outage_minute','rpo_limit','rto_limit'))
    def assessment(value,path):
        obj(value,dict(passed=False,checks=sequence(lambda v,p:obj(v,dict(label='',passed=False),p)),explanation=''),path)
    def audit_event(value,path):
        obj(value,dict(minute=0,kind='',message='',parameters=lambda v,p:None,detail=lambda v,p:None),path,optional=('parameters','detail'))
        if 'parameters' in value and type(value['parameters']) is not dict: fail(path+'.parameters','Objekt mit historischen Aktionsdaten')
        if 'detail' in value:
            if value['kind']=='assessment': assessment(value['detail'],path+'.detail')
            elif value['kind']=='signin':
                obj(value['detail'],dict(user='',source='',target='',mfa=False,authenticated=False,reason='',access=''),path+'.detail')
                if value['detail']['access'] not in ('not_checked','allowed','denied'):fail(path+'.detail.access','not_checked, allowed oder denied')
            elif value['kind']=='ticket_message':
                obj(value['detail'],dict(id='',task='',direction='',author='',text='',reply_to=''),path+'.detail')
                if value['detail']['direction'] not in ('question','answer') or not value['detail']['text'].strip() or len(value['detail']['text'])>5000:fail(path+'.detail','begrenzte Ticketfrage oder Antwort')
            elif value['kind']=='diagnostic':
                if type(value['detail']) is not dict: fail(path+'.detail','Diagnoseobjekt')
                if value['detail'].get('kind')=='management':management_result(value['detail'],path+'.detail')
                elif 'network' in value['detail']: access_result(value['detail'],path+'.detail')
                else: connection_result(value['detail'],path+'.detail')
            else: fail(path+'.detail','Detail nur für Diagnose, Aufgabenprüfung, Ticket oder Lernanmeldung')

    base=fresh()
    fields={key:value for key,value in base.items() if type(value) in (str,bool,int,float)}
    fields.update(dict(
        tariffs=lambda v,p:validate_tariffs(v),locations=mapping(integer),groups=mapping(sequence(text)),
        users=mapping(lambda v,p:obj(v,base['users']['lea'],p)),
        resource_groups=mapping(lambda v,p:obj(v,base['resource_groups']['rg-app'],p)),
        resources=mapping(lambda v,p:obj(v,base['resources']['web'],p)),
        local_inventory=sequence(lambda v,p:obj(v,dict(name='',role='',dependency=''),p)),
        network=lambda v,p:obj(v,dict(vnet='',subnets=mapping(text),onprem='',vpn=False,dns=mapping(text),rules=sequence(lambda v,p:obj(v,base['network']['rules'][0],p))),p),
        roles=sequence(role),documents=documents,
        document_storage=mapping(lambda v,p:obj(v,dict(kind='',host=''),p)),
        requests=lambda v,p:obj(v,dict(active='',deployments=mapping(lambda v,p:obj(v,dict(resource='',patched=False,app_version='',seats=0,members=mapping(text),reason=''),p)),company=mapping(lambda v,p:obj(v,dict(customer='',subject='',status='',version=0,modified=0),p)),provider=mapping(lambda v,p:obj(v,dict(customer='',subject='',status='',version=0,modified=0),p))),p),
        data_governance=mapping(lambda v,p:obj(v,data_record(),p)),
        service_principals=mapping(lambda v,p:obj(v,dict(name='',active=False),p)),
        application=lambda v,p:obj(v,dict(name='',principal=''),p),
        orders=mapping(lambda v,p:obj(v,dict(customer='',subject='',amount=0.0,status='',document='',modified=0,version=0),p)),
        backup=lambda v,p:obj(v,dict(interval=0,retention=0,enabled=False,last=0,
            points=sequence(lambda v,p:obj(v,dict(id='',minute=0,documents=documents),p)),
            jobs=sequence(lambda v,p:obj(v,dict(minute=0,status='',reason=''),p)),restore=restore),p),
        alarms=sequence(lambda v,p:obj(v,dict(id='',target='',metric='',threshold=0.0,window=0,destination='',streak=0),p)),
        alerts=sequence(lambda v,p:validate_alert(v,s['minute'])),
        metrics=sequence(lambda v,p:validate_metric_sample(v,s['minute'])),
        cost_ledger=sequence(lambda v,p:obj(v,dict(resource='',department='',amount=0.0),p)),
        policy=lambda v,p:obj(v,dict(regions=sequence(text),require_tags=False,deny_public=False),p),
        migration=lambda v,p:obj(v,dict(base['migration'],copied_version=0,copied_order_revision=0),p,optional=('copied_version','copied_order_revision')),
        local_migration=lambda v,p:obj(v,dict(local_migration_seed(),governance=mapping(lambda v,p:obj(v,data_record(),p)),documents=documents,orders=mapping(lambda v,p:obj(v,base['orders']['NL-1001'],p)),owned_documents=sequence(text),owned_orders=sequence(text)),p),
        onprem=lambda v,p:obj(v,dict(data_governance=mapping(lambda v,p:obj(v,data_record(),p)),lineage_pending=sequence(text),enabled=False,lan=False,
            services=mapping(lambda v,p:obj(v,dict(offset=0,status='',port=0,configured=False,allow_cloud=False,capacity_gb=0,used_gb=0),p)),
            accounts=mapping(lambda v,p:obj(v,dict(active=False),p)),groups=mapping(sequence(text)),
            shares=mapping(lambda v,p:obj(v,dict(read=sequence(text),write=sequence(text)),p)),dns=mapping(text),documents=documents,
            orders=mapping(lambda v,p:obj(v,base['orders']['NL-1001'],p)),
            backup=lambda v,p:obj(v,dict(enabled=False,interval=0,retention=0,last=0,
                points=sequence(lambda v,p:obj(v,dict(id='',minute=0,documents=documents,orders=mapping(lambda v,p:obj(v,base['orders']['NL-1001'],p))),p)),
                jobs=sequence(lambda v,p:obj(v,dict(minute=0,status='',reason=''),p)),
                restore=lambda v,p:None if v is None else obj(v,dict(scope='',source='',target='',point='',point_minute=0,status='',started=0,due=0,documents=documents,orders=mapping(lambda v,p:obj(v,base['orders']['NL-1001'],p)),reason='',finished_minute=0,outage_minute=0,rpo_limit=0,rto_limit=0),p,optional=('finished_minute','outage_minute','rpo_limit','rto_limit'))),p)),p),
        container_settings=mapping(mapping(text)),availability_event=lambda v,p:obj(v,dict(enabled=False,region='',zone=0,since=0),p),faults=lambda v,p:validate_faults(s),decisions=mapping(text),replies=mapping(text),diagnostics=sequence(diagnostic),events=sequence(audit_event),
        hints=sequence(lambda v,p:obj(v,dict(task='',level=0,minute=0),p)),
        completed=mapping(lambda v,p:obj(v,dict(passed=False,minute=0,seq=0),p))))
    obj(s,fields,'state')
    validate_local(s)
    validate_local_migration(s)
    validate_business_governance(s)
    validate_recovery_job(s['backup']['restore'],s['minute'])
    validate_recovery_job(s['onprem']['backup']['restore'],s['minute'])


def validate(s):
    try:return _validate(s)
    except Invalid:raise
    except ValueError as error:raise Invalid('Ungültige IPv4-Adresse oder Netzangabe: '+str(error)) from error


def _validate(s):
    if type(s) is not dict or set(s) != set(fresh()) or s.get('schema') != VERSION:
        raise Invalid('Unbekanntes Speicherformat oder unzulässige Hauptfelder. Alten Stand unverändert behalten.')
    def walk(v, depth=0):
        if depth > 15:
            raise Invalid('Import zu tief verschachtelt.')
        if isinstance(v, dict):
            if len(v) > 1000 or any(not isinstance(k, str) or len(k) > 120 or k in ('__proto__', 'constructor', 'prototype') for k in v):
                raise Invalid('Ungültige Schlüssel.')
            for item in v.values(): walk(item, depth+1)
        elif isinstance(v, list):
            if len(v) > 2000: raise Invalid('Zu viele Datensätze.')
            for item in v: walk(item, depth+1)
        elif isinstance(v, str):
            if len(v) > 20000: raise Invalid('Text zu lang.')
        elif type(v) in (int, float):
            if not math.isfinite(v) or abs(v) > 1e9: raise Invalid('Ungültige Zahl.')
        elif v is not None and type(v) is not bool:
            raise Invalid('Nicht unterstützter Datentyp.')
    walk(s)
    _validate_snapshot_shape(s)
    number(s['seq'],0,1000000000,True)
    number(s['cost'],0,1000000000)
    for key, required in [('users',{'it','lea','partner'}),('groups',{'IT','Vertrieb','Altprojekt'}),('documents',{'offer','payroll','public'})]:
        if not required<=set(s[key]): raise Invalid('Pflichtdatensätze fehlen in '+key+'.')
    if not {'web', 'db', 'storage', 'container', 'paas', 'testvm', 'saas'} <= set(s['resources']):
        raise Invalid('Pflichtressourcen fehlen.')
    for r in s['resources'].values():
        if set(r) != RESOURCE_FIELDS or r['group'] not in s['resource_groups'] or r['size'] not in s['tariffs']['sizes'] or r['kind'] not in ('VM', 'Database', 'Storage', 'File Share', 'App Service', 'Container Apps', 'SaaS'):
            raise Invalid('Ungültige Ressourcenfelder.')
        for key in ('public', 'locked', 'configured'):
            if type(r[key]) is not bool: raise Invalid('Boolescher Ressourcenwert erwartet.')
        if r['status'] not in ('running', 'stopped', 'deallocated') or r['tier'] not in ('hot', 'cool') or r['redundancy'] not in s['tariffs']['redundancy_multiplier'] or r['availability'] not in ('single', 'zones'):
            raise Invalid('Ungültige Ressourcenoption.')
        for key, low, high in [('instances', 1, 10), ('disk_gb', 0, 1024), ('port', 1, 65535), ('capacity_gb', 1, 10000), ('used_gb', 0, 10000)]: number(r[key], low, high, True)
        if r['kind']=='File Share' and r['port']!=445:raise Invalid('File-Share-Lernendpunkte benötigen SMB/TCP 445.')
        if r['kind']=='SaaS':
            if r['ip'] or r['subnet'] or r['public_ip']:raise Invalid('SaaS hat keine eigene Lern-NIC oder IP-Zuweisung.')
        else:
            if r['subnet'] not in s['network']['subnets']:raise Invalid('Ressource verweist auf unbekanntes Subnetz.')
            address=ipaddress.IPv4Address(r['ip']);subnet=ipaddress.IPv4Network(s['network']['subnets'][r['subnet']])
            if address not in subnet or int(address)-int(subnet.network_address)<4 or address==subnet.broadcast_address:raise Invalid('Private Adresse liegt außerhalb des Subnetzes oder ist für Azure reserviert (erste vier/letzte).')
            if r['public_ip']:
                public=ipaddress.IPv4Address(r['public_ip'])
                if public not in ipaddress.IPv4Network('198.51.100.0/24') or public in (ipaddress.IPv4Address('198.51.100.0'),ipaddress.IPv4Address('198.51.100.255')):raise Invalid('Öffentliche Lern-IP: 198.51.100.1 bis 198.51.100.254, keine echte Cloud-Adresse.')
            if r['kind']!='Storage' and r['public']!=bool(r['public_ip']):raise Invalid('Öffentlicher Ressourcenstatus muss zur zugewiesenen IP passen.')
    if set(s['container_settings'])!={key for key,r in s['resources'].items() if r['kind']=='Container Apps'}:raise Invalid('Container-Konfiguration muss genau die vorhandenen Container-Ressourcen abbilden.')
    for settings in s['container_settings'].values():validate_container_values(settings)
    incident=s['availability_event'];number(incident['zone'],1,3,True);number(incident['since'],0,s['minute'],True)
    if not incident['region'].strip() or len(incident['region'])>120:raise Invalid('Lernzonenausfall benötigt eine begrenzte Region.')
    for field in ('ip','public_ip'):
        addresses=[r[field] for r in s['resources'].values() if r[field]]
        if len(addresses)!=len(set(addresses)):raise Invalid('IP-Adresse doppelt vergeben: '+field)
    if set(s['network'])!={'vnet','subnets','onprem','vpn','dns','rules'}:raise Invalid('Netzwerkfelder ungültig.')
    vnet=ipaddress.IPv4Network(s['network']['vnet']);onprem=ipaddress.IPv4Network(s['network']['onprem'])
    private_ranges=[ipaddress.IPv4Network(cidr) for cidr in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if any(not any(net.subnet_of(private) for private in private_ranges) for net in (vnet,onprem)):raise Invalid('Dieses Lernmodell unterstützt nur private RFC-1918-Netze für VNet und Standort.')
    if vnet.overlaps(onprem):raise Invalid('VNet und Standortnetz überlappen sich.')
    subnets=s['network']['subnets']
    if not 1<=len(subnets)<=32:raise Invalid('Ein bis 32 Subnetze erforderlich.')
    checked=[]
    for ident,cidr in subnets.items():
        if not ident or len(ident)>50 or not ident.replace('-','').replace('_','').isalnum():raise Invalid('Subnetzkennung: Buchstaben, Ziffern, - und _.')
        net=ipaddress.IPv4Network(cidr)
        if net.prefixlen>29 or not net.subnet_of(vnet) or any(net.overlaps(previous) for previous in checked):raise Invalid('Subnetz außerhalb des VNet, kleiner als /29 oder überlappend.')
        checked.append(net)
    known_addresses={address for r in s['resources'].values() for address in (r['ip'],r['public_ip']) if address}
    if any(value not in s['resources'] and value not in known_addresses for value in s['network']['dns'].values()):raise Invalid('DNS-Ziel ist keine vorhandene Ressource oder zugewiesene IP-Adresse.')
    priorities, ids = set(), set()
    for r in s['network']['rules']:
        if set(r) != {'id', 'direction', 'protocol', 'source', 'destination', 'port', 'action', 'priority'}: raise Invalid('NSG-Felder ungültig.')
        number(r['priority'], 100, 4096, True); number(r['port'], 0, 65535, True)
        if (r['direction'], r['priority']) in priorities or r['id'] in ids: raise Invalid('NSG-Priorität oder Regel-ID doppelt.')
        priorities.add((r['direction'], r['priority'])); ids.add(r['id'])
        if r['direction'] not in ('Inbound', 'Outbound') or r['action'] not in ('Allow', 'Deny') or r['protocol'] not in ('TCP', 'UDP', '*'): raise Invalid('NSG-Option ungültig.')
        for key in ('source', 'destination'):
            if r[key] not in ('*', 'Any', 'Internet', 'VirtualNetwork') and r[key] not in s['resources']: ipaddress.IPv4Network(r[key], strict=False)
    for u in s['users'].values():
        if set(u) != {'name', 'department', 'active', 'mfa', 'guest', 'expires', 'directory_role'}: raise Invalid('Benutzerfelder ungültig.')
        if any(type(u[k]) is not bool for k in ('active','mfa','guest')) or u['directory_role'] not in ('User', 'User Administrator', 'Global Administrator'): raise Invalid('Benutzeroption ungültig.')
        number(u['expires'], 0, 10000000, True)
    if any(not isinstance(m, list) or any(u not in s['users'] for u in m) for m in s['groups'].values()): raise Invalid('Gruppe verweist auf unbekannten Benutzer.')
    if set(s['service_principals']) & (set(s['users'])|set(s['groups'])): raise Invalid('Dienstidentität kollidiert mit Benutzer oder Gruppe.')
    if s['application']['principal'] not in s['service_principals']: raise Invalid('Dienstidentität der Anwendung fehlt.')
    for ident,order in s['orders'].items():
        if not ident or order['document'] not in s['documents'] or order['status'] not in ('Neu','In Bearbeitung','Erledigt'): raise Invalid('Auftragsreferenz oder Status ungültig.')
        number(order['amount'],0,1000000);number(order['version'],1,1000000000,True)
        if not order['customer'].strip() or not order['subject'].strip(): raise Invalid('Fiktiver Kunde und Betreff sind erforderlich.')
    valid_scopes = {'subscription', 'sales', 'hr', 'public', 'orders', 'requests'} | set(s['resources']) | set(s['documents']) | set(s['resource_groups'])
    for r in s['roles']:
        if set(r) != {'principal','role','scope'} or r['role'] not in ROLES or r['scope'] not in valid_scopes or r['principal'] not in (set(s['users']) | set(s['groups']) | set(s['service_principals'])): raise Invalid('Ungültige Rollenzuweisung.')
    for d in s['documents'].values():
        if set(d) != {'name','container','class','content','version','deleted','modified','versions'} or d['container'] not in ('sales','hr','public','restore') or d['class'] not in ('öffentlich','intern','vertraulich','besonders schutzbedürftig'): raise Invalid('Dokumentfelder ungültig.')
        if not isinstance(d['content'],str) or type(d['deleted']) is not bool or type(d['versions']) is not list: raise Invalid('Ungültige Dokumentdaten.')
        for version in d['versions']:
            if set(version) != set(d)-{'versions'} or not isinstance(version['content'],str): raise Invalid('Versionsfelder ungültig.')
    if set(s['document_storage'])!=set(s['documents']):raise Invalid('Jedes Dokument benötigt genau eine tatsächliche Speicherzuordnung.')
    for place in s['document_storage'].values():
        if place['kind'] not in STORAGE_TYPES or place['host'] not in s['resources'] or s['resources'][place['host']]['kind']!=STORAGE_TYPES[place['kind']]:raise Invalid('Speicherart und tatsächlicher Dienst passen nicht zusammen.')
        if place['kind']=='Files' and s['resources'][place['host']]['port']!=445:raise Invalid('Dateifreigaben verwenden im Lernmodell SMB/TCP 445.')
    service=s['requests']
    if set(service['deployments'])-set(REQUEST_MODELS) or service['active'] not in ('',*service['deployments']):raise Invalid('Unbekannte oder nicht bereitgestellte Anfragemodell-Auswahl.')
    for model,deployment in service['deployments'].items():
        profile=REQUEST_MODELS[model];target=deployment['resource']
        if target!=profile['resource'] or target not in s['resources'] or s['resources'][target]['kind']!=profile['kind']:raise Invalid('Bereitstellungsmodell und tatsächlicher Dienst passen nicht zusammen.')
        if not deployment['reason'].strip() or len(deployment['reason'])>2000 or len(deployment['app_version'])>100:raise Invalid('Modellentscheidung begründen.')
        if len(deployment['members'])>60 or any(user not in s['users'] or role not in ('Reader','Operator') for user,role in deployment['members'].items()):raise Invalid('Anfrage-Mitgliedschaft ungültig.')
        number(deployment['seats'],1 if model=='SaaS' else 0,60 if model=='SaaS' else 0,True)
        if model=='SaaS' and (deployment['app_version']!='provider-managed' or not deployment['patched'] or len(deployment['members'])>deployment['seats']):raise Invalid('SaaS-Anwendung/Patches sind anbieterverwaltet; Lizenzen müssen Mitglieder abdecken.')
        if model=='PaaS' and not deployment['patched']:raise Invalid('PaaS-Betriebssystem wird durch Anbieter gepflegt.')
    for records in (service['company'],service['provider']):
        if len(records)>100:raise Invalid('Höchstens 100 Anfragen je Modellablage.')
        for ident,row in records.items():
            if not ident.strip() or len(ident)>50 or not row['customer'].strip() or len(row['customer'])>120 or not row['subject'].strip() or len(row['subject'])>500 or row['status'] not in ('Neu','In Bearbeitung','Erledigt'):raise Invalid('Anfragedaten ungültig.')
            number(row['version'],1,1000000000,True);number(row['modified'],0,s['minute'],True)
    rules=s['data_governance']
    if set(rules)!=set(s['documents']):raise Invalid('Datenregeln müssen jedes vorhandene Dokument genau abdecken.')
    for ident,rule in rules.items():
        if set(rule)!=set(data_record()) or rule['owner'] not in (set(s['users'])|set(s['groups'])):raise Invalid('Datenverantwortung ungültig.')
        if not rule['purpose'].strip() or not rule['reason'].strip() or len(rule['purpose'])>500 or len(rule['reason'])>2000:raise Invalid('Zweck und begründete Fristentscheidung erforderlich.')
        number(rule['retention_until'],0,10000000,True)
        if type(rule['hold']) is not bool or rule['status'] not in ('active','purged') or rule['origin'] not in rules:raise Invalid('Aufbewahrungsregel ungültig.')
        root=rules[rule['origin']]
        if root['origin']!=rule['origin'] or rule!=root:raise Invalid('Wiederhergestellte Kopien müssen dieselbe Ursprungsregel behalten.')
        if rule['status']=='purged':
            copies=[s['documents'][ident]]+[point['documents'][ident] for point in s['backup']['points'] if ident in point['documents']]
            if any(d['content'] or d['versions'] or not d['deleted'] for d in copies):raise Invalid('Entfernte Daten dürfen keine Inhalte oder Versionen behalten.')
            pending=s['backup']['restore']
            if pending and pending['source']==ident:raise Invalid('Entfernte Daten dürfen keine laufende Wiederherstellung behalten.')
    for g in s['resource_groups'].values():
        if set(g) != {'region','department','owner'}: raise Invalid('Ressourcengruppenfelder ungültig.')
    number(s['minute'], 0, 10000000, True); number(s['workload'], 0, 1000, True); number(s['budget'], .01, 100000)
    b = s['backup']
    if set(b) != {'interval','retention','enabled','last','points','jobs','restore'}: raise Invalid('Sicherungsfelder ungültig.')
    number(b['interval'], 1, 10080, True); number(b['retention'], 1, 43200, True)
    for a in s['alarms']:
        if set(a) != {'id','target','metric','threshold','window','destination','streak'} or a['target'] not in s['resources'] or a['metric'] not in ('cpu','memory','response_ms','error_rate'): raise Invalid('Alarmfelder ungültig.')
        number(a['threshold'], 0, 100000); number(a['window'], 1, 1440, True);number(a['streak'],0,s['minute'],True)
        if any(not a[k].strip() or len(a[k])>120 for k in ('id','destination')):raise Invalid('Alarmkennung und Ziel benötigen begrenzten Text.')
    if len({a['id'] for a in s['alarms']})!=len(s['alarms']):raise Invalid('Doppelte Alarmkennung.')
    for alert in s['alerts']:validate_alert(alert,s['minute'])
    for point in s['metrics']:validate_metric_sample(point,s['minute'])
    fixed = {
        'policy': {'regions','require_tags','deny_public'},
        'migration': {'phase','target','synced','tested','cutover','rollback','cleaned','interrupted'},
    }
    if set(s['policy'])!=fixed['policy'] or not fixed['migration']<=set(s['migration']) or set(s['migration'])-fixed['migration']-{'copied_version','copied_order_revision'}: raise Invalid('Policy-/Migrationsfelder ungültig.')
    if not isinstance(s['policy']['regions'],list) or not s['policy']['regions'] or any(type(x) is not str for x in s['policy']['regions']): raise Invalid('Regionenliste ungültig.')
    if s['migration']['target'] not in ('paas','web','migrationvm'): raise Invalid('Migrationsziel ungültig.')
    for key in ('task','task_status','name','notes','company','tenant','subscription'):
        if type(s[key]) is not str: raise Invalid('Textfeld erwartet.')
    if s['task_status'] not in ('active','paused'): raise Invalid('Aufgabenstatus ungültig.')
    for key in ('replies','decisions'):
        if not isinstance(s[key],dict) or any(type(v) is not str for v in s[key].values()): raise Invalid('Textzuordnung erwartet.')
    list_keys={'alarms','alerts','metrics','cost_ledger','diagnostics','events','hints','local_inventory','roles'}
    if any(not isinstance(s[k],list) for k in list_keys): raise Invalid('Liste erwartet.')
    for key,allowed in [('cost_ledger',{'resource','department','amount'}),('hints',{'task','level','minute'}),('local_inventory',{'name','role','dependency'})]:
        if any(not isinstance(row,dict) or set(row)!=allowed for row in s[key]): raise Invalid('Nicht erlaubte Felder in '+key)
    for row in s['diagnostics']:
        if set(row)!={'seq','minute','test','args','result'} or row['test'] not in ('connection','access','application','request','local_connection','local_file','local_application','management') or not isinstance(row['result'],dict) or type(row['result'].get('allowed')) is not bool: raise Invalid('Diagnosefelder ungültig.')
    for row in s['events']:
        if not {'minute','kind','message'}<=set(row) or set(row)-{'minute','kind','message','parameters','detail'}: raise Invalid('Ereignisfelder ungültig.')
    for row in b['points']:
        if set(row)!={'id','minute','documents'} or not isinstance(row['documents'],dict): raise Invalid('Sicherungspunkt ungültig.')
        for doc in row['documents'].values():
            if set(doc)!={'name','container','class','content','version','deleted','modified','versions'} or type(doc['content']) is not str: raise Invalid('Sicherungsdokument ungültig.')
    if b['restore'] is not None:
        rest=b['restore']
        if not {'status','due','duration','point','source','target','point_minute','rpo','document'}<=set(rest) or set(rest)-{'status','due','duration','point','source','target','point_minute','rpo','document','failure_reason','started_minute','finished_minute','outage_minute','rpo_limit','rto_limit'} or rest['status'] not in ('running','success','failed') or set(rest['document'])!={'name','container','class','content','version','deleted','modified','versions'}: raise Invalid('Wiederherstellung ungültig.')
        if rest['source'] not in s['documents'] or not rest['target'].strip() or len(rest['target'])>120 or rest['target'] in ('__proto__','constructor','prototype'):raise Invalid('Wiederherstellungsquelle oder Ziel ungültig.')
        if (rest['status']=='failed' and not rest.get('failure_reason','').strip()) or len(rest.get('failure_reason',''))>2000 or (rest['status']!='failed' and rest.get('failure_reason','')):raise Invalid('Fehlergrund passt nicht zum Wiederherstellungsstatus.')
    if any(set(j)!={'minute','status','reason'} for j in b['jobs']): raise Invalid('Sicherungsjob ungültig.')
    for row in s['completed'].values():
        if set(row)!={'passed','minute','seq'} or type(row['passed']) is not bool: raise Invalid('Fortschrittsfelder ungültig.')
    # Exercise files are data; never evaluate expressions or execute imported strings.
    return s


def act(original, action, **p):
    s = copy.deepcopy(original)
    result = None
    if action=='container_config':
        if not {'id','values'}<=set(p) or set(p)-{'id','values','actor'} or type(p['id']) is not str or p['id'] not in s['container_settings']:raise Invalid('Vorhandene Container-Ressource und Name/Wert-Objekt erforderlich.')
        validate_container_values(p['values'])
    management_targets={'container_config':p.get('id'),'restore':p.get('id'),'configure':p.get('id'),'power':p.get('id'),'delete_resource':p.get('id'),
                        'create':p.get('group'),'group_create':'subscription','network':'subscription',
                        'request_deploy':'subscription','request_select':'subscription','request_config':REQUEST_MODELS.get(p.get('model'),{}).get('resource'),'request_grant':REQUEST_MODELS.get(p.get('model'),{}).get('resource'),'request_remove':REQUEST_MODELS.get(p.get('model'),{}).get('resource'),'storage_move':p.get('id'),'data_policy':'storage','data_purge':'storage','rule_add':'subscription','rule_remove':'subscription','subnet_set':'subscription','subnet_remove':'subscription'}
    if action in management_targets:require_management(s,p.get('actor','it'),management_targets[action])
    if action in ('business_policy','business_purge','local_lineage'):
        required={'business_policy':{'area','id','changes'},'business_purge':{'area','id','reason'},'local_lineage':{'id','source','reason'}}[action]
        if not required<=set(p) or set(p)-required-{'actor'} or any(type(p[key]) is not str for key in set(p)-{'changes'}):raise Invalid('Felder des Geschäftsdatenschritts ungültig.')
    if action in ('order_update','local_order_update'):
        records=s['orders'] if action=='order_update' or s['local_migration']['active'] else s['onprem']['orders']
        rules=s['data_governance'] if records is s['orders'] else s['onprem']['data_governance']
        if p.get('id') in records and rules[records[p['id']]['document']]['status']=='purged':raise Invalid('Endgültig entfernter Geschäftsvorgang kann nicht erneut bearbeitet werden.')
    m=s['local_migration']
    if action=='data_purge':
        related=business_related(s,'cloud',p.get('id'))
        if related['local'] or related['stage']:raise Invalid('Verbundenen Geschäftsvorgang mit lokalen und Migrationskopien im Bereich Datenbereinigung gezielt bereinigen.')
    if m['cloud_present']:
        if not m['active'] and ((action=='order_update' and p.get('id') in m['owned_orders']) or (action in ('file_write','file_delete','version_restore','restore') and (p.get('target',p.get('id')) in m['owned_documents']))):raise Invalid('Nach Rückfall ist die aufbewahrte Cloudkopie schreibgeschützt.')
        if action=='order_update' and p.get('id') in m['owned_orders'] and p.get('changes',{}).get('document',s['orders'][p['id']]['document']) not in m['owned_documents']:raise Invalid('Übernommener Auftrag benötigt einen zugeordneten Migrationsanhang.')
    if action=='business_policy':result=business_policy(s,p['area'],p['id'],p['changes'],p.get('actor','it'))
    elif action=='business_purge':result=business_purge(s,p['area'],p['id'],p['reason'],p.get('actor','it'))
    elif action=='local_lineage':result=local_lineage(s,p['id'],p['source'],p['reason'],p.get('actor','it'))
    elif action=='local_migration':
        result=local_migration_action(s,p)
    elif action.startswith('local_'):
        result=local_action(s,action,p)
    elif action == 'signin':
        if set(p)-{'user','mfa','source'}:raise Invalid('Unbekannte Anmeldeparameter.')
        result=record_signin(s,**p)
    elif action == 'storage_move':
        ident=p['id'];kind=p['kind'];host=p['host']
        if ident not in s['documents'] or kind not in STORAGE_TYPES or host not in s['resources'] or s['resources'][host]['kind']!=STORAGE_TYPES[kind]:raise Invalid('Passenden vorhandenen Speicherdienst wählen.')
        old=s['document_storage'][ident]
        require_management(s,p.get('actor','it'),host)
        if not p.get('reason','').strip() or len(p['reason'])>2000:raise Invalid('Speicherentscheidung begründen.')
        if s['data_governance'][ident]['status']!='purged' and not document_available(s,ident):raise Invalid('Bisherige Dokumentquelle nicht verfügbar.')
        destination=dict(kind=kind,host=host);s['document_storage'][ident]=destination
        if not document_available(s,ident,for_write=True):raise Invalid('Zielspeicher nicht verfügbar oder voll.')
        result=dict(document=ident,previous=old,current=destination,preserved='Inhalt, Versionen und Aufbewahrungsregel')
    elif action == 'request_deploy':
        model=p['model']
        if model not in REQUEST_MODELS or model in s['requests']['deployments']:raise Invalid('Unbekanntes oder bereits bereitgestelltes Modell.')
        profile=REQUEST_MODELS[model];key=profile['resource']
        if key in s['resources']:raise Invalid('Zielkennung bereits durch eine andere Ressource belegt.')
        if type(p.get('reason')) is not str or not p['reason'].strip():raise Invalid('Modellwahl begründen.')
        subnet=s['resources']['web']['subnet'];external=model=='SaaS'
        r=resource('Kundenanfragen · '+model,profile['kind'],'rg-app',ip='' if external else next_private_ip(s,subnet),subnet='' if external else subnet,status='running' if external else 'stopped',configured=external,disk_gb=0 if model!='IaaS' else 64)
        require_resource_policy(s,r)
        s['resources'][key]=r
        s['requests']['deployments'][model]=dict(resource=key,patched=model!='IaaS',app_version='provider-managed' if external else '',seats=2 if external else 0,members={},reason=p['reason'])
        if not external:
            if 'requests-app' in s['users'] or 'requests-app' in s['groups']:raise Invalid('Dienstidentitätskennung kollidiert.')
            s['service_principals'].setdefault('requests-app',dict(name='Dienstidentität der Anfrageanwendung',active=True))
            role=dict(principal='requests-app',role='Request Operator',scope='requests')
            if role not in s['roles']:s['roles'].append(role)
    elif action == 'request_select':
        model=p['model']
        if model and model not in s['requests']['deployments']:raise Invalid('Modell zuerst bereitstellen.')
        s['requests']['active']=model
        if model:s['network']['dns']['anfrage.intern']=s['requests']['deployments'][model]['resource']
        else:s['network']['dns'].pop('anfrage.intern',None)
    elif action == 'request_config':
        model=p['model'];deployment=s['requests']['deployments'][model];changes=p['changes']
        allowed={'seats'} if model=='SaaS' else {'app_version','patched'} if model=='IaaS' else {'app_version'}
        if type(changes) is not dict or not changes or set(changes)-allowed:raise Invalid('Dieses Modell erlaubt nur: '+', '.join(sorted(allowed)))
        deployment.update(changes)
        if model!='SaaS':s['resources'][deployment['resource']]['configured']=deployment['app_version']=='requests:1.0'
    elif action == 'request_grant':
        model=p['model'];deployment=s['requests']['deployments'][model]
        if 'assign' not in effective(s,p.get('actor','it'),deployment['resource'])[0]:raise Invalid('Anwendungsrollen erfordern zusätzlich die Lernberechtigung für Zugriffszuweisungen.')
        if p['role']=='none':deployment['members'].pop(p['user'],None)
        else:deployment['members'][p['user']]=p['role']
    elif action == 'request_remove':
        model=p['model'];deployment=s['requests']['deployments'][model];key=deployment['resource']
        require_unowned_resource(s,key)
        if any(place['host']==key for place in s['document_storage'].values()) or s['requests']['active']==model or s['resources'][key]['locked'] or any(resolve_target(s,host)==key for host in s['network']['dns']) or any(row['scope']==key for row in s['roles']):raise Invalid('Dokumentabhängigkeit, aktive Auswahl, DNS, Löschschutz oder Rollenbindung zuerst entfernen.')
        del s['requests']['deployments'][model];del s['resources'][key]
        # Company/provider records deliberately remain separate and preserved on cancellation.
    elif action == 'request_open':
        result=request_application(s,**p);record_signin(s,user=p.get('user','u11'),mfa=p.get('mfa',True),source=p.get('source','hq'),target='Kundenanfragen',authorized=result['authorization']['allowed']);event(s,'application_read','Kundenanfragen geöffnet: '+str(result['authorization']['allowed']))
    elif action in ('request_create','request_update'):
        auth={key:p[key] for key in ('user','source','mfa') if key in p}
        authorization=request_access(s,operation='request_write',**auth)
        if not authorization['allowed']:raise Invalid(authorization['reason'])
        records=request_rows(s);ident=p['id'];changes=p['changes']
        if type(changes) is not dict or set(changes)-{'customer','subject','status'}:raise Invalid('Anfragefelder nicht unterstützt.')
        if action=='request_create':
            if ident in records:raise Invalid('Anfragekennung existiert bereits.')
            row=dict(customer='',subject='',status='Neu',version=1,modified=s['minute'])
        else:
            if ident not in records or type(p.get('version')) is not int or p['version']!=records[ident]['version']:raise Invalid('Anfrage inzwischen geändert: neue Version laden.')
            row=dict(records[ident],version=records[ident]['version']+1,modified=s['minute'])
        row.update(changes);records[ident]=row;result=request_application(s,**auth)
    elif action == 'application_open':
        result=order_application(s,**p)
        record_signin(s,user=p.get('user','u11'),mfa=p.get('mfa',True),source=p.get('source','hq'),target='Auftragsanwendung',authorized=result['authorization']['allowed'])
        event(s,'application_read','Auftragsanwendung: '+('Zugriff erlaubt.' if result['authorization']['allowed'] else 'Zugriff verweigert.'))
    elif action in ('order_create','order_update'):
        auth={k:p[k] for k in ('user','source','mfa') if k in p}
        authorization=application_access(s,operation='orders_write',**auth)
        if not authorization['allowed']: raise Invalid(authorization['reason'])
        changes=p['changes']
        if type(changes) is not dict or set(changes)-{'customer','subject','amount','status','document'}: raise Invalid('Nicht erlaubte Auftragsfelder.')
        ident=p['id']
        if type(ident) is not str or not ident.strip() or len(ident)>50: raise Invalid('Auftragskennung fehlt oder ist zu lang.')
        if action=='order_create':
            if ident in s['orders']: raise Invalid('Auftragskennung bereits vorhanden.')
            order=dict(customer='',subject='',amount=0.0,status='Neu',document='offer',modified=s['minute'],version=1)
        else:
            if ident not in s['orders'] or type(p.get('version')) is not int or p['version']!=s['orders'][ident]['version']: raise Invalid('Auftrag wurde inzwischen geändert. Erneut laden und prüfen.')
            order=copy.deepcopy(s['orders'][ident]);order['version']+=1
        order.update(changes);order['modified']=s['minute']
        document=order['document']
        if document not in s['documents'] or not access(s,auth.get('user','u11'),document,mfa=auth.get('mfa',True),source=resolve_target(s) or 'web')['allowed'] or 'data_read' not in effective(s,s['application']['principal'],document)[0]:
            raise Invalid('Verknüpftes Dokument ist nicht für Benutzer und Dienstidentität lesbar.')
        s['orders'][ident]=order;s['order_revision']+=1
        if s['migration']['phase'] in ('copied','tested'):
            s['migration']['synced']=False;s['migration']['tested']=False
        result=order_application(s,**auth)
    elif action == 'service_identity':
        if type(p['changes']) is not dict or set(p['changes'])-{'name','active'}: raise Invalid('Dienstidentitätsfeld nicht unterstützt.')
        s['service_principals'][p['id']].update(p['changes'])
    elif action == 'availability_event':
        if set(p)!={'region','zone','enabled'} or type(p['region']) is not str or not p['region'].strip() or len(p['region'])>120 or type(p['enabled']) is not bool:raise Invalid('Region, Lernzone1–3 und boolescher Ausfallzustand erforderlich.')
        number(p['zone'],1,3,True)
        if p['enabled'] and p['region'] not in {r['region'] for r in s['resources'].values() if r['kind']!='SaaS'}:raise Invalid('Ausfallregion muss eine vorhandene Firmenressource enthalten.')
        old=s['availability_event'];same=old['enabled'] and p['enabled'] and old['region']==p['region'] and old['zone']==p['zone'];s['availability_event']=dict(p,since=old['since'] if same or not p['enabled'] else s['minute'])
        result=dict(kind='availability_event',message='Lernzonenausfall gesetzt. Tatsächliche verbleibende Instanzen und Datenabhängigkeiten prüfen.' if p['enabled'] else 'Lernzonenausfall beendet. Konfiguration, Zeit, Kosten und andere Störungen bleiben erhalten; Funktion erneut prüfen.')
    elif action == 'container_config':
        s['container_settings'][p['id']]=copy.deepcopy(p['values'])
        result=dict(kind='container_config',message='Container-Konfiguration gespeichert. Fehlende oder falsche Werte bleiben als Störung prüfbar. Funktion erneut testen; keine Zeit wurde vorgespult.')
    elif action == 'configure':
        r = s['resources'][p['id']]
        changes = p['changes']
        if not set(changes) <= RESOURCE_FIELDS - {'kind', 'group'}: raise Invalid('Nicht bearbeitbare Ressourcenfelder.')
        if changes.get('redundancy')=='ZRS' and (r['kind'] not in ('Storage','File Share') or 'ZRS' not in s['tariffs']['redundancy_multiplier']):raise Invalid('ZRS benötigt Storage/File Share und einen ausdrücklich gespeicherten ZRS-Lerntarif. Alte Tarife werden nicht nachträglich verändert.')
        if r['kind']=='Storage' and changes.get('status')=='deallocated' and r['status']!='deallocated':raise Invalid('Storage hat keine VM-Deallokierung. Für das Trainer-Verfügbarkeitsmodell running oder stopped verwenden; vorhandene alte Werte bleiben erhalten.')
        if r['kind']=='Storage' and set(changes)&{'size','os','disk_gb','image','instances','availability'}:raise Invalid('Storage Account ist keine VM: CPU-Größe, Betriebssystem, VM-Datenträger, Image und Instanzverteilung sind keine Speichereinstellungen. Für zonenredundanten Speicher Redundanz ZRS wählen; Speicherklasse, Kapazität, Belegung und Zugänge separat bearbeiten.')
        if r['kind']=='Container Apps' and set(changes)&{'os','disk_gb','tier','redundancy','capacity_gb','used_gb'}:raise Invalid('Container Apps: Plattform-Betriebssystem und VM-Datenträger sind keine Kundeneinstellungen. Speicherklasse/Redundanz/Kapazität gehören zur verbundenen Ablage. Image, Port, Konfigurationsstatus, Größe und Instanzen separat prüfen.')
        if r['kind']=='Container Apps' and changes.get('status')=='deallocated' and r['status']!='deallocated':raise Invalid('Container Apps: keine VM-Deallokierung. Laufzeit starten/stoppen; im Lernmodell bleiben reservierte Kapazitätskosten beim Stoppen bestehen. Alte Freigabewerte werden nicht umgeschrieben.')
        if r['kind']=='App Service' and set(changes)&{'os','disk_gb','tier','redundancy','capacity_gb','used_gb'}:raise Invalid('App Service: keine VM-Betriebssystem-/Datenträger- oder Storage-Klassenverwaltung. Plattformpflege beim Anbieter; Anwendungsversion, Port, Konfiguration, Plangröße und Instanzen bearbeiten. Historische Felder bleiben erhalten.')
        if r['kind']=='Database' and set(changes)&{'os','disk_gb','image','tier','redundancy','capacity_gb','used_gb'}:raise Invalid('Datenbank-Lernservice: keine VM-OS-/Image-/Datenträger- oder Blob-Klassenverwaltung. Wirksam sind Endpunkt, Konfigurationsstatus, reservierte Lernklasse, Instanzen, Zonenverteilung und Betriebszustand. Historische gemeinsame Felder bleiben erhalten.')
        if r['kind']=='Database' and changes.get('status')=='deallocated' and r['status']!='deallocated':raise Invalid('Datenbank hat keine VM-Deallokierung. Dienst starten/stoppen; reservierte Lernkapazität bleibt im Kostenmodell bestehen. Alte Freigabewerte werden nicht automatisch geändert.')
        if r['kind']=='App Service' and changes.get('status')=='deallocated':raise Invalid('App Service: Anwendung stoppen; der zugehörige Lernplan bleibt kostenpflichtig. Keine VM-Deallokierung.')
        if r['kind']=='File Share' and set(changes)-{'name','region','department','owner','locked','ip','public_ip','subnet','tier','redundancy','capacity_gb','used_gb','configured'}:raise Invalid('Dateifreigabe: keine VM-, Betriebssystem- oder Image-Einstellungen.')
        if r['kind']=='SaaS' and set(changes)-{'name','region','department','owner','locked'}: raise Invalid('Externer SaaS-Dienst: Compute, Betriebssystem und Laufzeit werden vom Anbieter verwaltet.')
        if r['kind']!='Storage' and 'public' in changes:raise Invalid('Öffentlichen Endpunkt über eine öffentliche Lern-IP zuweisen; Blob-Freigabe gibt es nur bei Storage.')
        r.update(changes)
        if r['kind'] not in ('Storage','SaaS') and 'public_ip' in changes:r['public']=bool(r['public_ip'])
        require_resource_policy(s,r)
    elif action == 'power':
        if s['resources'][p['id']]['kind']=='Storage':raise Invalid('Storage Account ist ein verwalteter Datendienst, keine startbare VM. Verfügbarkeitsausfälle simuliert die Lehrkraft über die Trainerstörung Dokumentquelle; es gibt keine VM-Deallokierung.')
        if s['resources'][p['id']]['kind']=='File Share':raise Invalid('Dateifreigabe ist keine VM. Verfügbarkeitsausfälle werden durch die Trainerstörung Dokumentquelle simuliert.')
        if s['resources'][p['id']]['kind']=='SaaS': raise Invalid('Externer SaaS-Dienst wird vom Anbieter betrieben; kein VM-Start/Stop.')
        if s['resources'][p['id']]['kind']=='Container Apps' and p['operation']=='deallocate':raise Invalid('Container Apps hat keine VM-Deallokierung. Laufzeit stoppen behält reservierte Lernkapazität; nicht mehr benötigte eigene Bereitstellung nach Abhängigkeitsprüfung entfernen.')
        if s['resources'][p['id']]['kind']=='Database' and p['operation']=='deallocate':raise Invalid('Datenbank-Lernservice ist keine VM. Dienst stoppen behält reservierte Lernkosten; keine VM-Zuordnung freigeben. Reales Azure-PostgreSQL hat ein anderes Stop-/Abrechnungsmodell.')
        if s['resources'][p['id']]['kind']=='App Service' and p['operation']=='deallocate':raise Invalid('App Service hat keine VM-Deallokierung. Anwendung stoppen behält Lern-Plankosten; nicht mehr benötigte eigene App-plus-Plan-Bereitstellung gezielt entfernen.')
        status = {'start': 'running', 'restart': 'running', 'shutdown': 'stopped', 'deallocate': 'deallocated'}
        s['resources'][p['id']]['status'] = status[p['operation']]
    elif action == 'group_create':
        ident = p['id']
        if ident in s['resource_groups'] or len(ident) > 50: raise Invalid('Gruppe existiert oder Name zu lang.')
        if p['region'] not in s['policy']['regions'] or any(type(p[key]) is not str or not p[key].strip() for key in ('department','owner')): raise Invalid('Region und Tags erforderlich.')
        s['resource_groups'][ident] = {k:p[k] for k in ('region','department','owner')}
    elif action == 'create':
        if set(p)-{'id','name','kind','group','ip','subnet','region','department','owner','actor'}:raise Invalid('Unbekannte Felder für neue Ressource.')
        if p['id'] in s['resources'] or p['group'] not in s['resource_groups']: raise Invalid('ID belegt oder Ressourcengruppe fehlt.')
        candidate=resource(p['name'],p['kind'],p['group'],ip=p['ip'] if p['kind']!='SaaS' else '',subnet=p.get('subnet',s['resources']['web']['subnet']) if p['kind']!='SaaS' else '',region=p.get('region','germanywestcentral'),department=p.get('department','IT'),owner=p.get('owner','IT-Leitung'))
        require_resource_policy(s,candidate)
        s['resources'][p['id']]=candidate
        if p['kind']=='Container Apps':s['container_settings'][p['id']]={}
    elif action == 'delete_resource':
        require_unowned_resource(s,p['id'])
        if any(place['host']==p['id'] for place in s['document_storage'].values()) or any(d['resource']==p['id'] for d in s['requests']['deployments'].values()) or p['id'] in ('web','db','storage','container','paas','saas','testvm') or s['resources'][p['id']]['locked'] or any(resolve_target(s,host)==p['id'] for host in s['network']['dns']) or any(r['scope'] == p['id'] for r in s['roles']): raise Invalid('Löschschutz oder Abhängigkeit: zuerst Ressourcen-, DNS- und Rollenzuweisungen prüfen. Kurs-Kernressourcen werden benötigt.')
        del s['resources'][p['id']];s['container_settings'].pop(p['id'],None)
    elif action == 'network':
        if not set(p['changes']) <= {'vnet','onprem','vpn','dns'}: raise Invalid('Netzwerkfeld nicht unterstützt.')
        s['network'].update(p['changes'])
    elif action == 'subnet_set':
        if set(p)-{'id','cidr','actor'}:raise Invalid('Unbekannte Subnetzfelder.')
        s['network']['subnets'][p['id']]=p['cidr']
    elif action == 'subnet_remove':
        if p['id'] not in s['network']['subnets']:raise Invalid('Subnetz unbekannt.')
        if any(r['subnet']==p['id'] for r in s['resources'].values()):raise Invalid('Subnetz noch belegt; Ressourcen zuerst in ein anderes Subnetz umziehen.')
        del s['network']['subnets'][p['id']]
    elif action == 'rule_add':
        s['network']['rules'].append(p['rule'])
    elif action == 'rule_remove':
        s['network']['rules'] = [r for r in s['network']['rules'] if r['id'] != p['id']]
    elif action == 'user':
        if not set(p['changes']) <= set(s['users']['it']): raise Invalid('Benutzerfeld nicht unterstützt.')
        s['users'].setdefault(p['id'], copy.deepcopy(s['users']['lea'])).update(p['changes'])
    elif action == 'membership':
        members = s['groups'].setdefault(p['group'], [])
        if p['member'] not in s['users']: raise Invalid('Benutzer fehlt.')
        if p['add'] and p['member'] not in members: members.append(p['member'])
        if not p['add'] and p['member'] in members: members.remove(p['member'])
    elif action in ('role_add','role_remove'):
        if not login(s,p.get('actor','it'))[0] or 'assign' not in effective(s, p.get('actor','it'), p['scope'])[0]: raise Invalid('Rollenzuweisung verweigert: aktive Anmeldung mit Lern-MFA und Zuweisungsrecht erforderlich; Contributor allein genügt nicht.')
        row = {k:p[k] for k in ('principal','role','scope')}
        if action == 'role_add' and row not in s['roles']: s['roles'].append(row)
        if action == 'role_remove': s['roles'] = [r for r in s['roles'] if r != row]
    elif action=='data_policy' and (business_related(s,'cloud',p['id'])['local'] or business_related(s,'cloud',p['id'])['stage']):
        result=business_policy(s,'cloud',p['id'],p['changes'],p.get('actor','it'))
    elif action == 'data_policy':
        ident=p['id'];old=s['data_governance'][ident];changes=p['changes']
        if old['status']=='purged':raise Invalid('Entfernte Daten können nicht wieder aktiviert werden.')
        if type(changes) is not dict or set(changes)!={'owner','purpose','retain_minutes','hold','reason'}:raise Invalid('Verantwortung, Zweck, Dauer, Sperre und Begründung gemeinsam angeben.')
        until=s['minute']+number(changes['retain_minutes'],0,43200,True)
        if until<old['retention_until']:raise Invalid('Eine laufende Aufbewahrungsfrist darf nicht verkürzt werden.')
        updated=dict(old,owner=changes['owner'],purpose=changes['purpose'],retention_until=until,hold=changes['hold'],reason=changes['reason'])
        for key,rule in s['data_governance'].items():
            if rule['origin']==old['origin']:s['data_governance'][key]=copy.deepcopy(updated)
        result=dict(origin=old['origin'],owner=updated['owner'],retention_until=until,hold=updated['hold'])
    elif action == 'data_purge':
        ident=p['id'];rule=s['data_governance'][ident]
        if rule['status']=='purged':raise Invalid('Daten sind bereits entfernt.')
        if type(p.get('reason')) is not str or not p['reason'].strip() or len(p['reason'])>2000:raise Invalid('Entfernung begründen.')
        if rule['hold']:raise Invalid('Löschsperre aktiv: erst fachlich prüfen und begründet aufheben.')
        if s['minute']<rule['retention_until']:raise Invalid('Aufbewahrungsfrist läuft noch; Inhalt darf nicht entfernt werden.')
        related={key for key,value in s['data_governance'].items() if value['origin']==rule['origin']}
        pending=s['backup']['restore']
        if pending and (pending['source'] in related or pending['target'] in related):s['backup']['restore']=None
        for key in related:
            s['data_governance'][key]['status']='purged'
            for docs in [s['documents'],*(point['documents'] for point in s['backup']['points'])]:
                if key in docs:docs[key].update(content='',versions=[],deleted=True)
        # Prior file-write commands also contain content in this bounded audit model.
        for row in s['events']:
            parameters=row.get('parameters',{})
            if row.get('message')=='file_write' and parameters.get('id') in related:parameters['content']='[Im aktuellen Lernstand entfernt]'
        result=dict(origin=rule['origin'],documents=sorted(related),status='purged',reason=p['reason'])
        event(s,'data_purge','Inhalte und Versionen aus aktuellem Bestand und modellierten Sicherungspunkten entfernt.',parameters=dict(origin=rule['origin']))
    elif action in ('file_write','file_delete','version_restore'):
        if s['data_governance'][p['id']]['status']=='purged':raise Invalid('Daten wurden endgültig aus diesem Lernstand entfernt.')
        if not document_available(s,p['id'],for_write=action!='file_delete'):raise Invalid('Tatsächlicher Dokument-Speicher nicht verfügbar oder voll.')
        d = s['documents'][p['id']]
        actor=p.get('actor','it')
        if not login(s,actor)[0] or ('data_write' not in effective(s,actor,p['id'])[0] and actor!='it'):raise Invalid('Aktive Anmeldung mit Lern-MFA und passendes Daten-Schreibrecht erforderlich.')
        previous = {k:copy.deepcopy(v) for k,v in d.items() if k != 'versions'}
        if action == 'version_restore':
            if type(p['version']) is not int or p['version']<0:raise Invalid('Eine vorhandene ganzzahlige Dateiversion wählen.')
            old = next((v for v in d['versions'] if v['version'] == p['version']),None)
            if old is None:raise Invalid('Diese frühere Dateiversion ist nicht vorhanden. Vorhandene Versionsnummer wählen.')
            d.update({k:copy.deepcopy(v) for k,v in old.items() if k not in ('version','modified')})
        elif action == 'file_write': d['content'] = p['content']; d['deleted'] = False
        else: d['deleted'] = True
        d['versions'].append(previous); d['version'] += 1; d['modified'] = s['minute']
    elif action == 'backup_config':
        if not set(p['changes']) <= {'interval','retention','enabled'}: raise Invalid('Sicherungsfeld nicht unterstützt.')
        s['backup'].update(p['changes'])
    elif action == 'backup_run': snapshot_backup(s)
    elif action == 'restore':
        if not {'point','id'}<=set(p) or set(p)-{'point','id','target','actor'}-RECOVERY_CONTEXT:raise Invalid('Wiederherstellungsfelder fehlen oder sind unbekannt.')
        b=s['backup']
        if b['restore'] and b['restore']['status']=='running':raise Invalid('Eine Wiederherstellung läuft bereits. Ergebnis nach kontrolliertem Zeitfortschritt prüfen.')
        if p['id'] not in s['documents'] or s['data_governance'][p['id']]['status']=='purged':raise Invalid('Entfernte oder unbekannte Daten dürfen nicht wiederhergestellt werden.')
        point=next((x for x in b['points'] if x['id']==p['point']),None)
        if point is None or p['id'] not in point['documents']:raise Invalid('Vorhandenen Wiederherstellungspunkt mit diesem Dokument wählen.')
        target=p.get('target',p['id']+'-restored')
        if type(target) is not str or not target.strip() or len(target)>120 or target in ('__proto__','constructor','prototype'):raise Invalid('Gültiges begrenztes Wiederherstellungsziel wählen.')
        pending=dict(status='running',due=s['minute']+5,duration=5,point=point['id'],source=p['id'],target=target,point_minute=point['minute'],rpo=s['minute']-point['minute'],document=copy.deepcopy(point['documents'][p['id']]),failure_reason='',started_minute=s['minute'])
        pending.update(recovery_context(s,p))
        problem=restore_problem(s,pending)
        if problem:raise Invalid('Wiederherstellung nicht gestartet: '+problem)
        b['restore']=pending
    elif action == 'advance': advance(s, number(p['minutes'], 1, 1440, True))
    elif action == 'workload': s['workload'] = number(p['value'], 0, 1000, True)
    elif action == 'alarm_add':
        if type(p.get('rule')) is not dict or set(p['rule'])!={'id','target','metric','threshold','window','destination'}:raise Invalid('Alarmregel enthält fehlende oder unbekannte Felder.')
        rule = dict(p['rule'], streak=0)
        if type(rule['target']) is not str or rule['target'] not in s['resources'] or s['resources'][rule['target']]['kind'] not in METRIC_KINDS:raise Invalid('Für diesen Diensttyp sind CPU-/RAM-/Antwort-/Fehleralarme nicht modelliert.')
        if any(a['id'] == rule['id'] for a in s['alarms']): raise Invalid('Alarm-ID bereits belegt.')
        s['alarms'].append(rule)
    elif action == 'budget': s['budget'] = number(p['value'], .01, 100000)
    elif action == 'policy':
        if set(p['changes']) - {'regions','require_tags','deny_public'}: raise Invalid('Policy-Feld ungültig.')
        s['policy'].update(p['changes'])
    elif action == 'decision':
        if p['key'].startswith('migration_'):raise Invalid('Migrationsentscheidungen bitte über die Migrationsplanung bearbeiten.')
        s['decisions'][p['key']] = p['value']
    elif action == 'migration_plan':
        if set(p)!={'workload','strategy','reason'} or type(p['reason']) is not str or not p['reason'].strip() or len(p['reason'])>20000:raise Invalid('System, Strategie und kurze Begründung erforderlich.')
        if s['migration']['phase'] not in ('inventory','prepared','rolled_back'):raise Invalid('Zuerst laufende Migration zurückrollen, bevor der Plan geändert wird.')
        assessment=migration_assessment(s,p['workload'])
        if p['strategy'] not in [o['strategy'] for o in assessment['options']]:raise Invalid('Migrationsstrategie unbekannt.')
        s['decisions'].update(migration_workload=p['workload'],migration_strategy=p['strategy'],migration_reason=p['reason'])
        s['decisions'].pop('migration_copy_fingerprint',None)
        s['migration']=copy.deepcopy(fresh()['migration'])
        result=assessment
    elif action == 'migration':
        m = s['migration']; step = p['step']
        if step == 'prepare':
            if m['cutover']:raise Invalid('Vor neuer Vorbereitung auf die Quelle zurückfallen.')
            option=migration_choice(s)
            target=option['target']
            if p.get('target',target)!=target:raise Invalid('Ziel widerspricht der gewählten Strategie.')
            if target=='migrationvm':
                if target not in s['resources']:
                    source=s['resources']['web']
                    candidate=resource('vm-auftrag-ziel','VM',source['group'],ip=next_private_ip(s,source['subnet'],'10.20.1.60'),subnet=source['subnet'],os=source['os'],size=source['size'],status='deallocated',region=source['region'],department=source['department'],owner=source['owner'])
                    require_resource_policy(s,candidate)
                    s['resources'][target]=candidate
                elif s['resources'][target]['kind']!='VM':raise Invalid('Rehost-Zielkennung durch anderen Ressourcentyp belegt.')
            require_resource_policy(s,s['resources'][target])
            m.clear();m.update(copy.deepcopy(fresh()['migration']))
            m.update(phase='prepared',target=target,rollback=True)
            s['decisions'].pop('migration_copy_fingerprint',None)
        elif step == 'copy' and m['phase'] in ('prepared','copied','tested') and not m['interrupted']:
            option=migration_choice(s)
            if option['target']!=m['target']:raise Invalid('Migrationsplan und vorbereitetes Ziel widersprechen sich.')
            m.update(phase='copied',synced=True,tested=False,copied_version=s['documents']['offer']['version'],copied_order_revision=s['order_revision'])
            s['decisions']['migration_copy_fingerprint']=migration_fingerprint(s)
            s['resources'][m['target']]['status']='running'
        elif step == 'test' and m['phase']=='copied' and m['synced'] and not m['interrupted'] and s['decisions'].get('migration_copy_fingerprint')==migration_fingerprint(s) and migration_target_ready(s):
            m.update(phase='tested',tested=True)
        elif step == 'cutover' and m['tested'] and m['phase']=='tested' and not m['interrupted'] and s['decisions'].get('migration_copy_fingerprint')==migration_fingerprint(s) and migration_target_ready(s):
            s['network']['dns']['auftrag.intern']=m['target'];m.update(phase='cutover',cutover=True)
        elif step == 'followup' and m['phase']=='cutover' and not m['interrupted'] and resolve_target(s)==m['target'] and migration_target_ready(s):m['phase']='verified'
        elif step == 'cleanup' and m['phase']=='verified' and not m['interrupted'] and resolve_target(s)==m['target'] and migration_target_ready(s):
            s['resources']['web']['status']='deallocated';m.update(cleaned=True,phase='complete')
        elif step == 'rollback' and m['rollback']:
            s['network']['dns']['auftrag.intern']='web';s['resources']['web']['status']='running'
            if m['target']!='web' and m['target'] in s['resources']:s['resources'][m['target']]['status']='deallocated' if s['resources'][m['target']]['kind']=='VM' else 'stopped'
            m.update(phase='rolled_back',cutover=False,tested=False,synced=False,cleaned=False)
            s['decisions'].pop('migration_copy_fingerprint',None)
        else:raise Invalid('Migration gescheitert: Reihenfolge, Datenabgleich, Verbindung oder Rückfall fehlt.')
    elif action == 'diagnose':
        test = p['test']; args = p.get('args',{})
        testers={'connection':connection,'access':access,'application':application_access,'request':request_access,'local_connection':local_connection,'local_file':local_access,'local_application':local_application_access,'management':management_access}
        if test not in testers: raise Invalid('Diagnoseart nicht unterstützt.')
        result = testers[test](s, **args)
        if test in ('access','application','request'):record_signin(s,user=args.get('user','lea' if test=='access' else 'u11'),mfa=args.get('mfa',True),source=args.get('source','hq'),target=('Dokument '+args.get('document','offer')) if test=='access' else 'Auftragsanwendung' if test=='application' else 'Kundenanfragen',authorized=result['allowed'])
        if test=='management':record_signin(s,user=args.get('user','u11'),mfa=args.get('mfa',True),source='management',target='Verwaltung '+args.get('target','web'),authorized=result['allowed'])
        s['diagnostics'].append(dict(seq=s['seq'], minute=s['minute'], test=test, args=args, result=result))
        s['diagnostics'] = s['diagnostics'][-200:]
        event(s, 'diagnostic', f"{test}: {'erlaubt' if result['allowed'] else 'verweigert'}", detail=result)
    elif action == 'notes': s['notes'] = str(p['text'])[:10000]; s['name'] = str(p.get('name',s['name']))[:80]
    elif action == 'reply': s['replies'][s['task']] = str(p['text'])[:10000]
    elif action == 'fault':
        if not {'id','enabled'}<=set(p) or set(p)-{'id','enabled','resolution'}:raise Invalid('Störungsfelder ungültig.')
        result=trainer_fault(s,p['id'],p['enabled'],p.get('resolution','restore'))
    else: raise Invalid('Aktion nicht unterstützt.')
    if action not in ('diagnose','notes','reply','application_open','request_open','signin','local_open','local_read'):
        s['seq'] += 1
        event(s, 'change', action, parameters=p)
    validate(s)
    m=s['local_migration']
    if m['active'] and local_migration_source_hash(s)!=m['source_hash']:raise Invalid('Eingefrorener lokaler Quellbestand darf nach Umschaltung nicht verändert werden.')
    if m['cloud_present'] and not m['active'] and local_migration_cloud_hash(s)!=m['cloud_hash']:raise Invalid('Zurückbehaltene Cloudkopie ist nach Rückfall schreibgeschützt.')
    return s, result


def view(s):
    out = copy.deepcopy(s)
    out['computed'] = dict(runtime_profiles={key:runtime_profile(s,key) for key in s['resources']},container_configuration={key:container_context(s,key) for key in s['container_settings']},availability={ident:resource_availability(s,ident) for ident in s['resources']},resource_faults={ident:resource_faults(s,ident) for ident in s['resources']},reference_request=dict(user='u11',source='hq',operation='request_read',mfa=True,model=s['requests']['active'],authorization=request_access(s)),local_tcp={ident:local_connection(s,'hq',ident,r['port']) for ident,r in s['onprem']['services'].items()} if s['onprem']['enabled'] else {},reference_application=dict(user='u11',source='hq',operation='orders_read',mfa=True,authorization=application_access(s)),trainer_faults=fault_summaries(s),recovery_timing={'cloud':recovery_timing(s['backup']['restore'],s['minute']),'local':recovery_timing(s['onprem']['backup']['restore'],s['minute'])},business_data=business_summaries(s),local_addresses={key:str(ipaddress.ip_network(s['network']['onprem']).network_address+v['offset']) for key,v in s['onprem']['services'].items()},local_application=local_application_access(s),request_models=copy.deepcopy(REQUEST_MODELS),request_monthly=request_monthly(s),active_target=resolve_target(s),active_metrics=metrics(s,resolve_target(s)),alarm_metrics={r['target']:metrics(s,r['target']) for r in s['alarms']},migration_assessments=[migration_assessment(s,row['name']) for row in s['local_inventory']],metrics={k:metrics(s,k) for k in ('web','paas','container')},
                           hourly=hourly(s), monthly=monthly(s),
                           service=connection(s), prices=tariff_description(s))
    return out
