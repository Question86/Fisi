"""Fisi application service, sharing authenticated workspace scope with Northlight."""
from copy import deepcopy
from pathlib import Path
import secrets
from domain import Invalid
from persistence import Conflict, strict_json
from server import Application
from fisi_store import FisiWorkspaceStore
from fisi_lab import LESSON, PROBES, CHOICES, apply_lab, assessment
from fisi_inventory import checked_collection, merge_reports
from fisi_ui import PAGE


class FisiApplication(Application):
    def __init__(self, root, local_solo=False):
        super().__init__(root)
        self.local_solo = bool(local_solo)
        self.fisi = FisiWorkspaceStore(self.store)
        self.fisi.ensure('solo', 'Mein Lernworkspace')

    def login(self, code, name):
        with self.lock:
            ident = self.fisi.find_code(self.hash_code(code))
            if ident:
                self.codes[self.hash_code(code)] = {'role': 'learner', 'instance': ident}
            result = super().login(code, name)
            session = self.session(result['token'])
            self.fisi.ensure(session['instance'], self.store.get(session['instance'])['name'])
            return result

    def solo_login(self):
        if not self.local_solo:
            raise PermissionError("Solo-Einstieg ist im gemeinsamen Serverbetrieb gesperrt. Zugangscode verwenden.")
        return self.login(self.trainer_code, 'Lokaler Einzelbetrieb')

    def homepage(self):
        page = self.packaged_asset('index.html')
        return PAGE if page is None else page

    def packaged_asset(self, name):
        base = Path(__file__).parent.resolve()
        target = base / 'static' / name
        if not target.exists():
            return None
        if target.is_symlink() or not target.resolve().is_relative_to(base) or not target.is_file():
            raise Invalid("Paketdatei liegt außerhalb der erlaubten lokalen Assets.")
        return target.read_bytes().decode('utf-8')

    def asset(self, path):
        files = {'/static/fisi.js': 'fisi.js', '/static/fisi-style.js': 'fisi-style.js', '/static/fisi.css': 'fisi.css'}
        if path not in files:
            return None
        return self.packaged_asset(files[path])

    def scope(self, session, ident=None):
        ident = session['instance'] if ident is None else ident
        if type(ident) is not str or len(ident) > 64:
            raise Invalid("Ungültige Workspace-Kennung.")
        self.get(session, ident)  # Existing server-side role, revocation and instance checks.
        self.fisi.ensure(ident, self.store.get(ident)['name'])
        return ident

    def fisi_response(self, session, ident=None):
        with self.lock:
            ident = self.scope(session, ident)
            record = self.fisi.read(ident)
            record.update(role=session['role'], participant=session.get('name', 'Lernende Person'), local_solo=self.local_solo,
                          lesson=deepcopy(LESSON), probes=deepcopy(PROBES), choices=deepcopy(CHOICES), assessment=assessment(record['state']['lab']))
            if session['role'] == 'trainer':
                record['workspaces'] = self.fisi.groups()
            return record

    def fisi_export(self, session, ident=None):
        with self.lock:
            return self.fisi.export(self.scope(session, ident))

    def fisi_action(self, session, payload):
        if type(payload) is not dict or set(payload) != {'instance', 'revision', 'action', 'parameters'}:
            raise Invalid("Workspace, Version, Aktion und Parameter sind erforderlich.")
        parameters = payload['parameters']
        if type(parameters) is not dict or type(payload['action']) is not str:
            raise Invalid("Ungültige Aktion oder Parameter.")
        with self.lock, self.store.lock:
            ident = self.scope(session, payload['instance'])
            current = self.fisi.read(ident)
            if type(payload['revision']) is not int or payload['revision'] != current['revision']:
                raise Conflict("Workspace wurde inzwischen geändert. Eigene Eingaben vor erneutem Speichern prüfen.")
            action = payload['action']
            result = None
            if action == 'workspace_create':
                if session['role'] != 'trainer':
                    raise PermissionError("Nur Trainer dürfen gemeinsame Workspaces anlegen.")
                if set(parameters) != {'name'} or type(parameters['name']) is not str or not 1 <= len(parameters['name'].strip()) <= 80:
                    raise Invalid("Einen Workspace-Namen mit 1 bis 80 Zeichen eingeben.")
                target = secrets.token_hex(16)
                code = secrets.token_urlsafe(18)
                self.store.ensure(target, parameters['name'].strip())
                self.fisi.create_group(target, parameters['name'], self.hash_code(code))
                result = {'workspace': target, 'code': code, 'name': parameters['name'].strip()}
            elif action == 'restore':
                if session['role'] != 'trainer':
                    raise PermissionError("Workspace-Wiederherstellung ist eine Traineraktion.")
                if set(parameters) != {'bundle_text', 'legacy_revision'} or type(parameters['bundle_text']) is not str or len(parameters['bundle_text'].encode('utf-8')) > 20 * 1024 * 1024:
                    raise Invalid("Sicherung und Referenzversion sind erforderlich.")
                self.fisi.restore(ident, payload['revision'], parameters['legacy_revision'], strict_json(parameters['bundle_text']))
                result = {'message': 'Workspace wiederhergestellt. Vorheriger Stand wurde lokal gesichert.'}
            else:
                def mutate(state):
                    if action in ('configure', 'diagnose', 'explain', 'intro', 'submit'):
                        state['lab'] = apply_lab(state['lab'], action, parameters, session.get('name', 'Lernende Person'))
                    elif action == 'inventory_import':
                        if set(parameters) != {'texts'} or type(parameters['texts']) is not list or not 1 <= len(parameters['texts']) <= 20 or any(type(value) is not str for value in parameters['texts']):
                            raise Invalid("Eine bis zwanzig Inventardateien als Text erwartet.")
                        if sum(len(value.encode('utf-8')) for value in parameters['texts']) > 2 * 1024 * 1024:
                            raise Invalid("Inventardateien zusammen maximal 2 MiB.")
                        for value in parameters['texts']:
                            state['inventory'] = merge_reports(state['inventory'], strict_json(value))
                    elif action == 'journal':
                        if set(parameters) != {'text'} or type(parameters['text']) is not str:
                            raise Invalid("Journaltext erwartet.")
                        state['journal'] = parameters['text']
                    else:
                        raise Invalid("Unbekannte Fisi-Aktion.")
                    return state
                self.fisi.update(ident, payload['revision'], mutate)
            return {'record': self.fisi_response(session, ident), 'result': result}
