"""Fisi behavior tests: actual state, atomic storage, identities and access refusals."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import threading
import urllib.request
import urllib.error
import uuid
import unittest
from unittest.mock import patch

from domain import Invalid
from persistence import Conflict
from fisi_app import FisiApplication
from fisi_lab import fresh_lab, apply_lab, assessment, PROBES, validate_lab
from fisi_inventory import checked_collection, merge_reports, synthetic_inventory, REPORT, COLLECTION
from server import make_server

EXPLANATION = 'Ich habe DNS, Netzwerkpfad und Dateirecht getrennt geprüft. Nur das Büronetz und die Support-Gruppe erhalten den benötigten Zugriff; Gäste bleiben an der vorgesehenen Grenze gesperrt.'


class LabTests(unittest.TestCase):
    def solved(self):
        lab = fresh_lab()
        for field, value in [('dns','192.0.2.20'),('firewall','office'),('readers','support')]:
            lab = apply_lab(lab, 'configure', {'field':field,'value':value}, 'Test')
        for probe in PROBES:
            lab = apply_lab(lab, 'diagnose', {'probe':probe}, 'Test')
        return apply_lab(lab, 'explain', {'text':EXPLANATION}, 'Test')

    def test_complete_independent_task_needs_real_configuration_fresh_probes_and_explanation(self):
        lab = fresh_lab()
        self.assertFalse(assessment(lab)['passed'])
        lab = self.solved()
        self.assertTrue(assessment(lab)['passed'])
        result = apply_lab(lab, 'submit', {}, 'Lea')
        self.assertEqual(result['minute'], lab['minute'] + 1)
        self.assertEqual(result['attempts'][-1]['author'], 'Lea')
        self.assertTrue(result['attempts'][-1]['passed'])

    def test_broken_dns_does_not_count_as_successful_security_denial(self):
        lab = fresh_lab()
        for probe in PROBES:
            lab = apply_lab(lab, 'diagnose', {'probe':probe}, 'Test')
        self.assertTrue(all(not row['result']['allowed'] for row in lab['diagnostics'].values()))
        self.assertTrue(all(not row['passed'] for row in assessment(lab)['checks'] if row['id'] in PROBES))

    def test_any_configuration_change_invalidates_previous_evidence(self):
        lab = self.solved()
        changed = apply_lab(lab, 'configure', {'field':'service','value':False}, 'Test')
        self.assertEqual(changed['diagnostics'], {})
        self.assertFalse(assessment(changed)['passed'])
        self.assertTrue(assessment(lab)['passed'])

    def test_everyone_or_guest_network_access_cannot_pass(self):
        for field, value in [('readers','everyone'),('firewall','all')]:
            lab = apply_lab(self.solved(), 'configure', {'field':field,'value':value}, 'Test')
            for probe in PROBES:
                lab = apply_lab(lab, 'diagnose', {'probe':probe}, 'Test')
            self.assertFalse(assessment(lab)['passed'])

    def test_bad_action_types_and_client_supplied_success_are_atomic(self):
        initial = fresh_lab()
        for action, parameters in [('configure',{'field':'service','value':1}),('configure',{'field':'role','value':'admin'}),('submit',{'passed':True}),('explain',{'text':'x'*4001})]:
            with self.subTest(action=action,parameters=parameters), self.assertRaises(Invalid):
                apply_lab(initial, action, parameters, 'Test')
            self.assertEqual(initial, fresh_lab())

    def test_forged_diagnostic_is_rejected_and_intro_is_actually_checked(self):
        lab = self.solved()
        lab['diagnostics']['support-office']['result']['allowed'] = False
        with self.assertRaises(Invalid):
            validate_lab(lab)
        with self.assertRaises(Invalid):
            apply_lab(fresh_lab(), 'intro', {'answer':'all'}, 'Test')
        self.assertTrue(apply_lab(fresh_lab(), 'intro', {'answer':'separate'}, 'Test')['intro'])

    def test_diagnostic_booleans_cannot_be_integer_lookalikes(self):
        lab = self.solved()
        lab['diagnostics']['support-office']['result']['allowed'] = 1
        with self.assertRaises(Invalid):
            validate_lab(lab)


class InventoryTests(unittest.TestCase):
    def report(self):
        return synthetic_inventory()['reports'][0]

    def test_single_and_collection_roundtrip(self):
        collection = synthetic_inventory()
        self.assertEqual(checked_collection(json.loads(json.dumps(collection))), collection)
        self.assertEqual(checked_collection(collection['reports'][0]), collection)

    def test_null_adapter_duplicate_device_and_bad_values_are_rejected(self):
        variants = []
        row = self.report(); row['devices'][0]['adapters'] = [None]; variants.append(row)
        row = self.report(); row['devices'].append(deepcopy(row['devices'][0])); variants.append(row)
        row = self.report(); row['devices'][0]['memoryMiB'] = True; variants.append(row)
        row = self.report(); row['devices'][0]['adapters'][0]['addresses'] = ['999.1.1.1/24']; variants.append(row)
        row = self.report(); row['collectedAt'] = '2026-01-01'; variants.append(row)
        for row in variants:
            with self.subTest(row=row), self.assertRaises(Invalid):
                checked_collection(row)

    def test_report_conflict_does_not_overwrite_existing_bytes(self):
        before = synthetic_inventory()
        incoming = self.report(); incoming['devices'][0]['name'] = 'Different'
        snapshot = deepcopy(before)
        with self.assertRaises(Invalid):
            merge_reports(before, incoming)
        self.assertEqual(before, snapshot)
        self.assertEqual(merge_reports(before, self.report()), before)

    def test_same_names_and_ids_from_different_sources_remain_separate(self):
        other = self.report(); other['source']['id'] = 'another-source'
        merged = merge_reports(synthetic_inventory(), other)
        self.assertEqual(len(merged['reports']), 2)
        self.assertEqual(merged['reports'][0]['devices'][0]['id'], merged['reports'][1]['devices'][0]['id'])

    def test_network_object_types_survive_same_name_and_identifier(self):
        row = self.report()
        row['devices'][0]['adapters'][0]['network']['kind'] = 'hyperv-switch'
        row['devices'][1]['adapters'][0]['network']['kind'] = 'scvmm-vmnetwork'
        normalized = checked_collection(row)['reports'][0]
        kinds = {device['adapters'][0]['network']['kind'] for device in normalized['devices']}
        self.assertEqual(kinds, {'hyperv-switch','scvmm-vmnetwork'})

    def test_native_single_collection_and_unknown_memory(self):
        native = {'schema':'mb-fisi-native-lab/v1','generatedAt':'2026-01-01T00:00:00Z','collector':'Example','mode':'local','devices':[{'id':'LOCAL:example','name':'Example','kind':'VM','memoryMiB':4*1024**3,'adapters':[{'name':'Ethernet','status':'Up','ipAddresses':[{'address':'192.0.2.40','prefix':24}],'switch':'Same name'}]}]}
        single = checked_collection(native)
        collection = checked_collection({'schema':'mb-fisi-native-lab-collection/v1','reports':[native]})
        self.assertEqual(single, collection)
        self.assertIsNone(single['reports'][0]['devices'][0]['memoryMiB'])
        native['devices'][0]['adapters'] = [None]
        with self.assertRaises(Invalid):
            checked_collection(native)

    def test_bounded_depth_and_device_count(self):
        row = self.report(); row['devices'] = row['devices'] * 101
        with self.assertRaises(Invalid):
            checked_collection(row)
        nested = value = {}
        for _ in range(15):
            value['x'] = {}; value = value['x']
        with self.assertRaises(Invalid):
            checked_collection(nested)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        # Keep bounded evidence inside the isolated candidate with inherited Windows ACLs.
        evidence = Path(__file__).parent / '.cache' / 'fisi-test-evidence' / uuid.uuid4().hex
        evidence.mkdir(parents=True)
        self.temp = type('Evidence', (), {'name':str(evidence)})()
        self.app = FisiApplication(self.temp.name, local_solo=True)
        login = self.app.solo_login()
        self.trainer = self.app.session(login['token'])

    def tearDown(self):
        pass

    def state(self, session=None, ident=None):
        return self.app.fisi_response(session or self.trainer, ident)

    def action(self, action, parameters=None, session=None, record=None):
        session = session or self.trainer
        record = record or self.state(session)
        return self.app.fisi_action(session, {'instance':record['id'],'revision':record['revision'],'action':action,'parameters':parameters or {}})

    def group(self):
        result = self.action('workspace_create', {'name':'Gemeinsam'})['result']
        token1 = self.app.login(result['code'],'Lea')['token']
        token2 = self.app.login(result['code'],'Nilo')['token']
        return result, self.app.session(token1), self.app.session(token2)

    def test_two_participants_share_state_stale_write_conflicts_and_foreign_scope_denies(self):
        group, one, two = self.group()
        stale = self.state(two)
        self.action('journal', {'text':'Gemeinsam untersucht'}, one)
        self.assertEqual(self.state(two)['state']['journal'], 'Gemeinsam untersucht')
        with self.assertRaises(Conflict):
            self.action('journal', {'text':'stale'}, two, stale)
        with self.assertRaises(PermissionError):
            self.state(one, 'solo')
        self.assertEqual(self.state()['state']['journal'], '')

    def test_learner_trainer_actions_are_denied(self):
        _, learner, _ = self.group()
        before = self.state(learner)
        with self.assertRaises(PermissionError):
            self.action('workspace_create', {'name':'Forbidden'}, learner)
        with self.assertRaises(PermissionError):
            self.action('restore', {'bundle_text':'{}','legacy_revision':0}, learner)
        self.assertEqual(self.state(learner), before)

    def test_journal_inventory_and_learning_share_one_revision(self):
        before = self.state()
        self.action('intro', {'answer':'separate'})
        with self.assertRaises(Conflict):
            self.action('journal', {'text':'old version'}, record=before)
        report = synthetic_inventory()['reports'][0]; report['source']['id'] = 'second'
        current = self.state()
        self.action('inventory_import', {'texts':[json.dumps(report)]})
        after = self.state()
        self.assertEqual(after['revision'], current['revision'] + 1)
        self.assertTrue(after['state']['lab']['intro'])
        self.assertEqual(len(after['state']['inventory']['reports']), 2)

    def test_multiple_imports_are_validated_atomically_including_duplicate_json_keys(self):
        before = self.state()
        good = synthetic_inventory()['reports'][0]; good['source']['id'] = 'new'
        bad = deepcopy(good); bad['devices'][0]['adapters'] = [None]
        for texts in ([json.dumps(good),json.dumps(bad)], ['{"schema":"x","schema":"y"}']):
            with self.assertRaises(Invalid):
                self.action('inventory_import', {'texts':texts})
            self.assertEqual(self.state(), before)

    def test_saved_group_codes_and_workspace_state_survive_restart(self):
        group, learner, _ = self.group()
        self.action('journal', {'text':'Bleibt nach Neustart'}, learner)
        restarted = FisiApplication(self.temp.name)
        login = restarted.login(group['code'], 'Nach Neustart')
        record = restarted.fisi_response(restarted.session(login['token']))
        self.assertEqual(record['id'], group['workspace'])
        self.assertEqual(record['state']['journal'], 'Bleibt nach Neustart')
        with self.assertRaises(PermissionError):
            restarted.solo_login()

    def test_full_export_restore_preserves_legacy_exercises_and_own_state(self):
        self.action('journal', {'text':'Gesicherter Stand'})
        old = self.app.get(self.trainer)
        self.app.dispatch(self.trainer, {'instance':'solo','revision':old['revision'],'action':'notes','parameters':{'text':'Referenzstand','name':'Test'}})
        bundle = self.app.fisi_export(self.trainer)
        self.action('journal', {'text':'Zwischenstand'})
        record = self.state()
        self.action('restore', {'bundle_text':json.dumps(bundle),'legacy_revision':record['legacy_revision']}, record=record)
        self.assertEqual(self.state()['state']['journal'], 'Gesicherter Stand')
        self.assertEqual(self.app.get(self.trainer)['state']['notes'], 'Referenzstand')
        self.assertTrue(list(Path(self.temp.name).glob('before-fisi-import-*.json')))

    def test_sql_failure_rolls_back_both_fisi_and_legacy_state(self):
        bundle = self.app.fisi_export(self.trainer)
        bundle['state']['journal'] = 'Must not commit'
        before = self.state(); old = self.app.get(self.trainer)
        with self.app.store.connect() as db:
            db.execute("CREATE TRIGGER fail_restore BEFORE UPDATE ON instances BEGIN SELECT RAISE(ABORT,'injected failure'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            self.action('restore', {'bundle_text':json.dumps(bundle),'legacy_revision':before['legacy_revision']}, record=before)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.app.get(self.trainer), old)

    def test_failed_backup_or_stale_legacy_revision_does_not_mutate(self):
        bundle = self.app.fisi_export(self.trainer); before = self.state()
        with patch.object(self.app.store, 'write_bundle_backup', side_effect=Invalid('Cannot back up')):
            with self.assertRaises(Invalid):
                self.action('restore', {'bundle_text':json.dumps(bundle),'legacy_revision':before['legacy_revision']})
        self.assertEqual(self.state(), before)
        with self.assertRaises(Conflict):
            self.action('restore', {'bundle_text':json.dumps(bundle),'legacy_revision':before['legacy_revision']+1})
        self.assertEqual(self.state(), before)

    def test_bad_import_and_bad_action_preserve_all_workspace_parts(self):
        before = self.state()
        for action, params in [('journal',{'text':None}),('submit',{'passed':True}),('configure',{'field':'dns','value':False})]:
            with self.assertRaises(Invalid):
                self.action(action, params)
            self.assertEqual(self.state(), before)


class FisiHTTPTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parent / '.cache' / 'fisi-http-evidence' / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.app = FisiApplication(self.root, local_solo=True)
        self.server = make_server(self.app, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.token = self.request('/api/fisi/bootstrap', {})['token']

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def request(self, path, data=None, token=None, headers=None):
        values = {'Content-Type':'application/json'}
        if token:
            values['Authorization'] = 'Bearer ' + token
        values.update(headers or {})
        request = urllib.request.Request(self.url + path, data=None if data is None else json.dumps(data).encode('utf-8'), headers=values)
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def state(self, token=None):
        return self.request('/api/fisi/state', token=token or self.token)

    def action(self, name, parameters=None, token=None, record=None):
        token = token or self.token
        record = record or self.state(token)
        return self.request('/api/fisi/action', {'instance':record['id'],'revision':record['revision'],'action':name,'parameters':parameters or {}}, token)

    def test_fisi_page_assets_and_exact_route_boundary(self):
        with urllib.request.urlopen(self.url, timeout=10) as response:
            page = response.read().decode('utf-8')
        self.assertIn('Fisi', page)
        self.assertIn('/static/fisi.js', page)
        for name in ('fisi.js','fisi-style.js'):
            with urllib.request.urlopen(self.url + '/static/' + name, timeout=10) as response:
                self.assertEqual(response.headers['Content-Type'], 'text/javascript; charset=utf-8')
                self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(response.read(), (Path(__file__).parent/'static'/name).read_bytes())
        for path in ('/static/../server.py','/static/%2e%2e/server.py','/static/fisi.js?file=server.py','/api/fisi/state-extra'):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(self.url + path, timeout=10)
            self.assertEqual(error.exception.code, 404)
        with urllib.request.urlopen(self.url + '/reference/', timeout=10) as response:
            self.assertIn('/static/client.js', response.read().decode('utf-8'))

    def test_bootstrap_is_not_available_in_shared_mode_and_host_origin_are_checked(self):
        self.app.local_solo = False
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/fisi/bootstrap', {})
        self.assertEqual(error.exception.code, 403)
        for headers in ({'Host':'attacker.invalid'}, {'Origin':'https://attacker.invalid'}):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request('/api/fisi/state', token=self.token, headers=headers)
            self.assertEqual(error.exception.code, 403)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/fisi/state')
        self.assertEqual(error.exception.code, 403)

    def test_generated_package_html_and_stylesheet_are_served_as_exact_local_files(self):
        import fisi_delivery
        import fisi_app
        emitted = self.root/'emitted'
        fisi_delivery.generated_assets(Path(__file__).parent, emitted)
        with patch.object(fisi_app, '__file__', str(emitted/'fisi_app.py')):
            with urllib.request.urlopen(self.url+'/',timeout=10) as response:
                self.assertEqual(response.read(),(emitted/'static/index.html').read_bytes())
            with urllib.request.urlopen(self.url+'/static/fisi.css',timeout=10) as response:
                self.assertEqual(response.headers['Content-Type'],'text/css; charset=utf-8')
                self.assertEqual(response.read(),(emitted/'static/fisi.css').read_bytes())
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(self.url+'/static/index.html',timeout=10)
            self.assertEqual(error.exception.code,404)

    def test_complete_learning_workflow_over_real_http_and_persistence(self):
        self.action('intro', {'answer':'separate'})
        for field, value in [('dns','192.0.2.20'),('firewall','office'),('readers','support')]:
            self.action('configure', {'field':field,'value':value})
        for probe in PROBES:
            self.action('diagnose', {'probe':probe})
        self.action('explain', {'text':EXPLANATION})
        result = self.action('submit')['record']
        self.assertTrue(result['assessment']['passed'])
        self.assertTrue(result['state']['lab']['attempts'][-1]['passed'])
        reopened = FisiApplication(self.root, local_solo=True)
        token = reopened.solo_login()['token']
        restored = reopened.fisi_response(reopened.session(token))
        self.assertEqual(restored['state'], result['state'])

    def test_two_http_clients_share_the_workspace_and_conflict_without_overwriting(self):
        group = self.action('workspace_create', {'name':'HTTP-Gruppe'})['result']
        one = self.request('/api/login', {'code':group['code'],'name':'Lea'})['token']
        two = self.request('/api/login', {'code':group['code'],'name':'Nilo'})['token']
        stale = self.state(two)
        self.action('journal', {'text':'Gemeinsam über HTTP'}, token=one)
        self.assertEqual(self.state(two)['state']['journal'], 'Gemeinsam über HTTP')
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.action('journal', {'text':'Must not overwrite'}, token=two, record=stale)
        self.assertEqual(error.exception.code, 409)
        for path in ('/api/fisi/state?instance=solo','/api/fisi/export?instance=solo'):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(path, token=one)
            self.assertEqual(error.exception.code, 403)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.action('workspace_create', {'name':'Forbidden'}, token=one)
        self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.state()['state']['journal'], '')

    def test_invalid_import_over_http_preserves_state(self):
        before = self.state()
        invalid = synthetic_inventory()['reports'][0]
        invalid['devices'][0]['adapters'] = [None]
        for texts in ([json.dumps(invalid)], ['{"schema":"x","schema":"y"}']):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.action('inventory_import', {'texts':texts})
            self.assertEqual(error.exception.code, 400)
            self.assertEqual(self.state(), before)

    def test_internal_exception_is_actually_logged_without_token_or_payload(self):
        before = self.state()
        secret = 'private-inventory-value-not-for-logs'
        with patch.object(self.app, 'fisi_action', side_effect=RuntimeError('injected storage failure')):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.action('journal', {'text':secret})
        self.assertEqual(error.exception.code, 500)
        log = (self.root/'server-errors.log').read_text(encoding='utf-8')
        self.assertIn('Traceback', log)
        self.assertIn('injected storage failure', log)
        self.assertNotIn(self.token, log)
        self.assertNotIn(secret, log)
        self.assertEqual(self.state(), before)


if __name__ == '__main__':
    unittest.main()
