"""Packaging unit tests plus real, freshly extracted Windows-runtime acceptance."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shutil
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import uuid
import zipfile

import fisi_delivery as delivery


def verify_manifest(root, filename):
    manifest=json.loads((root/filename).read_text(encoding='utf-8'))
    if manifest.get('schema')!='fisi-file-manifest/v1' or type(manifest.get('files')) is not dict:
        raise ValueError('Invalid package manifest.')
    expected=manifest['files']
    actual={file.relative_to(root).as_posix() for file in root.rglob('*') if file.is_file() and file.name!=filename}
    if actual!=set(expected):
        raise ValueError('Package has missing or undeclared files.')
    for name,digest in expected.items():
        target=root.joinpath(*PurePosixPath(name).parts)
        if not target.resolve().is_relative_to(root.resolve()) or target.is_symlink() or not re.fullmatch('[a-f0-9]{64}',digest) or hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
            raise ValueError('Package checksum mismatch.')
    return len(expected)


def checked_extract(archive, target):
    target=Path(target).resolve()
    if target.exists():
        raise ValueError('Extraction requires a fresh destination.')
    with zipfile.ZipFile(archive) as bundle:
        entries=bundle.infolist()
        if len(entries)>20000 or sum(item.file_size for item in entries)>512*1024*1024:
            raise ValueError('Package exceeds extraction bounds.')
        names=set()
        for item in entries:
            name=PurePosixPath(item.filename)
            if not item.filename or name.is_absolute() or '..' in name.parts or any(':' in part or '\\' in part for part in name.parts) or (item.external_attr>>16 & 0o170000)==0o120000:
                raise ValueError('Unsafe archive member.')
            identity=item.filename.casefold().rstrip('/')
            if identity in names:
                raise ValueError('Duplicate archive member.')
            names.add(identity)
        target.mkdir(parents=True)
        bundle.extractall(target)
    verify_manifest(target,'MANIFEST-SHA256.json')
    return target


def verify_windows(archive, output):
    if sys.platform!='win32':
        raise RuntimeError('Actual Windows-package acceptance requires Windows.')
    output=Path(output).resolve()
    if ' ' not in str(output):
        raise ValueError('Acceptance extraction path must contain spaces.')
    package=checked_extract(archive,output)
    runtime=package/'runtime/python.exe'
    environment=dict(os.environ)
    environment['PATH']=str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32')
    environment.pop('PYTHONHOME',None);environment.pop('PYTHONPATH',None)
    probe=subprocess.check_output([str(runtime),'-B','-c','import sys,json;print(json.dumps(dict(executable=sys.executable,path=sys.path,version=sys.version)))'],cwd=package,env=environment,timeout=30,text=True,encoding='utf-8',errors='replace')
    interpreter=json.loads(probe)
    if Path(interpreter['executable']).resolve()!=runtime.resolve() or not all(Path(item).resolve().is_relative_to(package) for item in interpreter['path']):
        raise AssertionError('Bundled interpreter escaped its declared package paths.')
    data=output.parent/(output.name+' data')
    if data.exists():
        raise ValueError('Acceptance requires fresh synthetic server data.')
    checks=['ZIP manifest verified','Fresh extraction path contains spaces','Bundled runtime launches with developer PATH removed','Interpreter imports only declared package paths']
    process=None

    def start():
        child=subprocess.Popen([str(runtime),'-B','-u',str(package/'app/server.py'),'--port','0','--no-browser','--data',str(data)],cwd=package,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
        lines=queue.Queue()
        def reader():
            for line in child.stdout:
                lines.put(line)
        threading.Thread(target=reader,daemon=True).start()
        try:
            for _ in range(30):
                line=lines.get(timeout=20)
                match=re.search(r'http://127\.0\.0\.1:\d+',line)
                if match:return child,match[0]
                if child.poll() is not None:break
        except queue.Empty:
            pass
        child.terminate();child.wait(timeout=10)
        raise RuntimeError('Bundled server did not start; inspect its isolated test output.')

    def request(base,path,body=None,token=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode('utf-8'),headers=headers)
        with urllib.request.urlopen(req,timeout=15) as response:
            return json.load(response)

    def action(base,token,name,parameters=None,record=None):
        record=record or request(base,'/api/fisi/state',token=token)
        return request(base,'/api/fisi/action',{'instance':record['id'],'revision':record['revision'],'action':name,'parameters':parameters or {}},token)

    result={'schema':'fisi-windows-acceptance/v1','status':'FAIL','checks':checks,'browser_acceptance':'Separate real Edge workflow required; HTTP/runtime acceptance does not prove browser interaction.'}
    try:
        process,base=start()
        token=request(base,'/api/fisi/bootstrap',{})['token']
        with urllib.request.urlopen(base+'/',timeout=15) as response:
            html=response.read().decode('utf-8')
        if 'Fisi' not in html or '/static/fisi.css' not in html:
            raise AssertionError('Built package did not serve its generated Fisi HTML/CSS entry point.')
        for name,mime in [('fisi.css','text/css'),('fisi.js','text/javascript')]:
            with urllib.request.urlopen(base+'/static/'+name,timeout=15) as response:
                if not response.headers['Content-Type'].startswith(mime) or response.read()!=(package/'app/static'/name).read_bytes():
                    raise AssertionError('Local package asset or MIME mismatch.')
        checks.append('Actual packaged server and local HTML/CSS/JavaScript assets work')
        action(base,token,'intro',{'answer':'separate'})
        for field,value in [('dns','192.0.2.20'),('firewall','office'),('readers','support')]:
            action(base,token,'configure',{'field':field,'value':value})
        for probe_name in ('support-office','support-guest','guest-office'):
            action(base,token,'diagnose',{'probe':probe_name})
        action(base,token,'explain',{'text':'DNS, Netzwerkpfad und Dateirecht wurden getrennt untersucht. Nur Büro und Support sind freigegeben; die negativen Fälle scheitern an der vorgesehenen Grenze.'})
        passed=action(base,token,'submit')['record']
        if not passed['assessment']['passed']:
            raise AssertionError('Packaged lesson did not reach its actual criteria.')
        checks.append('Complete substantive lesson and fresh positive/negative evidence')
        action(base,token,'journal',{'text':'Packaged restart evidence'})
        bundle=request(base,'/api/fisi/export',token=token)
        action(base,token,'journal',{'text':'Interim'})
        record=request(base,'/api/fisi/state',token=token)
        action(base,token,'restore',{'bundle_text':json.dumps(bundle),'legacy_revision':record['legacy_revision']},record)
        if request(base,'/api/fisi/state',token=token)['state']['journal']!='Packaged restart evidence':
            raise AssertionError('Workspace restore failed.')
        checks.append('Full workspace export/restore includes legacy exercises')
        before=request(base,'/api/fisi/state',token=token)
        invalid={'schema':'fisi-inventory-collection/v1','reports':[None]}
        try:
            action(base,token,'inventory_import',{'texts':[json.dumps(invalid)]})
            raise AssertionError('Malformed inventory was accepted.')
        except urllib.error.HTTPError as error:
            if error.code!=400:raise
        if request(base,'/api/fisi/state',token=token)!=before:
            raise AssertionError('Rejected import changed workspace state.')
        checks.append('Rejected untrusted import leaves actual state unchanged')
        group=action(base,token,'workspace_create',{'name':'Package QA group'})['result']
        one=request(base,'/api/login',{'code':group['code'],'name':'QA one'})['token']
        two=request(base,'/api/login',{'code':group['code'],'name':'QA two'})['token']
        stale=request(base,'/api/fisi/state',token=two)
        action(base,one,'journal',{'text':'Shared package evidence'})
        if request(base,'/api/fisi/state',token=two)['state']['journal']!='Shared package evidence':
            raise AssertionError('Independent participants did not share state.')
        try:
            action(base,two,'journal',{'text':'Stale overwrite'},stale)
            raise AssertionError('Stale write accepted.')
        except urllib.error.HTTPError as error:
            if error.code!=409:raise
        for route in ('/api/fisi/state?instance=solo','/api/fisi/export?instance=solo'):
            try:
                request(base,route,token=one)
                raise AssertionError('Foreign workspace access accepted.')
            except urllib.error.HTTPError as error:
                if error.code!=403:raise
        checks.append('Two participants, shared state, stale-write conflict and foreign-workspace denials')
        process.terminate();process.wait(timeout=10);process=None
        process,base=start()
        token=request(base,'/api/fisi/bootstrap',{})['token']
        after=request(base,'/api/fisi/state',token=token)
        if not after['assessment']['passed'] or after['state']['journal']!='Packaged restart evidence':
            raise AssertionError('Accepted solo state did not survive actual process restart.')
        learner=request(base,'/api/login',{'code':group['code'],'name':'QA restart'})['token']
        if request(base,'/api/fisi/state',token=learner)['state']['journal']!='Shared package evidence':
            raise AssertionError('Group code/state did not survive restart.')
        checks.append('Actual bundled-process restart preserves solo/group state and join code')
        result['runtime_version']=interpreter['version']
        result['shipped_powershell_files']=len(list(package.rglob('*.ps1')))
        if result['shipped_powershell_files']:
            raise AssertionError('Unexpected PowerShell collector/script in the explicit package.')
        result['status']='PASS'
    except Exception as error:
        result['failure_type']=type(error).__name__
        raise
    finally:
        if process and process.poll() is None:
            process.terminate();process.wait(timeout=10)
        (package/'ACCEPTANCE.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parent/'.cache'/'release-evidence'/uuid.uuid4().hex
        self.source=self.root/'inputs';self.source.mkdir(parents=True)
        for name in delivery.RUNTIME_SOURCES+delivery.DEVELOPMENT_SOURCES+delivery.STATIC_SOURCES:
            source=Path(__file__).parent/name
            target=self.source/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)

    def test_explicit_source_export_excludes_private_and_generated_runtime_state(self):
        (self.source/'private').mkdir();(self.source/'private/token.txt').write_text('not-for-publication')
        (self.source/'sessions.sqlite3').write_bytes(b'not-for-publication')
        result=delivery.export(self.source,self.root/'export',windows=False)
        public=self.root/'export/Source'
        verify_manifest(public,'SOURCE_MANIFEST.json')
        self.assertFalse((public/'private').exists())
        self.assertFalse((public/'sessions.sqlite3').exists())
        self.assertFalse(result['windows_built'])
        self.assertIn('href="/static/fisi.css"',(public/'static/index.html').read_text(encoding='utf-8'))
        self.assertIn(':root',(public/'static/fisi.css').read_text(encoding='utf-8'))

    def test_source_manifest_survives_git_checkout_with_windows_newline_setting(self):
        if not shutil.which('git'):self.skipTest('Git is required for an actual checkout conversion regression.')
        delivery.export(self.source,self.root/'git-export',license_name='MIT',windows=False)
        public=self.root/'git-export/Source'
        for args in (('init',),('config','core.autocrlf','true'),('add','.')):
            subprocess.run(['git','-C',str(public),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        checkout=self.root/'fresh-checkout';checkout.mkdir()
        subprocess.run(['git','-C',str(public),'checkout-index','--all','--prefix',str(checkout).replace('\\','/')+'/'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        verify_manifest(checkout,'SOURCE_MANIFEST.json')

    def test_windows_fixture_has_declared_assets_runtime_notice_and_checksums(self):
        fake=self.root/'synthetic-runtime-never-executed';(fake/'DLLs').mkdir(parents=True);(fake/'Lib').mkdir()
        stem=f'python{sys.version_info.major}{sys.version_info.minor}'
        for name in ('python.exe',stem+'.dll','vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt'):
            (fake/name).write_bytes(b'packaging-only fixture; never execute')
        (fake/'Lib/fixture.py').write_text('# fake runtime input')
        result=delivery.export(self.source,self.root/'windows-export',runtime_base=fake)
        package=self.root/'windows-export/Windows'
        verify_manifest(package,'MANIFEST-SHA256.json')
        self.assertTrue((package/'app/static/fisi.css').is_file())
        self.assertTrue((package/'runtime/LICENSE.txt').is_file())
        self.assertFalse((package/'app/test_fisi.py').exists())
        self.assertIn('--shared',(package/'GEMEINSAM-IM-LAN.cmd').read_text(encoding='utf-8'))
        for name,digest in result['assets'].items():
            self.assertEqual(hashlib.sha256((self.root/'windows-export'/name).read_bytes()).hexdigest(),digest)

    def test_reused_or_source_internal_output_and_invalid_version_are_refused(self):
        self.root.joinpath('existing').mkdir()
        for output in (self.root/'existing',self.source/'output'):
            with self.assertRaises(ValueError):delivery.export(self.source,output,windows=False)
        with self.assertRaises(ValueError):delivery.export(self.source,self.root/'bad-version',version='../escape',windows=False)

    def test_missing_declared_input_fails_before_output_creation(self):
        missing=self.source/'browser_acceptance.mjs'
        missing.rename(self.source/'not-selected.txt')
        with self.assertRaises(ValueError):delivery.export(self.source,self.root/'missing-output',windows=False)
        self.assertFalse((self.root/'missing-output').exists())

    def test_ci_is_read_only_and_actions_are_commit_pinned(self):
        workflow=delivery.documentation(delivery.VERSION,'UNLICENSED')['.github/workflows/ci.yml']
        self.assertIn('contents: read',workflow)
        self.assertNotIn('contents: write',workflow)
        actions=re.findall(r'uses: (\S+)',workflow)
        self.assertTrue(actions)
        self.assertTrue(all(re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}',item) for item in actions))
        accepted=workflow.split('name: Preserve exact packages after successful runtime and browser acceptance',1)[1]
        self.assertNotIn('if: always()',accepted)
        self.assertIn('if-no-files-found: error',accepted)
        for name in (f'Fisi-{delivery.VERSION}-Windows.zip',f'Fisi-{delivery.VERSION}-Source.zip','SHA256SUMS.txt','BUILD.json'):
            self.assertIn('${{ runner.temp }}/Fisi release artifacts/'+name,accepted)
        self.assertNotIn('private-run',accepted)

    def test_explicit_mit_choice_survives_public_export_and_ci_rebuild(self):
        delivery.export(self.source,self.root/'mit-export',license_name='MIT',windows=False)
        public=self.root/'mit-export/Source'
        self.assertEqual((public/'LICENSE').read_text(encoding='utf-8'),delivery.MIT)
        self.assertIn('Anwendungslizenz: **MIT**',(public/'README.md').read_text(encoding='utf-8'))
        self.assertIn('--license MIT',(public/'.github/workflows/ci.yml').read_text(encoding='utf-8'))
        self.assertNotIn('--license UNLICENSED',(public/'.github/workflows/ci.yml').read_text(encoding='utf-8'))
        self.assertIn('--license MIT',(public/'TESTING.md').read_text(encoding='utf-8'))
        verify_manifest(public,'SOURCE_MANIFEST.json')

    def test_release_workflow_has_only_the_explicit_branch_trigger_and_job_permissions(self):
        workflow=delivery.documentation(delivery.VERSION,'MIT')['.github/workflows/publish.yml']
        self.assertIn('on: [create]',workflow)
        self.assertIn('permissions: {}',workflow)
        self.assertIn("github.event.ref_type == 'branch' && github.event.ref == 'release/v"+delivery.VERSION+"'",workflow)
        self.assertIn('contents: write',workflow)
        self.assertIn('actions: read',workflow)
        self.assertIn('persist-credentials: false',workflow)
        self.assertNotIn('pull_request_target',workflow)
        self.assertTrue(all(re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}',item) for item in re.findall(r'uses: (\S+)',workflow)))

    def test_publish_refuses_other_events_before_running_any_command(self):
        with patch.dict(os.environ,{'GITHUB_REPOSITORY':'Question86/Fisi','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','GITHUB_SHA':'a'*40}),patch('subprocess.check_output') as command:
            with self.assertRaises(ValueError):delivery.publish_accepted_run()
            command.assert_not_called()

    def test_accepted_artifact_checks_reject_tampering_metadata_and_extra_files(self):
        root=self.root/'accepted';root.mkdir()
        assets={}
        for suffix in ('Source','Windows'):
            name=f'Fisi-{delivery.VERSION}-{suffix}.zip';(root/name).write_bytes(b'fixture artifact, never executed');assets[name]=delivery.sha((root/name).read_bytes())
        metadata={'schema':'fisi-build/v1','version':delivery.VERSION,'license':'MIT','windows_built':True,'assets':assets}
        (root/'BUILD.json').write_text(json.dumps(metadata),encoding='utf-8')
        (root/'SHA256SUMS.txt').write_text(''.join(digest+'  '+name+'\n' for name,digest in assets.items()),encoding='utf-8')
        self.assertEqual(delivery.verify_accepted_packages(root),metadata)
        (root/'private.sqlite3').write_bytes(b'not allowed')
        with self.assertRaises(ValueError):delivery.verify_accepted_packages(root)
        (root/'private.sqlite3').unlink()
        name=next(iter(assets));(root/name).write_bytes(b'tampered')
        with self.assertRaises(ValueError):delivery.verify_accepted_packages(root)
        (root/name).write_bytes(b'fixture artifact, never executed')
        metadata['license']='UNLICENSED';(root/'BUILD.json').write_text(json.dumps(metadata),encoding='utf-8')
        with self.assertRaises(ValueError):delivery.verify_accepted_packages(root)

    def test_checksum_tampering_and_zip_traversal_are_rejected(self):
        delivery.export(self.source,self.root/'tamper',windows=False)
        public=self.root/'tamper/Source';(public/'server.py').write_text('tampered')
        with self.assertRaises(ValueError):verify_manifest(public,'SOURCE_MANIFEST.json')
        archive=self.root/'bad.zip'
        with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('../escape.txt','bad')
        with self.assertRaises(ValueError):checked_extract(archive,self.root/'extract')
        self.assertFalse((self.root/'escape.txt').exists())


if __name__=='__main__':
    if '--verify-windows' in sys.argv:
        import argparse
        parser=argparse.ArgumentParser()
        parser.add_argument('--verify-windows',required=True)
        parser.add_argument('--out',required=True)
        args=parser.parse_args()
        print(json.dumps(verify_windows(args.verify_windows,args.out),indent=2))
    else:
        unittest.main()
