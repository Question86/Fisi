// Isolated Edge end-to-end acceptance harness. Uses only a fresh profile and local fixtures.
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {EventEmitter} from 'node:events';

function revisionExpression() {
  return `(()=>{const match=document.querySelector('.footer').textContent.match(/Workspace-Version ([0-9]+)/);if(!match)throw Error('Workspace revision missing from rendered footer');return Number(match[1]);})()`;
}
if(process.argv[2]==='--self-check') {
  for(const [text,expected] of [['Workspace-Version 0 · Aktualisieren',0],['Fisi · Workspace-Version 123 · Sitzung wechseln',123]]) {
    assert.equal(vm.runInNewContext(revisionExpression(),{document:{querySelector:()=>({textContent:text})}}),expected);
  }
  assert.throws(()=>vm.runInNewContext(revisionExpression(),{document:{querySelector:()=>({textContent:'missing revision'})}}),/revision missing/);
  console.log('PASS serialized browser revision expression, including zero and missing-value rejection');
  for(const signal of [false,true]) {
    const child=Object.assign(new EventEmitter(),{exitCode:null,signalCode:null});
    child.kill=()=>queueMicrotask(()=>{child.exitCode=signal?null:0;child.signalCode=signal?'SIGTERM':null;child.emit('exit',child.exitCode,child.signalCode);});
    await stop(child);
    child.kill=()=>assert.fail('Already stopped child must not be killed again');
    await stop(child);
  }
  console.log('PASS owned child lifecycle acknowledges normal and signal exit');
  process.exit(0);
}

const source = path.resolve(process.argv[2] || '.');
const output = path.resolve(process.argv[3] || path.join(source,'..','Fisi browser evidence'));
const python = process.argv[4] || process.env.FISI_PYTHON || 'python';
const edgeExecutable = process.env.FISI_EDGE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
await fs.mkdir(output,{recursive:true});
const run = path.join(output,'private-run-'+Date.now());
await fs.mkdir(run,{recursive:true});
const downloads = path.join(run,'downloads'); await fs.mkdir(downloads);
const evidence = {checks:[],screenshots:[],errors:[],network:[],engine:null,scope:'Fresh headless Edge profile, isolated synthetic server data; no existing browser profiles/windows.'};
const delay = ms => new Promise(resolve=>setTimeout(resolve,ms));
let edge, server, socket, sequence=0;
const pending = new Map();
const events = new Map();
function send(method,params={},sessionId) {
  const id=++sequence;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},20000);
    pending.set(id,{resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}});
    socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
}
async function until(fn,label,timeout=20000) {
  const end=Date.now()+timeout; let last;
  while(Date.now()<end) { try { const value=await fn(); if(value)return value; } catch(error){last=error;} await delay(120); }
  throw Error('Timed out: '+label+(last?' · '+last.message:''));
}
async function startServer(port=0) {
  const child=spawn(python,['-u','server.py','--port',String(port),'--no-browser','--data',path.join(run,'data')],{cwd:source,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let output='',errors='';
  child.stdout.on('data',chunk=>{output+=chunk.toString();});child.stderr.on('data',chunk=>{errors+=chunk.toString();});
  const base=await until(()=>{if(child.exitCode!==null)throw Error('Server exited: '+errors);return output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];},'isolated server startup');
  return {child,base};
}
async function stop(child) {
  if(!child||child.exitCode!==null||child.signalCode!==null)return;
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.off('exit',ended);reject(Error('Owned child process did not stop within five seconds'));},5000);
    function ended(){clearTimeout(timer);resolve();}
    child.once('exit',ended);child.kill();
  });
  assert(child.exitCode!==null||child.signalCode!==null,'owned child process stopped');
}
async function evaluate(session,expression) {
  const result=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},session);
  if(result.exceptionDetails)throw Error(result.exceptionDetails.text+' '+(result.exceptionDetails.exception?.description||''));
  return result.result.value;
}
async function page(base,code) {
  const target=await send('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await send('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  events.set(sessionId,{errors:[],requests:[]});
  await send('Page.enable',{},sessionId); await send('Runtime.enable',{},sessionId);await send('Network.enable',{},sessionId);
  await send('Emulation.setDeviceMetricsOverride',{width:1366,height:1000,deviceScaleFactor:1,mobile:false},sessionId);
  await send('Page.navigate',{url:base+(code?'/#join='+encodeURIComponent(code):'/')},sessionId);
  await ready(sessionId);
  return sessionId;
}
async function ready(session) { await until(()=>evaluate(session,`Boolean(document.querySelector('.sidebar [data-route="lab"]'))`),'rendered Fisi navigation'); }
async function click(session,selector) {
  await send('Page.bringToFront',{},session);
  const rect=await evaluate(session,`(()=>{const element=document.querySelector(${JSON.stringify(selector)});if(!element)throw Error('Missing selector');element.scrollIntoView({block:'center'});const r=element.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y);if(!hit||!(hit===element||element.contains(hit)))throw Error('Click target blocked by '+(hit?.tagName||'viewport')+'#'+(hit?.id||''));return {x,y};})()`);
  await send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...rect},session);
  await send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...rect},session);
}
async function fill(session,selector,value) {
  await send('Page.bringToFront',{},session);
  await evaluate(session,`(()=>{const element=document.querySelector(${JSON.stringify(selector)});if(!element)throw Error('Missing input');element.focus();element.select();})()`);
  await send('Input.insertText',{text:value},session);
}
async function select(session,selector,value) {
  await evaluate(session,`(()=>{const element=document.querySelector(${JSON.stringify(selector)});element.value=${JSON.stringify(value)};element.dispatchEvent(new Event('input',{bubbles:true}));element.dispatchEvent(new Event('change',{bubbles:true}));})()`);
}
async function revision(session) { return await evaluate(session,revisionExpression()); }
async function saved(session,fn) { const before=await revision(session);await fn();await until(async()=>await revision(session)>before,'server revision after save'); }
async function navigate(session,view) { await click(session,`.sidebar [data-route="${view}"]`);await until(()=>evaluate(session,`Boolean(document.querySelector('.sidebar [data-route="${view}"].active'))`),'navigation '+view); }
async function upload(session,selector,files) { const doc=await send('DOM.getDocument',{},session);const node=await send('DOM.querySelector',{nodeId:doc.root.nodeId,selector},session);assert(node.nodeId);await send('DOM.setFileInputFiles',{nodeId:node.nodeId,files},session); }
async function screenshot(session,name) {
  await evaluate(session,`new Promise(resolve=>{window.scrollTo(0,0);requestAnimationFrame(()=>requestAnimationFrame(resolve));})`);
  const metrics=await send('Page.getLayoutMetrics',{},session),size=metrics.cssContentSize;
  const clip={x:0,y:0,width:Math.min(size.width,1600),height:Math.min(size.height,6000),scale:1};
  const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip},session);
  const file=path.join(output,name);await fs.writeFile(file,Buffer.from(shot.data,'base64'));evidence.screenshots.push(file);
  // These four captures precede creation of group codes and contain only synthetic fixtures.
  const preview=await send('Page.captureScreenshot',{format:'jpeg',quality:65,captureBeyondViewport:true,clip:{...clip,height:Math.min(clip.height,1200),scale:0.75}},session);
  console.log('FISI_REVIEW_IMAGE',name.replace('.png','.jpg'),preview.data);
}
function pass(name){evidence.checks.push({name,passed:true});console.log('PASS',name);}
try {
  server=await startServer();
  const profile=path.join(run,'profile');
  edge=spawn(edgeExecutable,[
    '--headless=new','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0',
    '--user-data-dir='+profile,'--no-first-run','--no-default-browser-check',
    '--disable-background-networking','--disable-sync','about:blank'
  ],{windowsHide:true,stdio:['ignore','ignore','pipe']});
  let edgeErrors='';edge.stderr.on('data',chunk=>{edgeErrors+=chunk.toString();});
  const active=await until(async()=>{if(edge.exitCode!==null)throw Error('Edge exited: '+edgeErrors.slice(-1200));try{return await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8');}catch{return null;}},'isolated Edge startup');
  const [port,endpoint]=active.trim().split(/\r?\n/);
  socket=new WebSocket('ws://127.0.0.1:'+port+endpoint);
  await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
  socket.addEventListener('message',event=>{
    const message=JSON.parse(event.data);
    if(message.id){const waiter=pending.get(message.id);if(waiter){pending.delete(message.id);message.error?waiter.reject(Error(JSON.stringify(message.error))):waiter.resolve(message.result||{});}return;}
    const record=events.get(message.sessionId);
    if(message.method==='Runtime.exceptionThrown'&&record)record.errors.push(message.params.exceptionDetails.text+' '+(message.params.exceptionDetails.exception?.description||''));
    if(message.method==='Network.requestWillBeSent'&&record)record.requests.push(message.params.request.url);
    if(message.method==='Page.javascriptDialogOpening'){
      const known=message.params.type==='confirm'&&message.params.message.startsWith('Den aktuellen Workspace durch diese Sicherung ersetzen?');
      send('Page.handleJavaScriptDialog',{accept:known},message.sessionId).catch(()=>{});
      if(!known)evidence.errors.push('Unexpected dialog: '+message.params.type);
    }
  });
  evidence.engine=await send('Browser.getVersion');
  await send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloads});
  const solo=await page(server.base);
  assert(await evaluate(solo,`document.body.textContent.includes('Schritt für Schritt zum Durchblick.')`));
  pass('Actual Edge renders Fisi overview without local login');await screenshot(solo,'fisi-overview.png');
  await navigate(solo,'learn');await click(solo,'input[name="intro"][value="separate"]');
  await saved(solo,()=>click(solo,'#intro-form button[type="submit"]'));
  assert(await evaluate(solo,`document.body.textContent.includes('Verständnisfrage serverseitig bestätigt')`));pass('Introduction answer actually checked');
  await navigate(solo,'lab');const draft='Dieser ungespeicherte Entwurf bleibt beim Wechseln erhalten.';
  await fill(solo,'[data-draft="explanation"]',draft);await navigate(solo,'inventory');await navigate(solo,'lab');
  assert.equal(await evaluate(solo,`document.querySelector('[data-draft="explanation"]').value`),draft);pass('Unsaved form survives navigation');
  for(const [field,value] of [['dns','192.0.2.20'],['firewall','office'],['readers','support']]){
    await select(solo,`[data-config="${field}"] select`,value);
    await saved(solo,()=>click(solo,`[data-config="${field}"] button[type="submit"]`));
  }
  for(const probe of ['support-office','support-guest','guest-office'])await saved(solo,()=>click(solo,`[data-action="diagnose"][data-probe="${probe}"]`));
  await fill(solo,'[data-draft="explanation"]','Ich habe DNS, Netzwerkpfad und Dateirechte getrennt geprüft. Nur das Büronetz und die Support-Gruppe dürfen lesen; das Gästenetz scheitert am Netzwerk und Nilo im Büronetz am Dateirecht.');
  await saved(solo,()=>click(solo,'#explanation-form button[type="submit"]'));
  await saved(solo,()=>click(solo,'[data-action="submit"]'));
  assert(await evaluate(solo,`document.querySelector('#notice').textContent.includes('alle fachlichen Bedingungen erfüllt')`));
  assert.equal(await evaluate(solo,`document.querySelectorAll('.checks .success').length`),5);pass('Complete learning workflow with positive and intended negative boundaries');
  await screenshot(solo,'fisi-lab-completed.png');
  await navigate(solo,'progress');await fill(solo,'[data-draft="journal"]','Gesicherter Browser-Lernstand');await saved(solo,()=>click(solo,'#journal-form button[type="submit"]'));
  await click(solo,'[data-action="export"]');
  const backup=path.join(downloads,'fisi-workspace.json');await until(async()=>{try{return (await fs.stat(backup)).size>0;}catch{return false;}},'downloaded workspace export');
  const bundle=JSON.parse(await fs.readFile(backup,'utf8'));assert.equal(bundle.state.journal,'Gesicherter Browser-Lernstand');assert(bundle.northlight.exercises);
  await fill(solo,'[data-draft="journal"]','Zwischenstand, der ersetzt wird');await saved(solo,()=>click(solo,'#journal-form button[type="submit"]'));
  await saved(solo,()=>upload(solo,'#restore-file',[backup]));
  assert.equal(await evaluate(solo,`document.querySelector('[data-draft="journal"]').value`),'Gesicherter Browser-Lernstand');pass('Browser download and actual file-upload restore preserve Fisi and reference state');
  const good=structuredClone(bundle.state.inventory.reports[0]);good.id='browser-import';good.source={id:'browser-import',label:'Browser-Prüfbericht',kind:'imported'};good.collectedAt='2020-01-01T00:00:00Z';good.devices[0].name='<img src=x onerror="window.__inventoryInjected=true">';
  const bad=structuredClone(good);bad.id='invalid';bad.devices[0].adapters=[null];
  const goodFile=path.join(run,'good-inventory.json'),badFile=path.join(run,'bad-inventory.json');await fs.writeFile(goodFile,JSON.stringify(good));await fs.writeFile(badFile,JSON.stringify(bad));
  await navigate(solo,'inventory');const beforeImport=await revision(solo);await upload(solo,'#inventory-files',[goodFile,badFile]);
  await until(()=>evaluate(solo,`document.querySelector('#notice').classList.contains('error')&&document.querySelector('#notice').textContent.includes('null')`),'atomic rejected inventory upload');
  assert.equal(await revision(solo),beforeImport);assert(!(await evaluate(solo,`document.body.textContent.includes('Browser-Prüfbericht')`)));pass('Multi-file import rejects null adapter without partial mutation');
  await saved(solo,()=>upload(solo,'#inventory-files',[goodFile]));
  assert(await evaluate(solo,`document.body.textContent.includes('ÄLTER ALS 7 TAGE')`));
  assert(await evaluate(solo,`document.body.textContent.includes('<img src=x onerror=')`));assert(!(await evaluate(solo,'Boolean(window.__inventoryInjected)')));pass('Imported inventory renders inert text and visible age, separate from simulation');
  await screenshot(solo,'fisi-inventory.png');
  await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false},solo);
  assert(await evaluate(solo,`document.documentElement.scrollWidth<=window.innerWidth+1`));
  await screenshot(solo,'fisi-mobile.png');pass('Narrow layout has no page-wide horizontal overflow');
  await send('Emulation.setDeviceMetricsOverride',{width:1366,height:1000,deviceScaleFactor:1,mobile:false},solo);
  await navigate(solo,'overview');await evaluate(solo,'document.activeElement.blur()');await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9},solo);await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9},solo);
  assert(await evaluate(solo,`document.activeElement!==document.body`));pass('Keyboard focus reaches a real interactive element');
  const skipRoute=await evaluate(solo,'location.hash');
  await evaluate(solo,`document.querySelector('.skip').focus()`);
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13},solo);
  await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13},solo);
  assert(await evaluate(solo,`document.activeElement===document.querySelector('#main')`));
  assert.equal(await evaluate(solo,'location.hash'),skipRoute);pass('Keyboard skip link focuses content without replacing the view');
  await navigate(solo,'progress');await fill(solo,'#workspace-form input[name="name"]','Browser-Gruppe');await click(solo,'#workspace-form button[type="submit"]');
  const code=await until(()=>evaluate(solo,`document.querySelector('.workspace-card .callout code')?.textContent`),'created shared workspace code');
  const one=await page(server.base,code),two=await page(server.base,code);
  assert(!(await evaluate(one,`Boolean(document.querySelector('#workspace-form'))`)));
  await navigate(one,'progress');await fill(one,'[data-draft="journal"]','Entwurf A bleibt erhalten');
  await navigate(two,'progress');await fill(two,'[data-draft="journal"]','Gemeinsamer Stand von B');await saved(two,()=>click(two,'#journal-form button[type="submit"]'));
  await send('Page.bringToFront',{},one);
  await until(()=>evaluate(one,`document.querySelector('.connection').textContent.includes('Neuer Stand')`),'remote state change while preserving draft',12000);
  assert.equal(await evaluate(one,`document.querySelector('[data-draft="journal"]').value`),'Entwurf A bleibt erhalten');
  await saved(one,()=>click(one,'.footer [data-action="refresh"]'));
  assert.equal(await evaluate(one,`document.querySelector('[data-draft="journal"]').value`),'Entwurf A bleibt erhalten');
  await saved(one,()=>click(one,'#journal-form button[type="submit"]'));
  await send('Page.bringToFront',{},two);await until(()=>evaluate(two,`document.querySelector('[data-draft="journal"]').value==='Entwurf A bleibt erhalten'`),'second browser observes accepted shared write',12000);
  pass('Two independent browser participants share state; remote refresh preserves unsaved draft');
  await fill(two,'[data-draft="journal"]','Entwurf trotz Verbindungsunterbrechung');
  await send('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:-1,uploadThroughput:-1},two);
  await until(()=>evaluate(two,`document.querySelector('.connection').textContent.includes('Verbindung unterbrochen')`),'offline status',12000);
  await send('Network.emulateNetworkConditions',{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1},two);
  await until(()=>evaluate(two,`document.querySelector('.connection').textContent==='Verbunden'`),'reconnected status',12000);
  assert.equal(await evaluate(two,`document.querySelector('[data-draft="journal"]').value`),'Entwurf trotz Verbindungsunterbrechung');pass('Connection interruption/reconnect retains unsaved form');
  const previousPort=Number(new URL(server.base).port);await stop(server.child);server=await startServer(previousPort);
  await send('Page.navigate',{url:'about:blank'},solo);await until(()=>evaluate(solo,`location.href==='about:blank'&&!document.querySelector('.sidebar')`),'fresh solo document');
  await send('Page.navigate',{url:server.base+'/#/lab'},solo);await ready(solo);
  assert(await evaluate(solo,`document.body.textContent.includes('Bedingungen erfüllt')`));
  await send('Page.navigate',{url:'about:blank'},one);await until(()=>evaluate(one,`location.href==='about:blank'&&!document.querySelector('.sidebar')`),'fresh group document');
  await send('Page.navigate',{url:server.base+'/#join='+encodeURIComponent(code)},one);await ready(one);await navigate(one,'progress');
  assert.equal(await evaluate(one,`document.querySelector('[data-draft="journal"]').value`),'Entwurf A bleibt erhalten');pass('Actual process restart preserves solo progress and persisted shared join code/state');
  const reference=await page(server.base,code);
  await send('Page.navigate',{url:server.base+'/reference/'},reference);
  await until(()=>evaluate(reference,`Boolean(document.querySelector('#login input[name="code"]'))`),'reference login rendered by extracted script');
  await fill(reference,'#login input[name="code"]',code);await fill(reference,'#login input[name="name"]','Referenz-Smoke');
  await click(reference,'#login button[type="submit"], #login button');
  await until(()=>evaluate(reference,`Boolean(document.querySelector('.sidebar [data-page="overview"]'))&&!busy`),'authenticated reference view');
  await click(reference,'.sidebar [data-page="resources"]');
  await until(()=>evaluate(reference,`Boolean(document.querySelector('.sidebar [data-page="resources"].active'))`),'reference resources navigation');
  assert(await evaluate(reference,`document.querySelector('main.page').textContent.length>200`));
  pass('Extracted Northlight reference script renders login, authenticated overview and resource navigation');
  for(const record of events.values()) {evidence.errors.push(...record.errors);evidence.network.push(...record.requests.filter(url=>!url.startsWith('data:')&&!url.startsWith('blob:')&&url!=='about:blank'));}
  assert.equal(evidence.errors.length,0,JSON.stringify(evidence.errors));
  assert(evidence.network.every(url=>url.startsWith(server.base+'/')),'page made no remote asset/API requests');pass('No unhandled browser exceptions or external page asset/API requests');
  evidence.result='PASS';
} catch(error) { evidence.result='FAIL';evidence.failure=error.stack;console.error(error.stack);process.exitCode=1; }
finally {
  evidence.network=evidence.network.map(value=>{const url=new URL(value);return url.origin+url.pathname;});
  await fs.writeFile(path.join(output,'fisi-edge-workflow.json'),JSON.stringify(evidence,null,2));
  if(socket?.readyState===WebSocket.OPEN){try{await send('Browser.close');}catch{}socket.close();}
  await stop(edge).catch(()=>{});await stop(server?.child).catch(()=>{});
  console.log('RESULT',evidence.result,'checks',evidence.checks.length,'evidence',path.join(output,'fisi-edge-workflow.json'));
}
