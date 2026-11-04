'use strict';
(() => {
  const $ = selector => document.querySelector(selector);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const views = {overview:['◈','Übersicht'], learn:['▤','Lernen'], lab:['⌘','Praxislabor'], inventory:['⌁','Inventar & Netzplan'], progress:['◷','Fortschritt & Daten']};
  let token = sessionStorage.getItem('fisi-token'), record = null, route = 'overview', busy = false, pending = null, connection = 'Verbunden', joined = null;
  const drafts = new Map();
  const draftKey = name => `${record.id}/${name}`;
  const draft = (name, fallback) => drafts.has(draftKey(name)) ? drafts.get(draftKey(name)) : fallback;
  const dirty = () => record && [...drafts.keys()].some(key => key.startsWith(record.id + '/'));
  const options = (values, selected) => values.map(([value,label]) => `<option value="${escape(value)}"${String(value) === String(selected) ? ' selected' : ''}>${escape(label)}</option>`).join('');
  const button = (label, action, extra = '', cls = '') => `<button type="button" class="${cls}" data-action="${action}" ${extra}>${label}</button>`;
  const gotoButton = (label, target, cls = '') => `<button type="button" class="${cls}" data-route="${target}">${label}</button>`;
  const tag = text => `<span class="tag">${escape(text)}</span>`;
  const notice = (text, error = false) => { $('#notice').textContent = text; $('#notice').className = error ? 'error' : ''; };

  async function api(path, data) {
    const response = await fetch(path, {method:data === undefined ? 'GET' : 'POST', headers:{'Content-Type':'application/json', ...(token ? {Authorization:'Bearer ' + token} : {})}, ...(data === undefined ? {} : {body:JSON.stringify(data)})});
    let result; try { result = await response.json(); } catch { throw new Error('Der Server hat keine gültige Antwort geliefert.'); }
    if (!response.ok) { const error = new Error(result.error || 'Anfrage abgelehnt.'); error.status = response.status; throw error; }
    return result;
  }
  function setToken(value) { token = value; if (token) sessionStorage.setItem('fisi-token', token); else sessionStorage.removeItem('fisi-token'); }
  async function load() { record = await api('/api/fisi/state' + (record ? '?instance=' + encodeURIComponent(record.id) : '')); pending = null; connection = 'Verbunden'; render(); }
  async function action(name, parameters = {}, clear = []) {
    if (busy) return;
    busy = true;
    try {
      const result = await api('/api/fisi/action', {instance:record.id, revision:record.revision, action:name, parameters});
      for (const key of clear) drafts.delete(draftKey(key));
      record = result.record; pending = null; connection = 'Gespeichert';
      if (name === 'workspace_create') joined = result.result;
      render();
      notice(name === 'submit' ? (record.assessment.passed ? 'Abgabe gespeichert: alle fachlichen Bedingungen erfüllt.' : 'Abgabe gespeichert. Die markierten Bedingungen sind noch offen.') : result.result?.message || 'Änderung serverseitig gespeichert.');
    } catch (error) {
      if (error.status === 409) { pending = true; connection = 'Konflikt · Eingaben bleiben erhalten'; }
      notice(error.message, true); updateConnection();
    } finally { busy = false; }
  }
  function updateConnection() { const element = $('.connection'); if (element) element.textContent = pending ? 'Neuer Stand vorhanden · bitte aktualisieren' : connection; }
  function checks() { return `<ul class="checks">${record.assessment.checks.map(row => `<li><span class="mark ${row.passed ? 'success' : 'muted'}">${row.passed ? '✓' : '○'}</span><span>${escape(row.label)}</span></li>`).join('')}</ul>`; }
  function title(heading, sub) { return `<div class="page-heading"><div class="eyebrow">Dein Lernworkspace</div><h1>${heading}</h1><p class="sub">${sub}</p></div>`; }
  function overview() {
    const lab = record.state.lab, completed = Number(lab.intro) + Number(lab.attempts.some(row => row.passed));
    return title('Schritt für Schritt zum Durchblick.', 'Verstehen, selbst verändern und mit echten Zustandsprüfungen nachweisen.') + `
      <section class="hero"><div><span class="tag">DEIN NÄCHSTER LERNSCHRITT</span><h2>Ein Dateidienst.<br>Drei Grenzen, die du verstehst.</h2><p>Warum erreicht Lea den Dienst nicht? Untersuche Namensauflösung, Netzwerkpfad und Dateirechte – und gib genau den benötigten Zugriff frei.</p><div class="actions">${gotoButton(lab.intro ? 'Praxisauftrag öffnen →' : 'Mit dem Einstieg beginnen →', lab.intro ? 'lab' : 'learn', 'primary')}</div><small>Etwa 25 Minuten · vollständig synthetische Übung</small></div><div class="hero-art" aria-hidden="true"><div class="eyebrow">Praxis statt bloßes Anklicken</div><code>01 Auftrag verstehen<br>02 Zustand untersuchen<br>03 Gezielt konfigurieren<br>04 Erlaubt UND verweigert prüfen<br>05 Ergebnis begründen</code><p class="muted">Dein Serverzustand entscheidet.</p></div></section>
      <div class="stats"><div class="card"><div class="eyebrow">Lernschritte abgeschlossen</div><div class="stat-number">${completed} <small>/ 2</small></div><small>Einstieg und Praxisauftrag</small></div><div class="card"><div class="eyebrow">Simulationszeit</div><div class="stat-number">${lab.minute} <small>Min.</small></div><small>Kontrolliert durch deine Aktionen</small></div><div class="card"><div class="eyebrow">Workspace-Version</div><div class="stat-number">${record.revision}</div><small>Gemeinsamer gespeicherter Stand</small></div></div>
      <div class="section-title"><h2>Dein Lernweg</h2>${tag('Fisi · Netzwerk & Berechtigungen')}</div><div class="cards"><article class="card"><span class="module-icon" aria-hidden="true">▤</span><div class="row"><h2>Erst den Weg verstehen</h2>${tag(lab.intro ? 'Abgeschlossen' : 'Einstieg')}</div><p class="muted">Ein kurzer Einstieg trennt Erreichbarkeit, Dienstzustand und tatsächliche Datenrechte.</p><div class="progress"><span style="width:${lab.intro ? 100 : 0}%"></span></div>${gotoButton('Einstieg öffnen →','learn')}</article><article class="card"><span class="module-icon" aria-hidden="true">⌘</span><div class="row"><h2>Ein Dateidienst, drei Grenzen</h2>${tag(record.assessment.passed ? 'Bedingungen erfüllt' : 'Praxislabor')}</div><p class="muted">Repariere den Zugang für den Support, halte Gäste fern und sichere frische Nachweise.</p><div class="progress"><span style="width:${Math.round(record.assessment.checks.filter(row => row.passed).length / record.assessment.checks.length * 100)}%"></span></div>${gotoButton('Auftrag bearbeiten →','lab')}</article></div>`;
  }
  function learn() {
    return title('Ein Zugriff ist eine Kette.', 'Einführung · Netzwerkpfad und Berechtigung getrennt betrachten') + `<article class="card"><h2>Vom Namen bis zur Datei</h2><p>Ein Gerät muss zuerst den richtigen Dienst finden. Danach müssen der Netzwerkpfad und der Dienst funktionieren. Erst dann entscheidet die Dateiberechtigung darüber, ob eine Person Projektdaten lesen darf.</p><ol><li><strong>DNS:</strong> Welches Ziel gehört zum Namen <code>datei.fisi.test</code>?</li><li><strong>Netzwerk:</strong> Darf das Büronetz oder auch das Gästenetz dieses Ziel erreichen?</li><li><strong>Dienst:</strong> Läuft der Dateidienst?</li><li><strong>Dateirecht:</strong> Welche Gruppe darf die Projekte lesen?</li></ol><div class="callout">Ein Netzwerkadministrator besitzt dadurch nicht automatisch Leserechte auf alle Dateien. Ein Adapterstatus „Up“ beweist keinen erfolgreichen Zugriff.</div><h3>Kurze Verständnisfrage</h3><p>Der Dienst ist erreichbar. Nilo ist Gast und darf die Projektdatei nicht lesen. Was prüfst du als Nächstes?</p><form id="intro-form">${[['restart','Den Dienst sofort neu starten'],['separate','Das Dateirecht getrennt vom bereits funktionierenden Netzwerkpfad'],['all','Alle Personen zu Administratoren machen']].map(([value,label]) => `<label class="choice"><input type="radio" name="intro" data-draft="intro" value="${value}"${draft('intro','') === value ? ' checked' : ''} required><span>${label}</span></label>`).join('')}<button class="primary" type="submit">Antwort prüfen</button></form>${record.state.lab.intro ? '<p class="success">✓ Verständnisfrage serverseitig bestätigt.</p>' : ''}<div class="actions">${gotoButton('Zum Praxisauftrag →','lab','secondary')}</div></article>`;
  }
  function lab() {
    const state = record.state.lab;
    const labels = {dns:[['192.0.2.99','192.0.2.99 · derzeitiges Ziel'],['192.0.2.20','192.0.2.20 · Dateidienst']],firewall:[['closed','Keine Freigabe'],['office','Nur Büronetz'],['all','Büro- und Gästenetz']],readers:[['admins','Nur Administratoren'],['support','Support-Gruppe'],['everyone','Alle Personen']],service:[['true','Dienst läuft'],['false','Dienst gestoppt']]};
    const names = {dns:'DNS-Ziel für datei.fisi.test',firewall:'Netzwerkfreigabe',readers:'Leserecht auf Projekte',service:'Dateidienst'};
    return title(record.lesson.title, 'Praxisauftrag · alle Systeme und Personen sind simuliert') + `<ol class="steps">${record.lesson.steps.map((step,index) => `<li><b>${index + 1}</b>${escape(step)}</li>`).join('')}</ol><article class="card"><div class="row"><h2>Dein Auftrag</h2>${tag('Simulationsminute ' + state.minute)}</div><p>${escape(record.lesson.brief)}</p><ul>${record.lesson.facts.map(fact => `<li class="muted">${escape(fact)}</li>`).join('')}</ul></article><div class="two"><div><article class="card"><h2>Zustand untersuchen & gezielt ändern</h2><p class="muted">Jedes Speichern verändert genau eine Einstellung. Bisherige Diagnosen werden bei einer Änderung ungültig.</p><div class="form-grid">${Object.keys(labels).map(key => `<form data-config="${key}"><label>${names[key]}<select name="value" data-draft="config-${key}">${options(labels[key],draft('config-'+key,String(state.config[key])))}</select></label><div class="actions"><button class="small" type="submit">Einstellung speichern</button></div></form>`).join('')}</div></article><article class="card"><h2>Ergebnis begründen</h2><p class="muted">Erkläre, was du geändert hast und warum die beiden verweigerten Fälle trotzdem wichtig sind.</p><form id="explanation-form"><label>Deine Begründung<textarea data-draft="explanation" name="text" maxlength="4000">${escape(draft('explanation',state.explanation))}</textarea></label><div class="actions"><button type="submit">Begründung speichern</button></div></form></article></div><div><article class="card"><h2>Erlaubt und verweigert nachprüfen</h2><p class="muted">Hier wird der gespeicherte Simulationszustand geprüft. Es werden keine realen Rechner abgefragt.</p>${Object.entries(record.probes).map(([key,probe]) => { const row=state.diagnostics[key]; return `<section class="diagnostic"><div class="row"><strong>${escape(probe.label)}</strong><span class="badge ${row ? (row.result.allowed === probe.expected ? 'good' : 'bad') : ''}">${row ? (row.result.allowed ? 'Zugriff erlaubt' : 'Zugriff verweigert') : 'Noch kein Nachweis'}</span></div>${row ? `<p>${escape(row.result.reason)}</p><small>DNS ${row.result.dns ? '✓' : '×'} · Netzwerk ${row.result.network ? '✓' : '×'} · Dienst ${row.result.service ? '✓' : '×'} · Dateirecht ${row.result.data ? '✓' : '×'} · Minute ${row.minute}</small>` : '<p class="muted">Nach jeder Konfigurationsänderung erneut prüfen.</p>'}<div class="actions">${button('Fall prüfen','diagnose',`data-probe="${key}"`,'small')}</div></section>`; }).join('')}</article><article class="card"><h2>Deine Abgabe</h2>${checks()}<small>${escape(record.assessment.notice)}</small><div class="actions">${button('Lernauftrag abgeben','submit','','primary')}</div>${state.attempts.length ? `<p class="${state.attempts.at(-1).passed ? 'success' : 'muted'}">Letzte Abgabe: ${state.attempts.at(-1).passed ? 'Bedingungen erfüllt' : 'noch offene Bedingungen'} · Minute ${state.attempts.at(-1).minute}</p>` : ''}</article></div></div>`;
  }
  function networkPlan(reports) {
    const devices = reports.flatMap(report => report.devices.map(device => ({report,device})));
    const shown = devices.slice(0,40), networks = new Map();
    const keyFor = (report,network) => JSON.stringify([report.source.id,report.id,network.kind,network.id]);
    for (const {report,device} of shown) for (const adapter of device.adapters) if (adapter.network) { const key=keyFor(report,adapter.network); if(!networks.has(key))networks.set(key,{...adapter.network,index:networks.size}); }
    const height = Math.max(shown.length,networks.size,1) * 86 + 35;
    let svg = `<svg viewBox="0 0 900 ${height}" role="img" aria-label="Gemeldete Adapterzuordnungen; kein Nachweis von Erreichbarkeit">`;
    shown.forEach(({report,device},i) => device.adapters.forEach(adapter => { if(!adapter.network)return; const net=networks.get(keyFor(report,adapter.network)); svg += `<path d="M 355 ${i*86+48} C 440 ${i*86+48},450 ${net.index*86+48},530 ${net.index*86+48}" fill="none" stroke="#4d8d87" stroke-width="2" stroke-dasharray="6 5"/>`; }));
    shown.forEach(({report,device},i) => { svg+=`<rect x="20" y="${i*86+14}" width="335" height="67" rx="9" fill="#172c3e" stroke="#365168"/><text x="35" y="${i*86+39}">${escape(device.name.slice(0,40))}</text><text class="hint" x="35" y="${i*86+61}">${escape(report.source.kind === 'synthetic' ? 'Synthetisches Beispiel' : 'Importierte Konfiguration')} · ${device.adapters.length} Adapter</text>`; });
    for (const network of networks.values()) svg+=`<rect x="530" y="${network.index*86+14}" width="350" height="67" rx="9" fill="#173532" stroke="#3d6961"/><text x="545" y="${network.index*86+39}">${escape(network.label.slice(0,40))}</text><text class="hint" x="545" y="${network.index*86+61}">${escape(network.kind)} · gemeldetes Netzobjekt</text>`;
    return `<div class="network-plan">${svg}</svg></div>${devices.length > 40 ? '<p class="notice-inline">Der Netzplan zeigt die ersten 40 Geräte. Das Inventar darunter enthält alle Geräte.</p>' : ''}`;
  }
  function inventoryStatus(report) {
    if(report.source.kind === 'synthetic')return 'SYNTHETISCH';
    const age=Date.now()-Date.parse(report.collectedAt);
    if(age < -300000)return 'IMPORT · ZEITANGABE IN DER ZUKUNFT';
    return age > 7*24*60*60*1000 ? 'IMPORT · ÄLTER ALS 7 TAGE' : 'IMPORT · NICHT VERIFIZIERT';
  }
  function inventory() {
    const collection=record.state.inventory, reports=collection.reports;
    return title('Inventar & Netzplan', 'Konfigurationen nachvollziehen. Unbekannte Werte bleiben unbekannt.') + `<div class="callout warning">Inventar ist kein Erreichbarkeitsnachweis. „Up“, gleiche Adressen und Switch-Zuordnungen beweisen keinen erfolgreichen Paketweg. Die Simulation im Praxislabor ist davon getrennt.</div><article class="card"><div class="row"><h2>Berichte zusammenführen</h2><span class="badge">${reports.length} Quellenberichte</span></div><p class="muted">Importiere Fisi-Berichte, Fisi-Sammlungen oder unterstützte Native-Berichte. Identitäten bleiben quellspezifisch; Konflikte werden nicht still überschrieben. Alle ausgewählten Dateien werden gemeinsam vor dem Speichern geprüft.</p><label class="file">JSON-Dateien auswählen<input id="inventory-files" type="file" accept=".json,application/json" multiple></label><div class="actions">${button('Inventarsammlung exportieren','inventory_export','','secondary')}</div></article><article class="card"><h2>Gemeldete Netzzuordnungen</h2><p class="muted">Gestrichelte Linien sind Adapterzuordnungen. Hyper-V-Switches und SCVMM-VMNetworks bleiben unterschiedliche Objekttypen.</p>${networkPlan(reports)}</article><article class="card"><h2>Geräte und nachvollziehbare Quellen</h2>${reports.map(report => `<section><div class="row"><h3>${escape(report.source.label)}</h3>${tag(inventoryStatus(report))}</div><p class="notice-inline">Quelle ${escape(report.source.id)} · Erfasst ${escape(report.collectedAt)} · Bericht ${escape(report.id)}</p>${report.warnings.map(warning=>`<p class="notice-inline">${escape(warning)}</p>`).join('')}<div class="table-wrap"><table><thead><tr><th>Gerät / Identität</th><th>Adapter / Status</th><th>Adressen</th><th>Speicher</th></tr></thead><tbody>${report.devices.map(device=>`<tr><td><strong>${escape(device.name)}</strong><br><small>${escape(device.kind)} · ${escape(device.id)}</small><br><small>Gerät erfasst: ${escape(device.collectedAt || 'unbekannt')}</small></td><td>${device.adapters.map(adapter=>`${escape(adapter.name)} · ${escape(adapter.status)}<br><small>${escape(adapter.evidence)}</small>`).join('<br>') || 'Unbekannt · keine Adapterdaten'}</td><td>${device.adapters.map(adapter=>adapter.addresses.map(escape).join('<br>') || 'Unbekannt').join('<br>')}</td><td>${device.memoryMiB === null ? 'Unbekannt' : escape(device.memoryMiB)+' MiB'}</td></tr>`).join('')}</tbody></table></div></section>`).join('<hr>')}</article>`;
  }
  function progress() {
    const state=record.state.lab;
    return title('Fortschritt & Daten', 'Dein Stand liegt im Workspace auf dem Server, nicht nur in diesem Browser.') + `<div class="two"><article class="card"><h2>Aktueller Lernstand</h2><p>${state.intro ? '✓ Einstieg verstanden' : '○ Verständnisfrage noch offen'}</p>${checks()}<p class="notice-inline">${state.attempts.length} gespeicherte Abgabe(n). Historische Abgaben ersetzen keine aktuellen Nachweise. Lokale Sicherungen sind keine manipulationssicheren Prüfungszertifikate.</p><div class="actions">${gotoButton('Weiter im Praxislabor','lab','primary')}</div></article><article class="card journal"><h2>Lernjournal</h2><form id="journal-form"><label>Was hast du untersucht, gelernt oder noch nicht verstanden?<textarea data-draft="journal" name="text" maxlength="12000">${escape(draft('journal',record.state.journal))}</textarea></label><div class="actions"><button type="submit">Journal speichern</button></div></form></article></div><article class="card"><h2>Workspace sichern und wiederherstellen</h2><p class="muted">Die Sicherung enthält Fisi-Lernstand, Journal, Inventar und vorhandene Northlight-Referenzübungen. Beim Wiederherstellen bleibt die Workspace-Zuordnung bestehen; der bisherige Stand wird lokal gesichert. Exportierte Inventare können private Angaben enthalten – prüfe sie vor einer Weitergabe.</p><div class="actions">${button('Vollständige Sicherung herunterladen','export','','primary')}${record.role === 'trainer' ? '<label class="file">Workspace wiederherstellen<input id="restore-file" type="file" accept=".json,application/json"></label>' : '<small>Wiederherstellung übernimmt die Lehrkraft.</small>'}</div></article>${record.role === 'trainer' ? workspaceControls() : ''}`;
  }
  function workspaceControls() {
    return `<article class="card workspace-card"><h2>Gemeinsam im Workspace arbeiten</h2><p class="muted">Teilnehmende mit demselben Zugangscode arbeiten am selben gespeicherten Zustand. Andere Workspaces bleiben getrennt. Codes und Sitzungen sind vertraulich.</p><form id="workspace-form"><label>Name des neuen gemeinsamen Workspaces<input name="name" data-draft="workspace-name" maxlength="80" required value="${escape(draft('workspace-name',''))}" placeholder="Zum Beispiel: Netzwerkgruppe 1"></label><div class="actions"><button type="submit">Gemeinsamen Workspace anlegen</button></div></form>${joined ? `<div class="callout"><strong>${escape(joined.name)} ist angelegt.</strong><p>Zugangscode: <code>${escape(joined.code)}</code></p><p>Beitrittslink: <code>${escape(location.origin + '/#join=' + encodeURIComponent(joined.code))}</code></p><small>Im LAN benötigt der Link die freigegebene Serveradresse. Im lokalen Solobetrieb ist dieser Link nur auf diesem Rechner erreichbar.</small></div>` : ''}<label>Workspace als Trainer öffnen<select id="workspace-select">${options((record.workspaces || []).map(row=>[row.id,row.name]),record.id)}</select></label><p class="notice-inline">Web-/VPN-Zugriff muss am Server ausdrücklich eingerichtet werden. Fisi ändert keine Firewall, installiert kein VPN und fragt keine echten Schulrechner ab.</p></article>`;
  }
  function render() {
    if(!record)return;
    const requested=location.hash.replace(/^#\/?/,''); if(views[requested])route=requested;
    const content={overview,learn,lab,inventory,progress}[route]();
    $('#app').innerHTML=`<div class="shell"><aside class="sidebar"><div class="brand"><span class="brand-mark" aria-hidden="true">f</span>Fisi<span class="tag">LERNRAUM</span></div><p class="brand-sub">VERSTEHEN. AUSPROBIEREN.</p><div class="nav-label">Dein Lernbereich</div><nav aria-label="Hauptnavigation">${Object.entries(views).map(([key,[icon,label]])=>`<button class="nav ${key === route ? 'active' : ''}" data-route="${key}"${key === route ? ' aria-current="page"' : ''}><span class="nav-symbol" aria-hidden="true">${icon}</span>${label}</button>`).join('')}</nav><div class="sidefoot"><p><span class="dot"></span>${record.local_solo ? 'Lokaler Einzelbetrieb' : 'Gemeinsamer Serverbetrieb'}</p><p>Keine realen Cloud-Ressourcen.<br>Keine automatischen Netzabfragen.</p></div></aside><div><header class="topbar"><div><div class="breadcrumb">Fisi / ${views[route][1]}</div><div class="workspace-label">${escape(record.name)}</div></div><div class="row"><span class="connection">${pending ? 'Neuer Stand vorhanden' : escape(connection)}</span><span class="role">${record.role === 'trainer' ? 'Trainer' : 'Teilnahme'} · ${escape(record.participant)}</span></div></header><main id="main" class="content" tabindex="-1">${dirty() ? `<div class="callout warning">Ungespeicherte Eingaben bleiben beim Wechseln erhalten. ${button('Eigene Entwürfe ausdrücklich verwerfen','discard','','small secondary')}</div>` : ''}${pending ? `<div class="callout warning">Der gemeinsame Stand wurde geändert. Deine Eingaben sind erhalten. ${button('Aktuellen Stand laden','refresh','','small')}</div>` : ''}${content}<footer class="footer"><div class="row"><span>Fisi · Lernen durch nachvollziehbare Zustände</span><span>Workspace-Version ${record.revision} · ${button('Aktualisieren','refresh','','small secondary')} ${button('Sitzung wechseln','logout','','small secondary')}</span></div></footer></main></div></div>`;
    bind();
  }
  function download(name,value) { const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'})); const link=document.createElement('a'); link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000); }
  function navigate(target) { if(!views[target])return; route=target;history.replaceState(null,'','#/'+target);render();$('#main').focus(); }
  function bind() {
    document.querySelectorAll('[data-route]').forEach(element=>element.onclick=()=>navigate(element.dataset.route));
    document.querySelectorAll('[data-draft]').forEach(element=>element.addEventListener('input',()=>{ if(element.type==='radio'&&!element.checked)return; drafts.set(draftKey(element.dataset.draft),element.value); }));
    document.querySelectorAll('[data-config]').forEach(form=>form.onsubmit=event=>{event.preventDefault();const field=form.dataset.config;const raw=new FormData(form).get('value');action('configure',{field,value:field === 'service' ? raw === 'true' : raw},['config-'+field]);});
    const intro=$('#intro-form');if(intro)intro.onsubmit=event=>{event.preventDefault();action('intro',{answer:new FormData(intro).get('intro')},['intro']);};
    const explanation=$('#explanation-form');if(explanation)explanation.onsubmit=event=>{event.preventDefault();action('explain',{text:new FormData(explanation).get('text')},['explanation']);};
    const journal=$('#journal-form');if(journal)journal.onsubmit=event=>{event.preventDefault();action('journal',{text:new FormData(journal).get('text')},['journal']);};
    const room=$('#workspace-form');if(room)room.onsubmit=event=>{event.preventDefault();action('workspace_create',{name:new FormData(room).get('name')},['workspace-name']);};
    const select=$('#workspace-select');if(select)select.onchange=async()=>{if(dirty()){notice('Zuerst eigene Entwürfe speichern oder ausdrücklich verwerfen.',true);select.value=record.id;return;}try{record=await api('/api/fisi/state?instance='+encodeURIComponent(select.value));joined=null;pending=null;render();}catch(error){notice(error.message,true);}};
    const imports=$('#inventory-files');
    if(imports)imports.onchange=async()=>{
      try {
        const files=[...imports.files];
        if(!files.length)return;
        if(busy)throw Error('Laufende Aktion abwarten und Dateien erneut auswählen.');
        if(files.length>20||files.reduce((n,file)=>n+file.size,0)>2*1024*1024)throw Error('Maximal 20 Dateien mit zusammen 2 MiB.');
        const target={id:record.id,revision:record.revision};
        const texts=await Promise.all(files.map(file=>file.text()));
        if(!record||busy||record.id!==target.id||record.revision!==target.revision)throw Error('Zielworkspace oder Stand wurde inzwischen geändert. Dateien erneut auswählen.');
        await action('inventory_import',{texts});
      } catch(error) {
        notice(error.message,true);
      } finally {
        imports.value='';
      }
    };
    const restore=$('#restore-file');if(restore)restore.onchange=async()=>{try{const file=restore.files[0];if(!file)return;if(file.size>20*1024*1024)throw Error('Sicherung maximal 20 MiB.');if(dirty())throw Error('Eigene Eingaben zuerst speichern oder ausdrücklich verwerfen.');const expected={id:record.id,revision:record.revision,legacy:record.legacy_revision};const text=await file.text();if(expected.id!==record.id||expected.revision!==record.revision)throw Error('Zielworkspace wurde inzwischen geändert. Datei erneut auswählen.');if(!confirm('Den aktuellen Workspace durch diese Sicherung ersetzen? Der vorherige Stand wird lokal gesichert.'))return;await action('restore',{bundle_text:text,legacy_revision:expected.legacy});}catch(error){notice(error.message,true);}finally{restore.value='';}};
    document.querySelectorAll('[data-action]').forEach(element=>element.onclick=async()=>{const name=element.dataset.action;try{
      if(name==='diagnose')return action(name,{probe:element.dataset.probe});
      if(name==='submit'){if(dirty()){notice('Vor der Abgabe eigene Eingaben speichern oder ausdrücklich verwerfen.',true);return;}return action(name);}
      if(name==='refresh')return await load();
      if(name==='discard'){for(const key of [...drafts.keys()])if(key.startsWith(record.id+'/'))drafts.delete(key);render();return;}
      if(name==='inventory_export')return download('fisi-inventar.json',record.state.inventory);
      if(name==='export')return download('fisi-workspace.json',await api('/api/fisi/export?instance='+encodeURIComponent(record.id)));
      if(name==='logout'){if(dirty()){notice('Eigene Eingaben zuerst speichern oder ausdrücklich verwerfen.',true);return;}setToken(null);record=null;login();}
    }catch(error){notice(error.message,true);}});
  }
  function login() {
    $('#app').innerHTML=`<main class="login" id="main" tabindex="-1"><div class="brand"><span class="brand-mark">f</span>Fisi</div><h1>Dein gemeinsamer Lernraum.</h1><p class="muted">Gib den Zugangscode deiner Lehrkraft oder Gruppe ein. Mit demselben Code arbeitet ihr am selben Workspace.</p><form id="login-form"><label>Anzeigename<input name="name" maxlength="80" required autocomplete="nickname"></label><label>Zugangscode<input name="code" required maxlength="160" autocomplete="off"></label><div class="actions"><button type="submit" class="primary">Workspace öffnen →</button></div></form><p class="notice-inline">Ein Anzeigename ist ein Pseudonym, kein Identitätsnachweis. Für den lokalen Einzelbetrieb wird kein Code benötigt.</p></main>`;
    $('#login-form').onsubmit=async event=>{event.preventDefault();const data=new FormData(event.target);try{const result=await api('/api/login',{code:data.get('code'),name:data.get('name')});setToken(result.token);await load();}catch(error){notice(error.message,true);}};
  }
  async function start() {
    const parameters=new URLSearchParams(location.hash.slice(1)), code=parameters.get('join')||parameters.get('code');
    if(code){try{const result=await api('/api/login',{code,name:'Lernende Person'});setToken(result.token);history.replaceState(null,'',location.pathname);await load();return;}catch(error){setToken(null);login();notice(error.message,true);return;}}
    if(token){try{await load();return;}catch(error){if(error.status!==403){login();notice(error.message,true);return;}setToken(null);}}
    try{const result=await api('/api/fisi/bootstrap',{});setToken(result.token);await load();}catch(error){login();if(error.status!==403)notice(error.message,true);}
  }
  $('.skip').addEventListener('click',event=>{event.preventDefault();$('#main')?.focus();});
  window.addEventListener('hashchange',()=>{if(record)render();});
  setInterval(async()=>{if(!record||busy||document.hidden)return;try{const next=await api('/api/fisi/state?instance='+encodeURIComponent(record.id));connection='Verbunden';if(next.revision!==record.revision){if(dirty()){if(pending!==next.revision)notice('Ein anderer Teilnehmer hat gespeichert. Deine Eingaben bleiben erhalten; vor dem Speichern aktuellen Stand laden.');pending=next.revision;updateConnection();}else{record=next;pending=null;render();}}else updateConnection();}catch(error){connection=error.status===403?'Sitzung abgelaufen · erneut anmelden':'Verbindung unterbrochen · Eingaben bleiben erhalten';updateConnection();}},3000);
  start();
})();
