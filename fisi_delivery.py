"""Explicit-manifest Fisi source/Windows export; never copy a framework or runtime state."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import zipfile

VERSION = '0.1.0-alpha.1'
RUNTIME_SOURCES = ('__init__.py','domain.py','course.py','persistence.py','server.py','ui.py','fisi_app.py','fisi_inventory.py','fisi_lab.py','fisi_store.py','fisi_ui.py')
DEVELOPMENT_SOURCES = ('test_simulator.py','test_fisi.py','delivery.py','fisi_delivery.py','test_fisi_release.py','browser_acceptance.mjs')
STATIC_SOURCES = ('static/client.js','static/fisi.js','static/fisi-style.js')
START = r'''@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Fisi - Lernworkspace
"%~dp0runtime\python.exe" -B "%~dp0app\server.py" --port 0
if errorlevel 1 pause
'''
SHARED = r'''@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Fisi - gemeinsamer Lernworkspace
echo Teilnehmende oeffnen http://%COMPUTERNAME%:8765
echo Keine Firewallregel, Portfreigabe oder VPN-Verbindung wird angelegt.
echo Den Trainercode privat halten. Gruppen erhalten eigene Zugangscodes.
"%~dp0runtime\python.exe" -B "%~dp0app\server.py" --shared --host 0.0.0.0 --allow-host "%COMPUTERNAME%" --port 8765 --no-browser
if errorlevel 1 pause
'''
MIT = '''MIT License

Copyright (c) 2026 Fisi contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')


def checked_copy(source, destination):
    if not source.is_file() or source.is_symlink() or getattr(source.stat(),'st_file_attributes',0) & 1024:
        raise ValueError('Missing or linked release input: '+source.name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if source.read_bytes() != destination.read_bytes():
        raise ValueError('Copy verification failed: '+source.name)


def manifest(root, filename):
    rows={file.relative_to(root).as_posix():sha(file.read_bytes()) for file in sorted(root.rglob('*')) if file.is_file() and file.name != filename}
    write(root/filename,json.dumps({'schema':'fisi-file-manifest/v1','files':rows},indent=2,ensure_ascii=False)+'\n')
    return rows


def generated_assets(source, target):
    # Styles and the tiny HTML bootstrap are governed source inputs; emitted HTML/CSS are build outputs.
    style=(source/'static/fisi-style.js').read_text(encoding='utf-8')
    match=re.search(r'fisiStyle\.textContent = `([\s\S]*?)`;\s*document\.head\.append\(fisiStyle\);',style)
    if not match or '${' in match[1] or '\\' in match[1]:
        raise ValueError('Stylesheet extraction requires a literal, interpolation-free CSS template.')
    namespace={}
    import ast
    tree=ast.parse((source/'fisi_ui.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(item,ast.Name) and item.id=='PAGE' for item in node.targets):
            namespace['PAGE']=ast.literal_eval(node.value)
    page=namespace['PAGE']
    old='<script src="/static/fisi-style.js"></script>'
    if page.count(old)!=1:
        raise ValueError('Unexpected Fisi entry-point structure.')
    write(target/'static/fisi.css',match[1])
    write(target/'static/index.html',page.replace(old,'<link rel="stylesheet" href="/static/fisi.css">'))


def documentation(version, license_name):
    return {
        'README.md':f'''# Fisi

Verstehen. Ausprobieren. Nachweisen.

Fisi ist eine lokale Windows-Lernanwendung mit eigenständigem Lernauftrag,
serverseitiger Zustandsprüfung und gemeinsamen Lernworkspaces. Die Oberfläche
orientiert sich an der dunklen, türkisfarbenen Richtung der MB-FiSi Academy.

**Version {version}: Vorabversion zur Prüfung.** Eine Vorabversion ist keine
bestätigte stabile Unterrichtsfreigabe. Den tatsächlichen Prüfstand und offene
Punkte findest du in [KNOWN_LIMITS.md](KNOWN_LIMITS.md).

## Windows-Download und Start

Den Windows-Download von [GitHub Releases](https://github.com/Question86/Fisi/releases)
herunterladen, vollständig in einen lokalen Ordner entpacken und `START.cmd`
doppelklicken. Die Python-Laufzeit ist enthalten. Node, npm, Python-Installation,
Administratorrechte und Internet sind zum lokalen Lernen nicht erforderlich.
Der gesamte Ordner muss erhalten bleiben; nicht direkt aus der ZIP-Vorschau starten.

Im Einzelbetrieb öffnet sich der Lernworkspace ohne zusätzliche Anmeldung.
Änderungen werden auf dem Server gespeichert. Zum Beenden im Startfenster
Strg+C drücken. Beim nächsten Start bleiben die Daten erhalten. Standardablage
unter Windows: `%LOCALAPPDATA%\\Fisi`. Sie ist vom Downloadordner getrennt.

## Ein vollständiger Lernweg

1. Unter **Lernen** Netzwerkpfad und Dateirecht unterscheiden und die Verständnisfrage prüfen.
2. Im **Praxislabor** den Auftrag „Ein Dateidienst, drei Grenzen“ lesen.
3. DNS, Netzwerkfreigabe und Dateirecht getrennt untersuchen und gezielt ändern.
4. Den erlaubten Zugriff und beide vorgesehenen verweigerten Fälle frisch prüfen.
5. Die eigene Begründung speichern und den Auftrag abgeben.
6. Unter **Fortschritt & Daten** Journal und vollständige Workspace-Sicherung verwenden.

Die Simulation spricht keine realen Rechner oder Cloud-Ressourcen an. Das
Inventar ist getrennt gekennzeichnet: synthetische Beispiele und importierte
Konfigurationen sind keine erfolgreich geprüften Netzwerkpfade.

## Zusammenarbeiten

Siehe [SHARED_WORKSPACES.md](SHARED_WORKSPACES.md) für LAN, geschützten
Webzugang und VPN. Trainer erstellen unter **Fortschritt & Daten** einen
gemeinsamen Workspace. Teilnehmende mit dessen Code sehen denselben Zustand.
Andere Workspaces und Traineraktionen bleiben serverseitig gesperrt.

## Entwicklung und Rechte

[Architektur](ARCHITECTURE.md), [Tests](TESTING.md), [Erweitern](EXTENDING.md),
[Beiträge](CONTRIBUTING.md), [Sicherheitsmeldung](SECURITY.md) und
[Komponenten/Rechte](THIRD_PARTY_NOTICES.md). Anwendungslizenz: **{license_name}**.
Der Quellbaum enthält keine Werkfaden-Arbeitsräume, Lernstandsdateien oder echten Inventare.
''',
        'ARCHITECTURE.md':'''# Architektur und erhaltene Funktionen

Der Python-HTTP-Server bleibt Autorität für Sitzungen, Rollen und Speicherung.
Ein Fisi-Workspace speichert Lernzustand, Inventar und Journal unter einer
gemeinsamen Version. Gleichzeitige veraltete Änderungen werden mit HTTP 409
abgewiesen; die Oberfläche behält eigene Entwürfe beim Wechseln und Nachladen.

| Bereich | Zuständigkeit | Prüfpfad |
| --- | --- | --- |
| `fisi_lab.py` | Eigener deterministischer Lernauftrag; kontrollierte Zeit, getrennte Netz-/Dateirechte, frische Nachweise, Begründung und Abgabe | `test_fisi.LabTests`, HTTP-Lernablauf |
| `fisi_inventory.py` | Geschlossene begrenzte Schemata, Native-Datenadapter, quellspezifische Identitäten und explizite Berichtskonflikte | `test_fisi.InventoryTests`, atomare Importtests |
| `fisi_store.py` | Ein Fisi-Zustand pro Workspace, CAS-Versionen, gemeinsamer SQLite-Snapshot und Rollback bei vollständiger Wiederherstellung | `test_fisi.WorkspaceTests` |
| `fisi_app.py` | Sitzungs-/Workspace-Zuordnung, Rollen, Aktionen und feste lokale Assets | Workspace- und HTTP-Tests |
| `static/fisi.js` | API-Zugriff, Navigation, Ansichten und Entwurfserhalt ohne verbindliche Bewertung im Browser | Syntax und echter Edge-Lernablauf |
| `static/fisi-style.js` | Darstellung als deklarierte CSS-Vorlage; Paketbau erzeugt `static/fisi.css` | Paket- und Browserprüfung |
| `fisi_ui.py` | Kleiner HTML-Einstieg; Paketbau erzeugt `static/index.html` | Auslieferungsprüfung |
| `server.py` | HTTP, Host/Origin, authentifizierte API, lokaler Einstieg und Fehlerprotokoll | Original- und neue HTTP-Regressionen |
| `fisi_delivery.py` | Explizite öffentliche Dateiliste, Runtime, Dokumentation, CI und ZIP-Prüfsummen | `test_fisi_release`, fertiges Windows-Paket |

## Northlight bleibt fachliche Referenz und Kompatibilitätsbestand

`domain.py`, `course.py`, `persistence.py`, `ui.py`, `static/client.js`,
`delivery.py` und `test_simulator.py` behalten die bisherigen Fachfähigkeiten,
Kursdaten und Regressionen. Die neue Fisi-Aufgabe muss deren Lerntexte nicht
kopieren. Die ursprüngliche HTTP-Fachschnittstelle bleibt vorhanden; ihre
Referenzoberfläche liegt unter `/reference/`. Sie ist kein zweiter neuer
Hauptbereich der Fisi-Navigation.

Alte aktive und geparkte Übungen bleiben in den bisherigen SQLite-Tabellen.
Fisi verwendet zusätzliche Tabellen derselben Datenbank für seinen eigenen
Lernauftrag und gehashte Gruppencodes. Eine vollständige Fisi-Sicherung enthält
beide Zustandsbereiche. Wiederherstellung prüft beide Versionsstände und schreibt
beide Bereiche in einer Transaktion; vorher wird der bisherige Stand gesichert.
Ein Referenzstand und der eigenständige Fisi-Auftrag sind unterschiedliche Aufgaben.

Der Netzplan zeigt gemeldete Adapterzuordnungen als gestrichelte Linien. Er
behauptet keine vollständige Topologie und keine erfolgreiche Erreichbarkeit.
Gleichnamige Hyper-V-Switches und SCVMM-VMNetworks sind verschiedene Objekttypen.
''',
        'SHARED_WORKSPACES.md':'''# Gemeinsame Workspaces: lokal, LAN, Web und VPN

## Einzelbetrieb

`START.cmd` bindet ausschließlich an Loopback und wählt einen freien lokalen Port.
Nur dieser ausdrücklich lokale Modus bietet den Einstieg ohne Zugangscode.
Er ist ein lokaler Lernbetrieb, kein manipulationssicheres Prüfungssystem.

## LAN

`GEMEINSAM-IM-LAN.cmd` startet den Server ausdrücklich mit `--shared`,
bindet an `0.0.0.0:8765` und erlaubt den eigenen Computernamen als Host.
Teilnehmende öffnen die ausgegebene Adresse. Die Lehrkraft hält den Trainercode
privat, öffnet die Traineroberfläche und erstellt einen gemeinsamen Workspace.
Gruppencodes geben nur Teilnehmerrechte in genau diesem Workspace.

Fisi verändert keine Firewall. Erforderliche Netzfreigaben muss die zuständige
Administration ausdrücklich einrichten. Für eine andere freigegebene Adresse:

```text
runtime\\python.exe -B app\\server.py --shared --host 0.0.0.0 --allow-host SERVERNAME --port 8765 --no-browser
```

Anzeigenamen sind Pseudonyme, keine verifizierten Identitäten. Codes sind
vertraulich. Teilnehmer-Sitzungen laufen nach zwölf Stunden ab; Gruppencodes
bleiben lokal erhalten. Nach einem Serverneustart erneut über den Gruppencode
beitreten; der gespeicherte Workspace bleibt bestehen.

## Direkter Webzugang

Der Server enthält keinen eingebauten HTTPS- oder öffentlichen Hostingdienst.
Für Webzugang einen administrierten HTTPS-Reverse-Proxy mit passendem Host,
zusätzlichem Zugangsschutz und angemessenen Anfrage-/Ratenlimits verwenden.
Den Backendserver **immer mit `--shared` starten, auch bei Loopback-Bindung**:

```text
runtime\\python.exe -B app\\server.py --shared --host 127.0.0.1 --allow-host lernen.example.org --port 8765 --no-browser
```

Host und Origin müssen zum freigegebenen Namen passen. Trainercode und
Gruppencodes niemals in öffentliche Seiten, Git, Logs oder Bildschirmfotos übernehmen.
Kein öffentlicher Server wurde allein durch dieses Paket eingerichtet oder abgenommen.

## Optionaler VPN-Zugang

Ein bereits genehmigter VPN-Client kann die private Serveradresse erreichbar
machen. Anmeldung, Gerätefreigabe, automatisches Verbinden und Wiederverbinden
gehören zur administrierten VPN-Lösung. Fisi installiert und konfiguriert kein
VPN und speichert keine VPN-Zugangsdaten. Die Fisi-Oberfläche behält ungespeicherte
Eingaben bei einer Verbindungsunterbrechung; eine konkrete reale VPN-Verbindung
muss separat an autorisierten Zielen geprüft werden.
''',
        'TESTING.md':f'''# Tests und Nachweisgrenzen

Für Quelltests Python 3.13 verwenden. Kein Paketdownload ist erforderlich:

```text
python -m unittest discover -s . -p "test_*.py" -v
node --check static/fisi.js
node --check static/fisi-style.js
node --check static/client.js
```

Node 22 wird nur für JavaScript-/Browser-Entwicklung benötigt, nicht zum Lernen.
Tests auf einer getrennten beschreibbaren Kopie ausführen. Generierte
`.cache`, `test-evidence` und Browserprofile sind private Testausgaben und
gehören nicht in Git oder Releases.

Windows- und Quellpaket bauen:

```text
python fisi_delivery.py --out "../Fisi release output" --license {license_name}
python test_fisi_release.py --verify-windows "../Fisi release output/Fisi-0.1.0-alpha.1-Windows.zip" --out "../Fisi freshly extracted path with spaces"
node browser_acceptance.mjs "../Fisi release output/Windows/app" "../Fisi browser evidence" "../Fisi release output/Windows/runtime/python.exe"
```

Die Browserprüfung startet ausschließlich ein neues Headless-Edge-Profil und
einen lokalen Server mit synthetischen Daten. Sie interagiert nicht mit
vorhandenen Benutzerfenstern oder Profilen. Das Protokoll enthält einzelne
PASS/FAIL-Nachweise und Screenshots, nicht Trainer-/Gruppencodes oder Profile.

Ein grüner Syntaxcheck beweist keine Bedienbarkeit. Backendtests beweisen keine
Browser-, echte LAN-/VPN-, Hypervisor- oder Klassenraumabnahme. Das fertige ZIP
aus einem frischen Pfad mit Leerzeichen prüfen; eine Entwicklungsordnerprüfung
ersetzt das nicht. Nur tatsächlich ausgeführte Nachweise als bestanden ausweisen.
''',
        'EXTENDING.md':'''# Einen begrenzten Beitrag ergänzen

Der erste eigenständige Lernauftrag ist in `fisi_lab.py` deklariert. Seine
Beschreibung, Schritte und Prüffälle sind Daten; die Zustandsregeln besitzen
eigene Funktionen. Neue Inhalte benötigen versionierte Datenverträge und
positive sowie negative Verhaltensprüfungen. Keine fremden Python- oder
JavaScript-Dateien als normale Kursdateien ausführen.

Die erhaltene Northlight-Kursdefinition in `course.py` und deren Datenvalidierung
bleiben für fachliche Vertiefungen verfügbar. Neue Bedienwege erst anbieten,
wenn sie geprüft sind. Eine neue Aufgabe muss nicht eine Northlight-Aufgabe kopieren.

Inventare verwenden `fisi-inventory/v1` oder `fisi-inventory-collection/v1`.
Maximal 20 Berichte, 500 Geräte insgesamt, 100 Geräte pro Bericht, 16 Adapter
pro Gerät und zusammen 2 MiB. Geräte- und Netzidentitäten bleiben quellspezifisch.
`null`-Adapter, doppelte Kennungen und widersprüchliche Berichte werden abgelehnt.
Nicht belegte Einheiten und Einzelabfragen bleiben unbekannt mit Hinweis.

Darstellung gehört in reguläre Frontenddateien, Rechte und Bewertungen auf den
Server. Beim Ändern von Zuständen zusätzlich Rollback, veraltete Versionen,
Fremdworkspace und Neustart testen. Der Paketbauer kopiert nur seine explizite
Dateiliste; neue notwendige Dateien dort deklarieren und Pakettests erweitern.
''',
        'CONTRIBUTING.md':'''# Beiträge

Repository klonen, Python 3.13 bereitstellen und die Tests aus TESTING.md auf
einer isolierten Kopie ausführen. Für Browser-/Syntaxprüfungen Node 22 und Edge
verwenden. Die Anwendung selbst benötigt keine Node-Installation.

Kleine Pull Requests mit Problem, erwarteter Wirkung und tatsächlich ausgeführten
Prüfungen sind willkommen. Fachprüfungen nicht entfernen, um die Oberfläche
schneller fertigzustellen. Keine echten Inventare, Schülerdaten, Tokens,
Sitzungen, lokalen Datenbanken oder privaten Pfade einchecken. Für neue Inhalte
Quellen und Nutzungsrechte angeben; keine fremden Lizenzen umdeuten.

Werkfaden ist die getrennte Entwicklungsumgebung des ursprünglichen Projekts
und kein Bestandteil dieses öffentlichen Produktrepositorys. Zum Testen eines
begrenzten Produktbeitrags ist kein privater Framework-Workspace erforderlich.
''',
        'SECURITY.md':'''# Sicherheitsmeldungen

Reproduzierbare Sicherheitsprobleme über den privaten GitHub-Sicherheitskanal
des Repositorys melden, sofern aktiviert. Andernfalls zuerst einen öffentlichen
Issue ohne Geheimnisse und ohne direkt ausnutzbare Details mit der Bitte um
einen privaten Kontaktweg eröffnen. Niemals Tokens, Schülerdaten oder reale
Inventare in öffentliche Issues oder Logs schreiben.

Der lokale Modus ist ausschließlich für Loopback. Gemeinsamer Webbetrieb
benötigt `--shared`, HTTPS und administrierten Zugangsschutz. Der Server führt
keine Inventar-Collector, Scans, VM-Änderungen oder externen Kursmodule aus.
Lokale Spielstandsdateien sind keine manipulationssicheren Prüfungsnachweise.
Interne Fehler stehen in `server-errors.log` im gewählten Datenordner; normale
Anfrageinhalte und Sitzungstokens werden dort nicht protokolliert.
''',
        'THIRD_PARTY_NOTICES.md':f'''# Komponenten und Rechte

| Bestandteil | Herkunft / Status |
| --- | --- |
| Fisi-Anwendung und übernommener Northlight-Anwendungscode | Veröffentlichung durch den Projektinhaber autorisiert; Anwendungslizenz: {license_name} |
| Python-Laufzeit im Windows-Paket | Python Software Foundation; vollständige Hinweise unter `runtime/LICENSE.txt` |
| MB-FiSi Academy | Visuelle Richtung als Referenz; Copyright 2026 Marin Bilandzija. Kein Academy-Code oder fremder Lektionstext wurde in diese Fisi-Oberfläche kopiert. Für eine spätere Übernahme gelten MIT bzw. CC BY 4.0 mit den jeweiligen Hinweisen. |
| Native-Netzwerk-Labor | Kein Collector-, PowerShell- oder Dashboardcode enthalten. Der eigenständig implementierte Adapter verarbeitet das dokumentierte JSON-Datenformat. Der All-rights-reserved-Hinweis wird nicht als offene Code-Lizenz umgedeutet. |
| Werkfaden/KAIROS | Getrenntes Entwicklungswerkzeug; weder Frameworkcode, Frameworklizenzpflichten noch dessen Geschichte/Arbeitsräume werden als Produkt mitgeliefert. |

Die Python-Distribution enthält eigene Drittkomponentenhinweise in ihrem
Lizenztext. Betriebssystemkomponenten sind nicht neu lizenziert. Reale Inventare
und private Daten sind keine Beispiel- oder Auslieferungsbestandteile.
''',
        'KNOWN_LIMITS.md':'''# Bekannte Grenzen und Freigabestatus

Diese Version ist als **Vorabversion** bezeichnet. Sie darf nicht allein
aufgrund bestandener Backendtests als stabile Unterrichtsauslieferung gelten.
Die CI und das tatsächliche Testprotokoll des jeweiligen Releases sind maßgeblich.

- Ein eigener vollständiger Lernauftrag und ein Einstieg sind vorhanden; weitere
  Northlight-Kurse bleiben im Quell-/Kompatibilitätsbestand, nicht als neue Fisi-Lernmodule angeboten.
- Freitext wird gespeichert; seine inhaltliche Qualität bespricht die Lehrkraft.
- Importierte Konfiguration ist kein Erreichbarkeits-, Echtheits- oder vollständiger Topologienachweis.
- Älter als sieben Tage erfasste Importe werden sichtbar markiert. Das ist eine Anzeigegrenze, kein fachlicher Gültigkeitsnachweis.
- Windows-/Hyper-V-/SCVMM-Collector und aktive Proben sind nicht enthalten und nicht abgenommen.
- Öffentlicher Webhost, konkrete VPN-Lösung und reale Klassenraum-Netzbedingungen sind nicht eingerichtet oder abgenommen.
- Anzeigenamen sind Pseudonyme. Lokale Sicherungen sind keine unveränderlichen Prüfungszertifikate.
- In der ursprünglichen geschützten Entwicklungsumgebung war der Browserzugriff
  nicht ausführbar: Pluginhost fehlte und Headless Edge scheiterte an Windows-Prozessrechten.
  Ein später erfolgreicher isolierter CI-/Windows-Browserlauf muss mit eigenem Nachweis dokumentiert werden.

Keine fehlende Prüfung durch ein Beispielbild oder eine syntaktisch gültige Datei ersetzen.
''',
        '.gitignore':'''__pycache__/
*.pyc
.cache/
.artifacts/
test-evidence/
dist/
runtime/
*.sqlite3
*.sqlite3-*
server-errors.log
private/
''',
        'RELEASING.md':f'''# Gezielte Veröffentlichung einer geprüften Vorabversion

Die normale CI besitzt nur Leserechte. Nach erfolgreichem Windows-/Edge-Lauf
die synthetischen Screenshots und Prüfprotokolle dieses Commits prüfen.
Erst dann den Branch `release/v{version}` exakt auf diesem Commit erstellen.
Das ausdrücklich gewählte Branch-create-Ereignis startet den getrennten
Veröffentlichungsjob mit minimalen Release-/Artefaktrechten.

Der Job akzeptiert ausschließlich Question86/Fisi, diese Vorabversion und einen
erfolgreichen main-Push-CI-Lauf desselben Commits. Er lädt dessen unveränderte
Pakete, prüft Prüfsummen und beide Abnahmeprotokolle, erstellt zunächst einen
Releaseentwurf und prüft die hochgeladenen Dateien durch erneuten Download.
Erst danach veröffentlicht er die Vorabversion und prüft den Download erneut.
Bestehende Releases/Tags werden nicht überschrieben. Bei einem Fehler bleibt
die Veröffentlichung unbestätigt; Ursache untersuchen und gezielt beheben.
''',
        '.github/workflows/publish.yml':'''name: Fisi publish accepted prerelease
on: [create]
permissions: {}
jobs:
  publish:
    if: github.event.ref_type == 'branch' && github.event.ref == 'release/v0.1.0-alpha.1'
    runs-on: windows-2025
    timeout-minutes: 15
    permissions:
      contents: write
      actions: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.13'
      - name: Verify accepted artifacts, upload draft, redownload and publish prerelease
        run: python fisi_delivery.py --publish-accepted-run
        env:
          GH_TOKEN: ${{ github.token }}
      - name: Preserve post-publication download verification
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: fisi-published-verification
          if-no-files-found: error
          path: release-verification/PUBLISHED.json
''',
        '.github/workflows/ci.yml':'''name: Fisi acceptance
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  windows:
    runs-on: windows-2025
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.13'
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '22'
      - name: Source regression
        run: python -m unittest discover -s . -p "test_*.py" -v
      - name: JavaScript syntax
        run: |
          node --check static/fisi.js
          node --check static/fisi-style.js
          node --check static/client.js
          node --check browser_acceptance.mjs
      - name: Build explicit Windows and source packages
        shell: pwsh
        run: |
          $fisiArtifactRoot = Join-Path $env:RUNNER_TEMP 'Fisi release artifacts'
          python fisi_delivery.py --out "$fisiArtifactRoot" --license UNLICENSED
      - name: Fresh Windows ZIP acceptance
        shell: pwsh
        run: |
          $fisiArtifactRoot = Join-Path $env:RUNNER_TEMP 'Fisi release artifacts'
          $fisiExtractRoot = Join-Path $env:RUNNER_TEMP 'Fisi fresh path with spaces'
          python test_fisi_release.py --verify-windows "$fisiArtifactRoot/Fisi-0.1.0-alpha.1-Windows.zip" --out "$fisiExtractRoot"
      - name: Real Edge workflow against bundled runtime
        shell: pwsh
        run: |
          $fisiExtractRoot = Join-Path $env:RUNNER_TEMP 'Fisi fresh path with spaces'
          $fisiBrowserEvidence = Join-Path $env:RUNNER_TEMP 'Fisi browser evidence'
          node browser_acceptance.mjs "$fisiExtractRoot/app" "$fisiBrowserEvidence" "$fisiExtractRoot/runtime/python.exe"
      - name: Publish only explicit synthetic acceptance artifacts
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: fisi-acceptance
          if-no-files-found: warn
          path: |
            ${{ runner.temp }}/Fisi browser evidence/fisi-edge-workflow.json
            ${{ runner.temp }}/Fisi browser evidence/*.png
            ${{ runner.temp }}/Fisi fresh path with spaces/ACCEPTANCE.json
      - name: Preserve exact packages after successful runtime and browser acceptance
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: fisi-accepted-packages
          if-no-files-found: error
          path: |
            ${{ runner.temp }}/Fisi release artifacts/Fisi-0.1.0-alpha.1-Windows.zip
            ${{ runner.temp }}/Fisi release artifacts/Fisi-0.1.0-alpha.1-Source.zip
            ${{ runner.temp }}/Fisi release artifacts/SHA256SUMS.txt
            ${{ runner.temp }}/Fisi release artifacts/BUILD.json
'''.replace('--license UNLICENSED','--license '+license_name),
    }


def bundle_runtime(target, base=None):
    base=Path(base or sys.base_prefix)
    stem=f'python{sys.version_info.major}{sys.version_info.minor}'
    target.mkdir(parents=True)
    for name in ('python.exe',stem+'.dll','vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt'):
        checked_copy(base/name,target/name)
    if (base/'python3.dll').is_file():
        checked_copy(base/'python3.dll',target/'python3.dll')
    for file in sorted((base/'DLLs').iterdir()):
        if file.is_file() and file.suffix.lower() in ('.pyd','.dll'):
            checked_copy(file,target/file.name)
    excluded={'site-packages','test','tests','idlelib','tkinter','turtledemo','ensurepip','__pycache__'}
    with zipfile.ZipFile(target/(stem+'.zip'),'w',zipfile.ZIP_DEFLATED) as archive:
        for file in sorted((base/'Lib').rglob('*')):
            relative=file.relative_to(base/'Lib')
            if file.is_file() and not set(relative.parts)&excluded and file.suffix.lower() in ('.py','.json','.txt','.dat','.pem','.cfg'):
                if file.is_symlink() or getattr(file.stat(),'st_file_attributes',0) & 1024:
                    raise ValueError('Linked runtime input refused.')
                archive.write(file,relative.as_posix())
    write(target/(stem+'._pth'),stem+'.zip\n.\n../app\n')


def export(source, output, version=VERSION, license_name='UNLICENSED', windows=True, runtime_base=None):
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists() or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('A fresh export directory outside the source tree is required.')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-z0-9.]+)?',version):
        raise ValueError('Invalid release version.')
    if license_name not in ('MIT','UNLICENSED'):
        raise ValueError('An explicit supported owner license choice is required.')
    expected=RUNTIME_SOURCES+DEVELOPMENT_SOURCES+STATIC_SOURCES
    # Resolve every declared input before creating output. Never discover a publication set by globbing.
    for name in expected:
        file=source/name
        if not file.is_file() or file.is_symlink() or getattr(file.stat(),'st_file_attributes',0) & 1024 or not file.resolve().is_relative_to(source):
            raise ValueError('Missing or linked source input: '+name)
    output.mkdir(parents=True)
    public=output/'Source';public.mkdir()
    for name in expected:
        checked_copy(source/name,public/name)
    generated_assets(source,public)
    docs=documentation(version,license_name)
    docs['LICENSE']=MIT if license_name=='MIT' else 'Fisi application code: no general open-source license has yet been granted by the project owner. Publication of the included Northlight application code was explicitly authorized. Third-party components retain their separate notices.\n'
    for name,content in docs.items():
        write(public/name,content)
    source_rows=manifest(public,'SOURCE_MANIFEST.json')
    source_zip=Path(shutil.make_archive(str(output/f'Fisi-{version}-Source'),'zip',public))
    assets=[source_zip]
    if windows:
        package=output/'Windows';package.mkdir();app=package/'app';app.mkdir()
        for name in RUNTIME_SOURCES+STATIC_SOURCES:
            checked_copy(source/name,app/name)
        generated_assets(source,app)
        for name,content in docs.items():
            if not name.startswith('.'):
                write(package/name,content)
        write(package/'START.cmd',START.replace('\n','\r\n'))
        write(package/'GEMEINSAM-IM-LAN.cmd',SHARED.replace('\n','\r\n'))
        bundle_runtime(package/'runtime',runtime_base)
        manifest(package,'MANIFEST-SHA256.json')
        assets.append(Path(shutil.make_archive(str(output/f'Fisi-{version}-Windows'),'zip',package)))
    sums={file.name:sha(file.read_bytes()) for file in assets}
    write(output/'SHA256SUMS.txt',''.join(digest+'  '+name+'\n' for name,digest in sums.items()))
    result={'schema':'fisi-build/v1','version':version,'license':license_name,'status':'prerelease' if '-' in version else 'unaccepted-candidate','source_files':len(source_rows),'assets':sums,'windows_built':windows,'notice':'A build is not acceptance or publication. Execute the actual artifact and browser checks.'}
    write(output/'BUILD.json',json.dumps(result,indent=2)+'\n')
    return result


def verify_accepted_packages(root):
    root=Path(root)
    expected={f'Fisi-{VERSION}-Windows.zip',f'Fisi-{VERSION}-Source.zip'}
    if {item.name for item in root.iterdir()}!=expected|{'SHA256SUMS.txt','BUILD.json'}:
        raise ValueError('Accepted package artifact contains undeclared or missing files.')
    build=json.loads((root/'BUILD.json').read_text(encoding='utf-8'))
    if build.get('schema')!='fisi-build/v1' or build.get('version')!=VERSION or build.get('license')!='MIT' or build.get('windows_built') is not True or set(build.get('assets',{}))!=expected:
        raise ValueError('Accepted package metadata does not match this MIT Windows prerelease.')
    sums={}
    for line in (root/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        match=re.fullmatch(r'([a-f0-9]{64})  (Fisi-[A-Za-z0-9.-]+\.zip)',line)
        if not match or match[2] in sums:raise ValueError('Invalid or duplicate checksum entry.')
        sums[match[2]]=match[1]
    if sums!=build['assets']:raise ValueError('Checksum file and build metadata disagree.')
    for name,digest in sums.items():
        file=root/name
        if file.is_symlink() or not file.is_file() or sha(file.read_bytes())!=digest:
            raise ValueError('Accepted package checksum mismatch.')
    return build


def publish_accepted_run():
    import os
    import subprocess
    import tempfile

    repo=os.environ.get('GITHUB_REPOSITORY')
    commit=os.environ.get('GITHUB_SHA','')
    if repo!='Question86/Fisi' or os.environ.get('GITHUB_EVENT_NAME')!='create' or os.environ.get('GITHUB_REF')!='refs/heads/release/v'+VERSION or not re.fullmatch('[a-f0-9]{40}',commit):
        raise ValueError('Publication requires the explicit release-branch event in Question86/Fisi.')
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    if event.get('ref_type')!='branch' or event.get('ref')!='release/v'+VERSION:
        raise ValueError('Wrong publication event payload.')
    def gh(*args):
        repository_args=[] if args[0]=='api' else ['--repo',repo]
        return subprocess.check_output(['gh',*map(str,args),*repository_args],text=True,encoding='utf-8',timeout=180)
    runs=json.loads(gh('run','list','--workflow','ci.yml','--commit',commit,'--branch','main','--event','push','--status','success','--json','databaseId,headSha,conclusion,event'))
    runs=[run for run in runs if run.get('headSha')==commit and run.get('conclusion')=='success' and run.get('event')=='push']
    if not runs:raise ValueError('No successful main Windows/Edge acceptance run for this exact commit.')
    run_id=max(run['databaseId'] for run in runs)
    tag='v'+VERSION
    if json.loads(gh('api',f'repos/{repo}/git/matching-refs/tags/{tag}')):
        raise ValueError('Existing release tag must not be reused or moved.')
    # Existing releases/tags are intentionally not edited or overwritten by this path.
    with tempfile.TemporaryDirectory(prefix='Fisi-publish-') as temp:
        root=Path(temp);packages=root/'packages';evidence=root/'evidence'
        gh('run','download',run_id,'--name','fisi-accepted-packages','--dir',packages)
        gh('run','download',run_id,'--name','fisi-acceptance','--dir',evidence)
        build=verify_accepted_packages(packages)
        reports=list(evidence.rglob('fisi-edge-workflow.json'));windows=list(evidence.rglob('ACCEPTANCE.json'))
        if len(reports)!=1 or len(windows)!=1:raise ValueError('Missing or ambiguous acceptance evidence.')
        browser=json.loads(reports[0].read_text(encoding='utf-8'));runtime=json.loads(windows[0].read_text(encoding='utf-8'))
        if browser.get('result')!='PASS' or not browser.get('checks') or not all(check.get('passed') is True for check in browser['checks']) or browser.get('errors') or runtime.get('status')!='PASS':
            raise ValueError('Runtime or browser acceptance is not passing.')
        verification={'schema':'fisi-release-verification/v1','commit':commit,'acceptance_run':run_id,'assets':build['assets'],'browser':{'result':browser['result'],'checks':browser['checks'],'engine':browser['engine']},'windows':runtime,'limits':'Prerelease. No real classroom, VPN, public webhost, Hyper-V or SCVMM acceptance claimed.'}
        verification_file=root/'RELEASE_VERIFICATION.json';write(verification_file,json.dumps(verification,ensure_ascii=False,indent=2)+'\n')
        notes=root/'notes.md';write(notes,f'Fisi {VERSION} — Vorabversion unter MIT.\n\nEigener vollständiger Lernauftrag, gemeinsame Workspaces mit Rollen/Versionskonflikten, validierter Inventarimport und Windows-Start mit mitgelieferter Laufzeit.\n\nGeprüfter Commit: `{commit}`. [Windows-/Edge-Abnahme](https://github.com/{repo}/actions/runs/{run_id}). Die ZIPs stammen unverändert aus genau diesem erfolgreichen Lauf.\n\nEnthalten: Windows-ZIP, Quell-ZIP, SHA-256-Prüfsummen, Build- und Abnahmenachweis. Entpacken und START.cmd öffnen.\n\nGrenzen: Vorabversion; kein eingerichteter öffentlicher Webhost/VPN, keine realen Collector oder Klassenraumabnahme. Hinweise in KNOWN_LIMITS.md und SHARED_WORKSPACES.md beachten.\n')
        assets=sorted(packages.iterdir())+[verification_file]
        gh('release','create',tag,*assets,'--target',commit,'--title','Fisi '+VERSION,'--notes-file',notes,'--draft','--prerelease','--latest=false')
        expected={file.name:sha(file.read_bytes()) for file in assets}
        def redownload(name):
            target=root/name
            gh('release','download',tag,'--dir',target)
            actual={file.name:sha(file.read_bytes()) for file in target.iterdir() if file.is_file()}
            if actual!=expected:raise ValueError('Uploaded release asset set or checksum mismatch.')
        redownload('draft-download')
        gh('release','edit',tag,'--draft=false','--prerelease','--latest=false')
        redownload('published-download')
        result={'status':'PASS','commit':commit,'acceptance_run':run_id,'url':f'https://github.com/{repo}/releases/tag/{tag}','redownloaded_assets':expected}
        output=Path('release-verification');output.mkdir(exist_ok=True)
        write(output/'PUBLISHED.json',json.dumps(result,indent=2)+'\n')
        return result


def main():
    parser=argparse.ArgumentParser(description='Build clean Fisi source and offline Windows packages.')
    parser.add_argument('--out')
    parser.add_argument('--version',default=VERSION)
    parser.add_argument('--license',choices=('MIT','UNLICENSED'))
    parser.add_argument('--publish-accepted-run',action='store_true')
    parser.add_argument('--source-only',action='store_true')
    args=parser.parse_args()
    if args.publish_accepted_run:
        print(json.dumps(publish_accepted_run(),indent=2));return
    if not args.out or not args.license:parser.error('--out and --license are required for a build')
    print(json.dumps(export(Path(__file__).parent,args.out,args.version,args.license,not args.source_only),indent=2))


if __name__=='__main__':
    main()
