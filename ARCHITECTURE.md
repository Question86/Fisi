# Architektur und erhaltene Funktionen

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
