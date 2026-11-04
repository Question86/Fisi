# Gemeinsame Workspaces: lokal, LAN, Web und VPN

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
runtime\python.exe -B app\server.py --shared --host 0.0.0.0 --allow-host SERVERNAME --port 8765 --no-browser
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
runtime\python.exe -B app\server.py --shared --host 127.0.0.1 --allow-host lernen.example.org --port 8765 --no-browser
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
