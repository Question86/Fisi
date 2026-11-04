# Sicherheitsmeldungen

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
