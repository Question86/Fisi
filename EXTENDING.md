# Einen begrenzten Beitrag ergänzen

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
