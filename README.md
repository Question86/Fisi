# Fisi

Verstehen. Ausprobieren. Nachweisen.

Fisi ist eine lokale Windows-Lernanwendung mit eigenständigem Lernauftrag,
serverseitiger Zustandsprüfung und gemeinsamen Lernworkspaces. Die Oberfläche
orientiert sich an der dunklen, türkisfarbenen Richtung der MB-FiSi Academy.

**Version 0.1.0-alpha.1: Vorabversion zur Prüfung.** Eine Vorabversion ist keine
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
unter Windows: `%LOCALAPPDATA%\Fisi`. Sie ist vom Downloadordner getrennt.

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
[Komponenten/Rechte](THIRD_PARTY_NOTICES.md). Anwendungslizenz: **UNLICENSED**.
Der Quellbaum enthält keine Werkfaden-Arbeitsräume, Lernstandsdateien oder echten Inventare.
