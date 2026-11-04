# Gezielte Veröffentlichung einer geprüften Vorabversion

Die normale CI besitzt nur Leserechte. Nach erfolgreichem Windows-/Edge-Lauf
die synthetischen Screenshots und Prüfprotokolle dieses Commits prüfen.
Erst dann den Branch `release/v0.1.0-alpha.1` exakt auf diesem Commit erstellen.
Das ausdrücklich gewählte Branch-create-Ereignis startet den getrennten
Veröffentlichungsjob mit minimalen Release-/Artefaktrechten.

Der Job akzeptiert ausschließlich Question86/Fisi, diese Vorabversion und einen
erfolgreichen main-Push-CI-Lauf desselben Commits. Er lädt dessen unveränderte
Pakete, prüft Prüfsummen und beide Abnahmeprotokolle, erstellt zunächst einen
Releaseentwurf und prüft die hochgeladenen Dateien durch erneuten Download.
Erst danach veröffentlicht er die Vorabversion und prüft den Download erneut.
Bestehende Releases/Tags werden nicht überschrieben. Bei einem Fehler bleibt
die Veröffentlichung unbestätigt; Ursache untersuchen und gezielt beheben.
