# Tests und Nachweisgrenzen

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
python fisi_delivery.py --out "../Fisi release output" --license MIT
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
