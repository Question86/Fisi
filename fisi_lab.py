"""Independent deterministic Fisi lesson: network path, data rights and evidence."""
from copy import deepcopy
from domain import Invalid

LESSON = {
    "id": "net-01", "title": "Ein Dateidienst, drei Grenzen",
    "subtitle": "DNS, Netzwerkpfad und Dateirechte getrennt untersuchen",
    "minutes": 25,
    "brief": "Lea aus dem Support soll den internen Dateidienst erreichen und Projekte lesen können. Gäste dürfen weder über das Gästenetz zugreifen noch intern Projektdaten lesen. Repariere nur die benötigten Einstellungen. Weise den erlaubten und beide verweigerten Fälle frisch nach und begründe deine Lösung.",
    "objectives": ["Namensauflösung und Netzwerkpfad unterscheiden", "Eine begrenzte Freigabe statt pauschaler Rechte wählen", "Positive und negative Nachweise nach einer Änderung erneuern"],
    "steps": ["Auftrag lesen", "Zustand untersuchen", "Gezielt ändern", "Drei Fälle nachprüfen", "Begründung speichern", "Abgeben"],
    "facts": ["Alle Personen, Adressen und Systeme in dieser Übung sind synthetisch.", "Der Dateidienst hat die Beispieladresse 192.0.2.20.", "Lea gehört zur Gruppe Support; Nilo ist Gast.", "Eine Verwaltungsberechtigung ist keine Leseberechtigung auf Projektdaten."],
}
PROBES = {
    "support-office": {"label": "Lea · Büronetz · Projekte lesen", "user": "support", "network": "office", "expected": True},
    "support-guest": {"label": "Lea · Gästenetz · Projekte lesen", "user": "support", "network": "guest", "expected": False},
    "guest-office": {"label": "Nilo · Büronetz · Projekte lesen", "user": "guest", "network": "office", "expected": False},
}
DEFAULT_CONFIG = {"dns": "192.0.2.99", "firewall": "closed", "readers": "admins", "service": True}
CHOICES = {"dns": ("192.0.2.99", "192.0.2.20"), "firewall": ("closed", "office", "all"), "readers": ("admins", "support", "everyone"), "service": (False, True)}


def fresh_lab():
    return {"schema": 1, "minute": 0, "version": 0, "config": dict(DEFAULT_CONFIG), "diagnostics": {}, "explanation": "", "attempts": [], "intro": False}


def diagnostic(config, key):
    if key not in PROBES:
        raise Invalid("Unbekannter Diagnosefall.")
    probe = PROBES[key]
    dns = config["dns"] == "192.0.2.20"
    network = config["firewall"] == "all" or (config["firewall"] == "office" and probe["network"] == "office")
    data = config["readers"] == "everyone" or (config["readers"] == "support" and probe["user"] == "support")
    allowed = dns and network and data and config["service"]
    reason = "Dateidienst nicht aufgelöst" if not dns else "Netzwerkpfad gesperrt" if not network else "Dienst gestoppt" if not config["service"] else "Dateirecht verweigert" if not data else "Dateidienst erreicht; Projektdatei gelesen"
    return {"allowed": allowed, "dns": dns, "network": network, "service": config["service"], "data": data, "reason": reason}


def assessment(lab):
    config = lab["config"]
    checks = [{"id": "bounded", "label": "Nur Büronetz und Support freigegeben", "passed": config == {"dns": "192.0.2.20", "firewall": "office", "readers": "support", "service": True}}]
    for key, probe in PROBES.items():
        record = lab["diagnostics"].get(key)
        fresh = record is not None and record["version"] == lab["version"]
        actual = diagnostic(config, key)
        # A denial caused by broken DNS is not evidence of the intended security boundary.
        correct_boundary = actual["dns"] and actual["service"]
        if key == "support-guest":
            correct_boundary = correct_boundary and not actual["network"] and actual["data"]
        elif key == "guest-office":
            correct_boundary = correct_boundary and actual["network"] and not actual["data"]
        checks.append({"id": key, "label": probe["label"] + " · frischer Nachweis", "passed": fresh and actual["allowed"] == probe["expected"] and correct_boundary})
    checks.append({"id": "explanation", "label": "Eigene Begründung gespeichert (mindestens 60 Zeichen)", "passed": len(lab["explanation"].strip()) >= 60})
    return {"passed": all(row["passed"] for row in checks), "checks": checks, "notice": "Die fachlichen Bedingungen werden aus dem Zustand geprüft. Die inhaltliche Qualität des Freitexts bespricht ihr mit der Lehrkraft."}


def validate_lab(lab):
    required = {"schema", "minute", "version", "config", "diagnostics", "explanation", "attempts", "intro"}
    if type(lab) is not dict or set(lab) != required or type(lab["schema"]) is not int or lab["schema"] != 1:
        raise Invalid("Ungültiges Fisi-Lernstandsformat.")
    for key in ("minute", "version"):
        if type(lab[key]) is not int or not 0 <= lab[key] <= 1_000_000:
            raise Invalid("Ungültige Simulationszeit oder Version.")
    if lab['version'] > lab['minute']:
        raise Invalid("Konfigurationsversion liegt außerhalb der Simulationszeit.")
    if type(lab["intro"]) is not bool or type(lab["explanation"]) is not str or len(lab["explanation"]) > 4000:
        raise Invalid("Ungültige Einführung oder Begründung.")
    if type(lab["config"]) is not dict or set(lab["config"]) != set(CHOICES):
        raise Invalid("Ungültige Konfiguration.")
    for key, options in CHOICES.items():
        value = lab["config"][key]
        if not any(type(value) is type(option) and value == option for option in options):
            raise Invalid("Unzulässiger Konfigurationswert: " + key)
    if type(lab["diagnostics"]) is not dict or set(lab["diagnostics"]) - set(PROBES):
        raise Invalid("Ungültige Diagnosen.")
    for key, row in lab["diagnostics"].items():
        if type(row) is not dict or set(row) != {"version", "minute", "result"}:
            raise Invalid("Ungültiger Diagnosenachweis.")
        if type(row["version"]) is not int or row["version"] != lab["version"] or type(row["minute"]) is not int or not 0 <= row["minute"] <= lab["minute"]:
            raise Invalid("Diagnose passt nicht zum Konfigurationsstand.")
        result = row['result']
        if type(result) is not dict or set(result) != {'allowed','dns','network','service','data','reason'} or any(type(result[field]) is not bool for field in ('allowed','dns','network','service','data')) or type(result['reason']) is not str or row['minute'] < row['version']:
            raise Invalid("Ungültige Typen im Diagnosenachweis.")
        if result != diagnostic(lab["config"], key):
            raise Invalid("Diagnose widerspricht dem tatsächlichen Zustand.")
    if type(lab["attempts"]) is not list or len(lab["attempts"]) > 20:
        raise Invalid("Zu viele Abgaben.")
    for row in lab["attempts"]:
        if type(row) is not dict or set(row) != {"minute", "version", "passed", "author"} or type(row["passed"]) is not bool or type(row["author"]) is not str or len(row["author"]) > 80:
            raise Invalid("Ungültige Abgabehistorie.")
        if any(type(row[key]) is not int or not 0 <= row[key] <= lab[key] for key in ("minute", "version")):
            raise Invalid("Ungültige Abgabezeit.")
    return lab


def apply_lab(lab, action, parameters, author):
    validate_lab(lab)
    out = deepcopy(lab)
    if type(parameters) is not dict:
        raise Invalid("Parameter müssen ein Objekt sein.")
    if action == "configure":
        if set(parameters) != {"field", "value"} or parameters["field"] not in CHOICES:
            raise Invalid("Genau ein bekanntes Konfigurationsfeld ändern.")
        out["config"][parameters["field"]] = parameters["value"]
        out["version"] += 1
        out["diagnostics"] = {}
    elif action == "diagnose":
        if set(parameters) != {"probe"} or parameters["probe"] not in PROBES:
            raise Invalid("Genau einen bekannten Diagnosefall auswählen.")
        out["diagnostics"][parameters["probe"]] = {"version": out["version"], "minute": out["minute"] + 1, "result": diagnostic(out["config"], parameters["probe"])}
    elif action == "explain":
        if set(parameters) != {"text"} or type(parameters["text"]) is not str:
            raise Invalid("Begründung als Text erwartet.")
        out["explanation"] = parameters["text"]
    elif action == "intro":
        if set(parameters) != {"answer"} or type(parameters["answer"]) is not str:
            raise Invalid("Eine Antwort auswählen.")
        if parameters["answer"] != "separate":
            raise Invalid("Noch nicht richtig: Ein erreichbarer Dienst beweist keine Leseberechtigung. Untersuche Netzwerkpfad und Dateirecht getrennt.")
        out["intro"] = True
    elif action == "submit":
        if parameters:
            raise Invalid("Die Abgabe erwartet keine vorgegebenen Ergebnisse.")
        result = assessment(out)
        out["attempts"] = (out["attempts"] + [{"minute": out["minute"] + 1, "version": out["version"], "passed": result["passed"], "author": str(author)[:80]}])[-20:]
    else:
        raise Invalid("Unbekannte Lernaktion.")
    out["minute"] += 1
    validate_lab(out)
    return out
