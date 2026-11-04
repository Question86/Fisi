"""Bounded inventory data contracts; original implementation, no collector code."""
from copy import deepcopy
from datetime import datetime
import hashlib
import ipaddress
import json
from domain import Invalid

REPORT = "fisi-inventory/v1"
COLLECTION = "fisi-inventory-collection/v1"
MAX_BYTES = 2 * 1024 * 1024


def bounded_tree(value, depth=0, counter=None):
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if depth > 12 or counter[0] > 25000:
        raise Invalid("Inventar ist zu tief verschachtelt oder zu umfangreich.")
    if isinstance(value, str) and len(value) > 4000:
        raise Invalid("Inventartext ist zu lang.")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or len(key) > 128:
                raise Invalid("Ungültiger Inventarschlüssel.")
            bounded_tree(item, depth + 1, counter)
    elif type(value) is list:
        if len(value) > 1000:
            raise Invalid("Inventarliste ist zu groß.")
        for item in value:
            bounded_tree(item, depth + 1, counter)
    elif value is not None and type(value) not in (str, int, float, bool):
        raise Invalid("Ungültiger Inventarwert.")


def text(value, label, limit=160, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise Invalid("Ungültig: " + label)
    return value


def timestamp(value):
    text(value, "Erfassungszeit", 64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
    except ValueError as error:
        raise Invalid("Erfassungszeit braucht Datum, Uhrzeit und Zeitzone.") from error
    return value


def checked_report(report):
    bounded_tree(report)
    if type(report) is not dict or set(report) != {"schema", "id", "source", "collectedAt", "devices", "warnings"} or report["schema"] != REPORT:
        raise Invalid("Nicht unterstütztes Inventarformat.")
    text(report["id"], "Berichtskennung")
    timestamp(report["collectedAt"])
    source = report["source"]
    if type(source) is not dict or set(source) != {"id", "label", "kind"} or source["kind"] not in ("synthetic", "windows", "hyperv", "scvmm", "imported"):
        raise Invalid("Inventarquelle fehlt oder ist ungültig.")
    text(source["id"], "Quellkennung")
    text(source["label"], "Quellbezeichnung")
    if type(report["warnings"]) is not list or len(report["warnings"]) > 100:
        raise Invalid("Ungültige Hinweise.")
    for warning in report["warnings"]:
        text(warning, "Hinweis", 1000)
    devices = report["devices"]
    if type(devices) is not list or not 1 <= len(devices) <= 100:
        raise Invalid("Ein Bericht braucht 1 bis 100 Geräte.")
    ids = set()
    for device in devices:
        if type(device) is not dict or set(device) != {"id", "name", "kind", "collectedAt", "memoryMiB", "adapters"}:
            raise Invalid("Ungültiges Gerät.")
        text(device["id"], "Gerätekennung")
        if device["id"] in ids:
            raise Invalid("Doppelte Gerätekennung im Bericht; keine stille Zusammenführung.")
        ids.add(device["id"])
        text(device["name"], "Gerätename")
        text(device["kind"], "Gerätetyp")
        if device['collectedAt'] is not None:
            timestamp(device['collectedAt'])
        memory = device["memoryMiB"]
        if memory is not None and (type(memory) is not int or not 0 <= memory <= 16 * 1024 * 1024):
            raise Invalid("Arbeitsspeicher muss eine begrenzte MiB-Zahl oder unbekannt sein.")
        if type(device["adapters"]) is not list or len(device["adapters"]) > 16:
            raise Invalid("Ungültige Adapterliste.")
        adapter_ids = set()
        for adapter in device["adapters"]:
            if type(adapter) is not dict or set(adapter) != {"id", "name", "status", "addresses", "network", "evidence"}:
                raise Invalid("Ungültiger Adapter; null ist kein Adapter.")
            for key in ("id", "name", "status", "evidence"):
                text(adapter[key], "Adapter " + key, 500 if key == "evidence" else 160)
            if adapter["id"] in adapter_ids:
                raise Invalid("Doppelte Adapterkennung.")
            adapter_ids.add(adapter["id"])
            if type(adapter["addresses"]) is not list or len(adapter["addresses"]) > 32:
                raise Invalid("Ungültige Adressliste.")
            for address in adapter["addresses"]:
                try:
                    ipaddress.ip_interface(text(address, "IP-Adresse", 80))
                except ValueError as error:
                    raise Invalid("Ungültige IP-Adresse mit Präfix.") from error
            network = adapter["network"]
            if network is not None:
                if type(network) is not dict or set(network) != {"kind", "id", "label"} or network["kind"] not in ("hyperv-switch", "scvmm-vmnetwork", "reported-segment"):
                    raise Invalid("Netzobjekt braucht eine typisierte Identität.")
                text(network["id"], "Netzobjektkennung")
                text(network["label"], "Netzobjektbezeichnung")
    return deepcopy(report)


def from_native(report):
    """Accept data from the documented legacy format; do not reuse its collector/UI."""
    bounded_tree(report)
    allowed = {"schema", "generatedAt", "collector", "mode", "devices", "warnings", "activeProbes", "note"}
    if type(report) is not dict or set(report) - allowed or report.get("schema") != "mb-fisi-native-lab/v1":
        raise Invalid("Ungültiger Native-Bericht.")
    timestamp(report.get("generatedAt"))
    devices = report.get("devices")
    if type(devices) is not list or not 1 <= len(devices) <= 100:
        raise Invalid("Ungültige Native-Geräteliste.")
    # A legacy hostname is not a proven cross-report identity. Keep each full report separate.
    digest = hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()[:24]
    warnings = report.get('warnings', [])
    if type(warnings) is not list or len(warnings) > 98:
        raise Invalid("Ungültige Native-Hinweise.")
    for warning in warnings:
        text(warning, 'Native-Hinweis', 1000)
    collector = text(report.get('collector', 'Collector unbekannt'), 'Collector', 100)
    output = {"schema": REPORT, "id": "native-" + digest, "source": {"id": "native-" + digest, "label": "Native: " + collector, "kind": "imported"}, "collectedAt": report["generatedAt"], "devices": [], "warnings": warnings + ["Native-Identitäten gelten nur in diesem Bericht. Gleichnamige Geräte werden nicht automatisch zusammengeführt.", "MemoryAssigned/SCVMM-Einheiten sind in Altberichten nicht belegt; Speicher bleibt unbekannt."]}
    for device in devices:
        if type(device) is not dict or type(device.get("adapters")) is not list:
            raise Invalid("Ungültiges Native-Gerät.")
        adapters = []
        for index, adapter in enumerate(device["adapters"]):
            if type(adapter) is not dict:
                raise Invalid("Ungültiger Native-Adapter; null wird abgelehnt.")
            addresses = adapter.get("ipAddresses", [])
            if type(addresses) is not list:
                raise Invalid("Ungültige Native-IP-Liste.")
            normalized = []
            for address in addresses:
                if type(address) is not dict or type(address.get("address")) is not str or type(address.get("prefix")) is not int:
                    raise Invalid("Native-Adresse braucht einen belegten Präfix.")
                normalized.append(address["address"] + "/" + str(address["prefix"]))
            network = None
            if adapter.get("switch"):
                provider = str(device.get("provider", "")).lower()
                kind = "scvmm-vmnetwork" if "vmm" in provider else "hyperv-switch" if "hyper" in provider else "reported-segment"
                network = {"kind": kind, "id": str(device.get("id", "")) + ":" + str(index), "label": text(adapter["switch"], "gemeldetes Netz")}
            adapters.append({"id": str(index), "name": adapter.get("name"), "status": adapter.get("status") or "unbekannt", "addresses": normalized, "network": network, "evidence": "Importierte Konfigurationsangabe; keine bestätigte Erreichbarkeit"})
        output["devices"].append({"id": device.get("id"), "name": device.get("name"), "kind": device.get("kind") or "unbekannt", "collectedAt": device.get('collectedAt'), "memoryMiB": None, "adapters": adapters})
    return checked_report(output)


def checked_collection(value):
    bounded_tree(value)
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) > MAX_BYTES:
        raise Invalid("Inventar maximal 2 MiB.")
    if type(value) is not dict:
        raise Invalid("Ein Inventarobjekt erwartet.")
    schema = value.get("schema")
    if schema in (REPORT, "mb-fisi-native-lab/v1"):
        reports = [value]
    elif schema in (COLLECTION, "mb-fisi-native-lab-collection/v1") and set(value) == {"schema", "reports"}:
        reports = value["reports"]
    else:
        raise Invalid("Unbekanntes Einzelbericht- oder Sammlungsformat.")
    if type(reports) is not list or len(reports) > 20:
        raise Invalid("Maximal 20 Inventarberichte.")
    result = []
    identities = set()
    for report in reports:
        row = from_native(report) if type(report) is dict and report.get("schema") == "mb-fisi-native-lab/v1" else checked_report(report)
        identity = (row["source"]["id"], row["id"])
        if identity in identities:
            raise Invalid("Doppelter Bericht in einer Sammlung.")
        identities.add(identity)
        result.append(row)
    if sum(len(row["devices"]) for row in result) > 500:
        raise Invalid("Maximal 500 Geräte pro Workspace.")
    return {"schema": COLLECTION, "reports": result}


def merge_reports(existing, incoming):
    before = checked_collection(existing)
    added = checked_collection(incoming)
    rows = {(row["source"]["id"], row["id"]): row for row in before["reports"]}
    for row in added["reports"]:
        key = (row["source"]["id"], row["id"])
        if key in rows and rows[key] != row:
            raise Invalid("Berichtskonflikt: dieselbe Quell-/Berichtskennung hat andere Daten. Bestehende Daten wurden nicht überschrieben.")
        rows[key] = row
    return checked_collection({"schema": COLLECTION, "reports": list(rows.values())})


def synthetic_inventory():
    report = {"schema": REPORT, "id": "fisi-demo-01", "source": {"id": "fisi-synthetic", "label": "Fisi · synthetisches Beispiel", "kind": "synthetic"}, "collectedAt": "2026-01-01T00:00:00Z", "warnings": ["Synthetische Beispieldaten, keine reale Erfassung oder Netzprobe."], "devices": []}
    for ident, name, address in (("client", "Arbeitsplatz Support", "192.0.2.10/24"), ("files", "Dateidienst", "192.0.2.20/24")):
        report["devices"].append({"id": ident, "name": name, "kind": "Synthetisches Gerät", "collectedAt": report['collectedAt'], "memoryMiB": None, "adapters": [{"id": "lan", "name": "Ethernet", "status": "Up (synthetisch)", "addresses": [address], "network": {"kind": "reported-segment", "id": "office", "label": "Büronetz · Beispiel"}, "evidence": "Synthetische Anschlusszuordnung; kein Nachweis eines Paketwegs"}]})
    return checked_collection(report)
