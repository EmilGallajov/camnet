"""Lightweight built-in inventory (NetBox-style) with JSON persistence.

Stores discovered/ingested devices: hostname, role, interfaces+IPs, the config
source (local / upload / ssh), and a path to the saved config. The left sidebar
reads this; chat actions and the engine populate it.
"""
import json
import os
import threading
from datetime import datetime, timezone

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
_PATH = os.path.join(DATA_DIR, "inventory.json")
_lock = threading.Lock()

_DB = {"devices": {}, "events": []}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load():
    global _DB
    try:
        with open(_PATH) as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("devices", {})
    data.setdefault("events", [])
    _DB = data


def _save():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_DB, f, indent=2)
    os.replace(tmp, _PATH)


_load()


def upsert_device(hostname, role=None, interfaces=None, source=None,
                  config_path=None, primary_ip=None):
    with _lock:
        dev = _DB["devices"].get(hostname, {"hostname": hostname,
                                            "added_at": _now()})
        if role:
            dev["role"] = role
        if interfaces is not None:
            dev["interfaces"] = interfaces
        if source:
            dev["source"] = source
        if config_path:
            dev["config_path"] = config_path
        if primary_ip:
            dev["primary_ip"] = primary_ip
        if not dev.get("primary_ip") and interfaces:
            dev["primary_ip"] = interfaces[0].get("address", "").split("/")[0]
        dev["updated_at"] = _now()
        _DB["devices"][hostname] = dev
        _save()
        return dev


def update_device(hostname, fields):
    with _lock:
        dev = _DB["devices"].get(hostname)
        if not dev:
            return None
        dev.update({k: v for k, v in fields.items() if v is not None})
        dev["updated_at"] = _now()
        _save()
        return dev


def delete_device(hostname):
    with _lock:
        existed = _DB["devices"].pop(hostname, None) is not None
        _save()
        return existed


def add_event(kind, text):
    with _lock:
        _DB["events"].insert(0, {"at": _now(), "kind": kind, "text": text})
        _DB["events"] = _DB["events"][:100]
        _save()


def list_devices():
    return sorted(_DB["devices"].values(), key=lambda d: d["hostname"])


def get_device(hostname):
    return _DB["devices"].get(hostname)


def events(kind=None, limit=50):
    evs = _DB["events"]
    if kind:
        evs = [e for e in evs if e["kind"] == kind]
    return evs[:limit]


def clear_devices():
    with _lock:
        _DB["devices"] = {}
        _save()


def sync_from_analysis(analysis, iface_map, source):
    """Update inventory from a completed Batfish analysis."""
    roles = analysis.get("device_roles", {})
    for host in analysis.get("devices", []):
        ifaces = iface_map.get(host, [])
        upsert_device(host, role=roles.get(host, "Network"),
                      interfaces=ifaces, source=source)
    add_event("inventory",
              f"Synced {len(analysis.get('devices', []))} device(s) from {source} analysis.")
