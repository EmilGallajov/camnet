"""Persistent chat-history sessions (ChatGPT/Claude-style left rail).

Each session = {id, title, created, updated, messages:[{role,text,at}]}.
Stored as JSON under DATA_DIR so history survives restarts.
"""
import json
import os
import threading
import uuid
from datetime import datetime, timezone

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
_PATH = os.path.join(DATA_DIR, "chats.json")
_lock = threading.Lock()
_DB = {"sessions": {}}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load():
    global _DB
    try:
        with open(_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("sessions"), dict):
            _DB = data
    except Exception:  # noqa: BLE001
        _DB = {"sessions": {}}


def _save():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_DB, f, indent=2)
    os.replace(tmp, _PATH)


_load()


def new_session():
    sid = uuid.uuid4().hex[:12]
    with _lock:
        _DB["sessions"][sid] = {"id": sid, "title": "New chat",
                                "created": _now(), "updated": _now(),
                                "messages": []}
        _save()
    return sid


def append(sid, role, text):
    with _lock:
        s = _DB["sessions"].get(sid)
        if not s:
            s = {"id": sid, "title": "New chat", "created": _now(),
                 "messages": []}
            _DB["sessions"][sid] = s
        s["messages"].append({"role": role, "text": text, "at": _now()})
        if role == "user" and (s["title"] == "New chat" or not s["title"]):
            s["title"] = (text[:42] + "…") if len(text) > 42 else text
        s["updated"] = _now()
        _save()


def list_sessions():
    sessions = sorted(_DB["sessions"].values(),
                      key=lambda s: s.get("updated", ""), reverse=True)
    return [{"id": s["id"], "title": s.get("title", "New chat"),
             "updated": s.get("updated"), "count": len(s.get("messages", []))}
            for s in sessions]


def get_session(sid):
    return _DB["sessions"].get(sid)


def delete_session(sid):
    with _lock:
        existed = _DB["sessions"].pop(sid, None) is not None
        _save()
        return existed
