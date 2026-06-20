"""CamNet backend — chat-driven smart-city network intelligence.

Serves the console UI, drives the Batfish digital twin, keeps a built-in
inventory, ingests configs (ZIP upload / SSH pull), answers chat by parsing
intent into concrete actions, renders interactive topology, and exports a
Jinja2/WeasyPrint PDF. Single worker so in-memory state is shared.
"""
import math
import os
import re
import shutil
import tempfile
import threading
import zipfile
from datetime import datetime, timezone

from flask import (Flask, jsonify, render_template, request, send_file,
                   send_from_directory)

import agent
import chat_agent
import chats
import inventory
import llm
from engine import CamNetEngine, role_for
from report import build_report

LOCAL_CONFIG_DIR = os.environ.get("LOCAL_CONFIG_DIR", "/app/configs")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/app/uploads")
INGEST_CONFIGS = os.path.join(UPLOAD_DIR, "configs")
TOPO_DIR = os.environ.get("TOPO_DIR", "/app/topologies")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(INGEST_CONFIGS, exist_ok=True)

app = Flask(__name__, template_folder="templates")
engine = CamNetEngine()

STATE = {"analysis": None, "threats": None, "active_source": "local"}
CHAT_LOG = []
_lock = threading.Lock()


def _json_safe(obj):
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj


# --------------------------------------------------------------------------
# Global error handling — every failure returns scrubbed JSON, never a stack
# trace or the API key, and never an unhandled 500 HTML page.
# --------------------------------------------------------------------------
@app.errorhandler(Exception)
def _handle_any(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({"ok": False, "error": e.description,
                        "status": e.code}), e.code
    app.logger.exception("unhandled exception")
    return jsonify({"ok": False,
                    "error": llm._scrub(str(e)) or "internal error",
                    "status": 500}), 500


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log_chat(role, text):
    CHAT_LOG.append({"role": role, "text": text, "at": _now()})
    del CHAT_LOG[:-200]


def _config_dir():
    if STATE["active_source"] == "ingested" and _ingest_has_files():
        return UPLOAD_DIR
    return LOCAL_CONFIG_DIR


def _ingest_has_files():
    return os.path.isdir(INGEST_CONFIGS) and any(
        os.path.isfile(os.path.join(INGEST_CONFIGS, f))
        for f in os.listdir(INGEST_CONFIGS))


# --------------------------------------------------------------------------
# Core analysis
# --------------------------------------------------------------------------
def _run_analysis(give_topology=True, ping_flag=False, ip_map=None):
    source = STATE["active_source"]
    analysis = engine.analyze(
        _config_dir(), ip_ping_check_flag=ping_flag,
        ip_map=ip_map or {}, give_topology=give_topology, config_source=source)
    threats = llm.assess_threats(analysis)
    iface = engine.interface_addresses()
    inventory.sync_from_analysis(analysis, iface, source)
    STATE["analysis"], STATE["threats"] = analysis, threats
    return analysis, threats


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/topology/<layer>")
def topology_page(layer):
    if layer not in ("layer3", "ospf", "bgp"):
        return "Unknown layer", 404
    return render_template("topology.html", layer=layer)


# --------------------------------------------------------------------------
# Status / inventory / logs
# --------------------------------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({
        "batfish": engine.ready(),
        "gemini": llm.gemini_enabled(),
        "has_analysis": STATE["analysis"] is not None,
        "active_source": STATE["active_source"],
        "ingested_files": len(os.listdir(INGEST_CONFIGS)) if os.path.isdir(INGEST_CONFIGS) else 0,
        "device_count": len(inventory.list_devices()),
    })


@app.route("/api/inventory")
def get_inventory():
    return jsonify({"devices": inventory.list_devices(),
                    "events": inventory.events(limit=30)})


@app.route("/api/logs")
def get_logs():
    return jsonify({"chat": CHAT_LOG[-100:],
                    "events": inventory.events(limit=50)})


# --------------------------------------------------------------------------
# Analysis endpoint (left-panel button + programmatic)
# --------------------------------------------------------------------------
@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    if body.get("source") in ("local", "ingested"):
        STATE["active_source"] = body["source"]
    try:
        with _lock:
            analysis, threats = _run_analysis(
                give_topology=bool(body.get("give_topology", True)),
                ping_flag=bool(body.get("ip_ping_check_flag", False)),
                ip_map=body.get("ip_map") or {})
        return jsonify(_json_safe({"analysis": analysis, "threats": threats}))
    except Exception as e:  # noqa: BLE001
        app.logger.exception("analyze failed")
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------------------------------
# Ingest: ZIP upload + SSH pull
# --------------------------------------------------------------------------
@app.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400
    saved = 0
    try:
        if f.filename.lower().endswith(".zip"):
            with zipfile.ZipFile(f.stream) as z:
                for member in z.namelist():
                    if member.endswith("/"):
                        continue
                    name = os.path.basename(member)
                    if not name or name.startswith("."):
                        continue
                    with z.open(member) as src, open(
                            os.path.join(INGEST_CONFIGS, name), "wb") as dst:
                        shutil.copyfileobj(src, dst)
                        saved += 1
        else:  # single config file
            name = os.path.basename(f.filename)
            f.save(os.path.join(INGEST_CONFIGS, name))
            saved = 1
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Upload failed: {e}"}), 400

    if saved == 0:
        return jsonify({"error": "No usable files found in upload"}), 400
    STATE["active_source"] = "ingested"
    inventory.add_event("upload", f"Uploaded {saved} config file(s) via {f.filename}.")
    return jsonify({"saved": saved, "active_source": "ingested"})


@app.route("/api/ssh-pull", methods=["POST"])
def ssh_pull():
    body = request.get_json(silent=True) or {}
    host = (body.get("host") or "").strip()
    if not host:
        return jsonify({"error": "host is required"}), 400
    try:
        from ssh_pull import pull_config
        res = pull_config(
            host=host, username=body.get("username", ""),
            password=body.get("password", ""), dest_dir=INGEST_CONFIGS,
            device_type=body.get("device_type", "cisco_ios"),
            port=body.get("port", 22), secret=body.get("secret"))
        STATE["active_source"] = "ingested"
        inventory.upsert_device(res["hostname"], role=role_for(res["hostname"]),
                                source="ssh", config_path=res["path"],
                                primary_ip=host)
        inventory.add_event("ssh", f"Pulled config from {host} → {res['hostname']}.")
        return jsonify(res)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"SSH pull failed: {e}"}), 502


@app.route("/api/reset-source", methods=["POST"])
def reset_source():
    STATE["active_source"] = "local"
    return jsonify({"active_source": "local"})


# --------------------------------------------------------------------------
# Topology (interactive data + static PNG)
# --------------------------------------------------------------------------
@app.route("/api/topology-data/<layer>")
def topology_data(layer):
    a = STATE["analysis"] or {}
    topo = (a.get("topologies") or {}).get(layer, {})
    roles = a.get("device_roles", {})
    nodes = [{"id": d, "label": d, "group": roles.get(d, "Network")}
             for d in a.get("devices", [])]
    edges = [{"from": e["a"], "to": e["b"], "up": e.get("up", True),
              "status": e.get("status", "UP"), "title": e.get("title", ""),
              "detail": e.get("detail", {})}
             for e in topo.get("edges", [])]
    return jsonify({"layer": layer, "nodes": nodes, "edges": edges})


@app.route("/api/topology/<name>")
def topology_png(name):
    fn = f"{name}.png"
    if not os.path.exists(os.path.join(TOPO_DIR, fn)):
        return jsonify({"error": "not found"}), 404
    return send_from_directory(TOPO_DIR, fn, mimetype="image/png")


@app.route("/uploads/<path:fname>")
def serve_upload(fname):
    return send_from_directory(UPLOAD_DIR, fname)


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------
def _make_pdf():
    if not STATE["analysis"]:
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.join(UPLOAD_DIR, f"camnet_report_{ts}.pdf")
    build_report(STATE["analysis"], STATE["threats"], out,
                 devices=inventory.list_devices())
    inventory.add_event("report", f"Generated PDF report camnet_report_{ts}.pdf")
    return out


@app.route("/api/report")
def report():
    out = _make_pdf()
    if not out:
        return jsonify({"error": "Run an analysis first."}), 400
    return send_file(out, mimetype="application/pdf", as_attachment=True,
                     download_name=os.path.basename(out))


# --------------------------------------------------------------------------
# Device details + inventory CRUD
# --------------------------------------------------------------------------
@app.route("/api/device/<host>/details")
def device_details(host):
    try:
        if not STATE["analysis"]:
            inv = inventory.get_device(host)
            if inv:
                return jsonify({"hostname": host, "role": inv.get("role"),
                                "interfaces": inv.get("interfaces", []),
                                "routes": [], "bgp_peers": [], "ospf": [],
                                "acls": [], "protocols": [],
                                "note": "Run analysis for full details."})
        return jsonify(_json_safe(engine.device_details(host)))
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500


def _find_config(host):
    """Locate a device's config file, preferring the editable ingest copy."""
    cand = os.path.join(INGEST_CONFIGS, f"{host}.cfg")
    if os.path.exists(cand):
        return cand, True
    for base in (INGEST_CONFIGS, os.path.join(LOCAL_CONFIG_DIR, "configs")):
        if not os.path.isdir(base):
            continue
        for fn in os.listdir(base):
            fp = os.path.join(base, fn)
            if not os.path.isfile(fp):
                continue
            if os.path.splitext(fn)[0] == host:
                return fp, base == INGEST_CONFIGS
            try:
                with open(fp, errors="ignore") as f:
                    if re.search(rf"^hostname\s+{re.escape(host)}\b", f.read(),
                                 re.MULTILINE):
                        return fp, base == INGEST_CONFIGS
            except Exception:  # noqa: BLE001
                pass
    return None, False


@app.route("/api/device/<host>/config", methods=["GET"])
def get_device_config(host):
    path, editable = _find_config(host)
    if not path:
        return jsonify({"error": "config not found"}), 404
    with open(path, errors="ignore") as f:
        return jsonify({"hostname": host, "config": f.read(),
                        "editable": editable, "path": os.path.basename(path)})


@app.route("/api/device/<host>/config", methods=["PUT"])
def put_device_config(host):
    body = request.get_json(silent=True) or {}
    text = body.get("config", "")
    os.makedirs(INGEST_CONFIGS, exist_ok=True)
    out = os.path.join(INGEST_CONFIGS, f"{host}.cfg")
    with open(out, "w") as f:
        f.write(text)
    STATE["active_source"] = "ingested"
    inventory.upsert_device(host, config_path=out, source="ingested")
    inventory.add_event("config", f"Updated config for {host}. Re-run analysis.")
    return jsonify({"saved": True, "path": os.path.basename(out),
                    "active_source": "ingested"})


@app.route("/api/inventory/<host>", methods=["DELETE"])
def delete_device(host):
    inventory.delete_device(host)
    # also drop an ingested config copy if present
    cand = os.path.join(INGEST_CONFIGS, f"{host}.cfg")
    if os.path.exists(cand):
        os.remove(cand)
    inventory.add_event("inventory", f"Removed device {host}.")
    return jsonify({"deleted": host})


@app.route("/api/inventory/<host>", methods=["PUT"])
def update_device(host):
    body = request.get_json(silent=True) or {}
    fields = {k: v for k, v in body.items()
              if k in ("role", "primary_ip", "notes")}
    dev = inventory.update_device(host, fields)
    if not dev:
        return jsonify({"error": "device not found"}), 404
    inventory.add_event("inventory", f"Updated device {host}.")
    return jsonify(dev)


# --------------------------------------------------------------------------
# Jinja2 PDF template editor
# --------------------------------------------------------------------------
@app.route("/api/report-template", methods=["GET"])
def get_template():
    import report as rep
    return jsonify({"template": rep.get_template_text(),
                    "is_custom": rep.has_custom_template()})


@app.route("/api/report-template", methods=["PUT"])
def put_template():
    import report as rep
    body = request.get_json(silent=True) or {}
    text = body.get("template", "")
    if not text.strip():
        return jsonify({"error": "empty template"}), 400
    try:
        rep.validate_template(text)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Template error: {e}"}), 400
    rep.save_template_text(text)
    inventory.add_event("template", "Saved custom PDF report template.")
    return jsonify({"saved": True})


@app.route("/api/report-template/reset", methods=["POST"])
def reset_template():
    import report as rep
    rep.reset_template()
    inventory.add_event("template", "Reset PDF report template to default.")
    return jsonify({"reset": True})


# --------------------------------------------------------------------------
# AI agent system prompt (UI-editable)
# --------------------------------------------------------------------------
@app.route("/api/agent-prompt", methods=["GET"])
def get_agent_prompt():
    return jsonify({"prompt": agent.get_prompt(),
                    "is_custom": agent.has_custom_prompt(),
                    "default": agent.DEFAULT_SYSTEM})


@app.route("/api/agent-prompt", methods=["PUT"])
def put_agent_prompt():
    body = request.get_json(silent=True) or {}
    text = body.get("prompt", "")
    if not text.strip():
        return jsonify({"error": "empty prompt"}), 400
    agent.set_prompt(text)
    inventory.add_event("agent", "Updated AI agent system prompt.")
    return jsonify({"saved": True})


@app.route("/api/agent-prompt/reset", methods=["POST"])
def reset_agent_prompt():
    agent.reset_prompt()
    return jsonify({"reset": True})


# --------------------------------------------------------------------------
# Chat — intent dispatch
# --------------------------------------------------------------------------
@app.route("/api/chats", methods=["GET"])
def list_chats():
    return jsonify({"sessions": chats.list_sessions()})


@app.route("/api/chats", methods=["POST"])
def create_chat():
    return jsonify({"id": chats.new_session()})


@app.route("/api/chats/<sid>", methods=["GET"])
def get_chat(sid):
    s = chats.get_session(sid)
    if not s:
        return jsonify({"error": "not found"}), 404
    return jsonify(s)


@app.route("/api/chats/<sid>", methods=["DELETE"])
def del_chat(sid):
    chats.delete_session(sid)
    return jsonify({"deleted": sid})


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    sid = body.get("session_id")
    if not message:
        return jsonify({"reply": "Please type a question.", "attachments": []})
    if not sid or not chats.get_session(sid):
        sid = chats.new_session()
    chats.append(sid, "user", message)
    try:
        result = _dispatch(message, sid)
    except Exception as e:  # noqa: BLE001
        app.logger.exception("chat failed")
        result = {"reply": f"Something went wrong: {llm._scrub(str(e))}",
                  "attachments": []}
    chats.append(sid, "bot", result.get("reply", ""))
    result["session_id"] = sid
    return jsonify(_json_safe(result))


def _known_devices():
    a = STATE["analysis"]
    return (a.get("devices", []) if a
            else [d["hostname"] for d in inventory.list_devices()])


def _agent_context(message):
    a = STATE["analysis"]
    t = STATE["threats"] or {}
    devices = _known_devices()
    failed, findings = [], []
    if a:
        failed = [chat_agent.ASSERT_META.get(k, {}).get("name", k)
                  for k in _failed_set(a.get("default_asserts", {}))]
    for f in t.get("findings", []):
        findings.append(f"[{f.get('severity')}] {f.get('title')} — "
                        f"{f.get('detail', '')[:180]}")
    cfgs = {}
    low = message.lower()
    for h in devices:
        if h.lower() in low:
            path, _e = _find_config(h)
            if path:
                with open(path, errors="ignore") as f:
                    cfgs[h] = f.read()
    return {"devices": devices, "has_analysis": a is not None,
            "failed": failed, "configs": cfgs,
            "overall": t.get("overall"), "findings": findings}


def _history_text(sid, limit=6):
    s = chats.get_session(sid) if sid else None
    if not s:
        return ""
    msgs = s.get("messages", [])[-limit:]
    return "\n".join(f"{m['role']}: {m['text'][:200]}" for m in msgs)


def _dispatch(message, sid=None):
    """Primary brain: a single-call LLM planner+executor when Gemini is
    available, with the deterministic keyword dispatcher as fallback."""
    if llm.gemini_enabled():
        try:
            ctx = _agent_context(message)
            ctx["history"] = _history_text(sid)
            return agent.run(message, _agent_tools(), ctx)
        except Exception as e:  # noqa: BLE001
            app.logger.exception("agent failed, falling back to keyword dispatch")
            res = _keyword_dispatch(message)
            res["reply"] = (res.get("reply", "")
                            + f"\n\n_(AI agent busy: {llm._friendly_error(e)})_")
            return res
    return _keyword_dispatch(message)


# ---- tools exposed to the ReAct agent -----------------------------------
def _failed_set(asserts):
    out = {}
    for k, v in (asserts or {}).items():
        if k == "_summary" or not isinstance(v, dict):
            continue
        passed, bad = chat_agent._state(k, v)
        if passed is False:
            out[k] = len(bad)
    return out


def _agent_tools():
    def run_analysis():
        with _lock:
            a, t = _run_analysis()
        return {"observation": f"Analysis complete on {len(a['devices'])} devices "
                f"({a['config_source']}). Overall {t['overall']}; counts "
                f"{t['counts']}. Devices: {', '.join(a['devices'])}.",
                "attachments": [
                    {"type": "link", "label": "Download PDF report", "href": "/api/report"},
                    {"type": "link", "label": "Open OSPF topology", "href": "/topology/ospf"}]}

    def list_devices():
        devs = inventory.list_devices()
        lines = [f"{d['hostname']} ({d.get('role','Network')}, IP "
                 f"{d.get('primary_ip','—')}, src {d.get('source','local')})"
                 for d in devs]
        return {"observation": f"{len(devs)} devices: " + "; ".join(lines)}

    def get_device(host=None, **_):
        if not host:
            return {"observation": "missing 'host'"}
        try:
            d = engine.device_details(host)
        except Exception as e:  # noqa: BLE001
            return {"observation": f"error: {e}"}
        return {"observation": json.dumps(_json_safe({
            "hostname": d["hostname"], "role": d["role"],
            "protocols": d.get("protocols"),
            "interfaces": d.get("interfaces", [])[:12],
            "routes": d.get("routes", [])[:20],
            "bgp_peers": d.get("bgp_peers", []),
            "ospf": d.get("ospf", []),
            "acls": [a["name"] for a in d.get("acls", [])],
        }))[:1700]}

    def get_config(host=None, **_):
        if not host:
            return {"observation": "missing 'host'"}
        path, _ed = _find_config(host)
        if not path:
            return {"observation": f"no config found for {host}"}
        with open(path, errors="ignore") as f:
            return {"observation": f.read()[:3500]}

    def get_assertions(devices=None, **_):
        a = STATE["analysis"]
        if not a:
            return {"observation": "No analysis yet — call run_analysis first."}
        if isinstance(devices, str):
            devices = [devices]
        blocks = chat_agent.assertion_blocks(a, devices=devices or None)
        if not blocks:
            return {"observation": "No failing assertions"
                    + (f" for {devices}" if devices else "") + "."}
        summary = "; ".join(f"{b['assert_name']} ({len(b['records'])} record(s))"
                            for b in blocks)
        return {"observation": f"{len(blocks)} failing assertion(s): {summary}. "
                "Detailed tables shown to the user.", "attachments": blocks}

    def simulate_config_change(host=None, old_text=None, new_text=None, **_):
        a = STATE["analysis"]
        if not a:
            return {"observation": "Run an analysis first to have a baseline."}
        if not host or new_text is None:
            return {"observation": "need host and new_text (and old_text to replace)"}
        with _lock:
            res = engine.simulate_change(_config_dir(), host, old_text or "", new_text)
        if res.get("error"):
            return {"observation": res["error"]}
        base_fail = _failed_set(a.get("default_asserts", {}))
        cand_fail = _failed_set(res.get("candidate_asserts", {}))
        new_issues = {k: cand_fail[k] for k in cand_fail
                      if k not in base_fail or cand_fail[k] > base_fail.get(k, 0)}
        resolved = [k for k in base_fail if k not in cand_fail]
        meta = chat_agent.ASSERT_META
        def nm(k):
            return meta.get(k, {}).get("name", k)
        if new_issues:
            desc = "; ".join(f"{nm(k)} (+{cand_fail[k] - base_fail.get(k,0)} now {cand_fail[k]})"
                             for k in new_issues)
            obs = (f"Simulated change in {res['file']} ({host}): "
                   f"INTRODUCES new issues -> {desc}.")
        else:
            obs = (f"Simulated change in {res['file']} ({host}): no NEW assertion "
                   "failures introduced.")
        if resolved:
            obs += " Resolves: " + ", ".join(nm(k) for k in resolved) + "."
        obs += " (Simulation only — nothing was persisted.)"
        return {"observation": obs}

    def generate_pdf(**_):
        out = _make_pdf()
        if not out:
            return {"observation": "Run an analysis first."}
        return {"observation": "PDF generated.",
                "attachments": [{"type": "link", "label": os.path.basename(out),
                                 "href": "/uploads/" + os.path.basename(out)}]}

    def show_topology(layer="layer3", **_):
        if layer not in ("layer3", "ospf", "bgp"):
            layer = "layer3"
        return {"observation": f"Provided link to interactive {layer} topology.",
                "attachments": [{"type": "link",
                                 "label": f"Open {layer} topology",
                                 "href": f"/topology/{layer}"}]}

    return {
        "run_analysis": run_analysis, "list_devices": list_devices,
        "get_device": get_device, "get_config": get_config,
        "get_assertions": get_assertions,
        "simulate_config_change": simulate_config_change,
        "generate_pdf": generate_pdf, "show_topology": show_topology,
    }


def _keyword_dispatch(message):
    analysis = STATE["analysis"]
    known = (analysis.get("devices", []) if analysis
             else [d["hostname"] for d in inventory.list_devices()])
    intent = chat_agent.parse_intent(message, known)
    act = intent["action"]

    if act == "help":
        return {"reply": _HELP, "attachments": []}

    if act == "howto_upload":
        return {"reply": "Use **➕ Add configs → Upload .zip** in the left panel "
                "(a zip of Cisco/Batfish configs). I'll ingest them, then say "
                "*run analysis*.", "attachments": []}

    if act == "howto_ssh":
        return {"reply": "Use **➕ Add configs → Pull via SSH** in the left panel: "
                "enter host, username, password (and enable secret if needed). "
                "I'll SSH in, grab `show running-config`, save it, and add the "
                "device to inventory. Then say *run analysis*.", "attachments": []}

    if act == "analyze":
        with _lock:
            a, t = _run_analysis()
        links = [{"type": "link", "label": "Download PDF report",
                  "href": "/api/report"}]
        for layer in ("layer3", "ospf", "bgp"):
            links.append({"type": "link", "label": f"Open {layer} topology",
                          "href": f"/topology/{layer}"})
        reply = (f"✅ Analysis complete on **{len(a['devices'])} device(s)** "
                 f"(source: {a['config_source']}). Overall risk: "
                 f"**{t['overall']}** — High {t['counts']['High']}, "
                 f"Medium {t['counts']['Medium']}, Low {t['counts']['Low']}. "
                 "Ask me to *check misconfigurations*, *show ospf topology*, or "
                 "*generate a PDF*.")
        return {"reply": reply, "attachments": links}

    if not analysis and act in ("check", "pdf", "topology", "device_detail"):
        return {"reply": "I need to build the digital twin first. Say "
                "**run analysis** (or add configs in the left panel).",
                "attachments": []}

    if act == "list_devices":
        devs = inventory.list_devices()
        lines = [f"- `{d['hostname']}` — {d.get('role','Network')} "
                 f"(IP {d.get('primary_ip','—')}, src {d.get('source','local')})"
                 for d in devs]
        return {"reply": f"**{len(devs)} device(s)** in inventory:\n" +
                "\n".join(lines), "attachments": []}

    if act == "device_detail":
        return _device_detail(intent.get("devices", []))

    if act == "check":
        return _check(intent.get("devices", []))

    if act == "pdf":
        out = _make_pdf()
        if not out:
            return {"reply": "Run an analysis first.", "attachments": []}
        return {"reply": "📄 Your PDF report is ready.",
                "attachments": [{"type": "link", "label": os.path.basename(out),
                                 "href": "/uploads/" + os.path.basename(out)}]}

    if act == "topology":
        layer = intent.get("layer", "layer3")
        return {"reply": f"🌐 Here's the interactive **{layer}** topology "
                "(opens in a new tab):",
                "attachments": [{"type": "link",
                                 "label": f"Open {layer} topology view",
                                 "href": f"/topology/{layer}"}]}

    # freeform → LLM (or mock)
    reply = llm.chat(message, {"analysis": analysis, "threats": STATE["threats"]})
    return {"reply": reply, "attachments": []}


def _device_detail(devices):
    if not devices:
        return {"reply": "Which device? Try e.g. *show payment-edge-r3*.",
                "attachments": []}
    parts = []
    for name in devices:
        d = inventory.get_device(name)
        if not d:
            parts.append(f"**{name}** — not in inventory.")
            continue
        ifs = d.get("interfaces", [])
        iflines = "\n".join(f"  - `{i['interface']}` → {i['address']}" for i in ifs) or "  (no addresses)"
        parts.append(f"**{d['hostname']}** — {d.get('role','Network')} "
                     f"· source {d.get('source','local')}\nInterfaces:\n{iflines}")
    return {"reply": "\n\n".join(parts), "attachments": []}


def _check(devices):
    analysis = STATE["analysis"]
    threats = STATE["threats"] or {}
    blocks = chat_agent.assertion_blocks(analysis, devices=devices or None)
    scope = f" for {', '.join(devices)}" if devices else ""
    if not blocks:
        return {"reply": f"✅ No failing Batfish assertions{scope}. The network "
                "model looks clean.", "attachments": []}
    # also surface matching threat findings text
    fl = []
    for f in threats.get("findings", []):
        if not devices or any(d.lower() in (f.get("detail", "") + f.get("title", "")).lower() for d in devices):
            fl.append(f"- **[{f['severity']}] {f['title']}** — {f['recommendation']}")
    reply = (f"🔎 Found **{len(blocks)} failing assertion(s)**{scope}. Details below.")
    if fl:
        reply += "\n\nRelated recommendations:\n" + "\n".join(fl)
    return {"reply": reply, "attachments": blocks}


_HELP = (
    "I'm CamNet. I turn plain requests into network actions. Try:\n"
    "- **run analysis** — build the digital twin & score risk\n"
    "- **list devices** / **show payment-edge-r3** — inventory & IPs\n"
    "- **check misconfigurations** (optionally *... on payment-edge-r3*)\n"
    "- **show ospf topology** / **bgp topology** / **layer3 topology**\n"
    "- **generate a PDF report**\n"
    "- **how do I upload / SSH** — ingest configs"
)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
