"""Fast unit tests for CamNet logic — no Batfish/Gemini required.

External dependencies (Batfish engine, Gemini API) are monkeypatched so these
run anywhere the Python deps are installed. Run: python -m pytest tests/test_unit.py
"""
import io
import json
import os
import sys
import zipfile

import pytest

_HERE = os.path.dirname(__file__)
for _cand in (os.path.join(_HERE, "..", "src", "app"), "/app", _HERE):
    if os.path.exists(os.path.join(_cand, "app.py")):
        sys.path.insert(0, _cand)
        break

import agent          # noqa: E402
import app as appmod  # noqa: E402
import chat_agent     # noqa: E402
import chats          # noqa: E402
import inventory      # noqa: E402
import llm            # noqa: E402
import report         # noqa: E402


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
FAKE_ANALYSIS = {
    "config_source": "local",
    "devices": ["traffic-core-r1", "payment-edge-r3"],
    "device_roles": {"traffic-core-r1": "Traffic control",
                     "payment-edge-r3": "Digital payments"},
    "default_asserts": {
        "undefinedReferences": {"count": 1, "passed": False,
                                "records": [{"Node": "payment-edge-r3",
                                             "Ref_Name": "MISSING-ACL"}]},
        "unusedStructures": {"count": 0, "passed": True, "records": []},
        "_summary": {"passed": False, "failed_checks": ["undefinedReferences"]},
    },
    "topologies": {
        "ospf": {"edges": [{"a": "traffic-core-r1", "b": "payment-edge-r3",
                            "up": False, "status": "AREA_MISMATCH",
                            "title": "OSPF", "detail": {"Status": "AREA_MISMATCH"}}]},
    },
    "ping_check": {"source": "1.1.1.1", "destination": "2.2.2.2", "pingable": True},
}
FAKE_THREATS = {"source": "mock", "overall": "High",
                "counts": {"High": 1, "Medium": 0, "Low": 0},
                "findings": [{"title": "Undefined ACL", "severity": "High",
                              "category": "Misconfig", "detail": "on payment-edge-r3",
                              "recommendation": "define it"}]}


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    """Point persistence at a temp dir so tests never touch real data."""
    monkeypatch.setattr(inventory, "_PATH", str(tmp_path / "inv.json"))
    monkeypatch.setattr(inventory, "_DB", {"devices": {}, "events": []})
    monkeypatch.setattr(chats, "_PATH", str(tmp_path / "chats.json"))
    monkeypatch.setattr(chats, "_DB", {"sessions": {}})
    monkeypatch.setattr(report, "USER_TPL", str(tmp_path / "tpl.j2"))
    monkeypatch.setattr(agent, "PROMPT_PATH", str(tmp_path / "prompt.txt"))
    ingest = tmp_path / "ingest"
    ingest.mkdir()
    monkeypatch.setattr(appmod, "INGEST_CONFIGS", str(ingest))
    appmod.STATE["analysis"] = None
    appmod.STATE["threats"] = None
    appmod.STATE["active_source"] = "local"


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


# --------------------------------------------------------------------------
# llm helpers
# --------------------------------------------------------------------------
def test_scrub_hides_key(monkeypatch):
    monkeypatch.setattr(llm, "GEMINI_API_KEY", "AIzaSECRET123")
    out = llm._scrub("error key=AIzaSECRET123 in url?key=AIzaSECRET123")
    assert "AIzaSECRET123" not in out
    assert "***" in out


def test_friendly_error_classifies():
    assert "429" in llm._friendly_error("429 Too Many Requests")
    assert "403" in llm._friendly_error("403 forbidden PERMISSION_DENIED")


def test_extract_json_variants():
    assert llm._extract_json('{"a":1}') == {"a": 1}
    assert llm._extract_json('```json\n{"a":2}\n```') == {"a": 2}
    assert llm._extract_json("noise {\"a\":3} tail")["a"] == 3
    assert llm._extract_json("not json at all") is None


def test_mock_threat_scoring_flags_undefined_ref():
    res = llm._mock_findings(FAKE_ANALYSIS)
    assert res["source"] == "mock"
    titles = " ".join(f["title"] for f in res["findings"]).lower()
    assert "undefined" in titles
    assert res["counts"]["Medium"] >= 1


# --------------------------------------------------------------------------
# chat_agent — intent parsing & assertion detail
# --------------------------------------------------------------------------
@pytest.mark.parametrize("msg,expected", [
    ("run analysis", "analyze"),
    ("list devices", "list_devices"),
    ("show ospf topology", "topology"),
    ("generate a pdf report", "pdf"),
    ("check misconfigurations", "check"),
    ("check misconfigurations but don't give me a pdf", "check"),
    ("just give assertion results, no pdf please", "check"),
])
def test_parse_intent(msg, expected):
    intent = chat_agent.parse_intent(msg, ["payment-edge-r3"])
    assert intent["action"] == expected


def test_parse_intent_topology_layer():
    assert chat_agent.parse_intent("show ospf topology", [])["layer"] == "ospf"
    assert chat_agent.parse_intent("open bgp graph", [])["layer"] == "bgp"


def test_assertion_blocks_failing_and_clean():
    blocks = chat_agent.assertion_blocks(FAKE_ANALYSIS)
    names = [b["assert_name"] for b in blocks]
    assert "assert_no_undefined_references" in names
    clean = {"default_asserts": {"undefinedReferences":
             {"count": 0, "passed": True, "records": []}}}
    assert chat_agent.assertion_blocks(clean) == []


def test_assertion_blocks_device_filter():
    blocks = chat_agent.assertion_blocks(FAKE_ANALYSIS, devices=["nonexistent-device"])
    assert blocks == []  # planted issue is on payment-edge-r3, not this device


# --------------------------------------------------------------------------
# inventory CRUD
# --------------------------------------------------------------------------
def test_inventory_crud():
    inventory.upsert_device("r1", role="Core",
                            interfaces=[{"interface": "Gi0/0", "address": "10.0.0.1/32"}],
                            source="local")
    d = inventory.get_device("r1")
    assert d["role"] == "Core" and d["primary_ip"] == "10.0.0.1"
    inventory.update_device("r1", {"role": "Edge"})
    assert inventory.get_device("r1")["role"] == "Edge"
    assert inventory.delete_device("r1") is True
    assert inventory.get_device("r1") is None


# --------------------------------------------------------------------------
# chats persistence
# --------------------------------------------------------------------------
def test_chats_session_lifecycle():
    sid = chats.new_session()
    chats.append(sid, "user", "hello there friend")
    chats.append(sid, "bot", "hi!")
    s = chats.get_session(sid)
    assert len(s["messages"]) == 2
    assert s["title"].startswith("hello")           # auto-title from 1st user msg
    assert any(x["id"] == sid for x in chats.list_sessions())
    assert chats.delete_session(sid) is True
    assert chats.get_session(sid) is None


# --------------------------------------------------------------------------
# report template management + HTML render (no WeasyPrint)
# --------------------------------------------------------------------------
def test_report_template_roundtrip_and_render():
    assert report.has_custom_template() is False
    report.save_template_text("<h1>{{ report.overall }} {{ devices|length }}</h1>")
    assert report.has_custom_template() is True
    html = report.render_html(FAKE_ANALYSIS, FAKE_THREATS,
                              [{"hostname": "r1", "role": "x", "primary_ip": "1.1.1.1"}])
    assert "High" in html and "1" in html
    report.reset_template()
    assert report.has_custom_template() is False


def test_report_template_validation_rejects_bad_jinja():
    with pytest.raises(Exception):
        report.validate_template("{% if %}")


# --------------------------------------------------------------------------
# agent (ReAct planner) — mocked Gemini
# --------------------------------------------------------------------------
def test_agent_freeform_plain_text(monkeypatch):
    monkeypatch.setattr(llm, "_gemini", lambda *a, **k: "Hi! How can I help you today?")
    res = agent.run("hello", {}, {"devices": [], "has_analysis": False})
    assert "help" in res["reply"].lower()
    assert res["attachments"] == []


def test_agent_routes_to_tool_and_responds(monkeypatch):
    seq = iter([
        '{"tool":"simulate_config_change","input":{"host":"r3","old_text":"a","new_text":"b"}}',
        "Heads up: that change would create a duplicate router-id. Want me to check which device?",
    ])
    monkeypatch.setattr(llm, "_gemini", lambda *a, **k: next(seq))
    called = {}

    def sim(host=None, old_text=None, new_text=None):
        called["host"] = host
        return {"observation": "INTRODUCES new issues -> assert_no_duplicate_router_ids"}

    res = agent.run("what if I change r3 router-id?",
                    {"simulate_config_change": sim},
                    {"devices": ["r3"], "has_analysis": True})
    assert called["host"] == "r3"
    assert "duplicate" in res["reply"].lower()


def test_agent_no_pdf_when_not_requested(monkeypatch):
    seq = iter(['{"tool":"get_assertions","input":{}}',
                "Found 1 issue. Want details on the missing ACL?"])
    monkeypatch.setattr(llm, "_gemini", lambda *a, **k: next(seq))
    blocks = [{"type": "assertion", "assert_name": "assert_no_undefined_references",
               "records": [], "columns": []}]
    res = agent.run("check issues but no pdf",
                    {"get_assertions": lambda **k: {"observation": "1 failing",
                                                    "attachments": blocks}},
                    {"devices": [], "has_analysis": True})
    assert all(a.get("type") != "link" for a in res["attachments"])


# --------------------------------------------------------------------------
# Flask API via test client (engine/LLM monkeypatched)
# --------------------------------------------------------------------------
def test_health_endpoint(client, monkeypatch):
    monkeypatch.setattr(appmod.engine, "ready", lambda: True)
    monkeypatch.setattr(appmod.llm, "gemini_enabled", lambda: False)
    r = client.get("/api/health").get_json()
    assert r["batfish"] is True and r["gemini"] is False


def test_chats_api_crud(client):
    sid = client.post("/api/chats").get_json()["id"]
    assert client.get("/api/chats").get_json()["sessions"] is not None
    chats.append(sid, "user", "hi")
    assert client.get(f"/api/chats/{sid}").get_json()["id"] == sid
    assert client.delete(f"/api/chats/{sid}").get_json()["deleted"] == sid


def test_chat_keyword_negation_no_pdf(client, monkeypatch):
    monkeypatch.setattr(appmod.llm, "gemini_enabled", lambda: False)  # force fallback
    appmod.STATE["analysis"] = FAKE_ANALYSIS
    appmod.STATE["threats"] = FAKE_THREATS
    r = client.post("/api/chat", json={
        "message": "check misconfigurations but dont give me a pdf"}).get_json()
    assert any(a.get("type") == "assertion" for a in r["attachments"])
    assert all(".pdf" not in (a.get("href") or "") for a in r["attachments"])


def test_analyze_orchestration(client, monkeypatch):
    monkeypatch.setattr(appmod.engine, "analyze", lambda *a, **k: dict(FAKE_ANALYSIS))
    monkeypatch.setattr(appmod.engine, "interface_addresses", lambda: {})
    monkeypatch.setattr(appmod.llm, "assess_threats", lambda a: dict(FAKE_THREATS))
    r = client.post("/api/analyze", json={"give_topology": False}).get_json()
    assert r["analysis"]["devices"] and r["threats"]["overall"] == "High"
    assert appmod.STATE["analysis"] is not None  # cached


def test_topology_data_endpoint(client):
    appmod.STATE["analysis"] = FAKE_ANALYSIS
    r = client.get("/api/topology-data/ospf").get_json()
    assert len(r["nodes"]) == 2
    edge = r["edges"][0]
    assert edge["up"] is False and edge["status"] == "AREA_MISMATCH"


def test_inventory_api(client):
    inventory.upsert_device("rX", role="Core", source="local")
    assert any(d["hostname"] == "rX"
               for d in client.get("/api/inventory").get_json()["devices"])
    client.put("/api/inventory/rX", json={"role": "Edge"})
    assert inventory.get_device("rX")["role"] == "Edge"
    client.delete("/api/inventory/rX")
    assert inventory.get_device("rX") is None


def test_report_template_api(client):
    assert client.get("/api/report-template").get_json()["is_custom"] is False
    assert client.put("/api/report-template",
                      json={"template": "<p>{{ report.overall }}</p>"}).status_code == 200
    assert client.put("/api/report-template",
                      json={"template": "{% if %}"}).status_code == 400  # bad jinja
    client.post("/api/report-template/reset")


def test_agent_prompt_api(client):
    assert "CamNet" in client.get("/api/agent-prompt").get_json()["prompt"]
    client.put("/api/agent-prompt", json={"prompt": "Be terse."})
    assert agent.get_prompt() == "Be terse."
    assert client.put("/api/agent-prompt", json={"prompt": " "}).status_code == 400
    client.post("/api/agent-prompt/reset")


def test_device_config_get_and_put(client):
    # GET reads bundled sample config (no Batfish needed)
    g = client.get("/api/device/payment-edge-r3/config").get_json()
    assert "MISSING-ACL" in g["config"]
    # PUT writes an editable ingested copy + flips source
    p = client.put("/api/device/payment-edge-r3/config",
                   json={"config": g["config"] + "\n! edited"}).get_json()
    assert p["saved"] is True and appmod.STATE["active_source"] == "ingested"


def test_global_error_handler_returns_json(client):
    r = client.get("/api/definitely-not-a-route")
    assert r.status_code == 404
    assert r.get_json()["ok"] is False


# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------
def test_safe_host_blocks_traversal():
    assert appmod._safe_host("payment-edge-r3") == "payment-edge-r3"
    assert appmod._safe_host("..") is None
    assert appmod._safe_host("") is None
    # traversal attempts can never escape the dir (no separators / no '..')
    for bad in ("../etc/passwd", "a/b/c", "..\\..\\win.ini", "x/../../y"):
        out = appmod._safe_host(bad)
        assert out is None or ("/" not in out and "\\" not in out and out != "..")


def test_ext_allowlist():
    assert appmod._ext_ok("router.cfg") and appmod._ext_ok("r1")  # blank ext ok
    assert not appmod._ext_ok("evil.exe") and not appmod._ext_ok("x.sh")


def test_request_size_cap_configured():
    assert appmod.app.config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024


def test_upload_rejects_bad_extension(client):
    r = client.post("/api/upload", content_type="multipart/form-data",
                    data={"file": (io.BytesIO(b"MZbinary"), "evil.exe")})
    assert r.status_code == 400


def test_upload_rejects_oversize_file(client):
    big = io.BytesIO(b"a" * (appmod.MAX_FILE_BYTES + 100))
    r = client.post("/api/upload", content_type="multipart/form-data",
                    data={"file": (big, "huge.cfg")})
    assert r.status_code == 400


def test_upload_zip_too_many_files_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(appmod.MAX_UPLOAD_FILES + 5):
            z.writestr(f"r{i}.cfg", f"hostname r{i}\n")
    buf.seek(0)
    r = client.post("/api/upload", content_type="multipart/form-data",
                    data={"file": (buf, "bomb.zip")})
    assert r.status_code == 400
    assert "too many" in r.get_json()["error"].lower()


def test_upload_zip_basename_only_no_zip_slip(client, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../../escape.cfg", "hostname escaped\n")  # Zip Slip attempt
    buf.seek(0)
    r = client.post("/api/upload", content_type="multipart/form-data",
                    data={"file": (buf, "slip.zip")})
    assert r.status_code == 200
    # file must land inside the (isolated) ingest dir as a basename, not escape it
    assert os.path.exists(os.path.join(appmod.INGEST_CONFIGS, "escape.cfg"))


def test_report_template_sandbox_blocks_ssti():
    # A malicious template trying to break out via dunder access must NOT render.
    report.save_template_text("{{ ().__class__.__bases__[0].__subclasses__() }}")
    with pytest.raises(Exception):
        report.render_html(FAKE_ANALYSIS, FAKE_THREATS, [])
    report.reset_template()
