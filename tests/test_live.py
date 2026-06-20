"""Live integration tests — require the running stack (app + Batfish).

Run inside the app container (Batfish reachable as host 'batfish', API on
localhost:8080):  python -m pytest tests/test_live.py
Tests skip gracefully if the stack/Batfish is not reachable.
"""
import os
import sys

import pytest
import requests

_HERE = os.path.dirname(__file__)
for _cand in (os.path.join(_HERE, "..", "src", "app"), "/app", _HERE):
    if os.path.exists(os.path.join(_cand, "app.py")):
        sys.path.insert(0, _cand)
        break

BASE = os.environ.get("CAMNET_BASE", "http://localhost:8080")


def _api_up():
    try:
        return requests.get(f"{BASE}/api/health", timeout=5).status_code == 200
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _api_up(), reason="CamNet API not reachable")


@pytest.fixture(scope="module", autouse=True)
def analyzed():
    """Ensure a fresh analysis on the bundled samples exists."""
    requests.post(f"{BASE}/api/reset-source", timeout=10)
    r = requests.post(f"{BASE}/api/analyze", timeout=180, json={
        "give_topology": True, "ip_ping_check_flag": True,
        "ip_map": {"source": "192.168.10.10", "destination": "192.168.30.10"}})
    assert r.status_code == 200
    return r.json()


# ---- API-level ----------------------------------------------------------
def test_health():
    h = requests.get(f"{BASE}/api/health", timeout=10).json()
    assert h["batfish"] is True


def test_analyze_finds_devices_and_planted_faults(analyzed):
    a, t = analyzed["analysis"], analyzed["threats"]
    assert set(a["devices"]) == {"traffic-core-r1", "surveillance-dist-r2",
                                 "payment-edge-r3"}
    # planted undefined ACL
    assert a["default_asserts"]["undefinedReferences"]["count"] >= 1
    # reachability reroutes despite the OSPF fault
    assert a["ping_check"]["pingable"] is True
    assert t["overall"] in ("Low", "Medium", "High")


def test_topology_ospf_has_red_faulty_edge():
    edges = requests.get(f"{BASE}/api/topology-data/ospf", timeout=15).json()["edges"]
    faulty = [e for e in edges if not e["up"]]
    assert any(e["status"] == "AREA_MISMATCH" for e in faulty)
    # the up edges should still be present (full mesh minus the broken one)
    assert any(e["up"] for e in edges)


def test_topology_layers_all_present():
    for layer in ("layer3", "ospf", "bgp"):
        d = requests.get(f"{BASE}/api/topology-data/{layer}", timeout=15).json()
        assert len(d["nodes"]) == 3


def test_pdf_report_generation():
    r = requests.get(f"{BASE}/api/report", timeout=60)
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 5000


def test_device_details_rich():
    d = requests.get(f"{BASE}/api/device/payment-edge-r3/details", timeout=30).json()
    assert "BGP" in d["protocols"] and "OSPF" in d["protocols"]
    assert len(d["interfaces"]) >= 4
    assert len(d["routes"]) >= 1
    assert any(acl["name"] == "PAYMENT-PROTECT" for acl in d["acls"])


def test_chat_check_without_pdf():
    r = requests.post(f"{BASE}/api/chat", timeout=90, json={
        "message": "check misconfigurations but dont give me a pdf, just results"}).json()
    assert all(".pdf" not in (a.get("href") or "") for a in r.get("attachments", []))
    assert "session_id" in r


def test_chat_history_persisted():
    sid = requests.post(f"{BASE}/api/chats", timeout=10).json()["id"]
    requests.post(f"{BASE}/api/chat", timeout=90,
                  json={"message": "hello", "session_id": sid})
    s = requests.get(f"{BASE}/api/chats/{sid}", timeout=10).json()
    assert len(s["messages"]) >= 2  # user + bot persisted


# ---- engine-level: separated-session simulation (no Gemini) -------------
@pytest.fixture(scope="module")
def engine():
    from engine import CamNetEngine
    eng = CamNetEngine()
    eng.connect()
    eng.load_snapshot("/app/configs")
    return eng


def _failed(eng, asserts):
    import chat_agent
    out = {}
    for k, v in asserts.items():
        if k == "_summary" or not isinstance(v, dict):
            continue
        passed, bad = chat_agent._state(k, v)
        if passed is False:
            out[k] = len(bad)
    return out


def test_simulation_uses_separate_session_and_detects_dup_routerid(engine):
    baseline = engine.default_asserts()
    base_fail = _failed(engine, baseline)
    res = engine.simulate_change("/app/configs", "payment-edge-r3",
                                 "bgp router-id 10.0.0.3", "bgp router-id 10.0.0.1")
    assert "error" not in res
    cand_fail = _failed(engine, res["candidate_asserts"])
    assert "duplicateRouterIds" in cand_fail and "duplicateRouterIds" not in base_fail
    # live snapshot must be untouched after the simulation
    after = _failed(engine, engine.default_asserts())
    assert "duplicateRouterIds" not in after


def test_simulation_can_resolve_planted_ospf_mismatch(engine):
    res = engine.simulate_change(
        "/app/configs", "payment-edge-r3",
        "network 10.1.23.0 0.0.0.255 area 1",
        "network 10.1.23.0 0.0.0.255 area 0")
    assert "error" not in res
    cand_fail = _failed(engine, res["candidate_asserts"])
    assert "ospfSessionCompatibility" not in cand_fail
