"""Chat intent parsing + Batfish assertion detailing.

The chatbot turns free text into concrete requests (analyze, list/filter devices,
device detail, check misconfigurations, generate PDF, show topology) and renders
failed Batfish assertions as human-readable detail blocks in the chat log.
"""
import re

# Internal assert key -> presentation metadata (Batfish-style assert names).
ASSERT_META = {
    "fileParseStatus": {
        "name": "assert_all_files_parsed",
        "desc": "Every device configuration parses cleanly in the digital twin.",
        "fail": "Found configuration file(s) that did not fully parse.",
    },
    "initIssues": {
        "name": "assert_no_init_issues",
        "desc": "No problems were hit while building the network model.",
        "fail": "Found snapshot initialization issue(s), when none were expected.",
    },
    "undefinedReferences": {
        "name": "assert_no_undefined_references",
        "desc": "No configuration references a structure that does not exist.",
        "fail": "Found undefined reference(s), when none were expected.",
    },
    "unusedStructures": {
        "name": "assert_no_unused_structures",
        "desc": "No defined structures are left unused.",
        "fail": "Found unused structure(s), when none were expected.",
    },
    "bgpSessionCompatibility": {
        "name": "assert_no_incompatible_bgp_sessions",
        "desc": "All BGP neighbor configurations are mutually compatible.",
        "fail": "Found incompatible BGP session(s), when none were expected.",
    },
    "bgpSessionStatus": {
        "name": "assert_bgp_sessions_established",
        "desc": "All configured BGP sessions would establish.",
        "fail": "Found BGP session(s) that would not establish.",
    },
    "ospfSessionCompatibility": {
        "name": "assert_no_incompatible_ospf_sessions",
        "desc": "All OSPF adjacencies are compatible.",
        "fail": "Found incompatible OSPF session(s), when none were expected.",
    },
    "duplicateRouterIds": {
        "name": "assert_no_duplicate_router_ids",
        "desc": "Each device has a unique BGP router-ID.",
        "fail": "Found duplicate BGP router-ID(s), when none were expected.",
    },
}

_BGP_OK = {"UNIQUE_MATCH", "DYNAMIC_MATCH"}
_OSPF_OK = {"ESTABLISHED"}
_EST_OK = {"ESTABLISHED"}


def _state(key, entry):
    """Return (passed, bad_records) for an assertion entry."""
    records = entry.get("records", []) or []
    passed = entry.get("passed")
    if key == "bgpSessionCompatibility":
        bad = [r for r in records if r.get("Configured_Status") not in _BGP_OK]
        return len(bad) == 0, bad
    if key == "ospfSessionCompatibility":
        bad = [r for r in records if r.get("Session_Status") not in _OSPF_OK]
        return len(bad) == 0, bad
    if key == "bgpSessionStatus":
        bad = [r for r in records if r.get("Established_Status") not in _EST_OK]
        return (passed if passed is not None else len(bad) == 0), bad
    if passed is True:
        return True, []
    if passed is False:
        return False, records  # empty-is-good checks: records ARE the problem
    return None, []


def _filter_by_devices(records, devices):
    if not devices:
        return records
    dl = {d.lower() for d in devices}
    out = []
    for r in records:
        hay = " ".join(str(v) for v in r.values()).lower()
        if any(d in hay for d in dl):
            out.append(r)
    return out


def assertion_blocks(analysis, devices=None, include_passed=False):
    """Build chat attachment blocks for assertions (failed by default)."""
    blocks = []
    asserts = analysis.get("default_asserts", {})
    for key, meta in ASSERT_META.items():
        entry = asserts.get(key)
        if not isinstance(entry, dict):
            continue
        passed, bad = _state(key, entry)
        bad = _filter_by_devices(bad, devices)
        if passed is False or (passed is None and bad):
            cols = list(bad[0].keys()) if bad else []
            blocks.append({
                "type": "assertion",
                "assert_name": meta["name"],
                "message": meta["fail"],
                "description": meta["desc"],
                "passed": False,
                "columns": cols,
                "records": bad[:25],
            })
        elif include_passed and passed is True:
            blocks.append({
                "type": "assertion",
                "assert_name": meta["name"],
                "message": "Passed — " + meta["desc"],
                "description": meta["desc"],
                "passed": True,
                "columns": [],
                "records": [],
            })
    return blocks


def parse_intent(message, known_devices):
    m = (message or "").lower().strip()
    mentioned = [d for d in known_devices if d.lower() in m]

    def has(*ws):
        return any(w in m for w in ws)

    if has("how", "upload") and "upload" in m:
        return {"action": "howto_upload"}
    if "ssh" in m and has("how", "connect", "pull", "add"):
        return {"action": "howto_ssh"}
    if has("help", "what can you", "commands"):
        return {"action": "help"}
    if has("run analysis", "analyze", "analyse", "scan", "re-run", "rerun",
           "re analyze", "build twin", "build the twin"):
        return {"action": "analyze"}
    if has("topology", "topolog", "graph", "map", "diagram") or \
       re.search(r"\b(ospf|bgp|layer ?3|l3)\b.*\b(layer|view|map|graph|topolog)", m):
        layer = "layer3"
        if "ospf" in m:
            layer = "ospf"
        elif "bgp" in m:
            layer = "bgp"
        return {"action": "topology", "layer": layer}
    # "...but don't give a pdf / no pdf / just results" → not a PDF request
    pdf_negated = bool(re.search(
        r"\b(no|not|don'?t|without|skip|just|only)\b[^.]{0,30}\b(pdf|report)\b", m))
    wants_check = has("misconfig", "assert", "assertion", "issue", "problem",
                      "fail", "check", "wrong", "vulnerab", "threat", "risk",
                      "audit")
    if has("pdf", "report", "export") and not pdf_negated and not wants_check:
        return {"action": "pdf", "devices": mentioned}
    if wants_check:
        return {"action": "check", "devices": mentioned}
    if has("pdf", "report", "export") and not pdf_negated:
        return {"action": "pdf", "devices": mentioned}
    if mentioned and has("ip", "address", "interface", "detail", "info",
                         "about", "config", "show", "tell"):
        return {"action": "device_detail", "devices": mentioned}
    if has("list device", "devices", "inventory", "what device",
           "which device", "show device"):
        return {"action": "list_devices"}
    if mentioned:
        return {"action": "device_detail", "devices": mentioned}
    return {"action": "freeform"}
