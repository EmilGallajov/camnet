"""LLM layer: Google Gemini wrapper for (a) threat classification and
(b) conversational chat, with a deterministic rule-based mock fallback so the
demo runs fully offline when no API key is configured."""
import json
import os
import re

import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent"

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


def _scrub(text):
    """Never leak the API key into user-facing errors/logs."""
    s = str(text)
    if GEMINI_API_KEY:
        s = s.replace(GEMINI_API_KEY, "***")
    return re.sub(r"key=[A-Za-z0-9_\-]+", "key=***", s)


def _friendly_error(e):
    s = _scrub(e)
    if "429" in s:
        return "Gemini rate/quota limit hit (HTTP 429)"
    if "403" in s or "401" in s or "PERMISSION" in s.upper():
        return "Gemini key not authorized (HTTP 403)"
    return s


def gemini_enabled():
    k = GEMINI_API_KEY
    return bool(k) and not k.upper().startswith("REPLACE")


def _gemini(prompt, temperature=0.3, fast=False):
    import time
    url = GEMINI_URL.format(m=GEMINI_MODEL)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }
    last = None
    tries = 1 if fast else 3  # interactive chat fails fast to its fallback
    for attempt in range(tries):
        r = requests.post(url, params={"key": GEMINI_API_KEY},
                          json=payload, timeout=40)
        if r.status_code in (429, 503) and attempt < tries - 1:
            last = r
            time.sleep(3 * (attempt + 1))  # 3s, 6s
            continue
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    last.raise_for_status()  # exhausted retries


# --------------------------------------------------------------------------
# Context trimming — keep prompts small.
# --------------------------------------------------------------------------
def _trim(analysis):
    asserts = analysis.get("default_asserts", {})
    slim = {}
    for k, v in asserts.items():
        if k == "_summary":
            slim[k] = v
            continue
        slim[k] = {
            "count": v.get("count", 0),
            "passed": v.get("passed"),
            "records": v.get("records", [])[:4],
        }
    return {
        "devices": analysis.get("devices", []),
        "device_roles": analysis.get("device_roles", {}),
        "config_source": analysis.get("config_source"),
        "asserts": slim,
        "ping_check": analysis.get("ping_check"),
    }


# --------------------------------------------------------------------------
# Threat assessment
# --------------------------------------------------------------------------
def _overall(counts):
    if counts.get("High"):
        return "High"
    if counts.get("Medium"):
        return "Medium"
    return "Low"


def _mock_findings(analysis):
    a = analysis.get("default_asserts", {})
    findings = []

    def add(title, sev, cat, detail, rec):
        findings.append({"title": title, "severity": sev, "category": cat,
                         "detail": detail, "recommendation": rec})

    def cnt(key):
        return a.get(key, {}).get("count", 0)

    # Parse failures
    fp = a.get("fileParseStatus", {})
    if fp.get("passed") is False:
        add("Config parse failures", "High", "Integrity",
            "One or more device configs failed to parse cleanly in the digital twin.",
            "Review the flagged files; unparsed config means blind spots in analysis.")

    if cnt("initIssues"):
        add("Snapshot initialization issues", "High", "Integrity",
            f"{cnt('initIssues')} initialization issue(s) detected when modeling the network.",
            "Resolve init issues so reachability/ACL analysis is trustworthy.")

    if cnt("undefinedReferences"):
        recs = a.get("undefinedReferences", {}).get("records", [])
        names = ", ".join({r.get("Ref_Name") or r.get("Struct_Name") or "?"
                           for r in recs}) or "see report"
        add("Undefined reference(s)", "Medium", "Misconfiguration",
            f"{cnt('undefinedReferences')} undefined reference(s) — e.g. {names}. "
            "An interface applies a structure (ACL/route-map) that does not exist, "
            "so the intended security control is silently absent.",
            "Define the missing structure or remove the dangling reference. "
            "On an untrusted/payment edge this can mean an open filter.")

    if cnt("unusedStructures"):
        add("Unused structures", "Low", "Hygiene",
            f"{cnt('unusedStructures')} defined structure(s) are never referenced.",
            "Prune dead config to reduce attack surface and operator confusion.")

    if cnt("duplicateRouterIds"):
        add("Duplicate BGP router-IDs", "High", "Routing",
            "Two or more devices share a BGP router-ID, which breaks session "
            "establishment and can blackhole traffic.",
            "Assign globally unique router-IDs (typically the Loopback0 address).")

    bss = a.get("bgpSessionStatus", {})
    if bss.get("passed") is False:
        add("BGP sessions not established", "Medium", "Routing",
            "One or more iBGP/eBGP sessions are not in ESTABLISHED state.",
            "Check neighbor reachability, AS numbers, and update-source settings.")

    ping = analysis.get("ping_check")
    if ping and ping.get("source"):
        if not ping.get("pingable"):
            add("Reachability failure", "High", "Availability",
                f"Traffic from {ping['source']} to {ping['destination']} is NOT "
                "deliverable in the modeled network — a service outage risk.",
                "Verify routing/ACLs along the path before this reaches production.")

    if not findings:
        add("No critical issues detected", "Low", "Status",
            "The digital twin found no failing assertions in this snapshot.",
            "Continue monitoring; re-run analysis after any config change.")

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "source": "mock",
        "overall": _overall(counts),
        "counts": counts,
        "findings": findings,
    }


def _gemini_threats(analysis):
    ctx = json.dumps(_trim(analysis), indent=2)
    prompt = (
        "You are a senior network-security analyst for a smart-city operations "
        "center. Below is JSON output from a Batfish network digital twin "
        "(assertions, reachability, devices and their city roles).\n\n"
        f"{ctx}\n\n"
        "Classify the concrete risks. Respond with STRICT JSON only, no prose, "
        "in this exact shape:\n"
        '{"overall":"Low|Medium|High","counts":{"High":n,"Medium":n,"Low":n},'
        '"findings":[{"title":"...","severity":"Low|Medium|High",'
        '"category":"...","detail":"...","recommendation":"..."}]}\n'
        "Rules: undefined ACL/route-map on an untrusted or payment-facing "
        "interface = High. Parse/init failures = High. Duplicate router-id = "
        "High. Reachability failure for a requested flow = High. Unused "
        "structures = Low. Keep detail and recommendation to one sentence each, "
        "grounded in the data. counts must match the findings list."
    )
    raw = _gemini(prompt)
    obj = _extract_json(raw)
    if not obj or "findings" not in obj:
        raise ValueError("Gemini returned unparseable threat JSON")
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in obj.get("findings", []):
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
    obj["counts"] = counts
    obj["overall"] = _overall(counts)
    obj["source"] = "gemini"
    return obj


def assess_threats(analysis):
    if gemini_enabled():
        try:
            return _gemini_threats(analysis)
        except Exception as e:  # noqa: BLE001
            base = _mock_findings(analysis)
            base["note"] = f"{_friendly_error(e)}; used heuristic mock."
            return base
    return _mock_findings(analysis)


# --------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------
def chat(message, context):
    if gemini_enabled():
        try:
            return _gemini_chat(message, context)
        except Exception as e:  # noqa: BLE001
            return _mock_chat(message, context) + f"\n\n_({_friendly_error(e)})_"
    return _mock_chat(message, context)


def _gemini_chat(message, context):
    analysis = context.get("analysis") or {}
    threats = context.get("threats") or {}
    ctx = json.dumps({"analysis": _trim(analysis), "threats": threats}, indent=2)
    prompt = (
        "You are CamNet, an expert AI assistant for smart-city network "
        "operators, backed by a Batfish network digital twin. Use the analysis "
        "context below as your primary source of truth and ground answers in it "
        "(cite device names, severities, assertion results, AS numbers, IPs). "
        "You MAY also apply general networking/security expertise to explain, "
        "advise, or answer follow-ups, but never invent specific facts about "
        "this network that aren't in the data — if a specific detail is missing, "
        "say so and suggest how to get it (e.g. run analysis, open a device). "
        "Use short paragraphs or bullet markdown. Be concrete and practical.\n\n"
        f"CONTEXT:\n{ctx}\n\nOPERATOR REQUEST: {message}"
    )
    return _gemini(prompt, temperature=0.5, fast=True)


def _mock_chat(message, context):
    analysis = context.get("analysis") or {}
    threats = context.get("threats") or {}
    m = message.lower()

    if not analysis:
        return ("No analysis has been run yet. Click **Run analysis** in the left "
                "panel and I'll be able to answer questions about the network.")

    devices = analysis.get("devices", [])
    roles = analysis.get("device_roles", {})

    if any(w in m for w in ("list device", "what device", "which device", "devices", "inventory")):
        lines = [f"- `{d}` — {roles.get(d, 'Network')}" for d in devices]
        return f"There are **{len(devices)} devices** in the snapshot:\n" + "\n".join(lines)

    if any(w in m for w in ("threat", "risk", "security", "vulnerab", "danger")):
        c = threats.get("counts", {})
        lines = [f"Overall risk: **{threats.get('overall', 'Unknown')}** "
                 f"(High {c.get('High',0)} / Medium {c.get('Medium',0)} / Low {c.get('Low',0)}).",
                 ""]
        for f in threats.get("findings", []):
            lines.append(f"- **[{f['severity']}] {f['title']}** — {f['detail']}")
        return "\n".join(lines)

    if any(w in m for w in ("fail", "which check", "assert", "broke", "wrong")):
        summ = analysis.get("default_asserts", {}).get("_summary", {})
        failed = summ.get("failed_checks", [])
        if not failed:
            return "✅ All assertion checks passed in the latest snapshot."
        return ("The following checks failed: "
                + ", ".join(f"`{c}`" for c in failed)
                + ". Ask about any one for detail.")

    if any(w in m for w in ("reach", "ping", "connect")):
        p = analysis.get("ping_check")
        if not p:
            return ("No reachability check was run. Enable the reachability "
                    "toggle and set source/destination IPs, then re-run analysis.")
        verdict = "✅ reachable" if p.get("pingable") else "❌ NOT reachable"
        return f"Flow `{p['source']} → {p['destination']}` is {verdict}."

    if any(w in m for w in ("acl", "missing", "undefined", "reference")):
        ur = analysis.get("default_asserts", {}).get("undefinedReferences", {})
        if ur.get("count"):
            return (f"⚠️ {ur['count']} undefined reference(s) detected. The planted "
                    "issue is an `ip access-group MISSING-ACL` on the payment edge's "
                    "untrusted uplink — the ACL is referenced but never defined, so "
                    "the filter is silently absent. Define it before deploy.")
        return "No undefined references in the current snapshot."

    # default summary
    summ = analysis.get("default_asserts", {}).get("_summary", {})
    return (f"I'm analyzing **{len(devices)}** smart-city devices. Overall risk is "
            f"**{threats.get('overall', 'Unknown')}**, with "
            f"{len(summ.get('failed_checks', []))} failing check(s). "
            "Try: *list devices*, *what are the threats*, *which checks failed*, "
            "or *is the payment LAN reachable*.")


# --------------------------------------------------------------------------
def _extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                return None
    return None
