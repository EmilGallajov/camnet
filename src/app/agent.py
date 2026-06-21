"""ReAct-style LLM agent for CamNet.

Instead of static keyword matching, the agent reasons step-by-step and calls
tools (run analysis, inspect devices/configs, fetch assertions, simulate a
hypothetical config change and diff the impact, generate a PDF, show topology),
then answers the user in natural language grounded in what it observed.

Tool implementations are injected by app.py; this module owns the reasoning loop,
the Gemini calls, and the (UI-editable) system prompt.
"""
import json
import os

import llm

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
PROMPT_PATH = os.path.join(DATA_DIR, "agent_prompt.txt")
MAX_STEPS = 4

DEFAULT_SYSTEM = (
    "You are CamNet, a friendly but expert network-security assistant for "
    "smart-city infrastructure, backed by a Batfish network digital twin. "
    "Chat naturally and conversationally — like ChatGPT/Claude: warm, brief, "
    "plain language, and usually end with a short helpful follow-up question or "
    "suggestion. Ground every factual claim in the retrieved context / tool "
    "observations — never invent device names, IPs, AS numbers or results; if "
    "something isn't in the data, say so. For hypothetical 'what if I change X' "
    "questions ALWAYS use simulate_config_change to actually test it in the twin "
    "before answering. Only generate a PDF when the user explicitly asks for a "
    "PDF/report FILE."
)

TOOLS_DOC = """\
- run_analysis(): build/refresh the digital twin and risk scoring. Call this first if no analysis exists.
- list_devices(): list inventory devices with roles and IPs.
- get_device(host): full detail for one device — interfaces, routing table, ACLs, BGP peers, OSPF, protocols.
- get_config(host): the raw device configuration text (use to find exact text before simulating a change).
- get_assertions(devices=null): current Batfish assertion results / misconfigurations, optionally filtered to a device list. Shows the user detailed assertion tables. Use this for "check misconfigurations" with NO PDF.
- simulate_config_change(host, old_text, new_text): hypothetically replace old_text with new_text in host's config, re-run the twin, and report what NEW issues the change would cause. Does NOT persist anything. For "what if" questions.
- generate_pdf(): build a downloadable PDF report. ONLY when the user explicitly asks for a PDF/report file.
- show_topology(layer): give the user a link to the interactive topology ("layer3" | "ospf" | "bgp")."""


# ---- UI-editable system prompt ------------------------------------------
def has_custom_prompt():
    return os.path.exists(PROMPT_PATH)


def get_prompt():
    if has_custom_prompt():
        with open(PROMPT_PATH, encoding="utf-8") as f:
            return f.read()
    return DEFAULT_SYSTEM


def set_prompt(text):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PROMPT_PATH, "w", encoding="utf-8") as f:
        f.write(text)


def reset_prompt():
    if has_custom_prompt():
        os.remove(PROMPT_PATH)


def _planner_prompt(message, context):
    devices = context.get("devices", [])
    failed = context.get("failed", [])
    cfgs = context.get("configs", {})
    cfg_block = ""
    for host, text in cfgs.items():
        cfg_block += f"\n--- config of {host} ---\n{text[:2200]}\n"
    return (
        get_prompt()
        + "\n\nDecide how to respond to the user's request:\n"
          "- If you need to perform an action, output ONLY a single JSON object "
          'and nothing else: {"tool":"<name>","input":{...}}\n'
          "- Otherwise (greetings, explanations, analytical answers you can give "
          "from the context below), just write your natural conversational reply "
          "as plain text — do NOT use JSON.\n"
        + "\nTOOLS:\n" + TOOLS_DOC
        + "\n\nGUIDANCE:\n"
          "- General questions you can answer from the context/config below → use "
          "\"final\" (no tool).\n"
          "- 'what if I change X' / hypothetical edits → tool simulate_config_change "
          "with host + old_text (an EXACT substring copied from the config below) + "
          "new_text. Then your result explains the impact.\n"
          "- 'check misconfigurations' / 'show me the issues' / 'any issues' "
          "(without asking for a file) → tool get_assertions. Do NOT generate a "
          "PDF unless the user explicitly asks for a PDF/report file.\n"
          "- Analytical questions (which/why/explain/summarize/compare, e.g. "
          "'which device is riskiest and why') → answer directly with \"final\", "
          "reasoning over the threat findings and assertions in the context below. "
          "Only call get_assertions if they specifically want the raw assertion tables.\n"
          "- Greetings / general chit-chat / questions answerable from context → "
          "\"final\".\n"
          "- For every \"final\" answer: be casual and conversational, keep it "
          "brief, and end with a short follow-up question or suggestion.\n"
          "- 'show/open ... topology' → tool show_topology (layer3|ospf|bgp).\n"
          "- explicit 'make/generate/download a PDF/report' → tool generate_pdf.\n"
          "- 'run/refresh analysis' → tool run_analysis.\n"
        + "\n\nCONTEXT:\nDevices: " + (", ".join(devices) or "none (run analysis first)")
        + "\nAnalysis available: " + str(bool(context.get("has_analysis")))
        + "\nOverall risk: " + str(context.get("overall") or "unknown")
        + "\nCurrently failing assertions: " + (", ".join(failed) or "none / unknown")
        + ("\nThreat findings:\n- " + "\n- ".join(context.get("findings", []))
           if context.get("findings") else "")
        + cfg_block
        + "\n\nUSER REQUEST: " + message + "\n\nYour JSON:"
    )


def run(message, tools, context):
    raw = llm._gemini(_planner_prompt(message, context), temperature=0.2, fast=True)
    obj = llm._extract_json(raw)
    # No tool requested → the model's plain text IS the conversational answer.
    if not obj or obj.get("tool") not in tools:
        if obj and isinstance(obj.get("final"), str):
            return {"reply": obj["final"], "attachments": []}
        return {"reply": raw.strip(), "attachments": []}

    tool = obj["tool"]
    inp = obj.get("input") or {}
    if not isinstance(inp, dict):
        inp = {}
    say = ""
    try:
        res = tools[tool](**inp)
    except TypeError as e:
        res = {"observation": f"bad arguments for {tool}: {e}"}
    except Exception as e:  # noqa: BLE001
        res = {"observation": f"tool {tool} error: {e}"}

    obs = res.get("observation", "") if isinstance(res, dict) else str(res)
    atts = res.get("attachments", []) if isinstance(res, dict) else []
    # Tool observations are written to be conversational already, so we return
    # them directly — reliable and fast (no flaky 2nd LLM call that the free-tier
    # rate limit would often drop, leaving a robotic fallback).
    return {"reply": obs or "Done.", "attachments": atts}
