# CamNet — Project Brief & Technical Specification

> Handoff document for Claude Code (plan mode). This describes the full idea, the
> architecture, every component, the data flow, and the current state of the
> codebase so work can continue or be rebuilt cleanly.

---

## 1. The Idea (Product Vision)

**CamNet** is an AI-powered cybersecurity and network-intelligence platform for
**smart-city infrastructure**. It continuously analyzes network configurations,
system logs, and operational data from connected city services — traffic lights,
surveillance cameras, digital payment systems, and public-service networks.

Core capabilities:

1. **Network digital twin (Batfish).** Builds a vendor-neutral model of the
   city's network from device configs. Simulates the *impact of configuration
   changes before deployment* — catching outages, reachability failures, ACL
   conflicts, and routing issues pre-deploy.
2. **Anomaly / threat detection.** Detects misconfigurations and suspicious
   network conditions that may indicate cyberattacks or service disruptions.
3. **Risk classification.** Every finding is classified **Low / Medium / High**
   and surfaced as a real-time alert to administrators.
4. **Conversational AI assistant.** Admins manage and query infrastructure in
   **natural language** — request device info, retrieve configs, analyze a
   device, ask which checks failed — without touching complex NMS interfaces.
5. **Reporting.** One-click **PDF report** consolidating assertions, topology
   maps, threat severity, and reachability results.

Goal: help cities keep digital services **secure, resilient, and highly
available** by combining predictive network analysis, anomaly detection, and
conversational automation.

---

## 2. Scope (this build)

- **Type:** Hackathon MVP — prioritize a working end-to-end demo over production
  hardening.
- **Primary demo goal:** Given Cisco (or any Batfish-supported) configs, the
  platform shows analysis results in a web UI, lets the user chat with an AI
  about the network, and generates a PDF report.
- **Explicitly out of scope (deferred):** pushing config to live devices,
  closed-loop remediation, multi-tenancy, persistent storage, auth/RBAC,
  real-time log streaming (anomaly detection is config-derived for now).

---

## 3. Architecture

Single entrypoint via **nginx** reverse proxy. Three Python services + the
official Batfish engine, orchestrated with Docker Compose.

```
                       ┌──────────────────────────────┐
  Browser  ──:8080──▶  │            nginx             │
                       │  /            → webui        │
                       │  /api/batfish → batfish-api  │
                       │  /api/netbox  → netbox-api   │
                       └──────────────────────────────┘
                          │            │           │
              ┌───────────┘            │           └────────────┐
              ▼                        ▼                        ▼
       ┌────────────┐          ┌──────────────┐         ┌──────────────┐
       │   webui    │          │ batfish-api  │ ──────▶  │   batfish    │
       │ (chat UI)  │          │ engine + LLM │  :9997   │ (digital     │
       └────────────┘          │ + PDF report │          │  twin)       │
                               └──────┬───────┘          └──────────────┘
                                      │ render-config
                               ┌──────▼───────┐         ┌──────────────┐
                               │  netbox-api  │ ──────▶  │   NetBox     │
                               │ (passthrough)│          │ (inventory)  │
                               └──────────────┘          └──────────────┘
```

| Service       | Internal port | nginx path     | Role                                          |
|---------------|---------------|----------------|-----------------------------------------------|
| `nginx`       | 80 (→host 8080)| —             | Reverse proxy / single entrypoint             |
| `webui`       | 8000          | `/`            | Claude-style chat + analysis console          |
| `batfish-api` | 8001          | `/api/batfish` | Batfish engine, LLM threat scoring, PDF report|
| `netbox-api`  | 8002          | `/api/netbox`  | Thin NetBox inventory/config passthrough      |
| `batfish`     | 9997 / 9996   | —              | Official `batfish/allinone` digital-twin engine|

---

## 4. Technology Stack

- **Network modeling:** Batfish (`batfish/allinone` Docker image) + `pybatfish`
  client. Vendor-neutral: Cisco IOS/NX-OS, Juniper, Arista, etc.
- **Backend:** Python 3.11, Flask, served by gunicorn.
- **Inventory / config source:** NetBox REST API (`render-config` endpoint).
- **LLM:** Google **Gemini** (`gemini-2.0-flash` via the
  `generativelanguage.googleapis.com` REST API). Used for (a) natural-language
  chat and (b) Low/Med/High threat classification. Has a deterministic
  rule-based **mock fallback** when no API key is set, so the demo runs offline.
- **Topology rendering:** `networkx` + `matplotlib` (Agg headless) → PNG.
- **PDF:** `reportlab`.
- **Frontend:** single self-contained `index.html` (vanilla JS, no build step),
  Claude-style three-pane chat console.
- **Reverse proxy:** nginx.
- **Orchestration:** Docker Compose.

---

## 5. Component Details

### 5.1 batfish-api  (`src/batfish/`)
The core service. Files:

- **`engine.py` — `CamNetEngine`**
  - `connect()` / `load_snapshot(config_dir)` — connects to Batfish, inits a
    snapshot. Accepts either a flat folder of configs or a `configs/` subdir;
    symlinks files into a temp snapshot dir when needed.
  - `list_devices()` / `device_config(hostname)` — inventory + per-device props
    and interfaces.
  - `default_asserts()` — runs the standard Batfish question set:
    `fileParseStatus`, `initIssues`, `undefinedReferences`, `unusedStructures`,
    `nodeProperties`, `interfaceProperties`, `bgpSessionCompatibility`,
    `bgpSessionStatus`, `ospfSessionCompatibility`, `mlagProperties`, plus a
    custom **duplicate BGP router-id** check. Each result has
    `count`/`records`, "empty-is-good" checks add a `passed` flag, and a
    `_summary` rolls up overall pass/fail + failed-check list.
  - `ping_check(ip_map)` — Batfish `reachability` query with
    `HeaderConstraints(srcIps, dstIps)`, `actions="SUCCESS"`. Returns
    `pingable: bool` + matching flows.
  - `generate_topologies()` — builds L3 (`layer3Edges`), OSPF (`ospfEdges`),
    BGP (`bgpEdges`) graphs and renders each to a PNG.
  - `analyze(...)` — orchestrates: load snapshot → list devices → default
    asserts → optional ping → optional topologies → single JSON dict.

- **`llm.py`** — Gemini wrapper + mock.
  - `assess_threats(analysis)` → `{source, overall, counts{High,Med,Low}, findings[]}`
    where each finding = `{title, severity, category, detail, recommendation}`.
  - `chat(message, context)` → grounded natural-language reply.
  - Real Gemini when `GEMINI_API_KEY` set; otherwise rule-based mock that reasons
    over assertion counts (init issues→High, undefined refs→Medium, unused→Low,
    duplicate router-ids→High, unreachable ping→High).
  - `_trim()` shrinks record lists to keep prompts within token limits.

- **`netbox_client.py` — `NetBoxClient`**
  - `ping()`, `list_devices()`, `render_config(device_id)` (POST
    `/api/dcim/devices/{id}/render-config/`), `pull_all_configs(dest_dir)`.
  - Reads `NETBOX_URL` / `NETBOX_TOKEN` from env. `configured` property gates use.

- **`report.py` — `build_report(analysis, threats, out_path)`**
  - reportlab PDF: (1) summary + overall threat level (color-coded),
    (2) Batfish assertions table, (3) threat findings, (4) reachability verdict,
    (5) topology images (L3/OSPF/BGP).

- **`app.py`** — Flask REST API (see endpoints below). Keeps last analysis +
  threats in an in-memory `STATE` dict (single gunicorn worker).

### 5.2 netbox-api  (`src/netbox_api/`)
Thin passthrough so the browser never holds the NetBox token.
- `GET /health`, `GET /devices`, `GET /devices/<id>/config`.
- Reuses a copy of `netbox_client.py`.

### 5.3 webui  (`src/webui/`)
- `app.py` — minimal Flask serving `templates/index.html`.
- **`index.html`** — Claude-style **three-pane** console:
  - **Left rail:** service status pills (Batfish/NetBox/Gemini), analysis
    controls (config source select, topology toggle, reachability toggle +
    src/dst IP inputs), Run-analysis button, Download-PDF button, device list.
  - **Center:** chat stream (user/bot bubbles), composer, quick-prompt chips,
    overall risk badge.
  - **Right rail:** severity counts (High/Med/Low), threat finding cards
    (color-coded left border), topology image thumbnails.
  - All API calls go to `/api/batfish/*`; topology imgs via
    `/api/batfish/topology/<name>`.
  - Theme: dark navy (`--bg:#0c1020`), teal accent (`--accent:#46e0c0`),
    Inter/JetBrains Mono. No external build step.

---

## 6. API Reference (as seen through nginx)

```
GET  /api/batfish/health
POST /api/batfish/analyze        body: {source, ip_ping_check_flag, ip_map, give_topology}
                                  source ∈ {"netbox","local"}
                                  ip_map = {source, destination}
                                  → {analysis:{...}, threats:{...}}
GET  /api/batfish/devices
GET  /api/batfish/devices/<name>
POST /api/batfish/chat           body: {message} → {reply}
GET  /api/batfish/report         → application/pdf
GET  /api/batfish/topology/<layer3|ospf|bgp>  → image/png

GET  /api/netbox/health
GET  /api/netbox/devices
GET  /api/netbox/devices/<id>/config
```

`/analyze` returns one JSON object:
```json
{
  "analysis": {
    "generated_at": "...", "network": "camnet", "snapshot": "snapshot",
    "devices": ["..."], "config_source": "local|netbox",
    "default_asserts": { "...": {"count":N,"records":[],"passed":bool}, "_summary":{...} },
    "ping_check": {"source","destination","pingable","flows"},   // if requested
    "topologies": {"layer3":{"image","edges"}, "ospf":{...}, "bgp":{...}}
  },
  "threats": {
    "source":"gemini|mock", "overall":"Low|Medium|High",
    "counts":{"High":n,"Medium":n,"Low":n},
    "findings":[{"title","severity","category","detail","recommendation"}]
  }
}
```

---

## 7. Data Flow (a full analysis run)

1. User clicks **Run analysis** in WebUI → `POST /api/batfish/analyze`.
2. **Config source selection** in `app.py`:
   - `source="netbox"` AND NetBox configured AND reachable →
     `pull_all_configs()` renders every active device's config into a temp dir.
   - If NetBox yields nothing, or `source="local"`, or NetBox unreachable →
     fall back to local folder `/app/configs` (mounted from `configs/configs`).
3. `CamNetEngine.analyze()` loads the snapshot into Batfish and runs asserts,
   optional ping, optional topology PNGs.
4. `llm.assess_threats(analysis)` classifies findings into Low/Med/High
   (Gemini or mock).
5. Result `{analysis, threats}` cached in `STATE`, returned to the UI.
6. UI populates findings, counts, device list, topology thumbnails.
7. User chats → `POST /api/batfish/chat` with the cached analysis as context.
8. User clicks **Download PDF** → `GET /api/batfish/report` builds + streams PDF.

---

## 8. Config Sources (important nuance)

**NetBox is the primary source**, but NetBox does **not store running-configs** —
it *renders* them from each device's assigned **Jinja2 config template + context
data** via `POST /api/dcim/devices/{id}/render-config/`. A device only yields a
config if it has a template assigned; devices without one are skipped, and if
nothing renders, CamNet auto-falls-back to the local folder.

**Local folder** (`configs/configs/`) is the safe demo path — any
Batfish-supported configs. Bundled samples model a small smart-city network
(traffic / surveillance / payment routers, OSPF + iBGP AS 65001) and include one
**intentional** issue (an undefined ACL `MISSING-ACL`) so findings appear.

---

## 9. Environment Variables

| Var              | Default            | Meaning                                  |
|------------------|--------------------|------------------------------------------|
| `NETBOX_URL`     | *(empty)*          | NetBox base URL; empty → local fallback  |
| `NETBOX_TOKEN`   | *(empty)*          | NetBox API token                         |
| `GEMINI_API_KEY` | *(empty)*          | Gemini key; empty → offline mock         |
| `GEMINI_MODEL`   | `gemini-2.0-flash` | Gemini model name                        |
| `BATFISH_HOST`   | `batfish`          | Batfish service host (set in compose)    |
| `LOCAL_CONFIG_DIR`| `/app/configs`    | Local config dir inside container        |

`.env.example` is provided; copy to `.env`. Everything left blank uses a safe
fallback so the stack runs fully offline.

---

## 10. Project Layout

```
camnet/
├─ docker-compose.yml
├─ .env.example
├─ .gitignore
├─ README.md
├─ nginx/nginx.conf
├─ configs/configs/            # local sample configs (demo fallback)
│  ├─ traffic-core-r1.cfg
│  ├─ surveillance-dist-r2.cfg
│  └─ payment-edge-r3.cfg
└─ src/
   ├─ batfish/                 # analysis engine + LLM + PDF + REST API
   │  ├─ app.py engine.py llm.py report.py netbox_client.py
   │  ├─ requirements.txt Dockerfile
   ├─ netbox_api/              # NetBox passthrough API
   │  ├─ app.py netbox_client.py requirements.txt Dockerfile
   └─ webui/                   # chat console
      ├─ app.py templates/index.html requirements.txt Dockerfile
```

---

## 11. Run / Deploy

```bash
cp .env.example .env          # optional: add NETBOX_* and GEMINI_API_KEY
docker compose up --build
# open http://localhost:8080
```

### Known deployment gotcha: Docker inside Proxmox LXC
Symptom: `open sysctl net.ipv4.ip_unprivileged_port_start ... permission denied`
when nginx starts. Causes & fixes:
- **Fastest (no host changes):** make nginx listen on a high port — change
  `nginx.conf` `listen 80;` → `listen 8080;` and compose `"8080:80"` →
  `"8080:8080"`. Avoids the privileged-port sysctl entirely.
- **Proper LXC fix:** run the LXC as **privileged** with
  `features: nesting=1,keyctl=1` in `/etc/pve/lxc/<CTID>.conf` (privileged is the
  *absence* of `unprivileged: 1`; converting an existing CT requires
  backup→`pct restore --unprivileged 0`).
- **Most robust:** run Docker in a Proxmox **VM** instead of LXC.

---

## 12. Current State / Known Limitations

- Analysis state is **in memory** (single gunicorn worker) — fine for demo,
  needs Redis/DB for production or multi-worker.
- Anomaly detection is **config-derived** (Batfish assertions + LLM reasoning);
  no live syslog/NetFlow ingestion yet.
- No auth / RBAC / multi-tenancy.
- LLM threat scoring quality depends on Gemini; mock is heuristic only.
- NetBox path requires config templates to be set up in NetBox.

---

## 13. Suggested Next Steps (for Claude Code plan mode)

Candidate work items, roughly prioritized:

1. **Apply the Proxmox nginx high-port fix** so the stack starts in the current
   environment.
2. **Persist state** — swap in-memory `STATE` for Redis (or SQLite) so
   multi-worker gunicorn works and history survives restarts.
3. **Real log/anomaly pipeline** — ingest syslog/NetFlow, add a baseline +
   rule/ML anomaly detector feeding the same threat model.
4. **Auth** — minimal token/login on the WebUI + APIs.
5. **Change simulation UX** — let an admin upload a *proposed* config and show
   the predicted diff/impact (Batfish's core strength) in the UI.
6. **Per-device drill-down** in the WebUI (wire `/devices/<name>`).
7. **Harden NetBox flow** — handle pagination, device filtering by site/role.
8. **Tests** — unit tests for `engine`, `llm` mock, `report`; a smoke test that
   runs an analysis against the bundled configs.

---

## 14. Acceptance Criteria (demo)

- `docker compose up --build` brings up all 5 containers.
- Visiting `http://<host>:8080` loads the chat console; status pills reflect
  reality (Gemini off → mock).
- Clicking **Run analysis** (local source) returns findings within ~30s,
  populates severity counts, finding cards, device list, and 3 topology images.
- Chat answers questions grounded in the analysis ("list devices", "what are the
  threats", "which checks failed").
- **Download PDF report** produces a multi-page PDF containing assertions,
  threat severity, reachability, and topology images.
