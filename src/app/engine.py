"""CamNet network digital-twin engine (Batfish wrapper).

Loads device configs into Batfish, runs the standard assertion set, optional
reachability checks, and renders L3/OSPF/BGP topology graphs to PNG.
"""
import math
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

BATFISH_HOST = os.environ.get("BATFISH_HOST", "batfish")
NETWORK = "camnet"
SNAPSHOT = "snapshot"
TOPO_DIR = os.environ.get("TOPO_DIR", "/app/topologies")

# Smart-city role labels keyed by hostname fragment, for nicer reporting.
ROLE_HINTS = {
    "traffic": "Traffic control",
    "surveillance": "Surveillance",
    "payment": "Digital payments",
}


def _cell(v):
    """Convert a DataFrame cell to a JSON-safe value (no NaN/NA leakage).

    pandas 3.x keeps NaN through ``astype(str)``, which Flask then serializes as
    a bare ``NaN`` token — invalid JSON. Normalize missing values to None here.
    """
    if v is None:
        return None
    try:
        if isinstance(v, float) and math.isnan(v):
            return None
    except Exception:  # noqa: BLE001
        pass
    return str(v)


def _df_records(df, limit=25):
    if df is None or len(df) == 0:
        return []
    rows = df.head(limit).to_dict(orient="records")
    return [{k: _cell(v) for k, v in row.items()} for row in rows]


def role_for(hostname):
    h = hostname.lower()
    for frag, role in ROLE_HINTS.items():
        if frag in h:
            return role
    return "Network"


class CamNetEngine:
    def __init__(self, host=BATFISH_HOST):
        self.host = host
        self.bf = None
        os.makedirs(TOPO_DIR, exist_ok=True)

    # ---- connection -------------------------------------------------------
    def connect(self, retries=40, delay=3):
        last = None
        for _ in range(retries):
            try:
                bf = Session(host=self.host)
                bf.set_network(NETWORK)
                self.bf = bf
                return True
            except Exception as e:  # noqa: BLE001
                last = e
                time.sleep(delay)
        raise RuntimeError(f"Could not connect to Batfish at {self.host}: {last}")

    def ready(self):
        try:
            if self.bf is None:
                self.connect(retries=1, delay=0)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _ensure(self):
        if self.bf is None:
            self.connect()

    # ---- snapshot ---------------------------------------------------------
    def _build_snapshot_dir(self, config_dir):
        tmp = tempfile.mkdtemp(prefix="camnet_snap_")
        cfg_out = os.path.join(tmp, "configs")
        os.makedirs(cfg_out, exist_ok=True)
        src = config_dir
        sub = os.path.join(config_dir, "configs")
        if os.path.isdir(sub):
            src = sub
        n = 0
        for fn in sorted(os.listdir(src)):
            fp = os.path.join(src, fn)
            if os.path.isfile(fp):
                shutil.copy(fp, os.path.join(cfg_out, fn))
                n += 1
        if n == 0:
            raise RuntimeError(f"No config files found in {src}")
        return tmp

    def load_snapshot(self, config_dir):
        self._ensure()
        snap = self._build_snapshot_dir(config_dir)
        self.bf.init_snapshot(snap, name=SNAPSHOT, overwrite=True)
        return True

    # ---- inventory --------------------------------------------------------
    def list_devices(self):
        df = self.bf.q.nodeProperties().answer().frame()
        return sorted(df["Node"].tolist()) if len(df) else []

    def interface_addresses(self):
        """Return {hostname: [{interface, address}]} for inventory/sidebar."""
        out = {}
        try:
            df = self.bf.q.interfaceProperties().answer().frame()
        except Exception:  # noqa: BLE001
            return out
        for _, row in df.iterrows():
            iface = str(row.get("Interface", ""))
            node = iface.split("[")[0]
            m = re.search(r"\[(.*)\]", iface)
            ifname = m.group(1) if m else iface
            prefixes = re.findall(r"\d+\.\d+\.\d+\.\d+/\d+",
                                  str(row.get("All_Prefixes", "")))
            for p in prefixes:
                out.setdefault(node, []).append({"interface": ifname, "address": p})
        return out

    def device_config(self, hostname):
        np_df = self.bf.q.nodeProperties(nodes=hostname).answer().frame()
        if_df = self.bf.q.interfaceProperties(nodes=hostname).answer().frame()
        return {
            "hostname": hostname,
            "role": role_for(hostname),
            "properties": _df_records(np_df, 5),
            "interfaces": _df_records(if_df, 50),
        }

    def device_details(self, hostname):
        """Rich per-device data: interfaces, routes, ACLs, BGP/OSPF, protocols."""
        q = self.bf.q

        def safe(fn, limit=300):
            try:
                return _df_records(fn().answer().frame(), limit)
            except Exception:  # noqa: BLE001
                return []

        interfaces = safe(lambda: q.interfaceProperties(nodes=hostname))
        routes = safe(lambda: q.routes(nodes=hostname))
        bgp_peers = safe(lambda: q.bgpPeerConfiguration(nodes=hostname))
        ospf = safe(lambda: q.ospfInterfaceConfiguration(nodes=hostname))
        np_list = safe(lambda: q.nodeProperties(nodes=hostname), 1)
        node = np_list[0] if np_list else {}

        protocols = []
        if bgp_peers:
            protocols.append("BGP")
        if ospf:
            protocols.append("OSPF")
        protocols.append("Connected/Static")

        return {
            "hostname": hostname,
            "role": role_for(hostname),
            "protocols": protocols,
            "config_format": node.get("Configuration_Format", ""),
            "interfaces": interfaces,
            "routes": routes,
            "bgp_peers": bgp_peers,
            "ospf": ospf,
            "acls": self._acls(hostname),
        }

    def _acls(self, hostname):
        out = []
        try:
            df = self.bf.q.namedStructures(
                nodes=hostname, structureTypes="IP_Access_List").answer().frame()
            for _, row in df.iterrows():
                out.append({
                    "name": str(row.get("Structure_Name")),
                    "definition": str(row.get("Structure_Definition"))[:2000],
                })
        except Exception:  # noqa: BLE001
            pass
        return out

    # ---- assertions -------------------------------------------------------
    def default_asserts(self):
        results = {}
        q = self.bf.q

        def run(key, func, empty_good=False):
            try:
                df = func().answer().frame()
                entry = {"count": len(df), "records": _df_records(df)}
                if empty_good:
                    entry["passed"] = len(df) == 0
                results[key] = entry
                return df
            except Exception as e:  # noqa: BLE001
                results[key] = {"count": 0, "records": [], "error": str(e)}
                return None

        fp = run("fileParseStatus", q.fileParseStatus)
        if fp is not None and len(fp):
            results["fileParseStatus"]["passed"] = bool((fp["Status"] == "PASSED").all())

        run("initIssues", q.initIssues, empty_good=True)
        run("undefinedReferences", q.undefinedReferences, empty_good=True)
        run("unusedStructures", q.unusedStructures, empty_good=True)
        run("nodeProperties", q.nodeProperties)
        run("interfaceProperties", q.interfaceProperties)

        run("bgpSessionCompatibility", q.bgpSessionCompatibility)
        bss = run("bgpSessionStatus", q.bgpSessionStatus)
        if bss is not None and "Established_Status" in getattr(bss, "columns", []):
            results["bgpSessionStatus"]["passed"] = (
                len(bss) == 0 or bool((bss["Established_Status"] == "ESTABLISHED").all())
            )

        run("ospfSessionCompatibility", q.ospfSessionCompatibility)
        run("mlagProperties", q.mlagProperties)

        results["duplicateRouterIds"] = self._duplicate_router_ids()

        failed = [k for k, v in results.items()
                  if isinstance(v, dict) and v.get("passed") is False]
        results["_summary"] = {
            "passed": len(failed) == 0,
            "failed_checks": failed,
            "total_checks": len([k for k in results if k != "_summary"]),
        }
        return results

    def _duplicate_router_ids(self):
        try:
            df = self.bf.q.bgpProcessConfiguration().answer().frame()
            seen = {}
            for _, row in df.iterrows():
                rid = str(row.get("Router_ID"))
                node = str(row.get("Node"))
                seen.setdefault(rid, set()).add(node)
            dups = {k: v for k, v in seen.items() if len(v) > 1}
            records = [{"Router_ID": k, "Nodes": ", ".join(sorted(v))}
                       for k, v in dups.items()]
            return {"count": len(records), "records": records,
                    "passed": len(records) == 0}
        except Exception as e:  # noqa: BLE001
            return {"count": 0, "records": [], "passed": True, "error": str(e)}

    # ---- reachability -----------------------------------------------------
    def ping_check(self, source, destination):
        try:
            ans = self.bf.q.reachability(
                headers=HeaderConstraints(srcIps=source, dstIps=destination),
                actions="SUCCESS",
            ).answer().frame()
            return {
                "source": source, "destination": destination,
                "pingable": len(ans) > 0, "flows": _df_records(ans, 5),
            }
        except Exception as e:  # noqa: BLE001
            return {"source": source, "destination": destination,
                    "pingable": False, "flows": [], "error": str(e)}

    # ---- topology ---------------------------------------------------------
    ROLE_COLORS = {
        "Traffic control": "#c0392b",
        "Surveillance": "#27ae60",
        "Digital payments": "#2980b9",
        "Network": "#7f8c8d",
    }

    @staticmethod
    def _host(val):
        s = str(val)
        m = re.match(r"([^\[]+)\[(.*)\]", s)
        if m:
            return m.group(1), m.group(2)
        return s, ""

    def generate_topologies(self):
        devices = self.list_devices()
        roles = {d: role_for(d) for d in devices}
        topo = {
            "layer3": self._topo_layer3(devices),
            "ospf": self._topo_ospf(devices),
            "bgp": self._topo_bgp(devices),
        }
        for name in ("layer3", "ospf", "bgp"):
            try:
                self._draw_rich(name, devices, roles, topo[name].get("edges", []))
                topo[name]["image"] = f"/api/topology/{name}"
            except Exception as e:  # noqa: BLE001
                topo[name]["image"] = None
                topo[name].setdefault("error", str(e))
        return topo

    @staticmethod
    def _dedupe(raw):
        """Merge undirected edges; a faulty direction makes the edge faulty."""
        merged = {}
        for e in raw:
            key = tuple(sorted([e["a"], e["b"]]))
            if key not in merged or not e["up"]:
                merged[key] = e
        return list(merged.values())

    def _topo_layer3(self, devices):
        edges = []
        try:
            df = self.bf.q.layer3Edges().answer().frame()
        except Exception as e:  # noqa: BLE001
            return {"edges": [], "error": str(e)}
        for _, row in df.iterrows():
            a, ai = self._host(row.get("Interface"))
            b, bi = self._host(row.get("Remote_Interface"))
            if a in devices and b in devices and a != b:
                edges.append({
                    "a": a, "b": b, "up": True, "status": "UP",
                    "title": f"L3 link · {a} [{ai}] ↔ {b} [{bi}]",
                    "detail": {"Type": "Layer-3 link", a: ai, b: bi,
                               "Status": "UP"},
                })
        return {"edges": self._dedupe(edges)}

    def _topo_ospf(self, devices):
        edges = []
        try:
            df = self.bf.q.ospfSessionCompatibility().answer().frame()
        except Exception as e:  # noqa: BLE001
            return {"edges": [], "error": str(e)}
        for _, row in df.iterrows():
            a, ai = self._host(row.get("Interface"))
            b, bi = self._host(row.get("Remote_Interface"))
            status = str(row.get("Session_Status", "UNKNOWN"))
            if a in devices and b in devices and a != b:
                edges.append({
                    "a": a, "b": b, "up": status == "ESTABLISHED", "status": status,
                    "title": f"OSPF · {a} ↔ {b} · {status}",
                    "detail": {"Type": "OSPF adjacency",
                               "Interfaces": f"{ai} ↔ {bi}",
                               "Area": str(row.get("Area", "")),
                               "Status": status},
                })
        return {"edges": self._dedupe(edges)}

    def _topo_bgp(self, devices):
        edges = []
        try:
            df = self.bf.q.bgpSessionStatus().answer().frame()
        except Exception as e:  # noqa: BLE001
            return {"edges": [], "error": str(e)}
        for _, row in df.iterrows():
            a = str(row.get("Node"))
            b = str(row.get("Remote_Node"))
            status = str(row.get("Established_Status", "UNKNOWN"))
            if a in devices and b in devices and a != b:
                edges.append({
                    "a": a, "b": b, "up": status == "ESTABLISHED", "status": status,
                    "title": f"BGP · {a}(AS{row.get('Local_AS')}) ↔ "
                             f"{b}(AS{row.get('Remote_AS')}) · {status}",
                    "detail": {"Type": str(row.get("Session_Type", "BGP")),
                               "Local AS": str(row.get("Local_AS", "")),
                               "Remote AS": str(row.get("Remote_AS", "")),
                               "Address families": str(row.get("Address_Families", "")),
                               "Status": status},
                })
        return {"edges": self._dedupe(edges)}

    def _draw_rich(self, name, devices, roles, edges):
        from matplotlib.lines import Line2D
        g = nx.Graph()
        g.add_nodes_from(devices)
        for e in edges:
            g.add_edge(e["a"], e["b"], up=e["up"], status=e["status"])
        plt.figure(figsize=(7.4, 5.6))
        plt.gcf().set_facecolor("white")
        if len(g.nodes) == 0:
            plt.text(0.5, 0.5, "no data", ha="center")
        else:
            pos = nx.spring_layout(g, seed=42, k=1.5)
            up_e = [(u, v) for u, v, d in g.edges(data=True) if d.get("up")]
            bad_e = [(u, v) for u, v, d in g.edges(data=True) if not d.get("up")]
            nx.draw_networkx_edges(g, pos, edgelist=up_e,
                                   edge_color="#2e9e7a", width=2.4)
            nx.draw_networkx_edges(g, pos, edgelist=bad_e,
                                   edge_color="#c0392b", width=3.2, style="dashed")
            ncolors = [self.ROLE_COLORS.get(roles.get(n, "Network"), "#7f8c8d")
                       for n in g.nodes]
            nx.draw_networkx_nodes(g, pos, node_color=ncolors,
                                   edgecolors="#222", node_size=2700, linewidths=1.5)
            nx.draw_networkx_labels(g, pos, font_color="white", font_size=8,
                                    font_weight="bold")
            elabels = {(u, v): d.get("status", "")
                       for u, v, d in g.edges(data=True)}
            nx.draw_networkx_edge_labels(
                g, pos, edge_labels=elabels, font_size=6, font_color="#333",
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.75))
        plt.title(f"{name.upper()} topology", color="#1a5276", fontsize=13,
                  fontweight="bold")
        plt.legend(handles=[
            Line2D([0], [0], color="#2e9e7a", lw=2.4, label="up / established"),
            Line2D([0], [0], color="#c0392b", lw=3, ls="--", label="faulty / down"),
        ], loc="lower right", fontsize=7, framealpha=0.9)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(TOPO_DIR, f"{name}.png"), dpi=165, facecolor="white")
        plt.close()

    # ---- what-if simulation ----------------------------------------------
    def simulate_change(self, config_dir, host, old_text, new_text):
        """Apply a hypothetical text change to `host`'s config in a throwaway
        snapshot and return the candidate assertion set (no persistence)."""
        src = config_dir
        sub = os.path.join(config_dir, "configs")
        if os.path.isdir(sub):
            src = sub
        files, target_fn = {}, None
        for fn in sorted(os.listdir(src)):
            fp = os.path.join(src, fn)
            if not os.path.isfile(fp):
                continue
            with open(fp, errors="ignore") as f:
                content = f.read()
            files[fn] = content
            stem = os.path.splitext(fn)[0]
            if target_fn is None and (
                    stem == host or
                    re.search(rf"^hostname\s+{re.escape(host)}\b", content, re.M)):
                target_fn = fn
        if target_fn is None:
            return {"error": f"device '{host}' not found in current configs"}

        original = files[target_fn]
        if old_text and old_text in original:
            files[target_fn] = original.replace(old_text, new_text)
        elif old_text:
            return {"error": f"text '{old_text}' not found in {target_fn}; "
                             "call get_config first and use exact text."}
        else:
            files[target_fn] = new_text

        tmp = tempfile.mkdtemp(prefix="camnet_sim_")
        cfgdir = os.path.join(tmp, "configs")
        os.makedirs(cfgdir)
        for fn, content in files.items():
            with open(os.path.join(cfgdir, fn), "w") as f:
                f.write(content)

        # Use a SEPARATE Batfish session + network so the live snapshot is
        # never disturbed: upload the same configs (with the edit) and re-assert.
        sim_bf = Session(host=self.host)
        sim_bf.set_network(NETWORK + "_sim")
        sim_bf.init_snapshot(tmp, name="cand", overwrite=True)
        saved = self.bf
        self.bf = sim_bf
        try:
            cand = self.default_asserts()
        finally:
            self.bf = saved
        return {"applied": True, "file": target_fn, "candidate_asserts": cand}

    # ---- orchestration ----------------------------------------------------
    def analyze(self, config_dir, ip_ping_check_flag=False, ip_map=None,
                give_topology=True, config_source="local"):
        self.load_snapshot(config_dir)
        devices = self.list_devices()
        out = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "network": NETWORK,
            "snapshot": SNAPSHOT,
            "config_source": config_source,
            "devices": devices,
            "device_roles": {d: role_for(d) for d in devices},
            "default_asserts": self.default_asserts(),
        }
        if ip_ping_check_flag and ip_map:
            out["ping_check"] = self.ping_check(
                ip_map.get("source"), ip_map.get("destination"))
        if give_topology:
            out["topologies"] = self.generate_topologies()
        return out
