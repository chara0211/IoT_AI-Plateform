"""
Network Behavior Graph Analysis (Enhanced)
- Builds a directed comm graph from telemetry + MQTT comm_target
- Detects: Lateral movement, botnet recruitment, coordinated attacks
- Exports: nodes + links usable by frontend (react-force-graph)
- Visualizes: highlighted edges, node roles, traffic sizing
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


# -----------------------------
# Helpers
# -----------------------------

def _to_dt(x):
    try:
        return pd.to_datetime(x, utc=True, errors="coerce")
    except Exception:
        return pd.NaT


def _is_anomalous_label(row: pd.Series) -> bool:
    """
    Accepts multiple conventions:
    - label: "Normal" / "Anomaly"
    - attack_label: "normal" / "dos" / "injection" / "spoofing"
    - is_anomalous: True/False
    - is_anomaly: True/False
    """
    if "is_anomalous" in row and pd.notna(row["is_anomalous"]):
        return bool(row["is_anomalous"])
    if "is_anomaly" in row and pd.notna(row["is_anomaly"]):
        return bool(row["is_anomaly"])

    lbl = str(row.get("label", "")).strip().lower()
    if lbl in ("anomaly", "anomalous", "attack", "malicious"):
        return True
    if lbl in ("normal", "ok", "benign"):
        return False

    a = str(row.get("attack_label", "")).strip().lower()
    if a and a != "normal":
        return True

    return False


def _safe_num(x, default=0.0):
    try:
        if pd.isna(x):
            return default
        return float(x)
    except Exception:
        return default


# -----------------------------
# Enhanced Analyzer
# -----------------------------

@dataclass
class EdgeAgg:
    count: int = 0
    total_packets: int = 0
    total_out_kb: int = 0
    total_in_kb: int = 0
    last_seen: Optional[pd.Timestamp] = None
    edge_type: str = "inferred"  # "explicit" | "inferred" | "c2" | "lateral"


class NetworkGraphAnalyzer:
    """
    Enhanced graph-based network behavior analyzer.

    Key idea:
    - If telemetry contains `comm_target`, we treat it as TRUE communication edge.
    - Otherwise, we fall back to inference heuristics.
    """

    def __init__(
        self,
        use_comm_target: bool = True,
        inference_enabled: bool = True,
        inference_time_window_sec: int = 30,
        inference_threshold: float = 0.55,
    ):
        self.graph = nx.DiGraph()
        self.edge_agg: Dict[Tuple[str, str], EdgeAgg] = {}

        self.use_comm_target = use_comm_target
        self.inference_enabled = inference_enabled
        self.inference_time_window_sec = inference_time_window_sec
        self.inference_threshold = inference_threshold

    # -----------------------------
    # Build graph
    # -----------------------------

    def build_communication_graph(self, telemetry_data: pd.DataFrame) -> nx.DiGraph:
        """
        Build a directed graph.
        Nodes: devices
        Edges: communications (explicit via comm_target OR inferred)
        """
        df = telemetry_data.copy()

        # Normalize timestamp
        if "timestamp" not in df.columns:
            df["timestamp"] = pd.Timestamp.now(tz="UTC")
        df["timestamp"] = df["timestamp"].apply(_to_dt).fillna(pd.Timestamp.now(tz="UTC"))

        # Create graph
        G = nx.DiGraph()

        # Add nodes (aggregated attributes)
        for _, row in df.iterrows():
            device_id = str(row.get("device_id", "")).strip()
            if not device_id:
                continue

            if device_id not in G.nodes:
                G.add_node(
                    device_id,
                    device_type=str(row.get("device_type", "unknown")),
                    is_anomalous=_is_anomalous_label(row),
                    avg_cpu=_safe_num(row.get("cpu_usage", 0)),
                    avg_memory=_safe_num(row.get("memory_usage", 0)),
                    total_traffic=int(_safe_num(row.get("network_in_kb", 0)) + _safe_num(row.get("network_out_kb", 0))),
                    last_seen=row["timestamp"],
                )
            else:
                # update rolling averages + traffic
                n = G.nodes[device_id]
                n["is_anomalous"] = n["is_anomalous"] or _is_anomalous_label(row)
                n["avg_cpu"] = (n["avg_cpu"] + _safe_num(row.get("cpu_usage", 0))) / 2.0
                n["avg_memory"] = (n["avg_memory"] + _safe_num(row.get("memory_usage", 0))) / 2.0
                n["total_traffic"] = int(n["total_traffic"] + _safe_num(row.get("network_in_kb", 0)) + _safe_num(row.get("network_out_kb", 0)))
                n["last_seen"] = max(n.get("last_seen", row["timestamp"]), row["timestamp"])

        # Add edges (explicit)
        if self.use_comm_target and "comm_target" in df.columns:
            for _, row in df.iterrows():
                src = str(row.get("device_id", "")).strip()
                dst = row.get("comm_target", None)
                if dst is None:
                    continue
                dst = str(dst).strip()
                if not src or not dst or src == dst:
                    continue

                if dst not in G.nodes:
                    G.add_node(dst, device_type="unknown", is_anomalous=False, avg_cpu=0, avg_memory=0, total_traffic=0, last_seen=row["timestamp"])

                self._add_or_update_edge(
                    G,
                    src,
                    dst,
                    row=row,
                    edge_type="explicit",
                    weight=1.0,
                )

        # Add edges (inferred heuristic fallback)
        if self.inference_enabled:
            # We only infer among records close in time
            df_sorted = df.sort_values("timestamp")
            rows = list(df_sorted.itertuples(index=False))
            for i in range(len(rows)):
                r1 = rows[i]
                for j in range(i + 1, len(rows)):
                    r2 = rows[j]
                    dt = (r2.timestamp - r1.timestamp).total_seconds()
                    if dt > self.inference_time_window_sec:
                        break

                    # infer both directions (could be chatty)
                    s1 = getattr(r1, "device_id", None)
                    s2 = getattr(r2, "device_id", None)
                    if not s1 or not s2 or s1 == s2:
                        continue

                    score_12 = self._calculate_communication_likelihood(r1, r2)
                    if score_12 >= self.inference_threshold:
                        self._add_or_update_edge(G, str(s1), str(s2), row=r1._asdict(), edge_type="inferred", weight=score_12)

                    score_21 = self._calculate_communication_likelihood(r2, r1)
                    if score_21 >= self.inference_threshold:
                        self._add_or_update_edge(G, str(s2), str(s1), row=r2._asdict(), edge_type="inferred", weight=score_21)

        self.graph = G
        return G

    def _add_or_update_edge(self, G: nx.DiGraph, src: str, dst: str, row, edge_type: str, weight: float):
        pkt = int(_safe_num(row.get("packet_rate", 0), 0))
        out_kb = int(_safe_num(row.get("network_out_kb", 0), 0))
        in_kb = int(_safe_num(row.get("network_in_kb", 0), 0))
        ts = row.get("timestamp", None)
        ts = _to_dt(ts) if ts is not None else pd.Timestamp.now(tz="UTC")

        key = (src, dst)
        agg = self.edge_agg.get(key, EdgeAgg(edge_type=edge_type))
        agg.count += 1
        agg.total_packets += pkt
        agg.total_out_kb += out_kb
        agg.total_in_kb += in_kb
        agg.last_seen = ts if agg.last_seen is None else max(agg.last_seen, ts)
        agg.edge_type = edge_type  # keep latest type if updated
        self.edge_agg[key] = agg

        # Graph edge attributes
        if G.has_edge(src, dst):
            e = G[src][dst]
            e["weight"] = max(float(e.get("weight", 0.0)), float(weight))
            e["count"] = agg.count
            e["total_packets"] = agg.total_packets
            e["total_out_kb"] = agg.total_out_kb
            e["last_seen"] = agg.last_seen
            e["type"] = agg.edge_type
        else:
            G.add_edge(
                src,
                dst,
                weight=float(weight),
                count=agg.count,
                total_packets=agg.total_packets,
                total_out_kb=agg.total_out_kb,
                last_seen=agg.last_seen,
                type=agg.edge_type,
            )

    def _calculate_communication_likelihood(self, device1, device2) -> float:
        """
        Inference heuristic (kept, but improved):
        - high outbound + other inbound
        - plus similarity ratio
        """
        d1 = device1 if isinstance(device1, dict) else device1._asdict()
        d2 = device2 if isinstance(device2, dict) else device2._asdict()

        net_out1 = _safe_num(d1.get("network_out_kb", 0))
        net_in2 = _safe_num(d2.get("network_in_kb", 0))

        if net_out1 < 250 or net_in2 < 250:
            return 0.0

        similarity = min(net_out1, net_in2) / max(net_out1, net_in2)
        # boost if high packet rates (chatty)
        pkt1 = _safe_num(d1.get("packet_rate", 0))
        pkt2 = _safe_num(d2.get("packet_rate", 0))
        pkt_boost = min((pkt1 + pkt2) / 2000.0, 1.0)  # 0..1

        return float(0.75 * similarity + 0.25 * pkt_boost)

    # -----------------------------
    # Detection
    # -----------------------------

    def detect_botnet_patterns(self) -> Dict:
        """
        Botnet / C2 detection:
        - hub-like nodes with high out-degree
        - fanout ratio out/(in+1)
        """
        results = {
            "botnet_detected": False,
            "c2_candidates": [],
            "recruited_devices": [],
            "confidence": 0.0,
        }

        if self.graph.number_of_nodes() < 4:
            return results

        out_degree = dict(self.graph.out_degree())
        in_degree = dict(self.graph.in_degree())

        N = self.graph.number_of_nodes()

        for node in self.graph.nodes:
            out_ = out_degree.get(node, 0)
            in_ = in_degree.get(node, 0)

            # Candidate hub
            if out_ >= max(3, int(0.25 * N)) and (out_ / (in_ + 1)) > 2.0:
                c2_score = out_ / max(N, 1)
                results["c2_candidates"].append(
                    {
                        "device_id": node,
                        "out_connections": out_,
                        "in_connections": in_,
                        "c2_score": round(float(c2_score), 3),
                    }
                )

        if results["c2_candidates"]:
            results["botnet_detected"] = True
            # recruited = union of successors
            rec = set()
            for c2 in results["c2_candidates"]:
                for s in self.graph.successors(c2["device_id"]):
                    rec.add(s)
                    # label those edges as c2 for visualization export
                    if self.graph.has_edge(c2["device_id"], s):
                        self.graph[c2["device_id"]][s]["type"] = "c2"
            results["recruited_devices"] = sorted(list(rec))
            results["confidence"] = 0.85

        return results

    def detect_lateral_movement(self, cutoff: int = 4) -> Dict:
        """
        Lateral movement:
        - find short paths among anomalous nodes
        """
        results = {
            "lateral_movement_detected": False,
            "attack_paths": [],
            "entry_point": None,
            "compromised_devices": [],
        }

        anomalous = [n for n in self.graph.nodes if self.graph.nodes[n].get("is_anomalous", False)]
        if len(anomalous) < 2:
            return results

        paths_found = []
        for i in range(len(anomalous)):
            for j in range(len(anomalous)):
                if i == j:
                    continue
                src = anomalous[i]
                dst = anomalous[j]
                try:
                    path = nx.shortest_path(self.graph, src, dst)
                    if 2 <= len(path) <= cutoff:
                        paths_found.append(path)
                except Exception:
                    continue

        # unique paths
        uniq = []
        seen = set()
        for p in paths_found:
            t = tuple(p)
            if t not in seen:
                seen.add(t)
                uniq.append(p)

        if uniq:
            results["lateral_movement_detected"] = True
            for p in uniq[:20]:
                results["attack_paths"].append(
                    {
                        "path": p,
                        "length": len(p),
                        "entry_point": p[0],
                        "final_target": p[-1],
                    }
                )

                # mark edges as lateral for export + visualization
                for k in range(len(p) - 1):
                    u, v = p[k], p[k + 1]
                    if self.graph.has_edge(u, v):
                        self.graph[u][v]["type"] = "lateral"

            # entry point = most frequent start
            starts = [p[0] for p in uniq]
            entry = max(set(starts), key=starts.count)
            results["entry_point"] = entry

            compromised = set()
            for p in uniq:
                compromised.update(p)
            results["compromised_devices"] = sorted(list(compromised))

        return results

    def detect_coordinated_attack(self, anomaly_ratio_threshold: float = 0.20) -> Dict:
        """
        Coordinated attack:
        - if too many anomalous nodes in current snapshot
        """
        results = {
            "coordinated_attack": False,
            "attack_wave": 0,
            "affected_devices": [],
            "attack_start_time": None,
        }

        N = self.graph.number_of_nodes()
        if N == 0:
            return results

        anomalous = [n for n in self.graph.nodes if self.graph.nodes[n].get("is_anomalous", False)]
        ratio = len(anomalous) / N

        if len(anomalous) >= 3 and ratio >= anomaly_ratio_threshold:
            results["coordinated_attack"] = True
            results["attack_wave"] = len(anomalous)
            results["affected_devices"] = anomalous
            results["attack_start_time"] = pd.Timestamp.now(tz="UTC").isoformat()

        return results

    def identify_critical_devices(self, min_score: float = 0.08) -> List[Dict]:
        """
        Critical devices = high betweenness centrality (bridges).
        """
        if self.graph.number_of_nodes() < 3:
            return []

        betweenness = nx.betweenness_centrality(self.graph)
        critical = []
        for dev, score in sorted(betweenness.items(), key=lambda x: x[1], reverse=True):
            if score >= min_score:
                critical.append(
                    {
                        "device_id": dev,
                        "criticality_score": round(float(score), 3),
                        "device_type": self.graph.nodes[dev].get("device_type", "unknown"),
                        "is_anomalous": bool(self.graph.nodes[dev].get("is_anomalous", False)),
                    }
                )
        return critical[:10]

    def detect_isolated_devices(self) -> List[str]:
        isolated = []
        for n in self.graph.nodes:
            if self.graph.in_degree(n) + self.graph.out_degree(n) <= 1:
                isolated.append(n)
        return isolated

    def get_network_health_score(self) -> float:
        """
        Health score:
        - penalize anomaly ratio
        - reward connectivity
        - penalize too many isolated nodes
        """
        N = self.graph.number_of_nodes()
        if N == 0:
            return 100.0

        anomalous = sum(1 for n in self.graph.nodes if self.graph.nodes[n].get("is_anomalous", False))
        anomaly_ratio = anomalous / N

        avg_degree = sum(dict(self.graph.degree()).values()) / N
        connectivity = min(avg_degree / 6.0, 1.0)

        isolated = len(self.detect_isolated_devices())
        isolated_ratio = isolated / N

        health = (1 - anomaly_ratio) * 65 + connectivity * 25 + (1 - isolated_ratio) * 10
        return round(float(max(0.0, min(100.0, health))), 2)

    # -----------------------------
    # Export for frontend
    # -----------------------------

    def export_for_frontend(self) -> Dict:
        """
        Build nodes[] + links[] for react-force-graph.
        Groups:
          - normal | anomalous | c2 | critical
        Link types:
          - inferred | explicit | c2 | lateral
        """
        # mark c2/critical nodes with groups
        node_group: Dict[str, str] = {}
        for n in self.graph.nodes:
            node_group[n] = "anomalous" if self.graph.nodes[n].get("is_anomalous", False) else "normal"

        # critical overrides normal
        critical = self.identify_critical_devices()
        for c in critical:
            if node_group.get(c["device_id"]) != "anomalous":
                node_group[c["device_id"]] = "critical"

        # c2 overrides everything
        bot = self.detect_botnet_patterns()
        for c2 in bot.get("c2_candidates", []):
            node_group[c2["device_id"]] = "c2"

        nodes = []
        for n in self.graph.nodes:
            nodes.append(
                {
                    "id": n,
                    "group": node_group.get(n, "normal"),
                    "device_type": self.graph.nodes[n].get("device_type", "unknown"),
                    "is_anomalous": bool(self.graph.nodes[n].get("is_anomalous", False)),
                    "traffic": int(self.graph.nodes[n].get("total_traffic", 0)),
                    "cpu": float(self.graph.nodes[n].get("avg_cpu", 0.0)),
                    "memory": float(self.graph.nodes[n].get("avg_memory", 0.0)),
                    "in": int(self.graph.in_degree(n)),
                    "out": int(self.graph.out_degree(n)),
                }
            )

        links = []
        for u, v, d in self.graph.edges(data=True):
            links.append(
                {
                    "source": u,
                    "target": v,
                    "type": d.get("type", "inferred"),
                    "weight": float(d.get("weight", 1.0)),
                    "count": int(d.get("count", 1)),
                    "total_packets": int(d.get("total_packets", 0)),
                    "total_out_kb": int(d.get("total_out_kb", 0)),
                }
            )

        return {"nodes": nodes, "links": links}

    # -----------------------------
    # Full analysis
    # -----------------------------

    def analyze_network(self, telemetry_data: pd.DataFrame) -> Dict:
        print("🔍 Building communication graph...")
        self.build_communication_graph(telemetry_data)

        print("🤖 Detecting botnet patterns...")
        botnet = self.detect_botnet_patterns()

        print("🔄 Detecting lateral movement...")
        lateral = self.detect_lateral_movement()

        print("⚡ Detecting coordinated attacks...")
        coordinated = self.detect_coordinated_attack()

        print("🎯 Identifying critical devices...")
        critical = self.identify_critical_devices()

        print("📊 Calculating network health...")
        health = self.get_network_health_score()

        isolated = self.detect_isolated_devices()

        export = self.export_for_frontend()

        return {
            "network_summary": {
                "total_devices": int(self.graph.number_of_nodes()),
                "total_connections": int(self.graph.number_of_edges()),
                "health_score": float(health),
                "isolated_devices": isolated,
            },
            "botnet_analysis": botnet,
            "lateral_movement": lateral,
            "coordinated_attack": coordinated,
            "critical_devices": critical,
            # NEW: frontend-ready graph payload
            "graph": export,
        }

    # -----------------------------
    # Visualization
    # -----------------------------

    def visualize_network(self, save_path: str = "network_graph.png", max_nodes: int = 200):
        """
        Matplotlib visualization:
        - Node color by group: normal/anomalous/c2/critical
        - Edge color by type: inferred/explicit/c2/lateral
        - Node size by traffic
        - Edge width by volume/count
        """
        if self.graph.number_of_nodes() == 0:
            print("⚠️ No nodes to visualize")
            return

        # Optionally downsample for readability
        G = self.graph
        if G.number_of_nodes() > max_nodes:
            # keep top nodes by degree
            deg = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
            keep = set([n for n, _ in deg])
            G = G.subgraph(keep).copy()

        # build groups using exporter
        exp = self.export_for_frontend()
        group_map = {n["id"]: n["group"] for n in exp["nodes"]}

        plt.figure(figsize=(16, 11))
        pos = nx.spring_layout(G, k=1.5, iterations=60, seed=42)

        # node colors
        def node_color(n):
            g = group_map.get(n, "normal")
            if g == "c2":
                return "#f97316"  # orange
            if g == "critical":
                return "#facc15"  # yellow
            if g == "anomalous":
                return "#ef4444"  # red
            return "#22c55e"     # green

        node_colors = [node_color(n) for n in G.nodes]

        # node sizes (traffic)
        sizes = []
        for n in G.nodes:
            t = int(_safe_num(self.graph.nodes[n].get("total_traffic", 0), 0))
            sizes.append(max(80, min(1800, 80 + t * 0.4)))

        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=sizes, alpha=0.85)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")

        # edge styling by type
        edge_colors = []
        edge_widths = []
        for u, v, d in G.edges(data=True):
            typ = d.get("type", "inferred")
            if typ == "lateral":
                edge_colors.append("#22d3ee")  # cyan
            elif typ == "c2":
                edge_colors.append("#fb923c")  # orange
            elif typ == "explicit":
                edge_colors.append("#e5e7eb")  # light gray
            else:
                edge_colors.append("#6b7280")  # gray

            # width = mix of count + out_kb
            count = int(d.get("count", 1))
            out_kb = int(d.get("total_out_kb", 0))
            w = 0.8 + min(5.0, (count / 10.0) + (out_kb / 3000.0))
            edge_widths.append(w)

        nx.draw_networkx_edges(
            G,
            pos,
            width=edge_widths,
            edge_color=edge_colors,
            alpha=0.55,
            arrows=True,
            arrowsize=14,
            connectionstyle="arc3,rad=0.12",
        )

        plt.title(
            "IoT Network Communication Graph\n"
            "Nodes: green=normal, red=anomalous, yellow=critical, orange=C2 | "
            "Edges: gray=inferred, white=explicit, cyan=lateral, orange=C2",
            fontsize=13,
            fontweight="bold",
        )
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(save_path, dpi=250, bbox_inches="tight")
        plt.close()
        print(f"✅ Network visualization saved: {save_path}")


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    print("=" * 80)
    print("🕸️ NETWORK BEHAVIOR GRAPH ANALYSIS (ENHANCED)")
    print("=" * 80)

    df = pd.read_csv("data/smart_system_anomaly_dataset.csv")

    # Ensure optional fields exist for demo compatibility
    if "label" not in df.columns:
        df["label"] = "Normal"
    if "timestamp" not in df.columns:
        df["timestamp"] = pd.Timestamp.now(tz="UTC").isoformat()

    sample = df.sample(n=min(200, len(df)), random_state=42)

    analyzer = NetworkGraphAnalyzer(
        use_comm_target=True,
        inference_enabled=True,
        inference_time_window_sec=30,
        inference_threshold=0.55,
    )

    results = analyzer.analyze_network(sample)

    print("\n🌐 Network Summary:")
    for k, v in results["network_summary"].items():
        print(f"   {k}: {v}")

    print("\n🤖 Botnet Detection:")
    if results["botnet_analysis"]["botnet_detected"]:
        print("   ⚠️ BOTNET DETECTED!")
        for c2 in results["botnet_analysis"]["c2_candidates"]:
            print(f"   C2: {c2['device_id']} | score={c2['c2_score']} | out={c2['out_connections']}")
    else:
        print("   ✅ No botnet detected")

    print("\n🔄 Lateral Movement:")
    if results["lateral_movement"]["lateral_movement_detected"]:
        print("   ⚠️ LATERAL MOVEMENT DETECTED!")
        print(f"   Entry point: {results['lateral_movement']['entry_point']}")
        for p in results["lateral_movement"]["attack_paths"][:5]:
            print("   Path:", " → ".join(p["path"]))
    else:
        print("   ✅ No lateral movement detected")

    print("\n⚡ Coordinated Attack:")
    if results["coordinated_attack"]["coordinated_attack"]:
        print("   ⚠️ COORDINATED ATTACK DETECTED!")
        print(f"   Affected devices: {results['coordinated_attack']['attack_wave']}")
    else:
        print("   ✅ No coordinated attack detected")

    print("\n🎯 Critical Devices (top 5):")
    for d in results["critical_devices"][:5]:
        print(f"   {d['device_id']} | score={d['criticality_score']} | anomalous={d['is_anomalous']}")

    print("\n📊 Generating visualization...")
    analyzer.visualize_network("network_analysis.png")

    with open("network_analysis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("✅ Results saved: network_analysis_results.json")
    print("=" * 80)
