"""
Network Behavior Graph Analysis
Detects: Lateral movement, botnet recruitment, coordinated attacks
"""

import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import json

class NetworkGraphAnalyzer:
    """
    Analyze device communication patterns using graph theory
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()  # Directed graph for communication
        self.device_profiles = {}
        
    def build_communication_graph(self, telemetry_data: pd.DataFrame) -> nx.DiGraph:
        """
        Build graph from device telemetry
        Nodes = Devices
        Edges = Communications (weighted by packet volume)
        """
        G = nx.DiGraph()
        
        # Add devices as nodes with attributes
        for _, row in telemetry_data.iterrows():
            device_id = row['device_id']
            
            if device_id not in G.nodes():
                G.add_node(device_id, 
                          device_type=row['device_type'],
                          avg_cpu=row['cpu_usage'],
                          avg_memory=row['memory_usage'],
                          total_traffic=row['network_in_kb'] + row['network_out_kb'],
                          is_anomalous=row['label'] != 'Normal')
        
        # Infer communications from network patterns
        # Devices with high outbound traffic likely communicating
        for idx1, row1 in telemetry_data.iterrows():
            for idx2, row2 in telemetry_data.iterrows():
                if idx1 != idx2:
                    # Heuristic: if similar timing and network activity
                    time_diff = abs((pd.to_datetime(row1['timestamp']) - 
                                   pd.to_datetime(row2['timestamp'])).total_seconds())
                    
                    if time_diff < 60:  # Within 1 minute
                        # Calculate communication score
                        comm_score = self._calculate_communication_likelihood(row1, row2)
                        
                        if comm_score > 0.5:
                            G.add_edge(row1['device_id'], 
                                     row2['device_id'],
                                     weight=comm_score,
                                     packet_volume=row1['network_out_kb'])
        
        self.graph = G
        return G
    
    def _calculate_communication_likelihood(self, device1: pd.Series, device2: pd.Series) -> float:
        """
        Calculate likelihood that two devices are communicating
        Based on network patterns and timing
        """
        # Network pattern similarity
        net_out1 = device1['network_out_kb']
        net_in2 = device2['network_in_kb']
        
        # High outbound from d1 and high inbound to d2 suggests communication
        if net_out1 > 500 and net_in2 > 500:
            similarity = min(net_out1, net_in2) / max(net_out1, net_in2)
            return similarity
        
        return 0.0
    
    def detect_botnet_patterns(self) -> Dict:
        """
        Detect botnet command-and-control patterns
        - Look for hub-and-spoke topology
        - Central node with many outgoing connections
        """
        results = {
            "botnet_detected": False,
            "c2_candidates": [],
            "recruited_devices": [],
            "confidence": 0.0
        }
        
        if len(self.graph.nodes()) < 3:
            return results
        
        # Calculate out-degree centrality (potential C&C servers)
        out_degree = dict(self.graph.out_degree())
        in_degree = dict(self.graph.in_degree())
        
        # C&C typically has high out-degree, low in-degree
        for node in self.graph.nodes():
            out = out_degree.get(node, 0)
            in_ = in_degree.get(node, 0)
            
            # Potential C&C: contacts many devices but receives few connections
            if out >= 3 and (out / (in_ + 1)) > 2:
                c2_score = out / len(self.graph.nodes())
                
                if c2_score > 0.3:  # More than 30% of network
                    results["botnet_detected"] = True
                    results["c2_candidates"].append({
                        "device_id": node,
                        "out_connections": out,
                        "in_connections": in_,
                        "c2_score": round(c2_score, 3)
                    })
                    
                    # Find recruited devices
                    recruited = list(self.graph.successors(node))
                    results["recruited_devices"].extend(recruited)
        
        if results["botnet_detected"]:
            results["confidence"] = 0.85
        
        return results
    
    def detect_lateral_movement(self) -> Dict:
        """
        Detect lateral movement patterns
        - Sequential compromise of devices
        - Path from external to internal devices
        """
        results = {
            "lateral_movement_detected": False,
            "attack_paths": [],
            "entry_point": None,
            "compromised_devices": []
        }
        
        # Find anomalous devices
        anomalous_nodes = [n for n in self.graph.nodes() 
                          if self.graph.nodes[n].get('is_anomalous', False)]
        
        if len(anomalous_nodes) < 2:
            return results
        
        # Find paths between anomalous devices
        for source in anomalous_nodes:
            for target in anomalous_nodes:
                if source != target:
                    try:
                        paths = list(nx.all_simple_paths(self.graph, source, target, cutoff=4))
                        
                        for path in paths:
                            if len(path) >= 2:  # At least 2 hops
                                results["lateral_movement_detected"] = True
                                results["attack_paths"].append({
                                    "path": path,
                                    "length": len(path),
                                    "entry_point": path[0],
                                    "final_target": path[-1]
                                })
                    except nx.NetworkXNoPath:
                        continue
        
        if results["lateral_movement_detected"]:
            # Identify most likely entry point
            entry_points = [p["entry_point"] for p in results["attack_paths"]]
            from collections import Counter
            most_common = Counter(entry_points).most_common(1)
            if most_common:
                results["entry_point"] = most_common[0][0]
            
            # All devices in attack paths are compromised
            all_devices = set()
            for path_info in results["attack_paths"]:
                all_devices.update(path_info["path"])
            results["compromised_devices"] = list(all_devices)
        
        return results
    
    def detect_coordinated_attack(self, time_window_minutes: int = 5) -> Dict:
        """
        Detect coordinated attacks
        - Multiple devices show anomalous behavior simultaneously
        """
        results = {
            "coordinated_attack": False,
            "attack_wave": [],
            "affected_devices": [],
            "attack_start_time": None
        }
        
        # Count anomalous nodes
        anomalous_nodes = [n for n in self.graph.nodes() 
                          if self.graph.nodes[n].get('is_anomalous', False)]
        
        if len(anomalous_nodes) >= 3:  # 3+ simultaneous anomalies
            results["coordinated_attack"] = True
            results["affected_devices"] = anomalous_nodes
            results["attack_wave"] = len(anomalous_nodes)
        
        return results
    
    def identify_critical_devices(self) -> List[Dict]:
        """
        Identify devices critical to network (high betweenness centrality)
        These are targets for attackers
        """
        if len(self.graph.nodes()) < 2:
            return []
        
        # Betweenness centrality: how often node appears on shortest paths
        betweenness = nx.betweenness_centrality(self.graph)
        
        # Sort by criticality
        critical_devices = []
        for device, score in sorted(betweenness.items(), key=lambda x: x[1], reverse=True):
            if score > 0.1:  # Significant bridging role
                critical_devices.append({
                    "device_id": device,
                    "criticality_score": round(score, 3),
                    "device_type": self.graph.nodes[device].get('device_type', 'unknown'),
                    "is_anomalous": self.graph.nodes[device].get('is_anomalous', False)
                })
        
        return critical_devices[:10]  # Top 10
    
    def detect_isolated_devices(self) -> List[str]:
        """
        Find isolated devices (potential victims or compromised devices)
        """
        isolated = []
        
        for node in self.graph.nodes():
            in_deg = self.graph.in_degree(node)
            out_deg = self.graph.out_degree(node)
            
            # Isolated if very few connections
            if in_deg + out_deg <= 1:
                isolated.append(node)
        
        return isolated
    
    def get_network_health_score(self) -> float:
        """
        Calculate overall network health (0-100)
        """
        if len(self.graph.nodes()) == 0:
            return 100.0
        
        # Factors affecting health
        anomalous_count = sum(1 for n in self.graph.nodes() 
                            if self.graph.nodes[n].get('is_anomalous', False))
        anomaly_ratio = anomalous_count / len(self.graph.nodes())
        
        # More connections generally better (resilient network)
        avg_degree = sum(dict(self.graph.degree()).values()) / len(self.graph.nodes())
        connectivity_score = min(avg_degree / 5, 1.0)  # Normalize
        
        # Health score (higher is better)
        health = (1 - anomaly_ratio) * 70 + connectivity_score * 30
        
        return round(health, 2)
    
    def analyze_network(self, telemetry_data: pd.DataFrame) -> Dict:
        """
        Complete network analysis
        """
        print("🔍 Building communication graph...")
        self.build_communication_graph(telemetry_data)
        
        print("🤖 Detecting botnet patterns...")
        botnet_results = self.detect_botnet_patterns()
        
        print("🔄 Detecting lateral movement...")
        lateral_results = self.detect_lateral_movement()
        
        print("⚡ Detecting coordinated attacks...")
        coordinated_results = self.detect_coordinated_attack()
        
        print("🎯 Identifying critical devices...")
        critical_devices = self.identify_critical_devices()
        
        print("📊 Calculating network health...")
        health_score = self.get_network_health_score()
        
        isolated_devices = self.detect_isolated_devices()
        
        return {
            "network_summary": {
                "total_devices": len(self.graph.nodes()),
                "total_connections": len(self.graph.edges()),
                "health_score": health_score,
                "isolated_devices": isolated_devices
            },
            "botnet_analysis": botnet_results,
            "lateral_movement": lateral_results,
            "coordinated_attack": coordinated_results,
            "critical_devices": critical_devices
        }
    
    def visualize_network(self, save_path: str = "network_graph.png"):
        """
        Visualize the network graph
        """
        plt.figure(figsize=(14, 10))
        
        # Position nodes using spring layout
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Color nodes by anomaly status
        node_colors = []
        for node in self.graph.nodes():
            if self.graph.nodes[node].get('is_anomalous', False):
                node_colors.append('#ff4444')  # Red for anomalous
            else:
                node_colors.append('#44ff44')  # Green for normal
        
        # Node sizes by traffic volume
        node_sizes = []
        for node in self.graph.nodes():
            traffic = self.graph.nodes[node].get('total_traffic', 100)
            node_sizes.append(traffic / 2)  # Scale down
        
        # Draw graph
        nx.draw_networkx_nodes(self.graph, pos, 
                              node_color=node_colors,
                              node_size=node_sizes,
                              alpha=0.7)
        
        nx.draw_networkx_labels(self.graph, pos, 
                               font_size=8,
                               font_weight='bold')
        
        # Draw edges with varying thickness
        edges = self.graph.edges()
        weights = [self.graph[u][v].get('weight', 1) * 2 for u, v in edges]
        
        nx.draw_networkx_edges(self.graph, pos,
                              width=weights,
                              alpha=0.5,
                              arrows=True,
                              arrowsize=15)
        
        plt.title("IoT Device Communication Network\nRed=Anomalous, Green=Normal, Size=Traffic Volume", 
                 fontsize=14, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✅ Network visualization saved: {save_path}")
        plt.close()


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("🕸️ NETWORK BEHAVIOR GRAPH ANALYSIS")
    print("=" * 80)
    
    # Load data
    df = pd.read_csv("data/smart_system_anomaly_dataset.csv")
    
    # Take sample for analysis
    sample_df = df.sample(n=min(100, len(df)), random_state=42)
    
    # Analyze network
    analyzer = NetworkGraphAnalyzer()
    results = analyzer.analyze_network(sample_df)
    
    # Print results
    print("\n" + "=" * 80)
    print("📊 NETWORK ANALYSIS RESULTS")
    print("=" * 80)
    
    print("\n🌐 Network Summary:")
    for key, value in results["network_summary"].items():
        print(f"   {key}: {value}")
    
    print("\n🤖 Botnet Detection:")
    if results["botnet_analysis"]["botnet_detected"]:
        print("   ⚠️ BOTNET DETECTED!")
        for c2 in results["botnet_analysis"]["c2_candidates"]:
            print(f"   C&C Candidate: {c2['device_id']} (score: {c2['c2_score']})")
        print(f"   Recruited devices: {len(results['botnet_analysis']['recruited_devices'])}")
    else:
        print("   ✅ No botnet detected")
    
    print("\n🔄 Lateral Movement:")
    if results["lateral_movement"]["lateral_movement_detected"]:
        print("   ⚠️ LATERAL MOVEMENT DETECTED!")
        print(f"   Entry point: {results['lateral_movement']['entry_point']}")
        print(f"   Attack paths found: {len(results['lateral_movement']['attack_paths'])}")
        for path_info in results['lateral_movement']['attack_paths'][:3]:
            print(f"   Path: {' → '.join(path_info['path'])}")
    else:
        print("   ✅ No lateral movement detected")
    
    print("\n⚡ Coordinated Attack:")
    if results["coordinated_attack"]["coordinated_attack"]:
        print("   ⚠️ COORDINATED ATTACK DETECTED!")
        print(f"   Affected devices: {results['coordinated_attack']['attack_wave']}")
    else:
        print("   ✅ No coordinated attack detected")
    
    print("\n🎯 Critical Devices:")
    for device in results["critical_devices"][:5]:
        status = "⚠️ ANOMALOUS" if device['is_anomalous'] else "✅"
        print(f"   {status} {device['device_id']} - Criticality: {device['criticality_score']}")
    
    # Visualize
    print("\n📊 Generating network visualization...")
    analyzer.visualize_network("network_analysis.png")
    
    # Save results
    with open("network_analysis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("✅ Results saved: network_analysis_results.json")
    
    print("\n" + "=" * 80)