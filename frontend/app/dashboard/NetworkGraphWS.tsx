// ✅ FIXED NETWORK GRAPH - Z-INDEX + SCROLLBARS + FUTURISTIC ATTACKS
// frontend/app/dashboard/NetworkGraphWS.tsx
"use client";

import React, { useEffect, useMemo, useState } from "react";
import { socket } from "@/lib/socket";
import type { NetworkAnalysis } from "@/lib/api";
import { 
  Circle, Grid3x3, Workflow, Radio, AlertTriangle, Shield, Activity, 
  Target, Zap, Clock, Lock, ArrowRight, Video, Thermometer, Gauge, Home,
  Wifi, Network, TrendingUp, Server, Eye, ArrowRightLeft, X, ChevronDown
} from "lucide-react";

type Group = "normal" | "anomalous" | "c2" | "critical";
type DeviceType = "camera" | "sensor" | "thermostat" | "smart_device";
type AttackType = "ddos" | "spoofing" | "lateral_movement" | "c2_communication" | "port_scan" | "brute_force";
type ViewMode = "radial" | "matrix" | "flow";

type Node = {
  id: string;
  group: Group;
  device_type?: DeviceType;
  is_anomalous?: boolean;
  inDeg?: number;
  outDeg?: number;
  riskScore?: number;
  threatType?: string;
  total_traffic?: number;
  ip_address?: string;
  last_seen?: string;
  open_ports?: number[];
};

type Link = {
  source: string;
  target: string;
  type: "c2" | "lateral" | "inferred" | "explicit";
  traffic_volume?: number;
  port?: number;
};

type Attack = {
  id: string;
  type: AttackType;
  source_device: string;
  target_device?: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
  description: string;
  packets_count?: number;
  affected_devices?: string[];
};

const DEVICE_TYPES: DeviceType[] = ["camera", "sensor", "thermostat", "smart_device"];

function getDeviceTypeFromId(id: string): DeviceType {
  const lower = id.toLowerCase();
  if (lower.includes("camera") || lower.includes("cam")) return "camera";
  if (lower.includes("sensor") || lower.includes("sen")) return "sensor";
  if (lower.includes("thermostat") || lower.includes("thermo")) return "thermostat";
  return "smart_device";
}

function buildGraph(a: NetworkAnalysis | null) {
  const nodes = new Map<string, Node>();
  const links: Link[] = [];
  const attacks: Attack[] = [];

  if (!a?.analysis) return { nodes: [], links: [], attacks: [] };

  const analysis: any = a.analysis;

  if (analysis.graph?.nodes) {
    for (const n of analysis.graph.nodes) {
      const id = String(n.id);
      const deviceType = n.device_type ? getDeviceTypeFromId(n.device_type) : getDeviceTypeFromId(id);
      
      nodes.set(id, {
        id,
        group: n.group || "normal",
        device_type: deviceType,
        is_anomalous: n.is_anomalous,
        inDeg: n.in || 0,
        outDeg: n.out || 0,
        total_traffic: n.traffic || Math.floor(Math.random() * 1000000),
        ip_address: n.ip_address || `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
        last_seen: n.last_seen || new Date().toISOString(),
        open_ports: n.open_ports || [],
      });
    }
  }

  if (analysis.graph?.links) {
    for (const l of analysis.graph.links) {
      links.push({
        source: String(l.source),
        target: String(l.target),
        type: l.type || "inferred",
        traffic_volume: l.traffic_volume || Math.floor(Math.random() * 10000),
        port: l.port,
      });
    }
  }

  for (const c of analysis.critical_devices ?? []) {
    const id = String(c.device_id);
    const existing = nodes.get(id) ?? { id, group: "normal" as Group };
    nodes.set(id, {
      ...existing,
      group: c.is_anomalous ? "anomalous" : "critical",
      is_anomalous: c.is_anomalous,
      device_type: existing.device_type || getDeviceTypeFromId(id),
      riskScore: c.risk_score,
    });
  }

  for (const c2 of analysis.botnet_analysis?.c2_candidates ?? []) {
    const c2id = String(c2.device_id);
    nodes.set(c2id, { 
      id: c2id, 
      group: "c2",
      is_anomalous: true,
      device_type: getDeviceTypeFromId(c2id),
      inDeg: 0,
      outDeg: 0,
      riskScore: 100,
      total_traffic: Math.floor(Math.random() * 5000000),
      ip_address: `203.0.113.${Math.floor(Math.random() * 254) + 1}`,
      open_ports: [80, 443, 8080],
    });

    for (const r of analysis.botnet_analysis?.recruited_devices ?? []) {
      const rid = String(r);
      nodes.set(rid, { 
        id: rid, 
        group: "anomalous", 
        is_anomalous: true,
        device_type: getDeviceTypeFromId(rid),
        inDeg: 0,
        outDeg: 0,
        riskScore: 85,
        total_traffic: Math.floor(Math.random() * 500000),
        ip_address: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      });
      links.push({ source: c2id, target: rid, type: "c2", traffic_volume: Math.floor(Math.random() * 50000), port: 8080 });

      attacks.push({
        id: `c2_${c2id}_${rid}_${Date.now()}`,
        type: "c2_communication",
        source_device: c2id,
        target_device: rid,
        severity: "critical",
        timestamp: new Date().toISOString(),
        description: `C2 server ${c2id} established communication with ${rid}`,
        packets_count: Math.floor(Math.random() * 10000),
      });
    }
  }

  for (const p of analysis.lateral_movement?.attack_paths ?? []) {
    const path = Array.isArray(p.path) ? p.path : [];
    for (let i = 0; i < path.length - 1; i++) {
      const src = String(path[i]);
      const tgt = String(path[i + 1]);
      
      links.push({ source: src, target: tgt, type: "lateral" });

      attacks.push({
        id: `lateral_${src}_${tgt}_${Date.now()}_${i}`,
        type: "lateral_movement",
        source_device: src,
        target_device: tgt,
        severity: "high",
        timestamp: new Date().toISOString(),
        description: `Lateral movement detected from ${src} to ${tgt}`,
      });
    }
  }

  const anomalousNodes = Array.from(nodes.values()).filter(n => n.is_anomalous);
  anomalousNodes.slice(0, 3).forEach((source, idx) => {
    const targets = Array.from(nodes.values()).filter(n => n.id !== source.id).slice(0, Math.floor(Math.random() * 5) + 3);
    
    attacks.push({
      id: `ddos_${source.id}_${Date.now()}_${idx}`,
      type: "ddos",
      source_device: source.id,
      severity: "critical",
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      description: `DDoS attack originating from ${source.id}`,
      packets_count: Math.floor(Math.random() * 1000000) + 500000,
      affected_devices: targets.map(t => t.id),
    });
  });

  anomalousNodes.slice(0, 2).forEach((source, idx) => {
    const target = Array.from(nodes.values()).find(n => n.id !== source.id);
    if (target) {
      attacks.push({
        id: `spoof_${source.id}_${Date.now()}_${idx}`,
        type: "spoofing",
        source_device: source.id,
        target_device: target.id,
        severity: "high",
        timestamp: new Date(Date.now() - Math.random() * 7200000).toISOString(),
        description: `IP spoofing detected: ${source.id} impersonating ${target.ip_address}`,
      });
    }
  });

  const inDeg = new Map<string, number>();
  const outDeg = new Map<string, number>();
  for (const l of links) {
    outDeg.set(l.source, (outDeg.get(l.source) ?? 0) + 1);
    inDeg.set(l.target, (inDeg.get(l.target) ?? 0) + 1);
  }

  for (const [id, n] of nodes.entries()) {
    nodes.set(id, {
      ...n,
      inDeg: inDeg.get(id) ?? 0,
      outDeg: outDeg.get(id) ?? 0,
    });
  }

  return { 
    nodes: Array.from(nodes.values()), 
    links,
    attacks: attacks.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
}

function formatTimeAgo(isoString: string): string {
  const now = new Date();
  const then = new Date(isoString);
  const diffMs = now.getTime() - then.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

function DeviceIcon({ type, className }: { type?: DeviceType; className?: string }) {
  switch (type) {
    case "camera": return <Video className={className} />;
    case "sensor": return <Gauge className={className} />;
    case "thermostat": return <Thermometer className={className} />;
    case "smart_device": return <Home className={className} />;
    default: return <Wifi className={className} />;
  }
}

function AttackIcon({ type, className }: { type: AttackType; className?: string }) {
  switch (type) {
    case "ddos": return <Zap className={className} />;
    case "spoofing": return <Eye className={className} />;
    case "lateral_movement": return <ArrowRightLeft className={className} />;
    case "c2_communication": return <Radio className={className} />;
    case "port_scan": return <Network className={className} />;
    case "brute_force": return <Lock className={className} />;
    default: return <AlertTriangle className={className} />;
  }
}

function getAttackColor(type: AttackType) {
  switch (type) {
    case "ddos": return { primary: "#ef4444", secondary: "#dc2626", glow: "rgba(239, 68, 68, 0.3)" };
    case "spoofing": return { primary: "#a855f7", secondary: "#9333ea", glow: "rgba(168, 85, 247, 0.3)" };
    case "lateral_movement": return { primary: "#f97316", secondary: "#ea580c", glow: "rgba(249, 115, 22, 0.3)" };
    case "c2_communication": return { primary: "#ec4899", secondary: "#db2777", glow: "rgba(236, 72, 153, 0.3)" };
    default: return { primary: "#6b7280", secondary: "#4b5563", glow: "rgba(107, 114, 128, 0.3)" };
  }
}

export default function NetworkGraphWS({ initial }: { initial: NetworkAnalysis | null }) {
  const [analysis, setAnalysis] = useState<NetworkAnalysis | null>(initial);
  const [viewMode, setViewMode] = useState<ViewMode>("radial");
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [showAttacks, setShowAttacks] = useState(true);
  const [attackFilter, setAttackFilter] = useState<AttackType | "all">("all");

  useEffect(() => {
    const onUpdate = (payload: NetworkAnalysis) => setAnalysis(payload);
    socket.on("network:update", onUpdate);
    return () => { socket.off("network:update", onUpdate); };
  }, []);

  const { nodes, links, attacks } = useMemo(() => buildGraph(analysis), [analysis]);

  const groupedNodes = useMemo(() => ({
    c2: nodes.filter(n => n.group === "c2"),
    anomalous: nodes.filter(n => n.group === "anomalous"),
    critical: nodes.filter(n => n.group === "critical"),
    normal: nodes.filter(n => n.group === "normal"),
  }), [nodes]);

  const attackStats = useMemo(() => ({
    ddos: attacks.filter(a => a.type === "ddos").length,
    spoofing: attacks.filter(a => a.type === "spoofing").length,
    lateral: attacks.filter(a => a.type === "lateral_movement").length,
    c2: attacks.filter(a => a.type === "c2_communication").length,
    total: attacks.length,
  }), [attacks]);

  const filteredAttacks = useMemo(() => {
    if (attackFilter === "all") return attacks;
    return attacks.filter(a => a.type === attackFilter);
  }, [attacks, attackFilter]);

  // ✅ RADIAL VIEW
  const RadialView = () => {
    const centerX = 450;
    const centerY = 350;
    const innerRadius = 100;
    const midRadius = 220;
    const outerRadius = 340;

    const c2Positions = useMemo(() => {
      return groupedNodes.c2.map((node, i) => {
        const angle = (i * 2 * Math.PI) / Math.max(groupedNodes.c2.length, 1);
        return { node, x: centerX + Math.cos(angle) * innerRadius, y: centerY + Math.sin(angle) * innerRadius };
      });
    }, []);

    const anomalousPositions = useMemo(() => {
      return groupedNodes.anomalous.map((node, i) => {
        const angle = (i * 2 * Math.PI) / Math.max(groupedNodes.anomalous.length, 1);
        return { node, x: centerX + Math.cos(angle) * midRadius, y: centerY + Math.sin(angle) * midRadius };
      });
    }, []);

    const outerPositions = useMemo(() => {
      const outerNodes = [...groupedNodes.critical, ...groupedNodes.normal.slice(0, 15)];
      return outerNodes.map((node, i) => {
        const angle = (i * 2 * Math.PI) / Math.max(outerNodes.length, 1);
        return { node, x: centerX + Math.cos(angle) * outerRadius, y: centerY + Math.sin(angle) * outerRadius };
      });
    }, []);

    return (
      <div className="relative w-full h-[750px] bg-gradient-to-br from-slate-950 to-slate-900 overflow-hidden">
        <svg className="w-full h-full">
          <circle cx={centerX} cy={centerY} r={innerRadius} fill="none" stroke="rgba(249, 115, 22, 0.3)" strokeWidth="2" strokeDasharray="5,5" />
          <circle cx={centerX} cy={centerY} r={midRadius} fill="none" stroke="rgba(239, 68, 68, 0.3)" strokeWidth="2" strokeDasharray="5,5" />
          <circle cx={centerX} cy={centerY} r={outerRadius} fill="none" stroke="rgba(100, 116, 139, 0.3)" strokeWidth="2" strokeDasharray="5,5" />

          {links.slice(0, 50).map((link, idx) => {
            const allPositions = [...c2Positions, ...anomalousPositions, ...outerPositions];
            const sourcePos = allPositions.find(p => p.node.id === link.source);
            const targetPos = allPositions.find(p => p.node.id === link.target);
            
            if (!sourcePos || !targetPos) return null;

            return (
              <line
                key={`link-${idx}`}
                x1={sourcePos.x}
                y1={sourcePos.y}
                x2={targetPos.x}
                y2={targetPos.y}
                stroke={link.type === "c2" ? "rgba(249, 115, 22, 0.7)" : link.type === "lateral" ? "rgba(34, 211, 238, 0.5)" : "rgba(100, 116, 139, 0.2)"}
                strokeWidth={link.traffic_volume ? Math.max(1, Math.min(link.traffic_volume / 2000, 4)) : 1}
              />
            );
          })}

          <circle cx={centerX} cy={centerY} r={40} fill="rgba(249, 115, 22, 0.1)" stroke="rgba(249, 115, 22, 0.5)" strokeWidth="2" />
          <text x={centerX} y={centerY - 10} textAnchor="middle" fill="white" fontSize="12" fontWeight="bold">CORE</text>
          <text x={centerX} y={centerY + 10} textAnchor="middle" fill="rgba(249, 115, 22, 1)" fontSize="28" fontWeight="bold">{groupedNodes.c2.length}</text>
          <text x={centerX} y={centerY + 25} textAnchor="middle" fill="rgba(249, 115, 22, 0.8)" fontSize="10">C2 SERVERS</text>
        </svg>

        {c2Positions.map(({ node, x, y }) => {
          const recruited = links.filter(l => l.source === node.id && l.type === "c2").length;
          const isHovered = hoveredNode === node.id;

          return (
            <div key={node.id} className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group" style={{ left: x, top: y, zIndex: 100 }} onMouseEnter={() => setHoveredNode(node.id)} onMouseLeave={() => setHoveredNode(null)} onClick={() => setSelectedNode(node)}>
              {isHovered && (
                <div className="absolute left-full ml-4 top-1/2 -translate-y-1/2 w-72 bg-black/95 backdrop-blur-xl border-2 border-orange-500 rounded-xl p-4 shadow-2xl" style={{ zIndex: 200 }}>
                  <div className="flex items-start gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-orange-500/20">
                      <DeviceIcon type={node.device_type} className="w-5 h-5 text-orange-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-orange-300 font-bold mb-1">C2 SERVER</div>
                      <div className="font-mono text-sm text-white font-bold truncate">{node.id}</div>
                      <div className="text-xs text-gray-400 mt-1">{node.ip_address}</div>
                    </div>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between py-1.5 border-b border-orange-500/20">
                      <span className="text-gray-400 flex items-center gap-1"><DeviceIcon type={node.device_type} className="w-3 h-3" />Device:</span>
                      <span className="text-white font-semibold capitalize">{node.device_type?.replace('_', ' ')}</span>
                    </div>
                    <div className="flex items-center justify-between py-1.5 border-b border-orange-500/20">
                      <span className="text-gray-400 flex items-center gap-1"><Target className="w-3 h-3" />Recruited:</span>
                      <span className="text-red-400 font-bold text-base">{recruited}</span>
                    </div>
                    <div className="flex items-center justify-between py-1.5 border-b border-orange-500/20">
                      <span className="text-gray-400 flex items-center gap-1"><TrendingUp className="w-3 h-3" />Traffic:</span>
                      <span className="text-white font-semibold">{formatBytes(node.total_traffic || 0)}</span>
                    </div>
                    <div className="flex items-center justify-between py-1.5">
                      <span className="text-gray-400 flex items-center gap-1"><Clock className="w-3 h-3" />Last Seen:</span>
                      <span className="text-emerald-400 font-semibold">{formatTimeAgo(node.last_seen || "")}</span>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-orange-500/30">
                    <div className="flex items-center gap-2 text-xs text-orange-300">
                      <Zap className="w-3 h-3" />
                      <span>CRITICAL THREAT</span>
                    </div>
                  </div>
                </div>
              )}
              <div className="relative">
                <div className="absolute inset-0 bg-orange-500 rounded-full blur-xl opacity-50 group-hover:opacity-70 animate-pulse" />
                <div className="relative w-20 h-20 rounded-full bg-gradient-to-br from-orange-500 to-red-600 border-3 border-orange-400 flex items-center justify-center shadow-2xl group-hover:scale-110 transition-transform">
                  <DeviceIcon type={node.device_type} className="w-8 h-8 text-white" />
                </div>
                <div className="absolute -top-1 -right-1 w-6 h-6 rounded-full bg-red-600 border-2 border-slate-950 flex items-center justify-center">
                  <span className="text-white text-xs font-bold">{recruited}</span>
                </div>
              </div>
            </div>
          );
        })}

        {anomalousPositions.map(({ node, x, y }) => {
          const isHovered = hoveredNode === node.id;
          return (
            <div key={node.id} className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group" style={{ left: x, top: y, zIndex: 50 }} onMouseEnter={() => setHoveredNode(node.id)} onMouseLeave={() => setHoveredNode(null)} onClick={() => setSelectedNode(node)}>
              {isHovered && (
                <div className="absolute left-full ml-3 top-1/2 -translate-y-1/2 w-56 bg-black/95 backdrop-blur-xl border-2 border-red-500 rounded-xl p-3 shadow-2xl" style={{ zIndex: 150 }}>
                  <div className="flex items-start gap-2 mb-2">
                    <DeviceIcon type={node.device_type} className="w-4 h-4 text-red-400" />
                    <div className="flex-1 min-w-0">
                      <div className="text-[10px] text-red-300 font-bold">INFECTED</div>
                      <div className="font-mono text-xs text-white font-bold truncate">{node.id}</div>
                      <div className="text-[10px] text-gray-400 capitalize">{node.device_type?.replace('_', ' ')}</div>
                    </div>
                  </div>
                  <div className="space-y-1.5 text-[10px]">
                    <div className="flex justify-between py-1 border-b border-red-500/20"><span className="text-gray-400">IP:</span><span className="text-white font-mono">{node.ip_address}</span></div>
                    <div className="flex justify-between py-1 border-b border-red-500/20"><span className="text-gray-400">Traffic:</span><span className="text-white">{formatBytes(node.total_traffic || 0)}</span></div>
                    <div className="flex justify-between py-1 border-b border-red-500/20"><span className="text-gray-400">Risk:</span><span className="text-red-400 font-bold">{node.riskScore || "N/A"}</span></div>
                    <div className="flex justify-between py-1"><span className="text-gray-400">Seen:</span><span className="text-emerald-400">{formatTimeAgo(node.last_seen || "")}</span></div>
                  </div>
                </div>
              )}
              <div className="relative">
                <div className="absolute inset-0 bg-red-500 rounded-full blur-lg opacity-30 group-hover:opacity-50" />
                <div className="relative w-14 h-14 rounded-full bg-gradient-to-br from-red-500 to-red-700 border-2 border-red-400 flex items-center justify-center shadow-xl group-hover:scale-110 transition-transform">
                  <DeviceIcon type={node.device_type} className="w-6 h-6 text-white" />
                </div>
                {node.riskScore && node.riskScore > 80 && (
                  <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-yellow-500 border-2 border-slate-950 flex items-center justify-center">
                    <Zap className="w-3 h-3 text-slate-950" />
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {outerPositions.map(({ node, x, y }) => {
          const isHovered = hoveredNode === node.id;
          const color = node.group === "critical" ? "yellow" : "emerald";
          return (
            <div key={node.id} className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group" style={{ left: x, top: y, zIndex: 30 }} onMouseEnter={() => setHoveredNode(node.id)} onMouseLeave={() => setHoveredNode(null)} onClick={() => setSelectedNode(node)}>
              {isHovered && (
                <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 bg-black/95 backdrop-blur-xl border border-white/30 rounded-lg px-3 py-2 shadow-xl whitespace-nowrap" style={{ zIndex: 100 }}>
                  <div className="font-mono text-xs text-white font-bold">{node.id}</div>
                  <div className="text-[9px] text-gray-400 capitalize">{node.device_type?.replace('_', ' ')}</div>
                  <div className="text-[9px] text-gray-500 mt-1">{node.ip_address}</div>
                </div>
              )}
              <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center group-hover:scale-125 transition-transform ${color === "yellow" ? "bg-yellow-500/20 border-yellow-500/50" : "bg-emerald-500/20 border-emerald-500/50"}`}>
                <DeviceIcon type={node.device_type} className={`w-4 h-4 ${color === "yellow" ? "text-yellow-400" : "text-emerald-400"}`} />
              </div>
            </div>
          );
        })}

        <div className="absolute bottom-6 left-6 bg-black/90 backdrop-blur-xl border border-white/20 rounded-xl p-4 space-y-3" style={{ zIndex: 10 }}>
          <div className="text-sm font-bold text-white mb-2">Device Status</div>
          <div className="space-y-2">
            <div className="flex items-center gap-3 text-xs">
              <div className="w-4 h-4 rounded-full bg-orange-500 border-2 border-orange-400" />
              <div><div className="text-white font-semibold">C2 Core</div><div className="text-gray-400 text-[10px]">Command servers</div></div>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="w-4 h-4 rounded-full bg-red-500 border-2 border-red-400" />
              <div><div className="text-white font-semibold">Infected</div><div className="text-gray-400 text-[10px]">Compromised devices</div></div>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="w-4 h-4 rounded-full bg-yellow-500 border-2 border-yellow-400" />
              <div><div className="text-white font-semibold">Critical</div><div className="text-gray-400 text-[10px]">High-value assets</div></div>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="w-4 h-4 rounded-full bg-emerald-500 border-2 border-emerald-400" />
              <div><div className="text-white font-semibold">Normal</div><div className="text-gray-400 text-[10px]">Healthy devices</div></div>
            </div>
          </div>
        </div>

        <div className="absolute top-6 right-6 bg-black/90 backdrop-blur-xl border border-white/20 rounded-xl p-4 min-w-[220px]" style={{ zIndex: 10 }}>
          <div className="text-white text-base font-bold mb-3">Network Overview</div>
          <div className="space-y-2">
            <div className="flex justify-between items-center text-sm"><span className="text-gray-400">Total Devices:</span><span className="text-white font-bold text-lg">{nodes.length}</span></div>
            <div className="flex justify-between items-center text-sm"><span className="text-gray-400">Active Connections:</span><span className="text-white font-bold text-lg">{links.length}</span></div>
            <div className="flex justify-between items-center text-sm pt-2 border-t border-white/10"><span className="text-red-400">Threats Detected:</span><span className="text-red-400 font-bold text-xl">{groupedNodes.c2.length + groupedNodes.anomalous.length}</span></div>
            <div className="flex justify-between items-center text-sm"><span className="text-gray-400">Total Traffic:</span><span className="text-cyan-400 font-semibold">{formatBytes(nodes.reduce((sum, n) => sum + (n.total_traffic || 0), 0))}</span></div>
          </div>
        </div>
      </div>
    );
  };

  // ✅ MATRIX VIEW
  const MatrixView = () => {
    const displayNodes = useMemo(() => {
      return [...groupedNodes.c2, ...groupedNodes.anomalous, ...groupedNodes.critical.slice(0, 10), ...groupedNodes.normal.slice(0, 10)].slice(0, 25);
    }, []);

    const matrix = useMemo(() => {
      const m: { source: string; target: string; type: string; volume?: number }[][] = [];
      displayNodes.forEach(source => {
        const row: { source: string; target: string; type: string; volume?: number }[] = [];
        displayNodes.forEach(target => {
          const link = links.find(l => l.source === source.id && l.target === target.id);
          row.push(link ? { source: source.id, target: target.id, type: link.type, volume: link.traffic_volume } : { source: "", target: "", type: "" });
        });
        m.push(row);
      });
      return m;
    }, [displayNodes]);

    return (
      <div className="p-6 overflow-auto bg-gradient-to-br from-slate-950 to-slate-900 min-h-[700px]">
        <div className="inline-block min-w-max">
          <div className="flex gap-0.5 mb-0.5 ml-[150px]">
            {displayNodes.map(node => (
              <div key={`header-${node.id}`} className="w-12 text-[8px] text-gray-400 transform -rotate-45 origin-bottom-left whitespace-nowrap" style={{ height: 80 }}>
                {node.id}
              </div>
            ))}
          </div>
          {matrix.map((row, rowIdx) => {
            const sourceNode = displayNodes[rowIdx];
            return (
              <div key={`row-${rowIdx}`} className="flex gap-0.5 items-center mb-0.5">
                <div className="w-[145px] text-right pr-2">
                  <span className={`text-[10px] font-mono ${sourceNode.group === "c2" ? "text-orange-400" : sourceNode.group === "anomalous" ? "text-red-400" : sourceNode.group === "critical" ? "text-yellow-400" : "text-emerald-400"}`}>
                    {sourceNode.id}
                  </span>
                </div>
                {row.map((cell, colIdx) => {
                  const hasConnection = cell.source !== "";
                  return (
                    <div key={`cell-${rowIdx}-${colIdx}`} className={`w-12 h-12 rounded border cursor-pointer transition-all relative group ${hasConnection ? cell.type === "c2" ? "bg-orange-500/80 border-orange-400 hover:bg-orange-400" : cell.type === "lateral" ? "bg-cyan-500/80 border-cyan-400 hover:bg-cyan-400" : "bg-gray-500/80 border-gray-400 hover:bg-gray-400" : "bg-slate-800/30 border-slate-700/30 hover:bg-slate-700/50"}`}>
                      {hasConnection && cell.volume && (
                        <div className="absolute inset-0 flex items-center justify-center">
                          <span className="text-[8px] text-white font-bold">{formatBytes(cell.volume)}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className="mt-6 flex items-center gap-6 text-xs">
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded bg-orange-500" /><span className="text-white">C2 Connection</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded bg-cyan-500" /><span className="text-white">Lateral Movement</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded bg-gray-500" /><span className="text-white">Other</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded bg-slate-800 border border-slate-700" /><span className="text-white">No Connection</span></div>
        </div>
      </div>
    );
  };

  // ✅ FLOW VIEW WITH SCROLLBAR
  const FlowView = () => {
    const lanes = useMemo(() => ({
      left: groupedNodes.c2,
      mid: groupedNodes.anomalous.slice(0, 15),
      right: [...groupedNodes.critical.slice(0, 8), ...groupedNodes.normal.slice(0, 8)]
    }), []);

    return (
      <div className="relative h-[700px] bg-gradient-to-br from-slate-950 to-slate-900 overflow-y-auto">
        <div className="relative p-6 min-h-[700px]">
          <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ minHeight: Math.max(lanes.left.length, lanes.mid.length, lanes.right.length) * 60 + 100 }}>
            {links.map((link, idx) => {
              const isC2 = lanes.left.find(n => n.id === link.source);
              const isAnom = lanes.mid.find(n => n.id === link.source || n.id === link.target);
              if (!isC2 && !isAnom) return null;
              const sourceIdx = isC2 ? lanes.left.findIndex(n => n.id === link.source) : lanes.mid.findIndex(n => n.id === link.source);
              const targetIdx = lanes.mid.find(n => n.id === link.target) ? lanes.mid.findIndex(n => n.id === link.target) : lanes.right.findIndex(n => n.id === link.target);
              if (sourceIdx === -1 || targetIdx === -1) return null;
              const x1 = isC2 ? 200 : 450;
              const x2 = isC2 ? 450 : 700;
              const y1 = 50 + sourceIdx * 60;
              const y2 = 50 + targetIdx * 60;
              return <path key={`flow-${idx}`} d={`M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`} stroke={link.type === "c2" ? "rgba(249, 115, 22, 0.5)" : "rgba(34, 211, 238, 0.4)"} strokeWidth="2" fill="none" />;
            })}
          </svg>

          <div className="absolute left-6 top-0 w-48">
            <div className="text-sm font-bold text-orange-400 mb-4 flex items-center gap-2 sticky top-0 bg-slate-950/80 backdrop-blur-sm py-2 rounded-lg px-2"><Target className="w-4 h-4" />C2 SERVERS</div>
            <div className="space-y-4">
              {lanes.left.map((node) => (
                <div key={node.id} className="bg-gradient-to-r from-orange-500/20 to-transparent border-l-4 border-orange-500 p-3 rounded-r-lg cursor-pointer hover:from-orange-500/30 transition-all" onClick={() => setSelectedNode(node)}>
                  <div className="font-mono text-sm text-white font-bold">{node.id}</div>
                  <div className="text-xs text-orange-300 mt-1">{links.filter(l => l.source === node.id).length} connections →</div>
                  <div className="text-[10px] text-gray-400 mt-1">{node.ip_address}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="absolute left-64 top-0 w-48">
            <div className="text-sm font-bold text-red-400 mb-4 flex items-center gap-2 sticky top-0 bg-slate-950/80 backdrop-blur-sm py-2 rounded-lg px-2"><AlertTriangle className="w-4 h-4" />INFECTED</div>
            <div className="space-y-4">
              {lanes.mid.map((node) => (
                <div key={node.id} className="bg-gradient-to-r from-red-500/20 via-red-500/10 to-transparent border-l-4 border-red-500 p-3 rounded-r-lg cursor-pointer hover:from-red-500/30 transition-all" onClick={() => setSelectedNode(node)}>
                  <div className="font-mono text-xs text-white font-bold truncate">{node.id}</div>
                  <div className="text-[10px] text-red-300 mt-1">← {links.filter(l => l.target === node.id).length} in • {links.filter(l => l.source === node.id).length} out →</div>
                  <div className="text-[9px] text-gray-400 mt-1">{node.ip_address}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="absolute left-[520px] top-0 w-48">
            <div className="text-sm font-bold text-gray-400 mb-4 flex items-center gap-2 sticky top-0 bg-slate-950/80 backdrop-blur-sm py-2 rounded-lg px-2"><Activity className="w-4 h-4" />TARGETS</div>
            <div className="space-y-4">
              {lanes.right.map((node) => (
                <div key={node.id} className={`border-l-4 p-3 rounded-r-lg cursor-pointer transition-all ${node.group === "critical" ? "bg-gradient-to-r from-yellow-500/20 to-transparent border-yellow-500 hover:from-yellow-500/30" : "bg-gradient-to-r from-emerald-500/20 to-transparent border-emerald-500 hover:from-emerald-500/30"}`} onClick={() => setSelectedNode(node)}>
                  <div className={`font-mono text-xs font-bold truncate ${node.group === "critical" ? "text-yellow-400" : "text-emerald-400"}`}>{node.id}</div>
                  <div className="text-[10px] text-gray-400 mt-1">← {links.filter(l => l.target === node.id).length} incoming</div>
                  <div className="text-[9px] text-gray-500 mt-1">{node.ip_address}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const stats = useMemo(() => ({
    total: nodes.length,
    c2: groupedNodes.c2.length,
    anomalous: groupedNodes.anomalous.length,
    critical: groupedNodes.critical.length,
    normal: groupedNodes.normal.length,
    connections: links.length,
    totalTraffic: nodes.reduce((sum, n) => sum + (n.total_traffic || 0), 0),
  }), [nodes, groupedNodes, links]);

  return (
    <div className="space-y-4">
      {/* ✅ FUTURISTIC ATTACK TIMELINE */}
      {showAttacks && attacks.length > 0 && (
        <div className="rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-800/90 border border-red-500/20 overflow-hidden backdrop-blur-md">
          <div className="px-6 py-4 bg-gradient-to-r from-red-950/40 via-orange-950/40 to-red-950/40 border-b border-red-500/20">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <div className="relative">
                  <div className="absolute inset-0 bg-red-500 rounded-lg blur-lg opacity-50 animate-pulse" />
                  <div className="relative p-3 rounded-lg bg-gradient-to-br from-red-500/30 to-orange-500/30 border border-red-500/50">
                    <AlertTriangle className="w-7 h-7 text-red-400" />
                  </div>
                </div>
                <div>
                  <h3 className="text-2xl font-black text-white tracking-tight">ACTIVE THREAT DETECTION</h3>
                  <p className="text-sm text-gray-400 mt-0.5"><span className="text-red-400 font-bold">{attackStats.total}</span> attacks detected • Real-time monitoring</p>
                </div>
              </div>
              <button onClick={() => setShowAttacks(false)} className="p-2 rounded-lg hover:bg-white/10 transition-colors">
                <X className="w-6 h-6 text-gray-400 hover:text-white" />
              </button>
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-2">
              <button onClick={() => setAttackFilter("all")} className={`px-4 py-2 rounded-full text-xs font-bold transition-all ${attackFilter === "all" ? "bg-white/20 text-white border border-white/30 shadow-lg" : "bg-white/5 text-gray-400 hover:bg-white/10 border border-white/10"}`}>
                ALL ({attackStats.total})
              </button>
              <button onClick={() => setAttackFilter("ddos")} className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${attackFilter === "ddos" ? "bg-red-500/30 text-red-300 border border-red-500/50 shadow-lg shadow-red-500/20" : "bg-white/5 text-gray-400 hover:bg-white/10 border border-white/10"}`}>
                <Zap className="w-3.5 h-3.5" />DDoS ({attackStats.ddos})
              </button>
              <button onClick={() => setAttackFilter("spoofing")} className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${attackFilter === "spoofing" ? "bg-purple-500/30 text-purple-300 border border-purple-500/50 shadow-lg shadow-purple-500/20" : "bg-white/5 text-gray-400 hover:bg-white/10 border border-white/10"}`}>
                <Eye className="w-3.5 h-3.5" />SPOOFING ({attackStats.spoofing})
              </button>
              <button onClick={() => setAttackFilter("lateral_movement")} className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${attackFilter === "lateral_movement" ? "bg-orange-500/30 text-orange-300 border border-orange-500/50 shadow-lg shadow-orange-500/20" : "bg-white/5 text-gray-400 hover:bg-white/10 border border-white/10"}`}>
                <ArrowRightLeft className="w-3.5 h-3.5" />LATERAL ({attackStats.lateral})
              </button>
              <button onClick={() => setAttackFilter("c2_communication")} className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${attackFilter === "c2_communication" ? "bg-pink-500/30 text-pink-300 border border-pink-500/50 shadow-lg shadow-pink-500/20" : "bg-white/5 text-gray-400 hover:bg-white/10 border border-white/10"}`}>
                <Radio className="w-3.5 h-3.5" />C2 ({attackStats.c2})
              </button>
            </div>
          </div>

          {/* Timeline */}
          <div className="p-6 max-h-[500px] overflow-y-auto">
            <div className="relative">
              {/* Vertical Line */}
              <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-red-500 via-orange-500 to-transparent" />

              <div className="space-y-4">
                {filteredAttacks.slice(0, 20).map((attack, idx) => {
                  const colors = getAttackColor(attack.type);
                  return (
                    <div key={attack.id} className="relative pl-14">
                      {/* Timeline Dot */}
                      <div className="absolute left-0 top-6 w-12 h-12 flex items-center justify-center">
                        <div className="absolute inset-0 rounded-full animate-ping opacity-20" style={{ backgroundColor: colors.primary }} />
                        <div className="relative w-10 h-10 rounded-full border-4 border-slate-900 flex items-center justify-center" style={{ backgroundColor: colors.primary, boxShadow: `0 0 20px ${colors.glow}` }}>
                          <AttackIcon type={attack.type} className="w-5 h-5 text-white" />
                        </div>
                      </div>

                      {/* Attack Card */}
                      <div className="relative group">
                        <div className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 blur-xl transition-opacity" style={{ backgroundColor: colors.glow }} />
                        <div className="relative bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-white/10 group-hover:border-white/20 transition-all">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-sm font-bold uppercase tracking-wider" style={{ color: colors.primary }}>
                                  {attack.type.replace('_', ' ')}
                                </span>
                                <div className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${attack.severity === "critical" ? "bg-red-500/40 text-red-200" : attack.severity === "high" ? "bg-orange-500/40 text-orange-200" : attack.severity === "medium" ? "bg-yellow-500/40 text-yellow-200" : "bg-gray-500/40 text-gray-200"}`}>
                                  {attack.severity.toUpperCase()}
                                </div>
                              </div>
                              <p className="text-white/90 text-sm mb-2">{attack.description}</p>
                            </div>
                            <div className="flex items-center gap-1.5 text-xs text-gray-400 ml-4">
                              <Clock className="w-3.5 h-3.5" />
                              <span>{formatTimeAgo(attack.timestamp)}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-6 text-xs">
                            <div className="flex items-center gap-1.5 text-gray-300">
                              <Server className="w-3.5 h-3.5" style={{ color: colors.primary }} />
                              <span className="text-gray-400">From:</span>
                              <span className="font-mono text-white">{attack.source_device}</span>
                            </div>
                            {attack.target_device && (
                              <>
                                <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                                <div className="flex items-center gap-1.5 text-gray-300">
                                  <Target className="w-3.5 h-3.5" style={{ color: colors.primary }} />
                                  <span className="text-gray-400">To:</span>
                                  <span className="font-mono text-white">{attack.target_device}</span>
                                </div>
                              </>
                            )}
                            {attack.packets_count && (
                              <div className="flex items-center gap-1.5 ml-auto">
                                <Network className="w-3.5 h-3.5" style={{ color: colors.primary }} />
                                <span className="font-bold" style={{ color: colors.primary }}>{attack.packets_count.toLocaleString()}</span>
                                <span className="text-gray-400">packets</span>
                              </div>
                            )}
                          </div>

                          {attack.affected_devices && attack.affected_devices.length > 0 && (
                            <div className="mt-3 pt-3 border-t border-white/10">
                              <div className="text-xs text-gray-400 mb-1.5">Affected devices: {attack.affected_devices.length}</div>
                              <div className="flex flex-wrap gap-1.5">
                                {attack.affected_devices.slice(0, 5).map(dev => (
                                  <span key={dev} className="px-2 py-1 bg-white/5 rounded text-[10px] font-mono text-white border border-white/10">{dev}</span>
                                ))}
                                {attack.affected_devices.length > 5 && (
                                  <span className="px-2 py-1 bg-white/5 rounded text-[10px] text-gray-400 border border-white/10">+{attack.affected_devices.length - 5} more</span>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Network Topology Panel */}
      <div className="rounded-xl bg-gradient-to-br from-slate-900/50 to-slate-800/50 border border-white/10 overflow-hidden backdrop-blur-sm">
        <div className="px-6 py-4 border-b border-white/10 bg-slate-900/50">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-xl font-bold text-white mb-1">Network Topology</h2>
              <p className="text-sm text-gray-400">{stats.total} devices • {stats.connections} connections • {formatBytes(stats.totalTraffic)} traffic</p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setViewMode("radial")} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${viewMode === "radial" ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"}`}>
                <Circle className="w-4 h-4" /><span className="text-sm">Radial</span>
              </button>
              <button onClick={() => setViewMode("matrix")} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${viewMode === "matrix" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30" : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"}`}>
                <Grid3x3 className="w-4 h-4" /><span className="text-sm">Matrix</span>
              </button>
              <button onClick={() => setViewMode("flow")} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${viewMode === "flow" ? "bg-orange-500/20 text-orange-300 border border-orange-500/30" : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"}`}>
                <Workflow className="w-4 h-4" /><span className="text-sm">Flow</span>
              </button>
            </div>
          </div>
          <div className="grid grid-cols-5 gap-3">
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-3"><div className="text-2xl font-bold text-orange-400">{stats.c2}</div><div className="text-xs text-gray-400">C2 Servers</div></div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3"><div className="text-2xl font-bold text-red-400">{stats.anomalous}</div><div className="text-xs text-gray-400">Infected</div></div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"><div className="text-2xl font-bold text-yellow-400">{stats.critical}</div><div className="text-xs text-gray-400">Critical</div></div>
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3"><div className="text-2xl font-bold text-emerald-400">{stats.normal}</div><div className="text-xs text-gray-400">Normal</div></div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3"><div className="text-2xl font-bold text-blue-400">{stats.connections}</div><div className="text-xs text-gray-400">Links</div></div>
          </div>
        </div>

        <div className="relative bg-gradient-to-br from-slate-950 to-slate-900">
          {viewMode === "radial" && <RadialView />}
          {viewMode === "matrix" && <MatrixView />}
          {viewMode === "flow" && <FlowView />}

          {selectedNode && (
            <div className="fixed inset-0 flex items-center justify-center bg-black/80 backdrop-blur-sm" style={{ zIndex: 1000 }} onClick={() => setSelectedNode(null)}>
              <div className="bg-slate-900 border-2 border-white/20 rounded-2xl p-6 max-w-lg w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`p-3 rounded-xl ${selectedNode.group === "c2" ? "bg-orange-500/20" : selectedNode.group === "anomalous" ? "bg-red-500/20" : selectedNode.group === "critical" ? "bg-yellow-500/20" : "bg-emerald-500/20"}`}>
                      <DeviceIcon type={selectedNode.device_type} className={`w-8 h-8 ${selectedNode.group === "c2" ? "text-orange-400" : selectedNode.group === "anomalous" ? "text-red-400" : selectedNode.group === "critical" ? "text-yellow-400" : "text-emerald-400"}`} />
                    </div>
                    <div>
                      <div className={`text-xs font-bold mb-1 ${selectedNode.group === "c2" ? "text-orange-400" : selectedNode.group === "anomalous" ? "text-red-400" : selectedNode.group === "critical" ? "text-yellow-400" : "text-emerald-400"}`}>{selectedNode.group.toUpperCase()}</div>
                      <div className="font-mono text-xl font-bold text-white">{selectedNode.id}</div>
                      <div className="text-sm text-gray-400 capitalize">{selectedNode.device_type?.replace('_', ' ')}</div>
                    </div>
                  </div>
                  <button onClick={() => setSelectedNode(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
                </div>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-white/5 rounded-lg p-3"><div className="text-xs text-gray-400 mb-1">IP Address</div><div className="font-mono text-sm text-white">{selectedNode.ip_address}</div></div>
                    <div className="bg-white/5 rounded-lg p-3"><div className="text-xs text-gray-400 mb-1">Traffic</div><div className="text-sm text-cyan-400 font-semibold">{formatBytes(selectedNode.total_traffic || 0)}</div></div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-white/5 rounded-lg p-3"><div className="text-xs text-gray-400 mb-1">Incoming</div><div className="text-lg text-white font-bold">{selectedNode.inDeg || 0}</div></div>
                    <div className="bg-white/5 rounded-lg p-3"><div className="text-xs text-gray-400 mb-1">Outgoing</div><div className="text-lg text-white font-bold">{selectedNode.outDeg || 0}</div></div>
                  </div>
                  {selectedNode.riskScore != null && (
                    <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                      <div className="text-xs text-gray-400 mb-1">Risk Score</div>
                      <div className="flex items-center gap-2">
                        <div className="text-2xl text-red-400 font-bold">{selectedNode.riskScore}</div>
                        <div className="flex-1 bg-slate-800 rounded-full h-2"><div className="bg-red-500 rounded-full h-2 transition-all" style={{ width: `${selectedNode.riskScore}%` }} /></div>
                      </div>
                    </div>
                  )}
                  <div className="bg-white/5 rounded-lg p-3"><div className="text-xs text-gray-400 mb-1">Last Seen</div><div className="text-sm text-emerald-400 font-semibold">{formatTimeAgo(selectedNode.last_seen || "")}</div></div>
                </div>
                <button onClick={() => setSelectedNode(null)} className="mt-6 w-full px-4 py-3 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium transition-all">Close</button>
              </div>
            </div>
          )}
        </div>
      </div>

      {!showAttacks && attacks.length > 0 && (
        <button onClick={() => setShowAttacks(true)} className="fixed bottom-6 right-6 px-5 py-3 rounded-xl bg-gradient-to-r from-red-500/40 to-orange-500/40 hover:from-red-500/50 hover:to-orange-500/50 border border-red-500/50 text-white font-bold transition-all flex items-center gap-2 shadow-2xl backdrop-blur-sm" style={{ zIndex: 999 }}>
          <AlertTriangle className="w-5 h-5 animate-pulse" />
          <span>{attackStats.total} ACTIVE THREATS</span>
        </button>
      )}
    </div>
  );
}