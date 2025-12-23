// ✅ SOLUTION COMPLÈTE: Network Graph AMÉLIORÉ
// frontend/app/dashboard/NetworkGraphWS.tsx
"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { Search, Filter, Eye, EyeOff, Maximize2 } from "lucide-react";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

type NetworkAnalysis = any;

type GraphNode = {
  id: string;
  group: "normal" | "anomalous" | "c2" | "critical";
  deviceType?: string;
  label?: string;
  riskScore?: number;
};

type GraphLink = {
  source: string;
  target: string;
  type: "c2" | "lateral" | "normal";
};

function buildGraphFromAnalysis(analysis: NetworkAnalysis | null) {
  const nodes = new Map<string, GraphNode>();
  const links: GraphLink[] = [];

  if (!analysis?.analysis) return { nodes: [], links: [] };

  const a = analysis.analysis;

  // 1) Critical devices
  for (const c of a.critical_devices ?? []) {
    nodes.set(c.device_id, {
      id: c.device_id,
      group: c.is_anomalous ? "anomalous" : "critical",
      deviceType: c.device_type,
      label: c.device_id,
      riskScore: c.criticality_score,
    });
  }

  // 2) C2 candidates
  const c2s = a.botnet_analysis?.c2_candidates ?? [];
  for (const c2 of c2s) {
    nodes.set(c2.device_id, {
      id: c2.device_id,
      group: "c2",
      label: c2.device_id,
      riskScore: c2.c2_score * 100,
    });

    const recruited = a.botnet_analysis?.recruited_devices ?? [];
    for (const r of recruited) {
      if (!nodes.has(r)) {
        nodes.set(r, { id: r, group: "anomalous", label: r });
      }
      links.push({ source: c2.device_id, target: r, type: "c2" });
    }
  }

  // 3) Lateral movement paths
  const paths = a.lateral_movement?.attack_paths ?? [];
  for (const p of paths) {
    const path = p.path ?? [];
    for (let i = 0; i < path.length; i++) {
      const id = path[i];
      if (!nodes.has(id)) {
        nodes.set(id, { id, group: "anomalous", label: id });
      }
      if (i < path.length - 1) {
        links.push({ source: path[i], target: path[i + 1], type: "lateral" });
      }
    }
  }

  // 4) Normal connections (si pas assez de données)
  if (nodes.size < 5) {
    const isolated = a.network_summary?.isolated_devices ?? [];
    for (const id of isolated) {
      if (!nodes.has(id)) {
        nodes.set(id, { id, group: "normal", label: id });
      }
    }
  }

  return { nodes: Array.from(nodes.values()), links };
}

export default function NetworkGraphWS({ initial }: { initial: NetworkAnalysis | null }) {
  const [data, setData] = useState<NetworkAnalysis | null>(initial);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "threats" | "c2">("all");
  const [showLabels, setShowLabels] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  
  const fgRef = useRef<any>();

  // ✅ POLL POUR MISE À JOUR LIVE
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const base = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000";
        const res = await fetch(`${base}/api/network/status?minutes=60`, { cache: "no-store" });
        if (!res.ok) return;
        const json = await res.json();
        if (alive) setData(json);
      } catch {}
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const graph = useMemo(() => buildGraphFromAnalysis(data), [data]);

  // ✅ FILTRAGE
  const filteredGraph = useMemo(() => {
    let filteredNodes = graph.nodes;
    let filteredLinks = graph.links;

    // Filtre par type
    if (filterType === "threats") {
      filteredNodes = filteredNodes.filter(n => n.group === "anomalous" || n.group === "c2" || n.group === "critical");
    } else if (filterType === "c2") {
      filteredNodes = filteredNodes.filter(n => n.group === "c2");
      const c2Ids = new Set(filteredNodes.map(n => n.id));
      filteredLinks = filteredLinks.filter(l => 
        c2Ids.has(l.source as string) || c2Ids.has(l.target as string)
      );
    }

    // Filtre par recherche
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filteredNodes = filteredNodes.filter(n => 
        n.id.toLowerCase().includes(query) ||
        n.deviceType?.toLowerCase().includes(query)
      );
      const nodeIds = new Set(filteredNodes.map(n => n.id));
      filteredLinks = filteredLinks.filter(l => 
        nodeIds.has(l.source as string) && nodeIds.has(l.target as string)
      );
    }

    return { nodes: filteredNodes, links: filteredLinks };
  }, [graph, filterType, searchQuery]);

  const health = data?.analysis?.network_summary?.health_score ?? null;

  // ✅ ZOOM TO FIT
  const handleFit = () => {
    if (fgRef.current) {
      fgRef.current.zoomToFit(400, 100);
    }
  };

  // ✅ CHERCHER UN NODE
  const handleSearch = () => {
    if (!searchQuery.trim() || !fgRef.current) return;
    const node = filteredGraph.nodes.find(n => 
      n.id.toLowerCase() === searchQuery.toLowerCase()
    );
    if (node) {
      fgRef.current.centerAt(node.x, node.y, 1000);
      fgRef.current.zoom(3, 1000);
      setSelectedNode(node);
    }
  };

  return (
    <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/50 to-slate-800/50 overflow-hidden backdrop-blur-xl">
      {/* ✅ HEADER AVEC STATS */}
      <div className="px-6 py-4 border-b border-white/10 bg-slate-900/50 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-bold text-white">Network Topology</div>
            <div className="text-sm text-gray-400 mt-1">
              {filteredGraph.nodes.length} devices • {filteredGraph.links.length} connections
            </div>
          </div>
          <span
            className={`px-3 py-1.5 rounded-lg text-xs font-bold border ${
              health === null
                ? "border-white/10 bg-white/5 text-gray-200"
                : health < 60
                ? "border-red-500/30 bg-red-500/10 text-red-300"
                : health < 80
                ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
            }`}
          >
            Health: {health === null ? "N/A" : `${health.toFixed(1)}%`}
          </span>
        </div>

        {/* ✅ CONTROLS */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Filters */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setFilterType("all")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterType === "all"
                  ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilterType("threats")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterType === "threats"
                  ? "bg-red-500/20 text-red-300 border border-red-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              Threats Only
            </button>
            <button
              onClick={() => setFilterType("c2")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterType === "c2"
                  ? "bg-orange-500/20 text-orange-300 border border-orange-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              C2 Only
            </button>
          </div>

          {/* Search */}
          <div className="flex-1 min-w-[200px] max-w-md">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleSearch()}
                placeholder="Search device..."
                className="w-full pl-10 pr-4 py-1.5 rounded-lg bg-black/40 border border-white/10 text-sm text-white placeholder:text-gray-500 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
          </div>

          {/* Toggle Labels */}
          <button
            onClick={() => setShowLabels(!showLabels)}
            className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-all"
            title={showLabels ? "Hide Labels" : "Show Labels"}
          >
            {showLabels ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>

          {/* Fit to View */}
          <button
            onClick={handleFit}
            className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-all"
            title="Fit to View"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ✅ GRAPH CANVAS - AMÉLIORÉ AVEC PLUS GROS NODES */}
      <div className="relative h-[500px] w-full bg-slate-950/50">
        <ForceGraph2D
          ref={fgRef}
          graphData={filteredGraph}
          nodeId="id"
          // ✅ FORCES PLUS FORTES = MEILLEUR ESPACEMENT
          d3Force={{
            charge: { strength: -800 },  // Repulsion forte
            link: { distance: 200 },      // Distance entre nodes
            center: { strength: 0.05 },
            collision: { radius: 50 },    // Éviter chevauchement
          }}
          cooldownTicks={200}
          warmupTicks={100}
          // ✅ TAILLE DES NODES AUGMENTÉE (x2)
          nodeRelSize={10}  // Was 5
          // ✅ LIENS PLUS VISIBLES
          linkWidth={(l: any) => {
            if (l.type === "lateral") return 4;     // Was 2
            if (l.type === "c2") return 3.5;        // Was 1.2
            return 1.5;                             // Was 0.8
          }}
          linkColor={(l: any) => {
            if (l.type === "lateral") return "rgba(34, 211, 238, 0.9)";  // Cyan
            if (l.type === "c2") return "rgba(249, 115, 22, 0.9)";       // Orange
            return "rgba(100, 116, 139, 0.4)";                           // Gray
          }}
          linkDirectionalArrowLength={8}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.2}
          // ✅ CUSTOM NODE RENDERING - PLUS GROS + LABELS
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
            // Validation
            if (typeof node.x !== "number" || typeof node.y !== "number") return;
            if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;

            const label = showLabels ? (node.label || node.id) : "";
            
            // ✅ NODE SIZE BASÉE SUR DEGREE + RISK
            const degree = (filteredGraph.links.filter(
              (l: any) => l.source === node.id || l.target === node.id
            ).length || 0);
            
            // ✅ TAILLE AUGMENTÉE: 15-40px (was 6-20px)
            let nodeSize = 15 + Math.min(degree * 2, 25);
            if (node.riskScore && node.riskScore > 50) {
              nodeSize += 5; // Bonus pour high-risk
            }

            // Couleurs selon groupe
            let fill = "rgba(34,197,94,0.9)";   // green - normal
            let stroke = "rgba(255,255,255,0.6)";
            
            if (node.group === "c2") {
              fill = "rgba(249,115,22,1)";      // orange
              stroke = "rgba(255,255,255,0.9)";
            } else if (node.group === "anomalous") {
              fill = "rgba(239,68,68,1)";       // red
              stroke = "rgba(255,255,255,0.9)";
            } else if (node.group === "critical") {
              fill = "rgba(250,204,21,1)";      // yellow
              stroke = "rgba(255,255,255,0.8)";
            }

            // ✅ GLOW EFFECT PLUS VISIBLE
            if (node.group !== "normal") {
              ctx.beginPath();
              ctx.arc(node.x, node.y, nodeSize + 15, 0, 2 * Math.PI);
              const gradient = ctx.createRadialGradient(
                node.x, node.y, nodeSize,
                node.x, node.y, nodeSize + 15
              );
              gradient.addColorStop(0, fill + "60");
              gradient.addColorStop(1, fill + "00");
              ctx.fillStyle = gradient;
              ctx.fill();
            }

            // Node principal
            ctx.beginPath();
            ctx.arc(node.x, node.y, nodeSize, 0, 2 * Math.PI);
            ctx.fillStyle = fill;
            ctx.fill();

            // Border
            ctx.lineWidth = selectedNode?.id === node.id ? 4 : 2.5;
            ctx.strokeStyle = selectedNode?.id === node.id ? "#ffffff" : stroke;
            ctx.stroke();

            // ✅ LABEL PLUS GRAND ET VISIBLE
            if (label && showLabels) {
              const fontSize = 14; // Was 12
              ctx.font = `bold ${fontSize}px Inter, sans-serif`;
              ctx.textAlign = "center";
              ctx.textBaseline = "middle";
              
              // Background pour label
              const textWidth = ctx.measureText(label).width;
              const padding = 8;
              
              ctx.fillStyle = "rgba(0, 0, 0, 0.9)";
              ctx.fillRect(
                node.x - textWidth / 2 - padding,
                node.y - nodeSize - 30,
                textWidth + padding * 2,
                fontSize + padding
              );

              // Border autour du label
              ctx.strokeStyle = fill;
              ctx.lineWidth = 2;
              ctx.strokeRect(
                node.x - textWidth / 2 - padding,
                node.y - nodeSize - 30,
                textWidth + padding * 2,
                fontSize + padding
              );

              // Texte
              ctx.fillStyle = "#ffffff";
              ctx.fillText(label, node.x, node.y - nodeSize - 22);

              // ✅ DEVICE TYPE (si disponible)
              if (node.deviceType) {
                ctx.font = `10px Inter, sans-serif`;
                ctx.fillStyle = "rgba(255,255,255,0.6)";
                ctx.fillText(node.deviceType, node.x, node.y - nodeSize - 8);
              }
            }
          }}
          onNodeClick={(node: any) => setSelectedNode(node)}
          backgroundColor="rgba(0,0,0,0)"
        />

        {/* ✅ SELECTED NODE INFO PANEL */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-64 bg-slate-900/95 backdrop-blur-xl border border-white/20 rounded-xl p-4 shadow-2xl">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-white">Node Details</h3>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                ×
              </button>
            </div>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-gray-400">ID:</span>
                <span className="ml-2 text-white font-mono">{selectedNode.id}</span>
              </div>
              {selectedNode.deviceType && (
                <div>
                  <span className="text-gray-400">Type:</span>
                  <span className="ml-2 text-white">{selectedNode.deviceType}</span>
                </div>
              )}
              <div>
                <span className="text-gray-400">Status:</span>
                <span className={`ml-2 px-2 py-0.5 rounded-full text-xs font-bold ${
                  selectedNode.group === "c2" ? "bg-orange-500/20 text-orange-300" :
                  selectedNode.group === "anomalous" ? "bg-red-500/20 text-red-300" :
                  selectedNode.group === "critical" ? "bg-yellow-500/20 text-yellow-300" :
                  "bg-emerald-500/20 text-emerald-300"
                }`}>
                  {selectedNode.group.toUpperCase()}
                </span>
              </div>
              {selectedNode.riskScore && (
                <div>
                  <span className="text-gray-400">Risk:</span>
                  <span className="ml-2 text-red-400 font-bold">{selectedNode.riskScore.toFixed(1)}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ✅ LEGEND */}
      <div className="px-6 py-4 border-t border-white/10 bg-slate-900/50">
        <div className="flex flex-wrap items-center gap-4 text-xs">
          <LegendDot color="bg-emerald-500" label="Normal" />
          <LegendDot color="bg-red-500" label="Anomalous" />
          <LegendDot color="bg-yellow-400" label="Critical" />
          <LegendDot color="bg-orange-500" label="C2 Candidate" />
          <div className="ml-auto text-gray-500">
            <span className="text-cyan-400">━</span> Lateral • <span className="text-orange-400">━</span> C2
          </div>
        </div>
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-3 w-3 rounded-full ${color} shadow-lg`} />
      <span className="text-gray-300">{label}</span>
    </span>
  );
}