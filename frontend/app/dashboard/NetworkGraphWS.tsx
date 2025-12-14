"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { socket } from "@/lib/socket";
import type { NetworkAnalysis } from "@/lib/api";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

type Group = "normal" | "anomalous" | "c2" | "critical";

type Node = {
  id: string;
  group: Group;

  device_type?: string;
  is_anomalous?: boolean;
  total_traffic?: number;

  inDeg?: number;
  outDeg?: number;

  // live enrichment from detection:new
  lastSeen?: string; // ISO
  riskScore?: number;
  threatType?: string;
  threatSeverity?: string;
};

type Link = {
  source: string;
  target: string;
  type: "c2" | "lateral" | "inferred";
  weight?: number;
};

function buildGraph(a: NetworkAnalysis | null) {
  const nodes = new Map<string, Node>();
  const links: Link[] = [];

  if (!a?.analysis) return { nodes: [], links: [] };

  const analysis: any = a.analysis;

  // 1) seed nodes (if backend returns them)
  const allIds: string[] =
    analysis.network_summary?.all_devices ??
    analysis.graph?.nodes?.map((n: any) => n.device_id) ??
    [];

  for (const id of allIds) {
    if (!nodes.has(id)) nodes.set(id, { id, group: "normal" });
  }

  // 2) node metadata (if available)
  const nodeMeta: any[] = analysis.graph?.nodes ?? [];
  for (const n of nodeMeta) {
    const id = String(n.device_id);
    const existing = nodes.get(id) ?? { id, group: "normal" as Group };
    nodes.set(id, {
      ...existing,
      device_type: n.device_type ?? existing.device_type,
      is_anomalous: n.is_anomalous ?? existing.is_anomalous,
      total_traffic: n.total_traffic ?? existing.total_traffic,
      group: (n.is_anomalous ? "anomalous" : existing.group) as Group,
    });
  }

  // 3) edges (if backend provides them)
  const backendEdges: any[] = analysis.graph?.edges ?? [];
  for (const e of backendEdges) {
    const src = e.source ?? e.from ?? e.u;
    const dst = e.target ?? e.to ?? e.v;
    if (!src || !dst) continue;

    const s = String(src);
    const t = String(dst);

    if (!nodes.has(s)) nodes.set(s, { id: s, group: "normal" });
    if (!nodes.has(t)) nodes.set(t, { id: t, group: "normal" });

    links.push({
      source: s,
      target: t,
      type: (e.type ?? "inferred") as "inferred",
      weight: typeof e.weight === "number" ? e.weight : undefined,
    });
  }

  // 4) overlay meaningful structures
  for (const c of analysis.critical_devices ?? []) {
    const id = String(c.device_id);
    const existing = nodes.get(id) ?? { id, group: "normal" as Group };
    nodes.set(id, {
      ...existing,
      group: c.is_anomalous ? "anomalous" : "critical",
      is_anomalous: c.is_anomalous ?? existing.is_anomalous,
      device_type: c.device_type ?? existing.device_type,
    });
  }

  for (const c2 of analysis.botnet_analysis?.c2_candidates ?? []) {
    const c2id = String(c2.device_id);
    const existing = nodes.get(c2id) ?? { id: c2id, group: "normal" as Group };
    nodes.set(c2id, { ...existing, group: "c2" });

    for (const r of analysis.botnet_analysis?.recruited_devices ?? []) {
      const rid = String(r);
      const ex = nodes.get(rid) ?? { id: rid, group: "normal" as Group };
      nodes.set(rid, { ...ex, group: "anomalous", is_anomalous: true });
      links.push({ source: c2id, target: rid, type: "c2" });
    }
  }

  for (const p of analysis.lateral_movement?.attack_paths ?? []) {
    const path = Array.isArray(p.path) ? p.path : [];
    for (let i = 0; i < path.length; i++) {
      const id = String(path[i]);
      const ex = nodes.get(id) ?? { id, group: "normal" as Group };
      nodes.set(id, { ...ex, group: "anomalous", is_anomalous: true });

      if (i < path.length - 1) {
        links.push({
          source: String(path[i]),
          target: String(path[i + 1]),
          type: "lateral",
        });
      }
    }
  }

  // degrees for tooltips + sizing
  const inDeg = new Map<string, number>();
  const outDeg = new Map<string, number>();
  for (const l of links) {
    outDeg.set(String(l.source), (outDeg.get(String(l.source)) ?? 0) + 1);
    inDeg.set(String(l.target), (inDeg.get(String(l.target)) ?? 0) + 1);
  }

  for (const [id, n] of nodes.entries()) {
    nodes.set(id, {
      ...n,
      inDeg: inDeg.get(id) ?? 0,
      outDeg: outDeg.get(id) ?? 0,
    });
  }

  return { nodes: [...nodes.values()], links };
}

function clamp(n: number, a: number, b: number) {
  return Math.max(a, Math.min(b, n));
}

export default function NetworkGraphWS({ initial }: { initial: NetworkAnalysis | null }) {
  const fgRef = useRef<any>(null);

  const [analysis, setAnalysis] = useState<NetworkAnalysis | null>(initial);
  const [hover, setHover] = useState<Node | null>(null);
  const [selected, setSelected] = useState<Node | null>(null);

  // UI controls
  const [showLabels, setShowLabels] = useState(true);
  const [showInferred, setShowInferred] = useState(true);
  const [signalOnly, setSignalOnly] = useState(false); // anomalies/c2/critical + neighbors
  const [search, setSearch] = useState("");

  // map deviceId -> last detection info (from detection:new)
  const [liveMap, setLiveMap] = useState<Record<string, Partial<Node>>>({});

  useEffect(() => {
    const onUpdate = (payload: NetworkAnalysis) => setAnalysis(payload);

    const onDetection = (d: any) => {
      const id = String(d.deviceId ?? d.device_id ?? "");
      if (!id) return;
      setLiveMap((prev) => ({
        ...prev,
        [id]: {
          lastSeen: d.createdAt ? new Date(d.createdAt).toISOString() : new Date().toISOString(),
          riskScore: typeof d.riskScore === "number" ? d.riskScore : undefined,
          threatType: d.threatType ?? undefined,
          threatSeverity: d.threatSeverity ?? undefined,
          device_type: d.deviceType ?? undefined,
          is_anomalous: !!d.isAnomaly,
          group: d.isAnomaly ? "anomalous" : undefined,
        },
      }));
    };

    socket.on("network:update", onUpdate);
    socket.on("detection:new", onDetection);

    return () => {
      socket.off("network:update", onUpdate);
      socket.off("detection:new", onDetection);
    };
  }, []);

  const baseGraph = useMemo(() => buildGraph(analysis), [analysis]);

  // merge live enrichment into nodes
  const mergedGraph = useMemo(() => {
    const nodes = baseGraph.nodes.map((n) => {
      const live = liveMap[n.id] ?? {};
      const group: Group =
        (live.group as Group) ??
        n.group ??
        "normal";

      return {
        ...n,
        ...live,
        group,
      } as Node;
    });

    const links = baseGraph.links;
    return { nodes, links };
  }, [baseGraph.nodes, baseGraph.links, liveMap]);

  // optionally reduce clutter: show “signal nodes” + their neighbors
  const graph = useMemo(() => {
    if (!signalOnly) return mergedGraph;

    const important = new Set(
      mergedGraph.nodes
        .filter((n) => n.group === "anomalous" || n.group === "c2" || n.group === "critical")
        .map((n) => n.id)
    );

    // add 1-hop neighbors of important nodes
    for (const l of mergedGraph.links) {
      const s = String(l.source);
      const t = String(l.target);
      if (important.has(s) || important.has(t)) {
        important.add(s);
        important.add(t);
      }
    }

    const nodes = mergedGraph.nodes.filter((n) => important.has(n.id));
    const nodeSet = new Set(nodes.map((n) => n.id));
    const links = mergedGraph.links.filter((l) => nodeSet.has(String(l.source)) && nodeSet.has(String(l.target)));

    return { nodes, links };
  }, [mergedGraph, signalOnly]);

  const health = (analysis as any)?.analysis?.network_summary?.health_score;

  const counts = useMemo(() => {
    const c = { normal: 0, anomalous: 0, c2: 0, critical: 0 };
    for (const n of graph.nodes) c[n.group]++;
    return c;
  }, [graph.nodes]);

  // filtered links (toggle inferred)
  const displayLinks = useMemo(() => {
    if (showInferred) return graph.links;
    return graph.links.filter((l) => l.type !== "inferred");
  }, [graph.links, showInferred]);

  const displayGraph = useMemo(() => {
    // Keep nodes that are referenced by remaining links
    const ids = new Set<string>();
    for (const l of displayLinks) {
      ids.add(String(l.source));
      ids.add(String(l.target));
    }
    // if removing inferred removes everything, keep nodes anyway
    const nodes = ids.size ? graph.nodes.filter((n) => ids.has(n.id)) : graph.nodes;
    return { nodes, links: displayLinks };
  }, [graph.nodes, displayLinks]);

  function centerOnNode(id: string) {
    const fg = fgRef.current;
    if (!fg) return;
    const node = displayGraph.nodes.find((n: any) => n.id === id);
    if (!node) return;
    fg.centerAt(node.x, node.y, 700);
    fg.zoom(2.2, 700);
  }

  function onSearch() {
    const id = search.trim();
    if (!id) return;
    centerOnNode(id);
    const n = displayGraph.nodes.find((x) => x.id === id) ?? null;
    setSelected(n as any);
  }

  // build “neighbors” for selected panel
  const neighbors = useMemo(() => {
    if (!selected) return { in: [] as string[], out: [] as string[] };
    const ins: string[] = [];
    const outs: string[] = [];
    for (const l of displayGraph.links) {
      const s = String(l.source);
      const t = String(l.target);
      if (t === selected.id) ins.push(s);
      if (s === selected.id) outs.push(t);
    }
    return {
      in: Array.from(new Set(ins)).slice(0, 12),
      out: Array.from(new Set(outs)).slice(0, 12),
    };
  }, [selected, displayGraph.links]);

  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
      {/* header row */}
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-gray-300">
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">live websocket</span>

        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">
          nodes: {displayGraph.nodes.length}
        </span>
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">
          links: {displayGraph.links.length}
        </span>

        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">
          normal: {counts.normal} • anomalous: {counts.anomalous} • c2: {counts.c2} • critical: {counts.critical}
        </span>

        <span className="ml-auto text-gray-400">health: {health?.toFixed?.(1) ?? "N/A"}%</span>
      </div>

      {/* controls */}
      <div className="mb-3 grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="rounded-sm bg-black/30 border border-white/10 p-3">
          <div className="text-xs font-semibold text-gray-200 mb-2">Controls</div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <button
              onClick={() => setShowLabels((v) => !v)}
              className={`px-2 py-1 rounded border ${showLabels ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-200" : "border-white/10 bg-white/5 text-gray-200"}`}
            >
              {showLabels ? "Labels: ON" : "Labels: OFF"}
            </button>

            <button
              onClick={() => setShowInferred((v) => !v)}
              className={`px-2 py-1 rounded border ${showInferred ? "border-white/10 bg-white/5 text-gray-200" : "border-orange-500/30 bg-orange-500/10 text-orange-200"}`}
            >
              {showInferred ? "Inferred: ON" : "Inferred: OFF"}
            </button>

            <button
              onClick={() => setSignalOnly((v) => !v)}
              className={`px-2 py-1 rounded border ${signalOnly ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-200" : "border-white/10 bg-white/5 text-gray-200"}`}
            >
              {signalOnly ? "Signal only: ON" : "Signal only: OFF"}
            </button>

            <button
              onClick={() => {
                const fg = fgRef.current;
                if (!fg) return;
                fg.zoomToFit(600, 40);
              }}
              className="px-2 py-1 rounded border border-white/10 bg-white/5 hover:border-white/20"
            >
              Zoom to fit
            </button>
          </div>

          <div className="mt-3 flex items-center gap-2">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search device_id (ex: camera_02)"
              className="w-full rounded bg-black/40 border border-white/10 px-3 py-2 text-xs text-gray-200 outline-none focus:border-white/30"
            />
            <button
              onClick={onSearch}
              className="px-3 py-2 rounded border border-white/10 bg-white/5 hover:border-white/20 text-xs"
            >
              Go
            </button>
          </div>

          <div className="mt-2 text-[11px] text-gray-500">
            Tip: active “Signal only” pour éviter le “hairball” (boule de spaghetti).
          </div>
        </div>

        <div className="rounded-sm bg-black/30 border border-white/10 p-3">
          <div className="text-xs font-semibold text-gray-200 mb-2">Legend (meaning)</div>
          <div className="grid grid-cols-2 gap-2 text-[11px] text-gray-300">
            <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded bg-green-500" /> Normal device</div>
            <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded bg-red-500" /> Anomalous (ML)</div>
            <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded bg-yellow-400" /> Critical (central)</div>
            <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded bg-orange-500" /> C2 candidate</div>
          </div>
          <div className="mt-3 text-[11px] text-gray-400 space-y-1">
            <div>• <span className="text-gray-200">Inferred links</span> = liens “probables” (heuristique).</div>
            <div>• <span className="text-cyan-200">Lateral</span> = chemins d’attaque (propagation).</div>
            <div>• <span className="text-orange-200">C2</span> = hub qui “commande” des devices (botnet).</div>
          </div>
        </div>

        <div className="rounded-sm bg-black/30 border border-white/10 p-3">
          <div className="text-xs font-semibold text-gray-200 mb-2">Selected device</div>

          {!selected ? (
            <div className="text-[11px] text-gray-400">
              Click sur un node pour voir ses détails (sinon hover = mini tooltip).
            </div>
          ) : (
            <div className="text-xs text-gray-300 space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold text-gray-100">{selected.id}</div>
                <span
                  className={[
                    "text-[11px] px-2 py-1 rounded border",
                    selected.group === "anomalous"
                      ? "bg-red-500/15 text-red-200 border-red-500/25"
                      : selected.group === "c2"
                      ? "bg-orange-500/15 text-orange-200 border-orange-500/25"
                      : selected.group === "critical"
                      ? "bg-yellow-500/15 text-yellow-200 border-yellow-500/25"
                      : "bg-green-500/10 text-green-200 border-green-500/20",
                  ].join(" ")}
                >
                  {selected.group}
                </span>
              </div>

              <div className="text-[11px] text-gray-400">
                type: <span className="text-gray-200">{selected.device_type ?? "—"}</span>
              </div>

              <div className="text-[11px] text-gray-400">
                in/out: <span className="text-gray-200">{selected.inDeg ?? 0}</span> /{" "}
                <span className="text-gray-200">{selected.outDeg ?? 0}</span>
              </div>

              <div className="text-[11px] text-gray-400">
                last seen:{" "}
                <span className="text-gray-200">
                  {selected.lastSeen ? new Date(selected.lastSeen).toLocaleString() : "—"}
                </span>
              </div>

              <div className="text-[11px] text-gray-400">
                risk: <span className="text-gray-200">{selected.riskScore ?? "—"}</span>{" "}
                {selected.threatSeverity ? <span className="text-gray-500">• {selected.threatSeverity}</span> : null}
              </div>

              <div className="text-[11px] text-gray-400">
                threat: <span className="text-gray-200">{selected.threatType ?? "—"}</span>
              </div>

              <div className="mt-2">
                <div className="text-[11px] text-gray-400 mb-1">incoming (max 12)</div>
                <div className="flex flex-wrap gap-2">
                  {neighbors.in.length ? neighbors.in.map((x) => (
                    <button
                      key={x}
                      onClick={() => { setSearch(x); centerOnNode(x); }}
                      className="px-2 py-1 rounded border border-white/10 bg-white/5 hover:border-white/20 text-[11px]"
                    >
                      {x}
                    </button>
                  )) : <span className="text-[11px] text-gray-500">—</span>}
                </div>
              </div>

              <div className="mt-2">
                <div className="text-[11px] text-gray-400 mb-1">outgoing (max 12)</div>
                <div className="flex flex-wrap gap-2">
                  {neighbors.out.length ? neighbors.out.map((x) => (
                    <button
                      key={x}
                      onClick={() => { setSearch(x); centerOnNode(x); }}
                      className="px-2 py-1 rounded border border-white/10 bg-white/5 hover:border-white/20 text-[11px]"
                    >
                      {x}
                    </button>
                  )) : <span className="text-[11px] text-gray-500">—</span>}
                </div>
              </div>

              <button
                onClick={() => setSelected(null)}
                className="mt-3 px-2 py-1 rounded border border-white/10 bg-white/5 hover:border-white/20 text-[11px]"
              >
                Clear selection
              </button>
            </div>
          )}
        </div>
      </div>

      {/* graph */}
      <div className="relative h-[420px] w-full rounded-sm border border-white/10 overflow-hidden">
        {/* hover tooltip */}
        {hover && !selected && (
          <div className="absolute z-10 left-3 top-3 rounded border border-white/10 bg-black/70 px-3 py-2 text-xs text-gray-200">
            <div className="font-semibold text-gray-100">{hover.id}</div>
            <div className="text-gray-400">group: {hover.group}</div>
            {hover.device_type && <div className="text-gray-400">type: {hover.device_type}</div>}
            <div className="text-gray-400">in/out: {hover.inDeg ?? 0} / {hover.outDeg ?? 0}</div>
          </div>
        )}

        {/* @ts-ignore */}
        <ForceGraph2D
          ref={fgRef}
          graphData={displayGraph}
          nodeId="id"

          onNodeHover={(n: any) => setHover(n ? (n as Node) : null)}
          onNodeClick={(n: any) => {
            const node = n as Node;
            setSelected(node);
            // focus on click
            const fg = fgRef.current;
            if (fg) {
              fg.centerAt(node.x, node.y, 600);
              fg.zoom(2.4, 600);
            }
          }}

          cooldownTicks={120}
          warmupTicks={60}
          linkDirectionalArrowLength={5}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.22}

          linkWidth={(l: any) => (l.type === "lateral" ? 2.2 : l.type === "c2" ? 1.8 : 0.8)}
          linkColor={(l: any) =>
            l.type === "lateral"
              ? "rgba(34,211,238,0.9)"
              : l.type === "c2"
              ? "rgba(249,115,22,0.9)"
              : "rgba(148,163,184,0.18)" // inferred ultra light
          }

          // Node rendering
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
            const n = node as Node;

            const degree = (n.inDeg ?? 0) + (n.outDeg ?? 0);
            const sizeByDegree = clamp(4 + degree * 0.6, 5, 12);
            const sizeByTraffic =
              typeof n.total_traffic === "number" ? clamp(4 + n.total_traffic / 500, 5, 14) : sizeByDegree;

            const r = n.group === "c2" || n.group === "critical" ? sizeByTraffic + 2 : sizeByTraffic;

            const fill =
              n.group === "c2"
                ? "rgba(249,115,22,0.95)"
                : n.group === "anomalous"
                ? "rgba(239,68,68,0.95)"
                : n.group === "critical"
                ? "rgba(250,204,21,0.95)"
                : "rgba(34,197,94,0.9)";

            // main dot
            ctx.beginPath();
            ctx.arc(n.x as number, n.y as number, r, 0, 2 * Math.PI, false);
            ctx.fillStyle = fill;
            ctx.fill();

            // ring for selected / anomalous emphasis
            if (selected?.id === n.id) {
              ctx.beginPath();
              ctx.arc(n.x as number, n.y as number, r + 5, 0, 2 * Math.PI, false);
              ctx.strokeStyle = "rgba(255,255,255,0.85)";
              ctx.lineWidth = 2;
              ctx.stroke();
            } else if (n.group === "anomalous") {
              ctx.beginPath();
              ctx.arc(n.x as number, n.y as number, r + 3, 0, 2 * Math.PI, false);
              ctx.strokeStyle = "rgba(239,68,68,0.45)";
              ctx.lineWidth = 2;
              ctx.stroke();
            }

            // labels: only if zoomed enough OR hovered/selected (this fixes the mess)
            const shouldLabel =
              showLabels && (globalScale > 1.6 || hover?.id === n.id || selected?.id === n.id);

            if (shouldLabel) {
              const fontSize = clamp(10 / globalScale, 8, 13);
              const label = n.id;

              ctx.font = `${fontSize}px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto`;
              const textW = ctx.measureText(label).width;

              // label background to be readable
              const x = (n.x as number) + r + 8;
              const y = (n.y as number) + 4;

              ctx.fillStyle = "rgba(0,0,0,0.55)";
              ctx.fillRect(x - 3, y - fontSize, textW + 6, fontSize + 4);

              ctx.fillStyle = "rgba(255,255,255,0.9)";
              ctx.fillText(label, x, y);
            }
          }}
          backgroundColor="rgba(0,0,0,0)"
        />
      </div>

      <div className="mt-3 text-[11px] text-gray-400 flex flex-wrap gap-3">
        <span>🟩 normal</span>
        <span>🟥 anomalous</span>
        <span>🟨 critical</span>
        <span>🟧 c2</span>
        <span>— inferred links (light)</span>
        <span>→ lateral / c2 links (strong)</span>
      </div>
    </div>
  );
}
