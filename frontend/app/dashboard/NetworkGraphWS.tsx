"use client";

import React, { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { socket } from "@/lib/socket";
import type { NetworkAnalysis } from "@/lib/api";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

type Group = "normal" | "anomalous" | "c2" | "critical";

type Node = {
  id: string;
  group: Group;

  // extra info (optional)
  device_type?: string;
  is_anomalous?: boolean;
  total_traffic?: number;

  // computed (optional)
  inDeg?: number;
  outDeg?: number;
};

type Link = {
  source: string;
  target: string;
  type: "c2" | "lateral" | "inferred";
  weight?: number;
};

// small helpers
const uniqPush = <T,>(arr: T[], item: T) => arr.push(item);

function buildGraph(a: NetworkAnalysis | null) {
  const nodes = new Map<string, Node>();
  const links: Link[] = [];

  if (!a?.analysis) return { nodes: [], links: [] };

  const analysis: any = a.analysis;

  // ---------------------------------------------------------
  // 1) Seed nodes from "all devices" if available (BEST)
  // ---------------------------------------------------------
  const allIds: string[] =
    analysis.network_summary?.all_devices ??
    analysis.graph?.nodes?.map((n: any) => n.device_id) ??
    [];

  for (const id of allIds) {
    if (!nodes.has(id)) nodes.set(id, { id, group: "normal" });
  }

  // ---------------------------------------------------------
  // 2) If backend provides rich node metadata, attach it
  // ---------------------------------------------------------
  const nodeMeta: any[] = analysis.graph?.nodes ?? [];
  for (const n of nodeMeta) {
    const id = n.device_id;
    const existing = nodes.get(id) ?? { id, group: "normal" as Group };
    nodes.set(id, {
      ...existing,
      device_type: n.device_type ?? existing.device_type,
      is_anomalous: n.is_anomalous ?? existing.is_anomalous,
      total_traffic: n.total_traffic ?? existing.total_traffic,
      group: (n.is_anomalous ? "anomalous" : existing.group) as Group,
    });
  }

  // ---------------------------------------------------------
  // 3) Add edges if backend provides them (BEST)
  // ---------------------------------------------------------
  const backendEdges: any[] = analysis.graph?.edges ?? [];
  for (const e of backendEdges) {
    const src = e.source ?? e.from ?? e.u;
    const dst = e.target ?? e.to ?? e.v;
    if (!src || !dst) continue;

    if (!nodes.has(src)) nodes.set(src, { id: src, group: "normal" });
    if (!nodes.has(dst)) nodes.set(dst, { id: dst, group: "normal" });

    links.push({
      source: String(src),
      target: String(dst),
      type: (e.type ?? "inferred") as "inferred",
      weight: typeof e.weight === "number" ? e.weight : undefined,
    });
  }

  // ---------------------------------------------------------
  // 4) Overlay “meaningful” structures (your current logic)
  //     These will upgrade node groups + add semantic links
  // ---------------------------------------------------------

  // critical devices
  for (const c of analysis.critical_devices ?? []) {
    const id = c.device_id;
    const existing = nodes.get(id) ?? { id, group: "normal" as Group };

    nodes.set(id, {
      ...existing,
      group: c.is_anomalous ? "anomalous" : "critical",
      is_anomalous: c.is_anomalous ?? existing.is_anomalous,
    });
  }

  // C2 candidates + recruited devices
  for (const c2 of analysis.botnet_analysis?.c2_candidates ?? []) {
    const c2id = c2.device_id;
    const existing = nodes.get(c2id) ?? { id: c2id, group: "normal" as Group };

    nodes.set(c2id, { ...existing, group: "c2" });

    for (const r of analysis.botnet_analysis?.recruited_devices ?? []) {
      const rid = String(r);
      const ex = nodes.get(rid) ?? { id: rid, group: "normal" as Group };
      nodes.set(rid, { ...ex, group: "anomalous", is_anomalous: true });

      links.push({ source: c2id, target: rid, type: "c2" });
    }
  }

  // lateral paths
  for (const p of analysis.lateral_movement?.attack_paths ?? []) {
    const path = p.path ?? [];
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

  // isolated fallback (if nothing at all)
  if (nodes.size === 0) {
    for (const id of analysis.network_summary?.isolated_devices ?? []) {
      nodes.set(String(id), { id: String(id), group: "normal" });
    }
  }

  // ---------------------------------------------------------
  // 5) Compute degrees (for tooltips)
  // ---------------------------------------------------------
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

export default function NetworkGraphWS({ initial }: { initial: NetworkAnalysis | null }) {
  const [analysis, setAnalysis] = useState<NetworkAnalysis | null>(initial);
  const [hover, setHover] = useState<Node | null>(null);

  useEffect(() => {
    const onUpdate = (payload: NetworkAnalysis) => setAnalysis(payload);
    socket.on("network:update", onUpdate);
    return () => socket.off("network:update", onUpdate);
  }, []);

  const graph = useMemo(() => buildGraph(analysis), [analysis]);
  const health = (analysis as any)?.analysis?.network_summary?.health_score;

  // quick counts
  const counts = useMemo(() => {
    const c = { normal: 0, anomalous: 0, c2: 0, critical: 0 };
    for (const n of graph.nodes) c[n.group]++;
    return c;
  }, [graph.nodes]);

  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-gray-300">
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">live websocket</span>
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">nodes: {graph.nodes.length}</span>
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">links: {graph.links.length}</span>

        <span className="px-2 py-1 rounded border border-white/10 bg-white/5">
          normal: {counts.normal} • anomalous: {counts.anomalous} • c2: {counts.c2} • critical: {counts.critical}
        </span>

        <span className="ml-auto text-gray-400">health: {health?.toFixed?.(1) ?? "N/A"}%</span>
      </div>

      <div className="relative h-[380px] w-full rounded-sm border border-white/10 overflow-hidden">
        {/* Hover tooltip */}
        {hover && (
          <div className="absolute z-10 left-3 top-3 rounded border border-white/10 bg-black/70 px-3 py-2 text-xs text-gray-200">
            <div className="font-semibold text-gray-100">{hover.id}</div>
            <div className="text-gray-400">group: {hover.group}</div>
            {hover.device_type && <div className="text-gray-400">type: {hover.device_type}</div>}
            {typeof hover.total_traffic === "number" && (
              <div className="text-gray-400">traffic: {hover.total_traffic}</div>
            )}
            <div className="text-gray-400">
              in: {hover.inDeg ?? 0} • out: {hover.outDeg ?? 0}
            </div>
          </div>
        )}

        {/* @ts-ignore */}
        <ForceGraph2D
          graphData={graph}
          nodeId="id"
          onNodeHover={(n: any) => setHover(n ? (n as Node) : null)}
          linkDirectionalArrowLength={5}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.18}
          linkWidth={(l: any) => (l.type === "lateral" ? 2 : l.type === "c2" ? 1.6 : 1.0)}
          linkColor={(l: any) =>
            l.type === "lateral"
              ? "rgba(34,211,238,0.9)"
              : l.type === "c2"
              ? "rgba(249,115,22,0.9)"
              : "rgba(148,163,184,0.35)" // inferred = gray
          }
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
            const fontSize = Math.max(8, 12 / globalScale);

            const color =
              node.group === "c2"
                ? "rgba(249,115,22,0.95)"
                : node.group === "anomalous"
                ? "rgba(239,68,68,0.95)"
                : node.group === "critical"
                ? "rgba(250,204,21,0.95)"
                : "rgba(34,197,94,0.9)";

            // slightly bigger for critical/c2
            const r = node.group === "critical" ? 7 : node.group === "c2" ? 7 : 6;

            ctx.beginPath();
            ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();

            ctx.font = `${fontSize}px sans-serif`;
            ctx.fillStyle = "rgba(255,255,255,0.85)";
            ctx.fillText(node.id, node.x + 10, node.y);
          }}
          backgroundColor="rgba(0,0,0,0)"
        />
      </div>

      <div className="mt-3 text-[11px] text-gray-400 flex flex-wrap gap-3">
        <span>🟩 normal</span>
        <span>🟥 anomalous</span>
        <span>🟨 critical</span>
        <span>🟧 c2</span>
        <span>— inferred links</span>
        <span>→ lateral / c2 links</span>
      </div>
    </div>
  );
}
