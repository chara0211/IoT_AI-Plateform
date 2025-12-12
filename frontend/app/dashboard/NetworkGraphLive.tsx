"use client";

import React, { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import type { NetworkAnalysis } from "@/lib/api";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

type GraphNode = {
  id: string;
  group: "normal" | "anomalous" | "c2" | "critical";
  label?: string;
};

type GraphLink = {
  source: string;
  target: string;
  type: "c2" | "lateral";
};

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function buildGraphFromAnalysis(analysis: NetworkAnalysis | null) {
  const nodes = new Map<string, GraphNode>();
  const links: GraphLink[] = [];

  if (!analysis?.analysis) return { nodes: [], links: [] };

  const a = analysis.analysis;

  // 1) Add critical devices
  for (const c of a.critical_devices ?? []) {
    nodes.set(c.device_id, {
      id: c.device_id,
      group: c.is_anomalous ? "anomalous" : "critical",
      label: `${c.device_id} (${c.device_type})`,
    });
  }

  // 2) C2 candidates + recruited devices
  const c2s = a.botnet_analysis?.c2_candidates ?? [];
  for (const c2 of c2s) {
    nodes.set(c2.device_id, {
      id: c2.device_id,
      group: "c2",
      label: `${c2.device_id} (C2 score ${c2.c2_score})`,
    });

    // If ML returns recruited_devices list, connect C2 to them
    const recruited = a.botnet_analysis?.recruited_devices ?? [];
    for (const r of recruited) {
      if (!nodes.has(r)) {
        nodes.set(r, { id: r, group: "anomalous" });
      }
      links.push({ source: c2.device_id, target: r, type: "c2" });
    }
  }

  // 3) Lateral movement paths → add edges along paths
  const paths = a.lateral_movement?.attack_paths ?? [];
  for (const p of paths) {
    const path = p.path ?? [];
    for (let i = 0; i < path.length; i++) {
      const id = path[i];
      if (!nodes.has(id)) nodes.set(id, { id, group: "anomalous" });

      if (i < path.length - 1) {
        links.push({ source: path[i], target: path[i + 1], type: "lateral" });
      }
    }
  }

  // 4) If nothing exists, still show isolated devices as nodes
  const isolated = a.network_summary?.isolated_devices ?? [];
  if (nodes.size === 0 && isolated.length) {
    for (const id of isolated) nodes.set(id, { id, group: "normal" });
  }

  return { nodes: Array.from(nodes.values()), links };
}

export default function NetworkGraphLive({
  initial,
  refreshMs = 5000,
}: {
  initial: NetworkAnalysis | null;
  refreshMs?: number;
}) {
  const [data, setData] = useState<NetworkAnalysis | null>(initial);

  // Poll backend for live updates
  useEffect(() => {
    let alive = true;

    const tick = async () => {
      try {
        const base = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000";
        const res = await fetch(`${base}/api/network/status?minutes=60`, { cache: "no-store" });
        if (!res.ok) return;
        const json = (await res.json()) as NetworkAnalysis;
        if (alive) setData(json);
      } catch {
        // ignore
      }
    };

    tick();
    const id = setInterval(tick, refreshMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [refreshMs]);

  const graph = useMemo(() => buildGraphFromAnalysis(data), [data]);

  const health = data?.analysis?.network_summary?.health_score ?? null;
  const totalDevices = data?.analysis?.network_summary?.total_devices ?? graph.nodes.length;
  const totalEdges = data?.analysis?.network_summary?.total_connections ?? graph.links.length;

  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
      {/* header line like console */}
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5 text-gray-200">
          devices: {totalDevices}
        </span>
        <span className="px-2 py-1 rounded border border-white/10 bg-white/5 text-gray-200">
          links: {totalEdges}
        </span>
        <span
          className={[
            "px-2 py-1 rounded border",
            health === null
              ? "border-white/10 bg-white/5 text-gray-200"
              : health < 60
              ? "border-red-500/25 bg-red-500/10 text-red-200"
              : health < 80
              ? "border-yellow-500/25 bg-yellow-500/10 text-yellow-200"
              : "border-green-500/20 bg-green-500/10 text-green-200",
          ].join(" ")}
        >
          health: {health === null ? "N/A" : `${health.toFixed?.(1) ?? health}%`}
        </span>

        <span className="ml-auto text-gray-400">
          live • refresh {Math.round(refreshMs / 1000)}s
        </span>
      </div>

      <div className="h-[380px] w-full rounded-sm border border-white/10 overflow-hidden">
        {/* @ts-ignore */}
        <ForceGraph2D
          graphData={graph}
          nodeId="id"
          linkDirectionalArrowLength={5}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.15}
          nodeRelSize={5}
          linkWidth={(l: any) => (l.type === "lateral" ? 2 : 1.2)}
          linkColor={(l: any) =>
            l.type === "lateral" ? "rgba(34,211,238,0.9)" : "rgba(249,115,22,0.9)"
          }
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
            const label = node.id;
            const fontSize = clamp(12 / globalScale, 8, 14);

            const color =
              node.group === "c2"
                ? "rgba(249,115,22,0.95)" // orange
                : node.group === "anomalous"
                ? "rgba(239,68,68,0.95)" // red
                : node.group === "critical"
                ? "rgba(250,204,21,0.95)" // yellow
                : "rgba(34,197,94,0.9)"; // green

            ctx.beginPath();
            ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();

            ctx.font = `${fontSize}px sans-serif`;
            ctx.textAlign = "left";
            ctx.textBaseline = "middle";
            ctx.fillStyle = "rgba(255,255,255,0.85)";
            ctx.fillText(label, node.x + 10, node.y);
          }}
          backgroundColor="rgba(0,0,0,0.0)"
        />
      </div>

      {/* legend */}
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-gray-300">
        <LegendDot color="bg-green-500" label="normal" />
        <LegendDot color="bg-red-500" label="anomalous" />
        <LegendDot color="bg-yellow-400" label="critical" />
        <LegendDot color="bg-orange-500" label="C2 candidate" />
        <span className="text-gray-500">links: orange=botnet • cyan=lateral path</span>
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-2.5 w-2.5 rounded ${color}`} />
      {label}
    </span>
  );
}
