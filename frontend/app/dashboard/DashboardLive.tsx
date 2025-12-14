// frontend/app/dashboard/DashboardLive.tsx
"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { io as ioClient, Socket } from "socket.io-client";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  ChevronDown,
  Clock,
  Filter,
  Network,
  PieChart,
  RefreshCcw,
  Shield,
  Zap,
  Eye,
  TrendingUp,
  Wifi,
  WifiOff,
  Info,
} from "lucide-react";

import NetworkGraphWS from "./NetworkGraphWS";
import LiveFeedWS from "./LiveFeedWS";

// ---- types (keep loose; compatible avec ton backend actuel)
type Summary = {
  total_detections: number;
  anomaly_count: number;
  normal_count: number;
  anomaly_ratio: number;
  critical_incidents: number;
  high_incidents: number;
};

type Detection = any;
type ThreatRow = { threatType: string; _count: number };
type NetworkStatus = any;

const WS_URL = process.env.NEXT_PUBLIC_BACKEND_WS_URL || "http://localhost:5000"; // socket.io server

export default function DashboardLive({
  initialSummary,
  initialDetections,
  initialAnomalies,
  initialThreats,
  initialNetworkStatus,
}: {
  initialSummary: Summary;
  initialDetections: Detection[];
  initialAnomalies: Detection[];
  initialThreats: ThreatRow[];
  initialNetworkStatus: NetworkStatus | null;
}) {
  // live states
  const [summary, setSummary] = useState<Summary>(initialSummary);
  const [detections, setDetections] = useState<Detection[]>(initialDetections ?? []);
  const [anomalies, setAnomalies] = useState<Detection[]>(initialAnomalies ?? []);
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(initialNetworkStatus ?? null);

  // threats distribution as map so updates are easy
  const [threatMap, setThreatMap] = useState<Record<string, number>>(() => {
    const m: Record<string, number> = {};
    (initialThreats ?? []).forEach((t) => (m[t.threatType] = t._count ?? 0));
    return m;
  });

  const [wsState, setWsState] = useState<"connected" | "disconnected" | "connecting">("connecting");
  const [lastLiveAt, setLastLiveAt] = useState<Date | null>(null);

  const socketRef = useRef<Socket | null>(null);

  const threats: ThreatRow[] = useMemo(() => {
    return Object.entries(threatMap)
      .map(([threatType, _count]) => ({ threatType, _count }))
      .sort((a, b) => (b._count ?? 0) - (a._count ?? 0));
  }, [threatMap]);

  // ---- WS connect
  useEffect(() => {
    const s = ioClient(WS_URL, {
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: 50,
      reconnectionDelay: 500,
    });

    socketRef.current = s;

    s.on("connect", () => {
      setWsState("connected");
      setLastLiveAt(new Date());
    });
    s.on("disconnect", () => {
      setWsState("disconnected");
    });
    s.on("connect_error", () => {
      setWsState("disconnected");
    });

    // 🔥 live detection
    s.on("detection:new", (d: Detection) => {
      setLastLiveAt(new Date());

      // prepend detection (cap to keep UI fast)
      setDetections((prev) => [d, ...prev].slice(0, 200));

      // if anomaly, update anomalies list too
      if (d?.isAnomaly) {
        setAnomalies((prev) => [d, ...prev].slice(0, 30));
      }

      // update summary numbers LIVE
      setSummary((prev) => {
        const total = (prev.total_detections ?? 0) + 1;
        const isAnomaly = !!d?.isAnomaly;
        const severity = String(d?.threatSeverity || "").toUpperCase();

        const anomaly_count = (prev.anomaly_count ?? 0) + (isAnomaly ? 1 : 0);
        const normal_count = (prev.normal_count ?? 0) + (isAnomaly ? 0 : 1);

        const critical_incidents =
          (prev.critical_incidents ?? 0) + (isAnomaly && severity === "CRITICAL" ? 1 : 0);

        const high_incidents =
          (prev.high_incidents ?? 0) + (isAnomaly && severity === "HIGH" ? 1 : 0);

        const anomaly_ratio = total ? anomaly_count / total : 0;

        return {
          total_detections: total,
          anomaly_count,
          normal_count,
          critical_incidents,
          high_incidents,
          anomaly_ratio,
        };
      });

      // update threat distribution LIVE (only anomalies)
      if (d?.isAnomaly && d?.threatType) {
        const tt = String(d.threatType);
        setThreatMap((m) => ({ ...m, [tt]: (m[tt] ?? 0) + 1 }));
      }
    });

    // 🔥 live network analysis
    s.on("network:update", (payload: any) => {
      setLastLiveAt(new Date());
      setNetworkStatus(payload);
    });

    return () => {
      s.removeAllListeners();
      s.disconnect();
      socketRef.current = null;
    };
  }, []);

  const activeFilters = ["source: MQTT", "mode: realtime", "time: last 60min"];

  return (
    <div className="min-h-screen bg-[#07090d] text-white">
      {/* Top bar */}
      <div className="border-b border-white/10 bg-black/40 sticky top-0 z-40 backdrop-blur">
        <div className="mx-auto max-w-[1600px] px-6 py-4">
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-md bg-[#0f1520] border border-white/10 grid place-items-center">
                <Shield className="h-5 w-5 text-blue-200" />
              </div>
              <div>
                <div className="text-sm text-gray-300">Security Console</div>
                <div className="text-base font-semibold text-gray-100">
                  IoT Security Platform <span className="text-gray-500 font-normal">• Live Monitor</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 text-sm text-gray-300">
              <LiveBadge state={wsState} lastLiveAt={lastLiveAt} />
              <span className="hidden sm:inline opacity-80">Window</span>
              <TimeBtn label="60 min" />
              <span className="opacity-80">to</span>
              <TimeBtn label="now" />
              <button
                className="ml-1 inline-flex items-center justify-center rounded-md bg-[#0f1520] p-2 border border-white/10 hover:border-white/20"
                title="Refresh (UI only)"
                onClick={() => window.location.reload()}
              >
                <RefreshCcw className="h-4 w-4 opacity-80" />
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="mt-4 flex items-center gap-6 text-sm">
            <Tab label="Live" active />
            <Tab label="Anomalies" />
            <Tab label="Insights" />
            <Tab label="Network" />
          </div>

          {/* Active filters */}
          <div className="mt-4 rounded-md bg-black/30 border border-white/10 px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-xs text-gray-400">
                <Filter className="h-4 w-4" />
                <span>Active Filters</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {activeFilters.map((f) => (
                  <FilterPill key={f} label={f} />
                ))}
              </div>
              <div className="ml-auto flex items-center gap-2 text-xs text-gray-400">
                <Clock className="h-4 w-4" />
                <span>{new Date().toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        {/* Top Stats (LIVE) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <MiniStat
            title="Total Detections"
            value={summary.total_detections.toLocaleString()}
            icon={<Activity className="h-4 w-4" />}
            accent="text-blue-200"
            help="Nombre total d’événements analysés depuis le lancement (live)."
          />
          <MiniStat
            title="Active Anomalies"
            value={summary.anomaly_count.toLocaleString()}
            icon={<AlertTriangle className="h-4 w-4" />}
            accent="text-orange-200"
            sub={`${(summary.anomaly_ratio * 100).toFixed(1)}% anomaly ratio`}
            help="Événements détectés comme suspects par le ML (live)."
          />
          <MiniStat
            title="Critical Incidents"
            value={summary.critical_incidents.toLocaleString()}
            icon={<Zap className="h-4 w-4" />}
            accent="text-red-200"
            sub={`${summary.high_incidents} high priority`}
            help="Incidents CRITICAL / HIGH (live)."
          />
          <MiniStat
            title="Normal Devices"
            value={summary.normal_count.toLocaleString()}
            icon={<Shield className="h-4 w-4" />}
            accent="text-green-200"
            sub="Healthy"
            help="Événements classés normaux (live)."
          />
        </div>

        {/* 3 panels row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Panel
            title="Signal overview"
            subtitle="How anomalies evolve over time (live derived)"
            badge={1}
            icon={<BarChart3 className="h-4 w-4" />}
          >
            <AnomalyCountMiniChart summary={summary} />
          </Panel>

          <Panel
            title="Detection mix"
            subtitle="Normal vs Anomaly vs Critical"
            badge={2}
            icon={<PieChart className="h-4 w-4" />}
          >
            <ConfidenceDonutMini
              normal={summary.normal_count}
              anomaly={summary.anomaly_count}
              critical={summary.critical_incidents}
              high={summary.high_incidents}
            />
          </Panel>

          <Panel
            title="Hot activity"
            subtitle="Heatmap based on risk (latest events)"
            badge={3}
            icon={<TrendingUp className="h-4 w-4" />}
          >
            <ServiceHeatMini detections={detections} />
          </Panel>
        </div>

        {/* Network (LIVE via network:update) */}
        <Panel
          title="Network Behavior (ML Engine)"
          subtitle="Graph + botnet/lateral/coordinated insights (live)"
          badge={4}
          icon={<Network className="h-4 w-4" />}
        >
          <NetworkPanel networkStatus={networkStatus} />

          <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <NetworkGraphWS initial={networkStatus} />
            </div>
            <div className="lg:col-span-1">
              <LiveFeedWS initial={detections.slice(0, 12)} />
            </div>
          </div>
        </Panel>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 space-y-4">
            <Panel
              title="Recent anomalies"
              subtitle="Explanations + SHAP factors"
              badge={5}
              icon={<AlertTriangle className="h-4 w-4" />}
            >
              <RecentAnomaliesConsole anomalies={anomalies} />
            </Panel>

            <Panel
              title="Threat distribution"
              subtitle="Count of anomaly types (live)"
              badge={6}
              icon={<Zap className="h-4 w-4" />}
            >
              <ThreatBars threats={threats} />
            </Panel>
          </div>

          <div className="space-y-4">
            <Panel title="Live feed" subtitle="Latest detections (live)" badge={7} icon={<Eye className="h-4 w-4" />}>
              <LiveFeedConsole detections={detections.slice(0, 20)} />
            </Panel>
          </div>
        </div>

        <DetectionsConsoleTable detections={detections} />
      </div>
    </div>
  );
}

/* ========================== small UI components ========================== */

function LiveBadge({ state, lastLiveAt }: { state: "connected" | "disconnected" | "connecting"; lastLiveAt: Date | null }) {
  const tone =
    state === "connected" ? "bg-green-500/15 text-green-200 border-green-500/25" :
    state === "connecting" ? "bg-yellow-500/15 text-yellow-200 border-yellow-500/25" :
    "bg-red-500/15 text-red-200 border-red-500/25";

  const Icon = state === "connected" ? Wifi : WifiOff;
  return (
    <div className={`inline-flex items-center gap-2 rounded-md border px-3 py-1 text-xs ${tone}`}>
      <Icon className="h-3.5 w-3.5" />
      <span className="font-medium">
        {state === "connected" ? "LIVE" : state === "connecting" ? "CONNECTING" : "OFFLINE"}
      </span>
      <span className="text-[11px] opacity-80">
        {lastLiveAt ? `• last: ${lastLiveAt.toLocaleTimeString()}` : ""}
      </span>
    </div>
  );
}

function TimeBtn({ label }: { label: string }) {
  return (
    <button className="inline-flex items-center gap-2 rounded-md bg-[#0f1520] px-3 py-1.5 border border-white/10 hover:border-white/20">
      <span className="text-blue-300 font-medium">{label}</span>
      <ChevronDown className="h-4 w-4 opacity-70" />
    </button>
  );
}

function Tab({ label, active = false }: { label: string; active?: boolean }) {
  return (
    <button
      className={[
        "relative pb-2 text-sm",
        active ? "text-white" : "text-gray-400 hover:text-gray-200",
      ].join(" ")}
    >
      {label}
      {active ? <span className="absolute left-0 -bottom-[1px] h-[2px] w-full bg-white/80" /> : null}
    </button>
  );
}

function FilterPill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-md bg-[#0f1520] border border-white/10 px-3 py-1 text-xs text-blue-200">
      {label}
      <span className="opacity-70">×</span>
    </span>
  );
}

function Panel({
  title,
  subtitle,
  badge,
  icon,
  children,
}: {
  title: string;
  subtitle?: string;
  badge: number;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/30 p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
            <span className="opacity-80">{icon}</span>
            {title}
          </div>
          {subtitle ? <div className="mt-1 text-xs text-gray-500">{subtitle}</div> : null}
        </div>
        <div className="flex h-6 w-6 items-center justify-center rounded-full bg-yellow-400 text-[11px] font-bold text-black">
          {badge}
        </div>
      </div>
      {children}
    </div>
  );
}

function MiniStat({
  title,
  value,
  icon,
  accent,
  sub,
  help,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  accent: string;
  sub?: string;
  help?: string;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/30 px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-gray-400 flex items-center gap-2">
          {title}
          {help ? (
            <span className="group relative inline-flex items-center">
              <Info className="h-3.5 w-3.5 text-gray-500" />
              <span className="pointer-events-none absolute left-0 top-full mt-2 w-64 rounded-md border border-white/10 bg-black/90 p-2 text-[11px] text-gray-200 opacity-0 group-hover:opacity-100 transition">
                {help}
              </span>
            </span>
          ) : null}
        </div>
        <div className={`inline-flex items-center gap-2 text-xs ${accent}`}>{icon}</div>
      </div>
      <div className="mt-1 text-2xl font-bold text-gray-100">{value}</div>
      {sub ? <div className="mt-1 text-xs text-gray-400">{sub}</div> : null}
    </div>
  );
}

/* ============================ charts (simple) ============================ */

function AnomalyCountMiniChart({ summary }: { summary: any }) {
  const seed = [
    summary.anomaly_count,
    summary.high_incidents,
    summary.critical_incidents,
    Math.max(1, Math.floor(summary.anomaly_count / 2)),
    Math.max(1, Math.floor(summary.anomaly_count / 3)),
    Math.max(1, Math.floor(summary.anomaly_count / 4)),
    0,
    0,
  ];
  const maxV = Math.max(...seed, 1);

  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3">
      <div className="flex h-40 items-end gap-1">
        {seed.map((v, i) => (
          <div key={i} className="flex-1">
            <div
              className="w-full rounded-t bg-orange-500/90"
              style={{ height: `${Math.max(2, (v / maxV) * 100)}%` }}
            />
          </div>
        ))}
      </div>
      <div className="mt-2 text-[11px] text-gray-400">
        Live: basé sur les événements WS reçus (pas besoin de refresh).
      </div>
    </div>
  );
}

function ConfidenceDonutMini({
  normal,
  anomaly,
  critical,
}: {
  normal: number;
  anomaly: number;
  critical: number;
  high: number;
}) {
  const total = Math.max(1, normal + anomaly);
  const normalPct = (normal / total) * 100;
  const anomalyPct = (anomaly / total) * 100;
  const criticalPct = Math.min(100, (critical / total) * 100);

  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3 flex items-center justify-center gap-6">
      <div className="relative h-32 w-32">
        <svg className="h-full w-full -rotate-90">
          <circle cx="64" cy="64" r="46" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="14" />
          <circle cx="64" cy="64" r="46" fill="none" stroke="#22c55e" strokeWidth="14" strokeDasharray={`${normalPct * 2.89} 289`} />
          <circle cx="64" cy="64" r="46" fill="none" stroke="#ef4444" strokeWidth="14" strokeDasharray={`${anomalyPct * 2.89} 289`} strokeDashoffset={`-${normalPct * 2.89}`} />
          <circle cx="64" cy="64" r="46" fill="none" stroke="#facc15" strokeWidth="14" strokeDasharray={`${criticalPct * 2.89} 289`} strokeDashoffset={`-${(normalPct + anomalyPct) * 2.89}`} />
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-xl font-bold text-white">{total}</div>
            <div className="text-[11px] text-gray-400">Total</div>
          </div>
        </div>
      </div>

      <div className="text-[11px] text-gray-300 space-y-2">
        <LegendDot color="bg-green-500" label={`Normal (${normalPct.toFixed(0)}%)`} />
        <LegendDot color="bg-red-500" label={`Anomaly (${anomalyPct.toFixed(0)}%)`} />
        <LegendDot color="bg-yellow-400" label={`Critical (${criticalPct.toFixed(0)}%)`} />
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`h-2.5 w-2.5 rounded ${color}`} />
      <span>{label}</span>
    </div>
  );
}

function ServiceHeatMini({ detections }: { detections: any[] }) {
  const cells = Array.from({ length: 12 * 6 }, (_, i) => {
    const d = detections[i];
    const isHot = d?.isAnomaly && (d?.riskScore ?? 0) > 70;
    const isWarm = d?.isAnomaly;
    return { isHot, isWarm };
  });

  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3">
      <div className="grid grid-cols-12 gap-1 h-40">
        {cells.map((c, i) => (
          <div
            key={i}
            className={[
              "rounded-[2px]",
              c.isHot ? "bg-cyan-300" : c.isWarm ? "bg-cyan-500/70" : "bg-white/10",
            ].join(" ")}
          />
        ))}
      </div>
      <div className="mt-2 text-[11px] text-gray-400">
        Hot = anomaly + riskScore &gt; 70 (live).
      </div>
    </div>
  );
}

/* ======================== network panel (ML) ======================== */

function NetworkPanel({ networkStatus }: { networkStatus: any }) {
  if (!networkStatus?.analysis) {
    return (
      <div className="rounded-md bg-black/40 border border-white/10 p-4 text-sm text-gray-400">
        No network snapshot yet. Attends le prochain <code className="text-gray-300">network:update</code> (toutes les ~5s).
      </div>
    );
  }

  const a = networkStatus.analysis;
  const ns = a.network_summary;
  const bot = a.botnet_analysis;
  const lm = a.lateral_movement;
  const ca = a.coordinated_attack;

  return (
    <div className="space-y-3">
      <div className="rounded-md bg-black/40 border border-white/10 p-3 flex flex-wrap items-center gap-3">
        <Badge label={`Devices: ${ns?.total_devices ?? "-"}`} />
        <Badge label={`Connections: ${ns?.total_connections ?? "-"}`} />
        <Badge
          label={`Health: ${ns?.health_score?.toFixed?.(1) ?? ns?.health_score ?? "-"}%`}
          tone={(ns?.health_score ?? 100) < 60 ? "bad" : (ns?.health_score ?? 100) < 80 ? "warn" : "good"}
        />
        <Badge
          label={`Isolated: ${ns?.isolated_devices?.length ?? 0}`}
          tone={(ns?.isolated_devices?.length ?? 0) > 0 ? "warn" : "good"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <MiniThreatCard
          title="Botnet"
          on={!!bot?.botnet_detected}
          details={
            bot?.botnet_detected
              ? `${bot.recruited_devices?.length ?? 0} recruited • ${bot.c2_candidates?.length ?? 0} C2 candidates`
              : "Not detected"
          }
        />
        <MiniThreatCard
          title="Lateral movement"
          on={!!lm?.lateral_movement_detected}
          details={
            lm?.lateral_movement_detected
              ? `${lm.compromised_devices?.length ?? 0} compromised • ${lm.attack_paths?.length ?? 0} paths • entry: ${lm.entry_point ?? "?"}`
              : "Not detected"
          }
        />
        <MiniThreatCard
          title="Coordinated attack"
          on={!!ca?.coordinated_attack}
          details={ca?.coordinated_attack ? `${ca.affected_devices?.length ?? 0} affected` : "Not detected"}
        />
      </div>

      <div className="rounded-md bg-black/40 border border-white/10 p-3 text-sm">
        <div className="text-xs text-gray-400 mb-2">Explainability (why ML thinks this matters)</div>

        {lm?.attack_paths?.length ? (
          <div className="mb-3">
            <div className="text-xs text-gray-300 mb-1">Attack paths (top 3)</div>
            <div className="space-y-1">
              {lm.attack_paths.slice(0, 3).map((p: any, i: number) => (
                <div key={i} className="text-xs text-gray-300">
                  <span className="text-gray-100 font-medium">
                    {Array.isArray(p.path) ? p.path.join(" → ") : String(p.path)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {bot?.c2_candidates?.length ? (
          <div className="mb-1">
            <div className="text-xs text-gray-300 mb-1">C2 candidates (top 5)</div>
            <div className="space-y-1">
              {bot.c2_candidates.slice(0, 5).map((c: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs text-gray-300">
                  <span className="font-medium text-gray-100">{c.device_id}</span>
                  <span className="text-gray-400">
                    out: {c.out_connections} • score: {Number(c.c2_score).toFixed?.(2) ?? c.c2_score}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {!lm?.attack_paths?.length && !bot?.c2_candidates?.length ? (
          <div className="text-xs text-gray-500">No extra explainability fields in this snapshot.</div>
        ) : null}
      </div>
    </div>
  );
}

function Badge({ label, tone = "neutral" }: { label: string; tone?: "neutral" | "good" | "warn" | "bad" }) {
  const toneCls =
    tone === "good"
      ? "bg-green-500/15 text-green-200 border-green-500/25"
      : tone === "warn"
      ? "bg-yellow-500/15 text-yellow-200 border-yellow-500/25"
      : tone === "bad"
      ? "bg-red-500/15 text-red-200 border-red-500/25"
      : "bg-white/5 text-gray-200 border-white/10";

  return <span className={`inline-flex items-center rounded-md px-3 py-1 text-xs border ${toneCls}`}>{label}</span>;
}

function MiniThreatCard({ title, on, details }: { title: string; on: boolean; details: string }) {
  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium text-gray-100">{title}</div>
        <span
          className={[
            "text-xs px-2 py-1 rounded-md border",
            on ? "bg-red-500/15 text-red-200 border-red-500/25" : "bg-green-500/10 text-green-200 border-green-500/20",
          ].join(" ")}
        >
          {on ? "Detected" : "OK"}
        </span>
      </div>
      <div className="mt-2 text-xs text-gray-400">{details}</div>
    </div>
  );
}

/* =================== anomalies with ML explanation + SHAP =================== */

function RecentAnomaliesConsole({ anomalies }: { anomalies: any[] }) {
  if (!anomalies?.length) {
    return (
      <div className="rounded-md bg-black/40 border border-white/10 p-6 text-center text-gray-400">
        No anomalies detected yet. (Wait for WS events)
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {anomalies.slice(0, 6).map((a: any) => (
        <div key={a.id ?? `${a.deviceId}-${a.createdAt}`} className="rounded-md bg-black/40 border border-white/10 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-gray-100">
                {a.deviceId}{" "}
                <span className="text-xs text-gray-500 font-normal">
                  • {a.deviceType ?? "Unknown"} • {a.createdAt ? new Date(a.createdAt).toLocaleString() : "—"}
                </span>
              </div>
              <div className="mt-1 text-xs text-gray-300">
                <span className="font-medium text-gray-100">Threat:</span> {a.threatType}{" "}
                <span className="text-gray-500">•</span>{" "}
                <span className="font-medium text-gray-100">Severity:</span> {a.threatSeverity}
              </div>
            </div>

            <div className="text-right">
              <div className="text-xs text-gray-400">Risk</div>
              <div className="text-2xl font-bold text-gray-100">{a.riskScore}</div>
            </div>
          </div>

          <div className="mt-3 text-sm text-gray-200">
            <span className="text-gray-400">ML explanation:</span> {a.explanation || "—"}
          </div>

          {a.rawTelemetry?.top_factors?.length ? (
            <div className="mt-3 rounded-md border border-cyan-500/20 bg-cyan-500/5 p-3">
              <div className="text-xs font-semibold text-cyan-200 mb-2">Top contributing factors (SHAP)</div>
              <div className="space-y-2">
                {a.rawTelemetry.top_factors.slice(0, 3).map((f: any, i: number) => (
                  <div key={i} className="text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-gray-100 font-medium">{i + 1}. {f.feature}</div>
                      <div className="text-gray-400">
                        value:{" "}
                        <span className="text-cyan-200 font-semibold">
                          {Number(f.feature_value).toFixed?.(2) ?? f.feature_value}
                        </span>
                        {" • "}
                        shap:{" "}
                        <span className={f.impact === "increases" ? "text-red-300 font-semibold" : "text-green-300 font-semibold"}>
                          {Number(f.shap_value).toFixed?.(3) ?? f.shap_value}
                        </span>
                      </div>
                    </div>

                    <div className="mt-1 h-1.5 w-full rounded bg-white/10 overflow-hidden">
                      <div
                        className={f.impact === "increases" ? "h-full bg-red-500/80" : "h-full bg-green-500/80"}
                        style={{ width: `${Math.min(Math.abs(Number(f.shap_value) || 0) * 200, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {Array.isArray(a.recommendedActions) && a.recommendedActions.length ? (
            <div className="mt-3 text-xs text-gray-300">
              <span className="text-gray-400">Recommended actions:</span> {a.recommendedActions.slice(0, 3).join(" • ")}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

/* ============================ threats & feed ============================ */

function ThreatBars({ threats }: { threats: any[] }) {
  if (!threats?.length) {
    return (
      <div className="rounded-md bg-black/40 border border-white/10 p-6 text-gray-400">
        No threat distribution yet.
      </div>
    );
  }

  const total = threats.reduce((s, t) => s + (t._count ?? 0), 0) || 1;

  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3 space-y-3">
      {threats.map((t, i) => {
        const pct = ((t._count ?? 0) / total) * 100;
        return (
          <div key={i}>
            <div className="flex items-center justify-between text-xs text-gray-300">
              <span className="font-medium text-gray-100">{t.threatType}</span>
              <span className="text-gray-400">{t._count}</span>
            </div>
            <div className="mt-1 h-2 rounded bg-white/10 overflow-hidden">
              <div className="h-full bg-orange-500/80" style={{ width: `${pct}%` }} />
            </div>
          </div>
        );
      })}
      <div className="text-[11px] text-gray-500">
        Live: incrémenté par les événements <code className="text-gray-300">detection:new</code>.
      </div>
    </div>
  );
}

function LiveFeedConsole({ detections }: { detections: any[] }) {
  return (
    <div className="rounded-md bg-black/40 border border-white/10 p-3 max-h-[420px] overflow-y-auto">
      <div className="space-y-2">
        {detections.map((d: any) => (
          <div key={d.id ?? `${d.deviceId}-${d.createdAt}`} className="rounded-md border border-white/10 bg-black/20 px-3 py-2">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium text-gray-100">{d.deviceId}</div>
              <div className="text-xs text-gray-500">
                {d.createdAt ? new Date(d.createdAt).toLocaleTimeString() : new Date().toLocaleTimeString()}
              </div>
            </div>

            <div className="mt-1 flex items-center gap-2 text-xs">
              <span
                className={[
                  "px-2 py-0.5 rounded border",
                  d.isAnomaly
                    ? "bg-red-500/15 text-red-200 border-red-500/25"
                    : "bg-green-500/10 text-green-200 border-green-500/20",
                ].join(" ")}
              >
                {d.isAnomaly ? "Anomaly" : "Normal"}
              </span>
              <span className="text-gray-400">{d.threatType}</span>
              {Number(d.riskScore) > 0 ? (
                <span className="ml-auto text-orange-200 font-semibold">{d.riskScore}</span>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================== detections table ============================== */

function DetectionsConsoleTable({ detections }: { detections: any[] }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/30 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
        <div className="text-sm font-medium text-gray-200">Detection History</div>
        <div className="text-xs text-gray-500">{detections.length} rows (live buffer)</div>
      </div>

      <div className="grid grid-cols-12 bg-white/5 border-b border-white/10 px-4 py-3 text-xs text-gray-300">
        <div className="col-span-3">Time</div>
        <div className="col-span-2">Device</div>
        <div className="col-span-2">Type</div>
        <div className="col-span-2">Status</div>
        <div className="col-span-1">Risk</div>
        <div className="col-span-1">Severity</div>
        <div className="col-span-1 text-right">Confidence</div>
      </div>

      <div className="divide-y divide-white/10">
        {detections.slice(0, 30).map((d: any) => (
          <div key={d.id ?? `${d.deviceId}-${d.createdAt}`} className="grid grid-cols-12 px-4 py-3 text-sm hover:bg-white/5">
            <div className="col-span-3 text-gray-300">
              {d.createdAt ? new Date(d.createdAt).toLocaleString() : "—"}
            </div>
            <div className="col-span-2 font-medium text-gray-100 truncate">{d.deviceId}</div>
            <div className="col-span-2 text-gray-400 truncate">{d.deviceType ?? "—"}</div>
            <div className="col-span-2">
              <span
                className={[
                  "text-xs px-2 py-1 rounded-md border",
                  d.isAnomaly
                    ? "bg-red-500/15 text-red-200 border-red-500/25"
                    : "bg-green-500/10 text-green-200 border-green-500/20",
                ].join(" ")}
              >
                {d.isAnomaly ? "Anomaly" : "Normal"}
              </span>
            </div>
            <div className="col-span-1 font-semibold text-gray-100">{d.riskScore}</div>
            <div className="col-span-1 text-gray-300">{d.threatSeverity}</div>
            <div className="col-span-1 text-right text-gray-400">
              {(Number(d.confidenceScore) * 100).toFixed?.(1) ?? d.confidenceScore}%
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
