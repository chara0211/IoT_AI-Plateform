// frontend/app/dashboard/page.tsx
import React from "react";
import {
  fetchDetections,
  fetchSummary,
  fetchRecentAnomalies,
  fetchThreatDistribution,
  fetchNetworkStatus,
} from "@/lib/api";
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
} from "lucide-react";

import NetworkGraphLive from "./NetworkGraphLive";
import LiveFeedWS from "./LiveFeedWS";
import NetworkGraphWS from "./NetworkGraphWS";

export default async function DashboardPage() {
  const [summary, detections, anomalies, threats, networkStatus] =
    await Promise.all([
      fetchSummary(),
      fetchDetections(50),
      fetchRecentAnomalies(10),
      fetchThreatDistribution(),
      fetchNetworkStatus().catch(() => null),
    ]);

  const activeFilters = ["source: Logs", "time: last 1 month"];

  return (
    <div className="min-h-screen bg-[#07090d] text-white">
      {/* Top bar */}
      <div className="border-b border-white/10 bg-black/40">
        <div className="mx-auto max-w-[1600px] px-6 py-4">
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-md bg-[#0f1520] border border-white/10 grid place-items-center">
                <Shield className="h-5 w-5 text-blue-200" />
              </div>
              <div>
                <div className="text-sm text-gray-300">Logs Console</div>
                <div className="text-base font-semibold text-gray-100">
                  IoT Security Platform
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 text-sm text-gray-300">
              <span className="hidden sm:inline opacity-80">Show data from</span>
              <TimeBtn label="1 month" />
              <span className="opacity-80">to</span>
              <TimeBtn label="now" />
              <button
                className="ml-1 inline-flex items-center justify-center rounded-md bg-[#0f1520] p-2 border border-white/10 hover:border-white/20"
                title="Refresh"
              >
                <RefreshCcw className="h-4 w-4 opacity-80" />
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="mt-4 flex items-center gap-6 text-sm">
            <Tab label="Explore Logs" active />
            <Tab label="Anomaly" />
            <Tab label="Insights" />
            <Tab label="Patterns" />
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
        {/* Top Stats (backend) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <MiniStat
            title="Total Detections"
            value={summary.total_detections.toLocaleString()}
            icon={<Activity className="h-4 w-4" />}
            accent="text-blue-200"
          />
          <MiniStat
            title="Active Anomalies"
            value={summary.anomaly_count.toLocaleString()}
            icon={<AlertTriangle className="h-4 w-4" />}
            accent="text-orange-200"
            sub={`${(summary.anomaly_ratio * 100).toFixed(1)}% anomaly ratio`}
          />
          <MiniStat
            title="Critical Incidents"
            value={summary.critical_incidents.toLocaleString()}
            icon={<Zap className="h-4 w-4" />}
            accent="text-red-200"
            sub={`${summary.high_incidents} high priority`}
          />
          <MiniStat
            title="Normal Devices"
            value={summary.normal_count.toLocaleString()}
            icon={<Shield className="h-4 w-4" />}
            accent="text-green-200"
            sub="Healthy"
          />
        </div>

        {/* 3 panels row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Panel title="Anomaly Count" badge={1} icon={<BarChart3 className="h-4 w-4" />}>
            <AnomalyCountMiniChart summary={summary} threats={threats} />
          </Panel>

          <Panel title="Confidence Distribution" badge={2} icon={<PieChart className="h-4 w-4" />}>
            <ConfidenceDonutMini
              normal={summary.normal_count}
              anomaly={summary.anomaly_count}
              critical={summary.critical_incidents}
              high={summary.high_incidents}
            />
          </Panel>

          <Panel title="Anomalies in Services" badge={3} icon={<TrendingUp className="h-4 w-4" />}>
            <ServiceHeatMini detections={detections} />
          </Panel>
        </div>

        {/* Network section (backend /api/network/status) */}
        <Panel
          title="Network Behavior Analysis (ML Engine)"
          badge={4}
          icon={<Network className="h-4 w-4" />}
        >
          <NetworkPanel networkStatus={networkStatus} />
          <NetworkGraphWS initial={networkStatus}  />
          <LiveFeedWS initial={detections.slice(0, 12)} />

        </Panel>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left (2 cols) */}
          <div className="lg:col-span-2 space-y-4">
            <Panel title="Recent Anomalies (ML Explanation + SHAP)" badge={5} icon={<AlertTriangle className="h-4 w-4" />}>
              <RecentAnomaliesConsole anomalies={anomalies} />
            </Panel>

            <Panel title="Threat Distribution" badge={6} icon={<Zap className="h-4 w-4" />}>
              <ThreatBars threats={threats} />
            </Panel>
          </div>

          {/* Right */}
          <div className="space-y-4">
            <Panel title="Live Feed" badge={7} icon={<Eye className="h-4 w-4" />}>
              <LiveFeedConsole detections={detections.slice(0, 12)} />
            </Panel>
          </div>
        </div>

        {/* Detections table */}
        <DetectionsConsoleTable detections={detections} />
      </div>
    </div>
  );
}

/* ========================== small UI components ========================== */

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
      {active ? (
        <span className="absolute left-0 -bottom-[1px] h-[2px] w-full bg-white/80" />
      ) : null}
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
  badge,
  icon,
  children,
}: {
  title: string;
  badge: number;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border border-white/10 bg-black/30 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
          <span className="opacity-80">{icon}</span>
          {title}
        </div>
        <div className="flex h-5 w-5 items-center justify-center rounded-full bg-yellow-400 text-[11px] font-bold text-black">
          {badge}
        </div>
      </div>
      <div className="h-auto">{children}</div>
    </div>
  );
}

function MiniStat({
  title,
  value,
  icon,
  accent,
  sub,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  accent: string;
  sub?: string;
}) {
  return (
    <div className="rounded-md border border-white/10 bg-black/30 px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-gray-400">{title}</div>
        <div className={`inline-flex items-center gap-2 text-xs ${accent}`}>
          {icon}
        </div>
      </div>
      <div className="mt-1 text-2xl font-bold text-gray-100">{value}</div>
      {sub ? <div className="mt-1 text-xs text-gray-400">{sub}</div> : null}
    </div>
  );
}

/* ============================ charts (simple) ============================ */

function AnomalyCountMiniChart({ summary }: { summary: any; threats: any[] }) {
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
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
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
        Uses backend summary counts (anomaly/high/critical).
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
    <div className="rounded-sm bg-black/40 border border-white/10 p-3 flex items-center justify-center gap-6">
      <div className="relative h-32 w-32">
        <svg className="h-full w-full -rotate-90">
          <circle
            cx="64"
            cy="64"
            r="46"
            fill="none"
            stroke="rgba(255,255,255,0.08)"
            strokeWidth="14"
          />
          <circle
            cx="64"
            cy="64"
            r="46"
            fill="none"
            stroke="#22c55e"
            strokeWidth="14"
            strokeDasharray={`${normalPct * 2.89} 289`}
          />
          <circle
            cx="64"
            cy="64"
            r="46"
            fill="none"
            stroke="#ef4444"
            strokeWidth="14"
            strokeDasharray={`${anomalyPct * 2.89} 289`}
            strokeDashoffset={`-${normalPct * 2.89}`}
          />
          <circle
            cx="64"
            cy="64"
            r="46"
            fill="none"
            stroke="#facc15"
            strokeWidth="14"
            strokeDasharray={`${criticalPct * 2.89} 289`}
            strokeDashoffset={`-${(normalPct + anomalyPct) * 2.89}`}
          />
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
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
      <div className="grid grid-cols-12 gap-1 h-40">
        {cells.map((c, i) => (
          <div
            key={i}
            className={[
              "rounded-[2px]",
              c.isHot
                ? "bg-cyan-300"
                : c.isWarm
                ? "bg-cyan-500/70"
                : "bg-white/10",
            ].join(" ")}
          />
        ))}
      </div>
      <div className="mt-2 text-[11px] text-gray-400">
        Heat based on latest detections (isAnomaly + riskScore).
      </div>
    </div>
  );
}

/* ======================== network panel (ML) ======================== */

function NetworkPanel({ networkStatus }: { networkStatus: any }) {
  if (!networkStatus?.analysis) {
    return (
      <div className="rounded-sm bg-black/40 border border-white/10 p-3 text-sm text-gray-400">
        No recent network activity (backend returned empty / or ML unavailable).
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
      {/* top line */}
      <div className="rounded-sm bg-black/40 border border-white/10 p-3 flex flex-wrap items-center gap-4">
        <Badge label={`Devices: ${ns?.total_devices ?? "-"}`} />
        <Badge label={`Connections: ${ns?.total_connections ?? "-"}`} />
        <Badge
          label={`Health Score: ${ns?.health_score?.toFixed?.(1) ?? ns?.health_score ?? "-"}%`}
          tone={(ns?.health_score ?? 100) < 60 ? "bad" : (ns?.health_score ?? 100) < 80 ? "warn" : "good"}
        />
        {ns?.isolated_devices?.length ? (
          <Badge label={`Isolated: ${ns.isolated_devices.length}`} tone="warn" />
        ) : (
          <Badge label="Isolated: 0" tone="good" />
        )}
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
          title="Lateral Movement"
          on={!!lm?.lateral_movement_detected}
          details={
            lm?.lateral_movement_detected
              ? `${lm.compromised_devices?.length ?? 0} compromised • ${lm.attack_paths?.length ?? 0} paths`
              : "Not detected"
          }
        />
        <MiniThreatCard
          title="Coordinated Attack"
          on={!!ca?.coordinated_attack}
          details={
            ca?.coordinated_attack
              ? `${ca.affected_devices?.length ?? 0} affected`
              : "Not detected"
          }
        />
      </div>

      {/* extra details */}
      <div className="rounded-sm bg-black/40 border border-white/10 p-3 text-sm">
        <div className="text-xs text-gray-400 mb-2">ML Engine Explanation</div>

        {/* botnet candidates */}
        {bot?.c2_candidates?.length ? (
          <div className="mb-3">
            <div className="text-xs text-gray-300 mb-1">C2 candidates</div>
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

        {/* lateral paths */}
        {lm?.attack_paths?.length ? (
          <div className="mb-3">
            <div className="text-xs text-gray-300 mb-1">Attack paths</div>
            <div className="space-y-1">
              {lm.attack_paths.slice(0, 3).map((p: any, i: number) => (
                <div key={i} className="text-xs text-gray-300">
                  <span className="text-gray-100 font-medium">
                    {Array.isArray(p.path) ? p.path.join(" → ") : String(p.path)}
                  </span>
                  {p.entry_point ? (
                    <span className="text-gray-500"> • entry: {p.entry_point}</span>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {!bot?.c2_candidates?.length && !lm?.attack_paths?.length ? (
          <div className="text-xs text-gray-500">
            No extra network explanation fields returned by ML engine.
          </div>
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

  return (
    <span className={`inline-flex items-center rounded-md px-3 py-1 text-xs border ${toneCls}`}>
      {label}
    </span>
  );
}

function MiniThreatCard({ title, on, details }: { title: string; on: boolean; details: string }) {
  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium text-gray-100">{title}</div>
        <span
          className={[
            "text-xs px-2 py-1 rounded-md border",
            on
              ? "bg-red-500/15 text-red-200 border-red-500/25"
              : "bg-green-500/10 text-green-200 border-green-500/20",
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
      <div className="rounded-sm bg-black/40 border border-white/10 p-6 text-center text-gray-400">
        No anomalies detected.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {anomalies.slice(0, 6).map((a: any) => (
        <div
          key={a.id}
          className="rounded-sm bg-black/40 border border-white/10 p-3"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-gray-100">
                {a.deviceId}{" "}
                <span className="text-xs text-gray-500 font-normal">
                  • {a.deviceType ?? "Unknown"} •{" "}
                  {new Date(a.createdAt).toLocaleString()}
                </span>
              </div>
              <div className="mt-1 text-xs text-gray-300">
                <span className="font-medium text-gray-100">Threat:</span>{" "}
                {a.threatType}{" "}
                <span className="text-gray-500">•</span>{" "}
                <span className="font-medium text-gray-100">Severity:</span>{" "}
                {a.threatSeverity}
              </div>
            </div>

            <div className="text-right">
              <div className="text-xs text-gray-400">Risk</div>
              <div className="text-2xl font-bold text-gray-100">
                {a.riskScore}
              </div>
            </div>
          </div>

          {/* ML explanation */}
          <div className="mt-3 text-sm text-gray-200">
            <span className="text-gray-400">ML explanation:</span>{" "}
            {a.explanation || "—"}
          </div>

          {/* SHAP */}
          {a.rawTelemetry?.top_factors?.length ? (
            <div className="mt-3 rounded-sm border border-cyan-500/20 bg-cyan-500/5 p-3">
              <div className="text-xs font-semibold text-cyan-200 mb-2">
                Top contributing factors (SHAP)
              </div>

              <div className="space-y-2">
                {a.rawTelemetry.top_factors.slice(0, 3).map((f: any, i: number) => (
                  <div key={i} className="text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-gray-100 font-medium">
                        {i + 1}. {f.feature}
                      </div>
                      <div className="text-gray-400">
                        value:{" "}
                        <span className="text-cyan-200 font-semibold">
                          {Number(f.feature_value).toFixed?.(2) ?? f.feature_value}
                        </span>
                        {" • "}
                        shap:{" "}
                        <span
                          className={
                            f.impact === "increases"
                              ? "text-red-300 font-semibold"
                              : "text-green-300 font-semibold"
                          }
                        >
                          {Number(f.shap_value).toFixed?.(3) ?? f.shap_value}
                        </span>
                      </div>
                    </div>

                    <div className="mt-1 h-1.5 w-full rounded bg-white/10 overflow-hidden">
                      <div
                        className={
                          f.impact === "increases"
                            ? "h-full bg-red-500/80"
                            : "h-full bg-green-500/80"
                        }
                        style={{
                          width: `${Math.min(Math.abs(Number(f.shap_value) || 0) * 200, 100)}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* recommended actions */}
          {Array.isArray(a.recommendedActions) && a.recommendedActions.length ? (
            <div className="mt-3 text-xs text-gray-300">
              <span className="text-gray-400">Recommended actions:</span>{" "}
              {a.recommendedActions.slice(0, 3).join(" • ")}
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
      <div className="rounded-sm bg-black/40 border border-white/10 p-6 text-gray-400">
        No threat distribution data.
      </div>
    );
  }

  const total = threats.reduce((s, t) => s + (t._count ?? 0), 0) || 1;

  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3 space-y-3">
      {threats.map((t, i) => {
        const pct = ((t._count ?? 0) / total) * 100;
        return (
          <div key={i}>
            <div className="flex items-center justify-between text-xs text-gray-300">
              <span className="font-medium text-gray-100">{t.threatType}</span>
              <span className="text-gray-400">{t._count}</span>
            </div>
            <div className="mt-1 h-2 rounded bg-white/10 overflow-hidden">
              <div
                className="h-full bg-orange-500/80"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function LiveFeedConsole({ detections }: { detections: any[] }) {
  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3 max-h-[380px] overflow-y-auto">
      <div className="space-y-2">
        {detections.map((d: any) => (
          <div
            key={d.id}
            className="rounded-sm border border-white/10 bg-black/20 px-3 py-2"
          >
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium text-gray-100">{d.deviceId}</div>
              <div className="text-xs text-gray-500">
                {new Date(d.createdAt).toLocaleTimeString()}
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
              {d.riskScore > 0 ? (
                <span className="ml-auto text-orange-200 font-semibold">
                  {d.riskScore}
                </span>
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
    <div className="rounded-md border border-white/10 bg-black/30 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
        <div className="text-sm font-medium text-gray-200">Detection History</div>
        <div className="text-xs text-gray-500">{detections.length} rows</div>
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
        {detections.slice(0, 20).map((d: any) => (
          <div key={d.id} className="grid grid-cols-12 px-4 py-3 text-sm hover:bg-white/5">
            <div className="col-span-3 text-gray-300">
              {new Date(d.createdAt).toLocaleString()}
            </div>
            <div className="col-span-2 font-medium text-gray-100 truncate">
              {d.deviceId}
            </div>
            <div className="col-span-2 text-gray-400 truncate">
              {d.deviceType ?? "—"}
            </div>
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
            <div className="col-span-1 font-semibold text-gray-100">
              {d.riskScore}
            </div>
            <div className="col-span-1 text-gray-300">
              {d.threatSeverity}
            </div>
            <div className="col-span-1 text-right text-gray-400">
              {(Number(d.confidenceScore) * 100).toFixed?.(1) ?? d.confidenceScore}
              %
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
