// frontend/app/dashboard/page.tsx
import DashboardLive from "./DashboardLive";
import {
  fetchDetections,
  fetchSummary,
  fetchRecentAnomalies,
  fetchThreatDistribution,
  fetchNetworkStatus,
} from "@/lib/api";

export default async function DashboardPage() {
  const [summary, detections, anomalies, threats, networkStatus] =
    await Promise.all([
      fetchSummary(),
      fetchDetections(10000),
      fetchRecentAnomalies(500),
      fetchThreatDistribution(),
      fetchNetworkStatus().catch(() => null),
    ]);

  return (
    <DashboardLive
      initialSummary={summary}
      initialDetections={detections}
      initialAnomalies={anomalies}
      initialThreats={threats}
      initialNetworkStatus={networkStatus}
    />
  );
}
