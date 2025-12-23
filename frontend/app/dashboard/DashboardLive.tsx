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
  Bell,
  CheckCircle2,
  XCircle,
  TrendingDown,
  Loader2,
  X,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Search,
} from "lucide-react";

import NetworkGraphWS from "./NetworkGraphWS";
import LiveFeedWS from "./LiveFeedWS";

// ---- types
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

const WS_URL = process.env.NEXT_PUBLIC_BACKEND_WS_URL || "http://localhost:5000";

//  FONCTION DE MAPPING BACKEND → FRONTEND
function mapDetectionData(d: any): Detection {
  return {
    ...d,
    id: d.detection_id ?? d.id,
    deviceId: d.device_id ?? d.deviceId,
    deviceType: d.device_type ?? d.deviceType,
    isAnomaly: d.is_anomaly ?? d.isAnomaly,
    confidenceScore: d.confidence_score ?? d.confidenceScore,
    riskScore: d.risk_score ?? d.riskScore,
    threatType: d.threat_type ?? d.threatType,
    threatSeverity: d.threat_severity ?? d.threatSeverity,
    recommendedActions: d.recommended_actions ?? d.recommendedActions ?? [],
    explanation: d.explanation,
    rawTelemetry: d.raw_telemetry ?? d.rawTelemetry,
    modelVotes: d.model_votes ?? d.modelVotes,
    createdAt: d.created_at ?? d.createdAt,
    protocol: d.protocol,
  };
}
//  HELPER FUNCTION TO GENERATE GUARANTEED UNIQUE KEYS
function generateUniqueKey(detection: Detection, index: number): string {
  // Always include a timestamp and random component
  const timestamp = Date.now();
  const random = Math.random().toString(36).substr(2, 9);
  
  // Use existing _eventKey if available
  if (detection._eventKey) {
    return `${detection._eventKey}-${timestamp}-${random}`;
  }
  
  // Otherwise create a composite key
  const baseKey = detection.id ?? 
                 detection.deviceId ?? 
                 `detection-${timestamp}`;
  
  return `${baseKey}-${timestamp}-${random}-${index}`;
}

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
  const [currentTime, setCurrentTime] = useState<string>("");
  const [isMounted, setIsMounted] = useState(false);

  const [summary, setSummary] = useState<Summary>(initialSummary);
  
  // ✅ MAPPER LES DONNÉES INITIALES
  const [detections, setDetections] = useState<Detection[]>(
    (initialDetections ?? []).map(mapDetectionData)
  );
  const [anomalies, setAnomalies] = useState<Detection[]>(
    (initialAnomalies ?? []).map(mapDetectionData)
  );
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(initialNetworkStatus ?? null);

  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null);
  const [showModal, setShowModal] = useState(false);

const [currentPage, setCurrentPage] = useState(1);
const [filterStatus, setFilterStatus] = useState<"all" | "anomaly" | "normal">("all");
const [filterSeverity, setFilterSeverity] = useState<"all" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO">("all");
const [filterDeviceType, setFilterDeviceType] = useState<string>("all");
const [filterThreatType, setFilterThreatType] = useState<string>("all");
const [searchQuery, setSearchQuery] = useState("");
const itemsPerPage = 20; //  Increased from 10 to 20

  const [notifications, setNotifications] = useState<Array<{
    id: string;
    type: "anomaly" | "critical" | "info" | "success";
    message: string;
    timestamp: Date;
  }>>([]);

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

  useEffect(() => {
    setIsMounted(true);
    setCurrentTime(new Date().toLocaleString());
    
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleString());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  //  Extract unique device types for filter dropdown
const deviceTypes = useMemo(() => {
  const types = new Set<string>();
  detections.forEach(d => {
    if (d.deviceType) types.add(d.deviceType);
  });
  return Array.from(types).sort();
}, [detections]);

//  Extract unique threat types for filter dropdown
const threatTypes = useMemo(() => {
  const types = new Set<string>();
  detections.forEach(d => {
    if (d.threatType) types.add(d.threatType);
  });
  return Array.from(types).sort();
}, [detections]);

  const addNotification = (type: "anomaly" | "critical" | "info" | "success", message: string) => {
    const id = `${Date.now()}-${Math.random()}`;
    setNotifications(prev => [{
      id,
      type,
      message,
      timestamp: new Date(),
    }, ...prev].slice(0, 5));

    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 10000);
  };

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
      addNotification("success", "✅ Connected to real-time feed");
    });
    
    s.on("disconnect", () => {
      setWsState("disconnected");
      addNotification("info", "⚠️ Disconnected from live feed");
    });
    
    s.on("connect_error", () => {
      setWsState("disconnected");
    });

    //  MAPPER LES DONNÉES WEBSOCKET - WITH DEBUG FOR RECOMMENDED ACTIONS
    s.on("detection:new", (rawData: any) => {
      setLastLiveAt(new Date());

      // ✅ DEBUG: Log the incoming data with recommended actions
      console.log('WebSocket received detection (RAW):', {
        deviceId: rawData.device_id,
        recommended_actions: rawData.recommended_actions,
        rawData: rawData
      });

      // ✅ MAPPER LES DONNÉES
      const detection = mapDetectionData(rawData);

      // ✅ DEBUG: Check what the mapping produced
      console.log('After mapping detection:', {
        deviceId: detection.deviceId,
        recommendedActions: detection.recommendedActions,
        hasRecommendedActions: Array.isArray(detection.recommendedActions),
        recommendedActionsLength: Array.isArray(detection.recommendedActions) ? detection.recommendedActions.length : 0
      });

      // ✅ CREATE A TRULY UNIQUE EVENT KEY
      const timestamp = Date.now();
      const uniqueId = crypto.randomUUID ? 
        crypto.randomUUID() : 
        `${timestamp}-${Math.random().toString(36).substr(2, 9)}-${Math.random().toString(36).substr(2, 9)}`;
      
      // Create multiple levels of uniqueness
      const eventKey = detection.id ?? 
                      `${detection.deviceId}-${timestamp}-${uniqueId}`;
      
      // ✅ Create detection with guaranteed unique key AND ensure recommendedActions is an array
      const detectionWithKey = { 
        ...detection, 
        // Ensure recommendedActions is always an array
        recommendedActions: Array.isArray(detection.recommendedActions) 
          ? detection.recommendedActions 
          : (detection.recommendedActions ? [detection.recommendedActions] : []),
        _eventKey: eventKey,
        _uniqueId: uniqueId, // Additional unique identifier
        _timestamp: timestamp, // Add timestamp for sorting
        _receivedAt: new Date().toISOString() // When we received it
      };

      // ✅ DEBUG: Check final detection object
      console.log('Final detectionWithKey:', {
        deviceId: detectionWithKey.deviceId,
        recommendedActions: detectionWithKey.recommendedActions,
        isArray: Array.isArray(detectionWithKey.recommendedActions),
        length: detectionWithKey.recommendedActions?.length || 0
      });

      // ✅ NOTIFICATIONS FOR ANOMALIES
      if (detection?.isAnomaly) {
        const severity = String(detection?.threatSeverity || "").toUpperCase();
        if (severity === "CRITICAL") {
          addNotification("critical", `🚨 CRITICAL THREAT: ${detection.deviceId} - ${detection.threatType}`);
        } else if (severity === "HIGH") {
          addNotification("anomaly", `⚠️ High Risk: ${detection.deviceId} - ${detection.threatType}`);
        }
      }

      // ✅ UPDATE DETECTIONS WITH DUPLICATE CHECKING
      setDetections((prev) => {
        // Check for duplicates based on multiple criteria
        const isDuplicate = prev.some(existing => {
          // Check by unique ID if available
          if (existing._uniqueId === uniqueId) return true;
          
          // Check by event key
          if (existing._eventKey === eventKey) return true;
          
          // Check by device ID and timestamp (within 100ms window)
          if (existing.deviceId === detection.deviceId) {
            const existingTime = existing.createdAt ? new Date(existing.createdAt).getTime() : existing._timestamp;
            const newTime = detection.createdAt ? new Date(detection.createdAt).getTime() : timestamp;
            
            // If timestamps are within 100ms, consider it a duplicate
            if (Math.abs(existingTime - newTime) < 100) {
              console.log('Duplicate detected by timestamp:', {
                deviceId: detection.deviceId,
                existingTime,
                newTime,
                difference: Math.abs(existingTime - newTime)
              });
              return true;
            }
          }
          
          return false;
        });

        if (isDuplicate) {
          console.log('🚫 Duplicate detection skipped:', {
            deviceId: detection.deviceId,
            eventKey,
            timestamp: detection.createdAt || timestamp
          });
          return prev; // Skip adding duplicate
        }

        console.log('✅ New detection added:', {
          deviceId: detection.deviceId,
          eventKey,
          isAnomaly: detection.isAnomaly,
          recommendedActionsCount: detectionWithKey.recommendedActions?.length || 0
        });

        // Add new detection and limit to 200
        return [detectionWithKey, ...prev];

      });

      // ✅ UPDATE ANOMALIES (only if it's an anomaly and not a duplicate)
      if (detection?.isAnomaly) {
        setAnomalies((prev) => {
          // Check for duplicates in anomalies too
          const isDuplicateAnomaly = prev.some(existing => 
            existing._uniqueId === uniqueId || 
            existing._eventKey === eventKey ||
            (existing.deviceId === detection.deviceId && 
            Math.abs(
              (existing.createdAt ? new Date(existing.createdAt).getTime() : existing._timestamp) - 
              (detection.createdAt ? new Date(detection.createdAt).getTime() : timestamp)
            ) < 100)
          );

          if (!isDuplicateAnomaly) {
            return [detectionWithKey, ...prev];
          }
          return prev;
        });
      }

      // ✅ UPDATE SUMMARY STATISTICS
      setSummary((prev) => {
        const total = (prev.total_detections ?? 0) + 1;
        const isAnomaly = !!detection?.isAnomaly;
        const severity = String(detection?.threatSeverity || "").toUpperCase();

        const anomaly_count = (prev.anomaly_count ?? 0) + (isAnomaly ? 1 : 0);
        const normal_count = (prev.normal_count ?? 0) + (isAnomaly ? 0 : 1);
        const critical_incidents = (prev.critical_incidents ?? 0) + (isAnomaly && severity === "CRITICAL" ? 1 : 0);
        const high_incidents = (prev.high_incidents ?? 0) + (isAnomaly && severity === "HIGH" ? 1 : 0);
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

      // ✅ UPDATE THREAT MAP (only for anomalies)
      if (detection?.isAnomaly && detection?.threatType) {
        setThreatMap((m) => {
          const tt = String(detection.threatType);
          return { ...m, [tt]: (m[tt] ?? 0) + 1 };
        });
      }
    });

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

  const filteredDetections = useMemo(() => {
    let filtered = detections;

    // Status filter (All / Anomalies / Normal)
    if (filterStatus === "anomaly") {
      filtered = filtered.filter(d => d.isAnomaly);
    } else if (filterStatus === "normal") {
      filtered = filtered.filter(d => !d.isAnomaly);
    }

    // ✅ Severity filter
    if (filterSeverity !== "all") {
      filtered = filtered.filter(d => d.threatSeverity === filterSeverity);
    }

    // ✅ Device type filter
    if (filterDeviceType !== "all") {
      filtered = filtered.filter(d => d.deviceType === filterDeviceType);
    }

    // ✅ Threat type filter
    if (filterThreatType !== "all") {
      filtered = filtered.filter(d => d.threatType === filterThreatType);
    }

    // Search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(d => 
        d.deviceId?.toLowerCase().includes(query) ||
        d.deviceType?.toLowerCase().includes(query) ||
        d.threatType?.toLowerCase().includes(query)
      );
    }

    // ✅ ALWAYS sort by most recent first (descending)
    return filtered.sort((a, b) => {
      const dateA = a.createdAt ? new Date(a.createdAt).getTime() : a._timestamp || 0;
      const dateB = b.createdAt ? new Date(b.createdAt).getTime() : b._timestamp || 0;
      return dateB - dateA; // Newest first
    });
  }, [detections, filterStatus, filterSeverity, filterDeviceType, filterThreatType, searchQuery]);

  const totalPages = Math.ceil(filteredDetections.length / itemsPerPage);
  const paginatedDetections = filteredDetections.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [filterStatus, filterSeverity, filterDeviceType, filterThreatType, searchQuery]);

  const activeFilters = ["source: MQTT Live Feed", "mode: Real-time Analysis", "window: 60 minutes"];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {showModal && selectedDetection && (
        <DetectionModal
          detection={selectedDetection}
          onClose={() => {
            setShowModal(false);
            setSelectedDetection(null);
          }}
        />
      )}

      <div className="fixed top-6 right-6 z-50 space-y-3 max-w-md">
        {notifications.map((notif) => (
          <div
            key={notif.id}
            className={`rounded-xl border p-4 backdrop-blur-xl shadow-2xl transition-all duration-300 ${
              notif.type === "critical"
                ? "bg-red-950/95 border-red-500/50 shadow-red-500/20"
                : notif.type === "anomaly"
                ? "bg-orange-950/95 border-orange-500/50 shadow-orange-500/20"
                : notif.type === "success"
                ? "bg-emerald-950/95 border-emerald-500/50 shadow-emerald-500/20"
                : "bg-blue-950/95 border-blue-500/50 shadow-blue-500/20"
            } animate-slide-in-right`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3 flex-1">
                <div className={`p-2 rounded-lg ${
                  notif.type === "critical" ? "bg-red-500/20" :
                  notif.type === "anomaly" ? "bg-orange-500/20" :
                  notif.type === "success" ? "bg-emerald-500/20" :
                  "bg-blue-500/20"
                }`}>
                  <Bell className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium leading-snug">{notif.message}</div>
                  <div className="mt-1 text-xs opacity-70">
                    {notif.timestamp.toLocaleTimeString()}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setNotifications(prev => prev.filter(n => n.id !== notif.id))}
                className="text-white/60 hover:text-white transition-colors flex-shrink-0"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="border-b border-white/10 bg-black/40 sticky top-0 z-40 backdrop-blur-xl">
        <div className="mx-auto max-w-[1800px] px-6 py-4">
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl blur opacity-50"></div>
                <div className="relative h-12 w-12 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 grid place-items-center shadow-lg">
                  <Shield className="h-7 w-7 text-white" />
                </div>
              </div>
              <div>
                <div className="text-sm text-gray-400 font-medium tracking-wide">SECURITY OPERATIONS CENTER</div>
                <div className="text-xl font-bold bg-gradient-to-r from-white via-blue-100 to-cyan-100 bg-clip-text text-transparent">
                  IoT Threat Detection Platform
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 text-sm">
              <LiveBadge state={wsState} lastLiveAt={lastLiveAt} />
              <div className="hidden lg:flex items-center gap-2 text-gray-400">
                <span className="text-xs font-medium">Time Window:</span>
                <TimeBtn label="60 min" />
                <span className="text-xs">→</span>
                <TimeBtn label="now" />
              </div>
              <button
                className="inline-flex items-center justify-center rounded-lg bg-white/5 p-2.5 border border-white/10 hover:border-white/30 hover:bg-white/10 transition-all group"
                title="Refresh Dashboard"
                onClick={() => window.location.reload()}
              >
                <RefreshCcw className="h-4 w-4 group-hover:rotate-180 transition-transform duration-500" />
              </button>
            </div>
          </div>

          <div className="mt-5 flex items-center gap-8 text-sm border-b border-white/5">
            <Tab label="Live Monitor" active />
            <Tab label="Threat Analysis" count={anomalies.length} />
            <Tab label="Network Topology" />
            <Tab label="Reports" />
            <Tab label="Settings" />
          </div>

          <div className="mt-4 rounded-xl bg-gradient-to-r from-slate-900/50 to-slate-800/50 border border-white/10 px-5 py-3 backdrop-blur-sm">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-xs text-gray-400">
                <Filter className="h-4 w-4" />
                <span className="font-semibold">FILTERS</span>
              </div>
              <div className="flex flex-wrap gap-2 flex-1">
                {activeFilters.map((f) => (
                  <FilterPill key={f} label={f} />
                ))}
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-400 border-l border-white/10 pl-4">
                <Clock className="h-4 w-4" />
                <span className="font-mono">{isMounted ? currentTime : ""}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-[1800px] px-6 py-8 space-y-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
          <KPICard
            title="Total Events"
            value={summary.total_detections.toLocaleString()}
            icon={<Activity className="h-5 w-5" />}
            gradient="from-blue-500 to-cyan-500"
            trend="+12.5%"
            trendUp
          />
          <KPICard
            title="Active Threats"
            value={summary.anomaly_count.toLocaleString()}
            icon={<AlertTriangle className="h-5 w-5" />}
            gradient="from-orange-500 to-red-500"
            subtitle={`${(summary.anomaly_ratio * 100).toFixed(1)}% detection rate`}
            trend="-3.2%"
            trendUp={false}
          />
          <KPICard
            title="Critical Alerts"
            value={summary.critical_incidents.toLocaleString()}
            icon={<Zap className="h-5 w-5" />}
            gradient="from-red-500 to-pink-500"
            subtitle={`${summary.high_incidents} high severity`}
          />
          <KPICard
            title="Healthy Devices"
            value={summary.normal_count.toLocaleString()}
            icon={<CheckCircle2 className="h-5 w-5" />}
            gradient="from-emerald-500 to-green-500"
            subtitle="No threats detected"
            trend="+5.1%"
            trendUp
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <GlassPanel
            title="Threat Timeline"
            subtitle="Anomaly detection over time"
            badge={1}
            icon={<BarChart3 className="h-4 w-4" />}
          >
            <AnomalyCountChart detections={detections} />

          </GlassPanel>

          <GlassPanel
            title="Security Distribution"
            subtitle="Status breakdown"
            badge={2}
            icon={<PieChart className="h-4 w-4" />}
          >
            <SecurityDonut
              normal={summary.normal_count}
              anomaly={summary.anomaly_count}
              critical={summary.critical_incidents}
            />
          </GlassPanel>

          <GlassPanel
            title="Activity Heatmap"
            subtitle="Risk intensity map"
            badge={3}
            icon={<TrendingUp className="h-4 w-4" />}
          >
            <HeatmapGrid detections={detections} />
          </GlassPanel>
        </div>

        <GlassPanel
          title="Network Security Analysis"
          subtitle="ML-powered topology & threat detection"
          badge={4}
          icon={<Network className="h-4 w-4" />}
          large
        >
          <NetworkSummary networkStatus={networkStatus} />

          <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <NetworkGraphWS initial={networkStatus} />
            </div>
            <div className="lg:col-span-1">
              <LiveFeedWS initial={detections.slice(0, 12)} />
            </div>
          </div>
        </GlassPanel>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <GlassPanel
              title="Anomaly Intelligence"
              subtitle="AI-powered threat analysis with SHAP explainability"
              badge={5}
              icon={<AlertTriangle className="h-4 w-4" />}
            >
              <AnomalyList 
                anomalies={anomalies} 
                onViewDetails={(detection) => {
                  setSelectedDetection(detection);
                  setShowModal(true);
                }}
              />
            </GlassPanel>

            <GlassPanel
              title="Threat Classification"
              subtitle="Attack vector distribution"
              badge={6}
              icon={<Zap className="h-4 w-4" />}
            >
              <ThreatDistribution threats={threats} />
            </GlassPanel>
          </div>

          <div className="space-y-6">
            <GlassPanel 
              title="Live Event Stream" 
              subtitle="Real-time detection feed" 
              badge={7} 
              icon={<Eye className="h-4 w-4" />}
            >
              <EventStream 
                detections={detections.slice(0, 20)}
                onViewDetails={(detection) => {
                  setSelectedDetection(detection);
                  setShowModal(true);
                }}
              />
            </GlassPanel>
          </div>
        </div>

        <DetectionTable 
          detections={paginatedDetections}
          totalDetections={filteredDetections.length}
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setCurrentPage}
          filterStatus={filterStatus}
          onFilterChange={setFilterStatus}
          filterSeverity={filterSeverity}
          onFilterSeverityChange={setFilterSeverity}
          filterDeviceType={filterDeviceType}
          onFilterDeviceTypeChange={setFilterDeviceType}
          filterThreatType={filterThreatType}
          onFilterThreatTypeChange={setFilterThreatType}
          deviceTypes={deviceTypes}
          threatTypes={threatTypes}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onViewDetails={(detection) => {
            setSelectedDetection(detection);
            setShowModal(true);
          }}
        />
      </div>
    </div>
  );
}

/* ========================== DETECTION MODAL ========================== */

function DetectionModal({ detection, onClose }: { detection: Detection; onClose: () => void }) {
  // ✅ DEBUG: Log pour vérifier les données
  console.log("Detection in modal:", detection);
  console.log("Recommended Actions:", detection.recommendedActions);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl bg-gradient-to-br from-slate-900 to-slate-800 border border-white/20 shadow-2xl">
        <div className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur-xl border-b border-white/10 px-8 py-6">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <h2 className="text-2xl font-bold text-white">{detection.deviceId}</h2>
                <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                  detection.isAnomaly
                    ? "bg-red-500/20 text-red-300 border-red-500/30"
                    : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                }`}>
                  {detection.isAnomaly ? "🚨 THREAT DETECTED" : "✓ NORMAL"}
                </span>
              </div>
              <div className="text-sm text-gray-400">
                {detection.createdAt ? new Date(detection.createdAt).toLocaleString() : "—"}
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 transition-all"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-8 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <InfoCard label="Device Type" value={detection.deviceType ?? "Unknown"} />
            <InfoCard label="Risk Score" value={detection.riskScore ?? 0} highlight />
            <InfoCard label="Threat Type" value={detection.threatType ?? "—"} />
            <InfoCard label="Severity" value={detection.threatSeverity ?? "—"} />
            <InfoCard label="Confidence" value={`${(Number(detection.confidenceScore) * 100).toFixed(1)}%`} />
            <InfoCard label="Protocol" value={detection.protocol ?? "—"} />
          </div>

          {detection.explanation && (
            <div className="rounded-xl bg-gradient-to-br from-cyan-950/50 to-blue-950/50 border border-cyan-500/30 p-6">
              <div className="flex items-center gap-2 mb-3">
                <Info className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-cyan-300">AI Analysis</h3>
              </div>
              <p className="text-gray-200 leading-relaxed">{detection.explanation}</p>
            </div>
          )}

          {detection.rawTelemetry?.top_factors?.length > 0 && (
            <div className="rounded-xl bg-gradient-to-br from-purple-950/50 to-pink-950/50 border border-purple-500/30 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Zap className="w-5 h-5 text-purple-400" />
                <h3 className="text-lg font-bold text-purple-300">SHAP Explainability Factors</h3>
              </div>
              <div className="space-y-4">
                {detection.rawTelemetry.top_factors.map((f: any, i: number) => (
                  <div key={i} className="bg-slate-900/50 rounded-lg p-4 border border-white/5">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-semibold">
                        {i + 1}. {f.feature}
                      </span>
                      <span className="font-mono text-gray-300">
                        Value: <span className="text-cyan-400 font-bold">{Number(f.feature_value).toFixed(2)}</span>
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-xs text-gray-400">SHAP Impact:</span>
                      <span className={`text-sm font-bold ${
                        f.impact === "increases" ? "text-red-400" : "text-emerald-400"
                      }`}>
                        {f.impact === "increases" ? "↑ Increases" : "↓ Decreases"} Risk ({Number(f.shap_value).toFixed(3)})
                      </span>
                    </div>
                    <div className="h-3 w-full rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          f.impact === "increases"
                            ? "bg-gradient-to-r from-red-500 to-orange-500"
                            : "bg-gradient-to-r from-emerald-500 to-green-500"
                        }`}
                        style={{ width: `${Math.min(Math.abs(f.shap_value) * 200, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ✅ RECOMMENDED ACTIONS - Avec vérification Array */}
          {Array.isArray(detection.recommendedActions) && detection.recommendedActions.length > 0 && (
            <div className="rounded-xl bg-gradient-to-br from-amber-950/50 to-orange-950/50 border border-amber-500/30 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-amber-400" />
                <h3 className="text-lg font-bold text-amber-300">Recommended Actions</h3>
              </div>
              <ul className="space-y-3">
                {detection.recommendedActions.map((action: string, idx: number) => (
                  <li key={idx} className="flex items-start gap-3 text-gray-200">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-amber-500/20 text-amber-400 font-bold text-sm flex items-center justify-center border border-amber-500/30">
                      {idx + 1}
                    </span>
                    <span className="flex-1">{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {detection.rawTelemetry && (
            <div className="rounded-xl bg-slate-950/50 border border-white/5 p-6">
              <h3 className="text-lg font-bold text-white mb-4">Raw Telemetry Data</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                {Object.entries(detection.rawTelemetry)
                  .filter(([key]) => key !== "top_factors")
                  .map(([key, value]) => (
                    <div key={key} className="bg-slate-900/50 rounded-lg p-3 border border-white/5">
                      <div className="text-gray-400 text-xs mb-1">{key}</div>
                      <div className="text-white font-mono text-sm truncate">
                        {typeof value === "number" ? value.toFixed(2) : String(value)}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-slate-900/95 backdrop-blur-xl border-t border-white/10 px-8 py-4 flex items-center justify-between">
          <div className="text-sm text-gray-400">
            Detection ID: <span className="font-mono text-gray-300">{detection.id ?? "—"}</span>
          </div>
          <button
            onClick={onClose}
            className="px-6 py-2 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium transition-all"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function InfoCard({ label, value, highlight }: { label: string; value: string | number; highlight?: boolean }) {
  return (
    <div className={`rounded-xl p-4 border ${
      highlight
        ? "bg-gradient-to-br from-red-950/50 to-orange-950/50 border-red-500/30"
        : "bg-slate-900/50 border-white/5"
    }`}>
      <div className="text-xs text-gray-400 mb-1">{label}</div>
      <div className={`text-xl font-bold ${highlight ? "text-red-400" : "text-white"}`}>
        {value}
      </div>
    </div>
  );
}


/* ========================== DETECTION TABLE ========================== */

function DetectionTable({ 
  detections, 
  totalDetections,
  currentPage, 
  totalPages, 
  onPageChange,
  filterStatus,
  onFilterChange,
  filterSeverity,
  onFilterSeverityChange,
  filterDeviceType,
  onFilterDeviceTypeChange,
  filterThreatType,
  onFilterThreatTypeChange,
  deviceTypes,
  threatTypes,
  searchQuery,
  onSearchChange,
  onViewDetails,
}: { 
  detections: Detection[]; 
  totalDetections: number;
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  filterStatus: "all" | "anomaly" | "normal";
  onFilterChange: (status: "all" | "anomaly" | "normal") => void;
  filterSeverity: "all" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  onFilterSeverityChange: (severity: "all" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO") => void;
  filterDeviceType: string;
  onFilterDeviceTypeChange: (type: string) => void;
  filterThreatType: string;
  onFilterThreatTypeChange: (type: string) => void;
  deviceTypes: string[];
  threatTypes: string[];
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onViewDetails: (detection: Detection) => void;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/50 to-slate-800/50 overflow-hidden backdrop-blur-xl">
      <div className="px-6 py-4 border-b border-white/10 bg-slate-900/50 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-bold text-white">Detection History</div>
            <div className="text-sm text-gray-400 mt-1">
              Showing {detections.length} of {totalDetections} events • All database records loaded
            </div>
          </div>
        </div>

        {/* ✅ FILTER ROW 1: Status Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <button
              onClick={() => onFilterChange("all")}
              className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                filterStatus === "all"
                  ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              All
            </button>
            <button
              onClick={() => onFilterChange("anomaly")}
              className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                filterStatus === "anomaly"
                  ? "bg-red-500/20 text-red-300 border border-red-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              Anomalies Only
            </button>
            <button
              onClick={() => onFilterChange("normal")}
              className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                filterStatus === "normal"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                  : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
              }`}
            >
              Normal Only
            </button>
          </div>

          <div className="flex-1 min-w-[200px] max-w-md">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Search devices, types, threats..."
                className="w-full pl-10 pr-4 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white placeholder:text-gray-500 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* ✅ FILTER ROW 2: Advanced Filters */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => onFilterSeverityChange(e.target.value as any)}
            className="px-4 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white focus:border-cyan-500/50 focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">🔴 CRITICAL</option>
            <option value="HIGH">🟠 HIGH</option>
            <option value="MEDIUM">🟡 MEDIUM</option>
            <option value="LOW">🟢 LOW</option>
            <option value="INFO">ℹ️ INFO</option>
          </select>

          {/* Device Type Filter */}
          <select
            value={filterDeviceType}
            onChange={(e) => onFilterDeviceTypeChange(e.target.value)}
            className="px-4 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white focus:border-cyan-500/50 focus:outline-none"
          >
            <option value="all">All Device Types</option>
            {deviceTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          {/* Threat Type Filter */}
          <select
            value={filterThreatType}
            onChange={(e) => onFilterThreatTypeChange(e.target.value)}
            className="px-4 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white focus:border-cyan-500/50 focus:outline-none"
          >
            <option value="all">All Threat Types</option>
            {threatTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          {/* Clear Filters Button */}
          {(filterStatus !== "all" || filterSeverity !== "all" || filterDeviceType !== "all" || filterThreatType !== "all" || searchQuery) && (
            <button
              onClick={() => {
                onFilterChange("all");
                onFilterSeverityChange("all");
                onFilterDeviceTypeChange("all");
                onFilterThreatTypeChange("all");
                onSearchChange("");
              }}
              className="px-4 py-2 rounded-lg bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30 text-xs font-medium transition-all"
            >
              ✕ Clear Filters
            </button>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-slate-900/50 border-b border-white/5 text-xs text-gray-400 uppercase tracking-wider">
              <th className="px-6 py-4 text-left font-semibold">Timestamp</th>
              <th className="px-6 py-4 text-left font-semibold">Device ID</th>
              <th className="px-6 py-4 text-left font-semibold">Device Type</th>
              <th className="px-6 py-4 text-left font-semibold">Threat Type</th>
              <th className="px-6 py-4 text-left font-semibold">Status</th>
              <th className="px-6 py-4 text-center font-semibold">Risk</th>
              <th className="px-6 py-4 text-center font-semibold">Severity</th>
              <th className="px-6 py-4 text-center font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {detections.map((d: Detection, idx: number) => (
              <tr
                key={generateUniqueKey(d, idx)}                
                className="hover:bg-white/5 transition-colors"
              >
                <td className="px-6 py-4 text-sm text-gray-400 font-mono">
                  {d.createdAt ? new Date(d.createdAt).toLocaleString() : "—"}
                </td>
                <td className="px-6 py-4 text-sm font-semibold text-white">{d.deviceId}</td>
                <td className="px-6 py-4 text-sm text-gray-400">{d.deviceType ?? "—"}</td>
                <td className="px-6 py-4 text-sm text-orange-300 font-medium">{d.threatType ?? "—"}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex px-3 py-1 rounded-full text-xs font-bold border ${
                    d.isAnomaly
                      ? "bg-red-500/20 text-red-300 border-red-500/30"
                      : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                  }`}>
                    {d.isAnomaly ? "ANOMALY" : "NORMAL"}
                  </span>
                </td>
                <td className="px-6 py-4 text-center">
                  <span className={`text-lg font-black ${
                    d.riskScore >= 80 ? "text-red-400" :
                    d.riskScore >= 60 ? "text-orange-400" :
                    d.riskScore >= 40 ? "text-yellow-400" :
                    "text-gray-500"
                  }`}>
                    {d.riskScore}
                  </span>
                </td>
                <td className="px-6 py-4 text-center">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                    d.threatSeverity === "CRITICAL" ? "bg-red-500/20 text-red-300" :
                    d.threatSeverity === "HIGH" ? "bg-orange-500/20 text-orange-300" :
                    d.threatSeverity === "MEDIUM" ? "bg-yellow-500/20 text-yellow-300" :
                    d.threatSeverity === "LOW" ? "bg-green-500/20 text-green-300" :
                    "bg-slate-700/50 text-gray-400"
                  }`}>
                    {d.threatSeverity}
                  </span>
                </td>
                <td className="px-6 py-4 text-center">
                  <button
                    onClick={() => onViewDetails(d)}
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30 transition-all text-xs font-medium"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="px-6 py-4 border-t border-white/10 bg-slate-900/50 flex items-center justify-between">
          <div className="text-sm text-gray-400">
            Page {currentPage} of {totalPages} • {totalDetections.toLocaleString()} total records
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              let pageNum;
              if (totalPages <= 5) {
                pageNum = i + 1;
              } else if (currentPage <= 3) {
                pageNum = i + 1;
              } else if (currentPage >= totalPages - 2) {
                pageNum = totalPages - 4 + i;
              } else {
                pageNum = currentPage - 2 + i;
              }
              return (
                <button
                  key={pageNum}
                  onClick={() => onPageChange(pageNum)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                    currentPage === pageNum
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                      : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}
            <button
              onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ========================== STYLED COMPONENTS ========================== */

function LiveBadge({ state, lastLiveAt }: { 
  state: "connected" | "disconnected" | "connecting"; 
  lastLiveAt: Date | null 
}) {
  const config = {
    connected: {
      bg: "bg-emerald-500/10",
      text: "text-emerald-300",
      border: "border-emerald-500/30",
      icon: Wifi,
      label: "LIVE",
      dot: "bg-emerald-500",
    },
    connecting: {
      bg: "bg-yellow-500/10",
      text: "text-yellow-300",
      border: "border-yellow-500/30",
      icon: Loader2,
      label: "CONNECTING",
      dot: "bg-yellow-500",
    },
    disconnected: {
      bg: "bg-red-500/10",
      text: "text-red-300",
      border: "border-red-500/30",
      icon: WifiOff,
      label: "OFFLINE",
      dot: "bg-red-500",
    },
  };

  const { bg, text, border, icon: Icon, label, dot } = config[state];

  return (
    <div className={`inline-flex items-center gap-2.5 rounded-lg border px-4 py-2 text-xs font-semibold ${bg} ${text} ${border} backdrop-blur-sm`}>
      <div className="relative">
        <div className={`h-2 w-2 rounded-full ${dot} ${state === 'connected' ? 'animate-pulse' : ''}`}></div>
        {state === 'connected' && (
          <div className={`absolute inset-0 h-2 w-2 rounded-full ${dot} animate-ping`}></div>
        )}
      </div>
      <Icon className={`h-4 w-4 ${state === 'connecting' ? 'animate-spin' : ''}`} />
      <span className="tracking-wide">{label}</span>
      {lastLiveAt && (
        <span className="text-[10px] opacity-70 font-mono">
          {lastLiveAt.toLocaleTimeString()}
        </span>
      )}
    </div>
  );
}

function TimeBtn({ label }: { label: string }) {
  return (
    <button className="inline-flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5 border border-white/10 hover:border-cyan-500/50 hover:bg-white/10 transition-all text-xs font-medium text-gray-300 hover:text-cyan-300">
      <span>{label}</span>
      <ChevronDown className="h-3 w-3 opacity-50" />
    </button>
  );
}

function Tab({ label, active = false, count }: { label: string; active?: boolean; count?: number }) {
  return (
    <button
      className={`relative pb-3 text-sm font-medium transition-all ${
        active ? "text-white" : "text-gray-400 hover:text-gray-200"
      }`}
    >
      <span className="flex items-center gap-2">
        {label}
        {count !== undefined && count > 0 && (
          <span className="px-2 py-0.5 rounded-full bg-gradient-to-r from-red-500 to-orange-500 text-white text-[10px] font-bold shadow-lg shadow-red-500/30 animate-pulse">
            {count}
          </span>
        )}
      </span>
      {active && (
        <span className="absolute left-0 right-0 -bottom-[1px] h-[2px] bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500"></span>
      )}
    </button>
  );
}

function FilterPill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/30 px-3 py-1.5 text-xs text-blue-200 font-medium hover:border-blue-400/50 transition-colors">
      {label}
      <button className="opacity-60 hover:opacity-100 transition-opacity">×</button>
    </span>
  );
}

function GlassPanel({
  title,
  subtitle,
  badge,
  icon,
  children,
  large,
}: {
  title: string;
  subtitle?: string;
  badge: number;
  icon?: React.ReactNode;
  children: React.ReactNode;
  large?: boolean;
}) {
  return (
    <div className={`rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/50 via-slate-800/50 to-slate-900/50 ${large ? 'p-8' : 'p-6'} hover:border-white/20 transition-all backdrop-blur-xl shadow-2xl shadow-black/50`}>
      <div className="mb-5 flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2.5 text-lg font-bold text-white">
            <span className="text-cyan-400">{icon}</span>
            {title}
          </div>
          {subtitle && (
            <div className="mt-1.5 text-sm text-gray-400">{subtitle}</div>
          )}
        </div>
        <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-sm font-black text-slate-900 shadow-lg shadow-amber-500/30">
          {badge}
        </div>
      </div>
      {children}
    </div>
  );
}

// ✅ PROFESSIONAL KPI CARD - NO GLOW/PULSE ON ICONS
function KPICard({
  title,
  value,
  icon,
  gradient,
  subtitle,
  trend,
  trendUp,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  gradient: string;
  subtitle?: string;
  trend?: string;
  trendUp?: boolean;
}) {
  return (
    <div className="group relative rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/80 to-slate-800/80 p-6 hover:border-white/20 transition-all backdrop-blur-xl shadow-xl hover:shadow-2xl">
      <div className="flex items-start justify-between mb-4">
        <div className="text-sm font-semibold text-gray-400 tracking-wide uppercase">
          {title}
        </div>
        {/* ✅ PROFESSIONAL ICON - Static, no pulse/glow */}
        <div className={`relative p-3 rounded-xl bg-gradient-to-br ${gradient} shadow-lg`}>
          <div className="relative z-10">{icon}</div>
        </div>
      </div>
      
      <div className="text-4xl font-black text-white mb-2 tracking-tight">
        {value}
      </div>
      
      {subtitle && (
        <div className="text-sm text-gray-400 mb-2">{subtitle}</div>
      )}
      
      {trend && (
        <div className={`flex items-center gap-1.5 text-xs font-semibold ${
          trendUp ? 'text-emerald-400' : 'text-red-400'
        }`}>
          {trendUp ? (
            <TrendingUp className="w-3.5 h-3.5" />
          ) : (
            <TrendingDown className="w-3.5 h-3.5" />
          )}
          <span>{trend} vs last hour</span>
        </div>
      )}
      
      <div className={`absolute inset-0 rounded-2xl bg-gradient-to-br ${gradient} opacity-0 group-hover:opacity-5 transition-opacity pointer-events-none`}></div>
    </div>
  );
}

/* ========================== CHART COMPONENTS ========================== */

function AnomalyCountChart({ detections }: { detections: any[] }) {
  // buckets: last 8 hours (oldest -> now)
  const now = Date.now();
  const H = 60 * 60 * 1000;

  const buckets = Array.from({ length: 8 }, (_, i) => {
    const start = now - (7 - i) * H;
    const end = start + H;
    return { start, end, count: 0 };
  });

  for (const d of detections ?? []) {
    if (!d?.isAnomaly) continue;
    const t = d?.createdAt ? new Date(d.createdAt).getTime() : NaN;
    if (!Number.isFinite(t)) continue;

    const idx = buckets.findIndex(b => t >= b.start && t < b.end);
    if (idx >= 0) buckets[idx].count += 1;
  }

  const data = buckets.map(b => b.count);
  const current = data[data.length - 1] ?? 0;
  const maxV = Math.max(...data, 1);

  return (
    <div className="rounded-xl bg-slate-950/50 border border-white/5 p-5">
      <div className="flex h-48 items-end gap-2">
        {data.map((v, i) => {
          const heightPercent = (v / maxV) * 100;

          return (
            <div
              key={i}
              className="flex-1 group relative h-full flex flex-col justify-end"
            >
              <div
                className="w-full rounded-t-lg bg-gradient-to-t from-orange-500 to-red-500 transition-all duration-300 group-hover:from-orange-400 group-hover:to-red-400"
                style={{ height: `${Math.max(2, heightPercent)}%` }}
              />
              <div className="absolute -top-8 left-1/2 -translate-x-1/2 text-xs font-bold text-white bg-slate-900/90 px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                {v} anomalies
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-3 flex justify-between text-[10px] text-gray-500">
        <span>-7h</span><span>-6h</span><span>-5h</span><span>-4h</span>
        <span>-3h</span><span>-2h</span><span>-1h</span>
        <span className="text-cyan-400 font-bold">Now</span>
      </div>

      <div className="mt-4 text-xs text-gray-500 flex items-center gap-2">
        <div className="h-1 w-12 rounded-full bg-gradient-to-r from-orange-500 to-red-500"></div>
        <span>Hourly anomalies (last 8h) • {current} this hour</span>
      </div>
    </div>
  );
}


function SecurityDonut({
  normal,
  anomaly,
  critical,
}: {
  normal: number;
  anomaly: number;
  critical: number;
}) {
  const total = Math.max(1, normal + anomaly);
  const normalPct = (normal / total) * 100;
  const anomalyPct = (anomaly / total) * 100;
  const criticalPct = Math.min(100, (critical / total) * 100);

  return (
    <div className="rounded-xl bg-slate-950/50 border border-white/5 p-5">
      <div className="flex items-center justify-center gap-8">
        <div className="relative h-40 w-40">
          <svg className="h-full w-full -rotate-90">
            <circle cx="80" cy="80" r="60" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="16" />
            <circle cx="80" cy="80" r="60" fill="none" stroke="#10b981" strokeWidth="16" strokeDasharray={`${normalPct * 3.77} 377`} className="transition-all duration-500" />
            <circle cx="80" cy="80" r="60" fill="none" stroke="#f97316" strokeWidth="16" strokeDasharray={`${anomalyPct * 3.77} 377`} strokeDashoffset={`-${normalPct * 3.77}`} className="transition-all duration-500" />
            <circle cx="80" cy="80" r="60" fill="none" stroke="#ef4444" strokeWidth="16" strokeDasharray={`${criticalPct * 3.77} 377`} strokeDashoffset={`-${(normalPct + anomalyPct) * 3.77}`} className="transition-all duration-500" />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-3xl font-black text-white">{total}</div>
            <div className="text-xs text-gray-500 font-medium">TOTAL</div>
          </div>
        </div>

        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-emerald-500 shadow-lg shadow-emerald-500/50"></div>
            <span className="text-gray-300 font-medium">Secure</span>
            <span className="ml-auto text-white font-bold">{normalPct.toFixed(0)}%</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-orange-500 shadow-lg shadow-orange-500/50"></div>
            <span className="text-gray-300 font-medium">At Risk</span>
            <span className="ml-auto text-white font-bold">{anomalyPct.toFixed(0)}%</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-red-500 shadow-lg shadow-red-500/50"></div>
            <span className="text-gray-300 font-medium">Critical</span>
            <span className="ml-auto text-white font-bold">{criticalPct.toFixed(0)}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function HeatmapGrid({ detections }: { detections: Detection[] }) {
  const cells = Array.from({ length: 12 * 8 }, (_, i) => {
    const d = detections[i];
    const isCritical = d?.isAnomaly && (d?.riskScore ?? 0) > 80;
    const isHigh = d?.isAnomaly && (d?.riskScore ?? 0) > 60;
    const isWarm = d?.isAnomaly;
    return { isCritical, isHigh, isWarm };
  });

  return (
    <div className="rounded-xl bg-slate-950/50 border border-white/5 p-5">
      <div className="grid grid-cols-12 gap-1.5 h-52">
        {cells.map((c, i) => (
          <div
            key={i}
            className={`rounded transition-all duration-300 hover:scale-110 ${
              c.isCritical
                ? "bg-red-500 shadow-lg shadow-red-500/50"
                : c.isHigh
                ? "bg-orange-500 shadow-md shadow-orange-500/30"
                : c.isWarm
                ? "bg-yellow-500/70"
                : "bg-slate-700/30"
            }`}
          />
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded bg-red-500"></div>
            <span>Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded bg-orange-500"></div>
            <span>High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded bg-yellow-500"></div>
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded bg-slate-700"></div>
            <span>Normal</span>
          </div>
        </div>
        <span>Last 96 events</span>
      </div>
    </div>
  );
}

/* ========================== NETWORK COMPONENTS ========================== */

function NetworkSummary({ networkStatus }: { networkStatus: NetworkStatus | null }) {
  if (!networkStatus?.analysis) {
    return (
      <div className="rounded-xl bg-slate-950/50 border border-white/5 p-6 text-center">
        <div className="inline-flex items-center gap-3 text-gray-400">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-sm font-medium">Waiting for network analysis data...</span>
        </div>
      </div>
    );
  }

  const a = networkStatus.analysis;
  const ns = a.network_summary;
  const bot = a.botnet_analysis;
  const lm = a.lateral_movement;
  const ca = a.coordinated_attack;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatBadge
          label="Total Devices"
          value={ns?.total_devices ?? "-"}
          icon={<Network className="w-4 h-4" />}
        />
        <StatBadge
          label="Connections"
          value={ns?.total_connections ?? "-"}
          icon={<Activity className="w-4 h-4" />}
        />
        <StatBadge
          label="Health Score"
          value={`${ns?.health_score?.toFixed?.(1) ?? "-"}%`}
          icon={<Shield className="w-4 h-4" />}
          color={(ns?.health_score ?? 100) < 60 ? "red" : (ns?.health_score ?? 100) < 80 ? "yellow" : "green"}
        />
        <StatBadge
          label="Isolated"
          value={ns?.isolated_devices?.length ?? 0}
          icon={<AlertTriangle className="w-4 h-4" />}
          color={(ns?.isolated_devices?.length ?? 0) > 0 ? "orange" : "green"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ThreatCard
          title="Botnet Activity"
          detected={!!bot?.botnet_detected}
          details={bot?.botnet_detected 
            ? `${bot.recruited_devices?.length ?? 0} devices recruited • ${bot.c2_candidates?.length ?? 0} C2 servers`
            : "No botnet activity detected"
          }
        />
        <ThreatCard
          title="Lateral Movement"
          detected={!!lm?.lateral_movement_detected}
          details={lm?.lateral_movement_detected
            ? `${lm.compromised_devices?.length ?? 0} compromised • ${lm.attack_paths?.length ?? 0} attack paths`
            : "No lateral movement detected"
          }
        />
        <ThreatCard
          title="Coordinated Attack"
          detected={!!ca?.coordinated_attack}
          details={ca?.coordinated_attack
            ? `${ca.affected_devices?.length ?? 0} devices affected`
            : "No coordinated attack detected"
          }
        />
      </div>

      {(lm?.attack_paths?.length || bot?.c2_candidates?.length) && (
        <div className="rounded-xl bg-slate-950/50 border border-white/5 p-5">
          <div className="text-sm font-semibold text-cyan-400 mb-3 flex items-center gap-2">
            <Info className="w-4 h-4" />
            Attack Intelligence
          </div>

          {lm?.attack_paths?.length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-gray-400 mb-2 font-medium">Attack Propagation Paths:</div>
              <div className="space-y-2">
                {lm.attack_paths.slice(0, 3).map((p: any, i: number) => (
                  <div key={i} className="text-xs text-gray-300 font-mono bg-slate-900/50 rounded-lg px-3 py-2 border border-white/5">
                    {Array.isArray(p.path) ? p.path.join(" → ") : String(p.path)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {bot?.c2_candidates?.length > 0 && (
            <div>
              <div className="text-xs text-gray-400 mb-2 font-medium">Command & Control Servers:</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {bot.c2_candidates.slice(0, 4).map((c: any, i: number) => (
                  <div key={i} className="flex items-center justify-between text-xs bg-slate-900/50 rounded-lg px-3 py-2 border border-white/5">
                    <span className="font-mono text-white">{c.device_id}</span>
                    <span className="text-gray-500">
                      Score: <span className="text-orange-400 font-bold">{Number(c.c2_score).toFixed(2)}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatBadge({ label, value, icon, color = "blue" }: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color?: "blue" | "green" | "yellow" | "orange" | "red";
}) {
  const colors = {
    blue: "from-blue-500/10 to-cyan-500/10 border-blue-500/30 text-blue-300",
    green: "from-emerald-500/10 to-green-500/10 border-emerald-500/30 text-emerald-300",
    yellow: "from-yellow-500/10 to-amber-500/10 border-yellow-500/30 text-yellow-300",
    orange: "from-orange-500/10 to-red-500/10 border-orange-500/30 text-orange-300",
    red: "from-red-500/10 to-pink-500/10 border-red-500/30 text-red-300",
  };

  return (
    <div className={`rounded-xl bg-gradient-to-br ${colors[color]} border p-4 backdrop-blur-sm`}>
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">{label}</span>
      </div>
      <div className="text-2xl font-black">{value}</div>
    </div>
  );
}

function ThreatCard({ title, detected, details }: {
  title: string;
  detected: boolean;
  details: string;
}) {
  return (
    <div className={`rounded-xl border p-5 transition-all ${
      detected
        ? "bg-gradient-to-br from-red-950/50 to-orange-950/50 border-red-500/30"
        : "bg-slate-950/50 border-emerald-500/20"
    }`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold text-white">{title}</span>
        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
          detected
            ? "bg-red-500/20 text-red-300 border border-red-500/30"
            : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
        }`}>
          {detected ? "🚨 ACTIVE" : "✓ CLEAR"}
        </span>
      </div>
      <p className="text-sm text-gray-400 leading-relaxed">{details}</p>
    </div>
  );
}

/* ========================== ANOMALY & FEED COMPONENTS ========================== */

function AnomalyList({ anomalies, onViewDetails }: { anomalies: Detection[]; onViewDetails: (d: Detection) => void }) {
  if (!anomalies?.length) {
    return (
      <div className="rounded-xl bg-slate-950/50 border border-white/5 p-12 text-center">
        <CheckCircle2 className="w-16 h-16 text-emerald-500/50 mx-auto mb-4" />
        <div className="text-lg font-semibold text-gray-400">No Active Threats</div>
        <div className="text-sm text-gray-500 mt-2">All systems operating normally</div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
      {anomalies.slice(0, 6).map((a: Detection, idx: number) => (
        <div
          key={generateUniqueKey(a, idx)}          
          className="rounded-xl bg-gradient-to-br from-red-950/30 to-orange-950/30 border border-red-500/20 p-5 hover:border-red-500/40 transition-all cursor-pointer"
          onClick={() => onViewDetails(a)}
        >
          <div className="flex items-start justify-between gap-4 mb-3">
            <div className="flex-1 min-w-0">
              <div className="text-base font-bold text-white mb-1 truncate">{a.deviceId}</div>
              <div className="flex items-center gap-2 text-xs text-gray-400">
                <span className="px-2 py-0.5 rounded bg-slate-800/50 border border-white/10">
                  {a.deviceType ?? "Unknown"}
                </span>
                <span className="opacity-70">•</span>
                <span>{a.createdAt ? new Date(a.createdAt).toLocaleString() : "—"}</span>
              </div>
            </div>
            <div className="text-right flex-shrink-0">
              <div className="text-xs text-gray-400 mb-1">Risk Score</div>
              <div className="text-3xl font-black text-red-400">{a.riskScore}</div>
            </div>
          </div>

          <div className="flex items-center gap-2 mb-3">
            <span className="px-3 py-1 rounded-lg bg-orange-500/20 text-orange-300 text-xs font-semibold border border-orange-500/30">
              {a.threatType}
            </span>
            <span className={`px-3 py-1 rounded-lg text-xs font-bold border ${
              a.threatSeverity === "CRITICAL"
                ? "bg-red-500/20 text-red-300 border-red-500/30"
                : "bg-orange-500/20 text-orange-300 border-orange-500/30"
            }`}>
              {a.threatSeverity}
            </span>
            <ExternalLink className="w-4 h-4 text-cyan-400 ml-auto" />
          </div>

          <div className="text-sm text-gray-300 leading-relaxed bg-slate-900/30 rounded-lg p-3 border border-white/5">
            <span className="text-cyan-400 font-semibold">AI:</span> {a.explanation || "Processing..."}
          </div>
        </div>
      ))}
    </div>
  );
}

function ThreatDistribution({ threats }: { threats: ThreatRow[] }) {
  if (!threats?.length) {
    return (
      <div className="rounded-xl bg-slate-950/50 border border-white/5 p-12 text-center text-gray-400">
        No threat data available
      </div>
    );
  }

  const total = threats.reduce((s, t) => s + (t._count ?? 0), 0) || 1;

  return (
    <div className="space-y-3">
      {threats.map((t, i) => {
        const pct = ((t._count ?? 0) / total) * 100;
        return (
          <div key={i} className="rounded-xl bg-slate-950/50 border border-white/5 p-4 hover:border-white/10 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-white">{t.threatType}</span>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">{pct.toFixed(1)}%</span>
                <span className="text-lg font-bold text-white">{t._count}</span>
              </div>
            </div>
            <div className="h-2.5 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-orange-500 via-red-500 to-pink-500 transition-all duration-500"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EventStream({ detections, onViewDetails }: { detections: Detection[]; onViewDetails: (d: Detection) => void }) {
  return (
    <div className="space-y-2 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
      {detections.map((d: Detection, idx: number) => (
        <div
            key={generateUniqueKey(d, idx)}          
            className={`rounded-lg border p-3 transition-all hover:scale-[1.02] cursor-pointer ${
            d.isAnomaly
              ? "bg-red-950/30 border-red-500/30 hover:border-red-500/50"
              : "bg-slate-900/50 border-white/5 hover:border-white/10"
          }`}
          onClick={() => onViewDetails(d)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-semibold text-white truncate">{d.deviceId}</span>
            <span className="text-xs text-gray-500 font-mono">
              {d.createdAt ? new Date(d.createdAt).toLocaleTimeString() : "now"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 rounded-md text-xs font-bold border ${
              d.isAnomaly
                ? "bg-red-500/20 text-red-300 border-red-500/30"
                : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
            }`}>
              {d.isAnomaly ? "THREAT" : "SAFE"}
            </span>
            <span className="text-xs text-gray-400 truncate">{d.threatType}</span>
            {d.riskScore > 0 && (
              <span className="ml-auto text-sm font-bold text-orange-400">{d.riskScore}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}