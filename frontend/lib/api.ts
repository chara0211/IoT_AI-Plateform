// frontend/lib/api.ts
const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000";

// ============================================================================
// TYPES
// ============================================================================

export type Detection = {
  id: number;
  deviceId: string;
  deviceType?: string | null;
  isAnomaly: boolean;
  confidenceScore: number;
  riskScore: number;
  threatType: string;
  threatSeverity: string;
  explanation: string;
  modelVotes: any;
  recommendedActions: any;
  rawTelemetry?: any;
  createdAt: string;
};

export type Summary = {
  total_detections: number;
  anomaly_count: number;
  normal_count: number;
  anomaly_ratio: number;
  critical_incidents: number;
  high_incidents: number;
};

export type ThreatDistribution = {
  threatType: string;
  _count: number;
}[];

export type NetworkAnalysis = {
  success: boolean;
  analysis: {
    network_summary: {
      total_devices: number;
      total_connections: number;
      health_score: number;
      isolated_devices: string[];
    };
    botnet_analysis: {
      botnet_detected: boolean;
      c2_candidates: Array<{
        device_id: string;
        out_connections: number;
        c2_score: number;
      }>;
      recruited_devices: string[];
    };
    lateral_movement: {
      lateral_movement_detected: boolean;
      attack_paths: Array<{
        path: string[];
        entry_point: string;
      }>;
      compromised_devices: string[];
    };
    coordinated_attack: {
      coordinated_attack: boolean;
      affected_devices: string[];
    };
  };
};

// ============================================================================
// API FUNCTIONS
// ============================================================================

export async function fetchDetections(limit = 10000, filters?: {
  deviceId?: string;
  severity?: string;
  isAnomaly?: boolean;
}): Promise<Detection[]> {
  const params = new URLSearchParams();
  params.append('limit', String(limit));
  
  if (filters?.deviceId) params.append('deviceId', filters.deviceId);
  if (filters?.severity) params.append('severity', filters.severity);
  if (filters?.isAnomaly !== undefined) params.append('isAnomaly', String(filters.isAnomaly));

  const res = await fetch(`${API_BASE}/api/detections?${params}`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch detections");
  return res.json();
}

export async function fetchDetectionById(id: number): Promise<Detection> {
  const res = await fetch(`${API_BASE}/api/detections/${id}`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch detection");
  return res.json();
}

export async function fetchSummary(): Promise<Summary> {
  const res = await fetch(`${API_BASE}/api/stats/summary`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch summary");
  return res.json();
}

export async function fetchThreatDistribution(): Promise<ThreatDistribution> {
  const res = await fetch(`${API_BASE}/api/stats/threats`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch threat distribution");
  return res.json();
}

export async function fetchTimeline(hours = 24): Promise<any[]> {
  const res = await fetch(`${API_BASE}/api/stats/timeline?hours=${hours}`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch timeline");
  return res.json();
}

export async function fetchRecentAnomalies(limit = 10): Promise<Detection[]> {
  const res = await fetch(`${API_BASE}/api/anomalies/recent?limit=${limit}`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch anomalies");
  return res.json();
}

export async function fetchNetworkStatus(): Promise<NetworkAnalysis> {
  const res = await fetch(`${API_BASE}/api/network/status`, { 
    cache: "no-store" 
  });
  
  if (!res.ok) throw new Error("Failed to fetch network status");
  return res.json();
}

export async function analyzeNetwork(devices: any[]): Promise<NetworkAnalysis> {
  const res = await fetch(`${API_BASE}/api/network/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devices }),
    cache: "no-store"
  });
  
  if (!res.ok) throw new Error("Failed to analyze network");
  return res.json();
}