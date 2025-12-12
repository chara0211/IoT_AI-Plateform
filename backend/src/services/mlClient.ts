// backend/src/services/mlClient.ts
import axios from "axios";

const ML_BASE_URL = process.env.ML_BASE_URL || "http://localhost:8000";

export interface MlDetectionResponse {
  device_id: string;
  is_anomaly: boolean;
  confidence_score: number;
  risk_score: number;
  threat_type: string;
  threat_severity: string;
  recommended_actions: string[];
  explanation: string;
  model_votes: Record<string, string>;
}

export interface EnhancedMlDetectionResponse extends MlDetectionResponse {
  shap_explanation?: {
    most_important_feature: string;
    most_important_value: number;
    total_positive_impact: number;
    total_negative_impact: number;
  };
  top_contributing_factors?: Array<{
    feature: string;
    shap_value: number;
    feature_value: number;
    impact: string;
    abs_shap: number;
  }>;
}

export interface NetworkAnalysisResponse {
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
        in_connections: number;
        c2_score: number;
      }>;
      recruited_devices: string[];
      confidence: number;
    };
    lateral_movement: {
      lateral_movement_detected: boolean;
      attack_paths: Array<{
        path: string[];
        length: number;
        entry_point: string;
        final_target: string;
      }>;
      entry_point: string | null;
      compromised_devices: string[];
    };
    coordinated_attack: {
      coordinated_attack: boolean;
      attack_wave: number;
      affected_devices: string[];
    };
    critical_devices: Array<{
      device_id: string;
      criticality_score: number;
      device_type: string;
      is_anomalous: boolean;
    }>;
  };
  devices_analyzed: number;
  timestamp: string;
}

// Standard detection
export async function detectAnomalyFromML(payload: any): Promise<MlDetectionResponse> {
  const url = `${ML_BASE_URL}/api/ml/detect`;
  const res = await axios.post(url, payload);
  return res.data;
}

// Detection with SHAP explanation
export async function detectWithExplanation(payload: any): Promise<EnhancedMlDetectionResponse> {
  const url = `${ML_BASE_URL}/api/ml/detect/explained`;
  const res = await axios.post(url, payload);
  return res.data;
}

// Network analysis for multiple devices
export async function analyzeNetwork(devices: any[]): Promise<NetworkAnalysisResponse> {
  const url = `${ML_BASE_URL}/api/ml/network/analyze`;
  const res = await axios.post(url, {
    telemetry_data: devices,
    time_window_minutes: 60
  });
  return res.data;
}

// Health check
export async function checkMlEngineHealth(): Promise<{ status: string; models_loaded: boolean }> {
  const url = `${ML_BASE_URL}/health`;
  const res = await axios.get(url);
  return res.data;
}