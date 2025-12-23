"""
ENHANCED FastAPI ML Service with Network Analysis & Explainable AI
Port: 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Optional
import logging
from routers.agent import router as agent_router

# Import our new enhancements
import sys
sys.path.append('.')
from network_graph_analyzer import NetworkGraphAnalyzer
from explainable_ai import ExplainableAI
import sys, asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Initialize FastAPI app
app = FastAPI(
    title="IoT Security ML Engine - Enhanced",
    description="Real-time anomaly detection with Network Analysis & Explainable AI",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# LOAD MODELS & INITIALIZE ENHANCERS
# ============================================================================

try:
    # Load ensemble model
    ensemble = joblib.load('models/ensemble_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    
    # Initialize explainable AI
    explainer = ExplainableAI()
    
    # Initialize network analyzer
    network_analyzer = NetworkGraphAnalyzer()
    
    logger.info("✅ Models and enhancements loaded successfully")
except Exception as e:
    logger.error(f"❌ Error loading models: {e}")
    raise

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class DeviceTelemetry(BaseModel):
    device_id: str
    device_type: str
    #  NEW (OPTIONAL BUT CRITICAL)
    comm_target: Optional[str] = None
    cpu_usage: float = Field(..., ge=0, le=100)
    memory_usage: float = Field(..., ge=0, le=100)
    network_in_kb: int = Field(..., ge=0)
    network_out_kb: int = Field(..., ge=0)
    packet_rate: int = Field(..., ge=0)
    avg_response_time_ms: float = Field(..., ge=0)
    service_access_count: int = Field(..., ge=0)
    failed_auth_attempts: int = Field(..., ge=0)
    is_encrypted: int = Field(..., ge=0, le=1)
    geo_location_variation: float = Field(..., ge=0)

class EnhancedDetectionResponse(BaseModel):
    """Enhanced detection response with explanations"""
    device_id: str
    is_anomaly: bool
    confidence_score: float
    risk_score: int
    threat_type: str
    threat_severity: str
    recommended_actions: List[str]
    explanation: str
    model_votes: Dict[str, str]
    # NEW: Explainable AI
    shap_explanation: Optional[Dict] = None
    top_contributing_factors: Optional[List[Dict]] = None

class NetworkAnalysisRequest(BaseModel):
    """Request for network analysis"""
    telemetry_data: List[DeviceTelemetry]
    time_window_minutes: Optional[int] = 60

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def engineer_features(data: DeviceTelemetry) -> np.ndarray:
    """Create derived features matching training"""
    network_total = data.network_in_kb + data.network_out_kb
    network_ratio = data.network_out_kb / (data.network_in_kb + 1)
    cpu_memory_product = data.cpu_usage * data.memory_usage
    
    features = np.array([[
        data.cpu_usage,
        data.memory_usage,
        data.network_in_kb,
        data.network_out_kb,
        data.packet_rate,
        data.avg_response_time_ms,
        data.service_access_count,
        data.failed_auth_attempts,
        data.is_encrypted,
        data.geo_location_variation,
        network_total,
        network_ratio,
        cpu_memory_product
    ]])
    
    return features

def classify_threat_type(data: DeviceTelemetry, is_anomaly: bool) -> str:
    """Rule-based threat classification"""
    if not is_anomaly:
        return "None"
    
    if data.cpu_usage > 70 and data.packet_rate > 800:
        return "DDoS Attack"
    if data.failed_auth_attempts > 7:
        return "Code Injection / Credential Stuffing"
    if data.geo_location_variation > 15:
        return "Location Spoofing / Identity Theft"
    if data.network_out_kb > data.network_in_kb * 3:
        return "Data Exfiltration"
    if data.cpu_usage > 75 and data.packet_rate > 600:
        return "Botnet Recruitment"
    
    return "Unknown Anomaly"

def calculate_risk_score(data: DeviceTelemetry, ml_confidence: float, is_anomaly: bool) -> int:
    """Context-aware risk scoring (0-100)"""
    if not is_anomaly:
        return 0
    
    risk = 0
    
    if data.cpu_usage > 80:
        risk += 25
    elif data.cpu_usage > 60:
        risk += 15
    elif data.cpu_usage > 40:
        risk += 5
    
    if data.packet_rate > 1000:
        risk += 25
    elif data.packet_rate > 700:
        risk += 15
    elif data.packet_rate > 400:
        risk += 5
    
    if data.failed_auth_attempts > 10:
        risk += 25
    elif data.failed_auth_attempts > 5:
        risk += 15
    elif data.failed_auth_attempts > 2:
        risk += 5
    
    risk += int(ml_confidence * 25)
    
    return min(int(risk), 100)

def get_recommended_actions(risk_score: int, threat_type: str) -> List[str]:
    """Get actions based on risk level"""
    if risk_score >= 80:
        return [
            "🚨 CRITICAL: Isolate device from network immediately",
            "Block all traffic to/from this device",
            "Capture network traffic for forensic analysis",
            "Alert security team and escalate",
            "Initiate incident response protocol"
        ]
    elif risk_score >= 60:
        return [
            "⚠️ HIGH: Restrict device network access",
            "Enable enhanced monitoring",
            "Alert administrator",
            "Review device logs",
            "Prepare for potential isolation"
        ]
    elif risk_score >= 40:
        return [
            "ℹ️ MEDIUM: Flag for security review",
            "Increase monitoring frequency",
            "Log all device activities",
            "Notify system administrator"
        ]
    else:
        return [
            "ℹ️ LOW: Continue monitoring",
            "Log for future analysis"
        ]

def get_severity(risk_score: int) -> str:
    """Determine threat severity"""
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFO"

# ============================================================================
# ENHANCED API ENDPOINTS
# ============================================================================

@app.get("/")
def root():
    """Root endpoint"""
    return {
        "service": "IoT Security ML Engine - Enhanced",
        "version": "2.0.0",
        "status": "operational",
        "new_features": [
            "Network Behavior Graph Analysis",
            "Explainable AI with SHAP"
        ],
        "endpoints": {
            "detect": "/api/ml/detect",
            "detect_explained": "/api/ml/detect/explained",
            "network_analysis": "/api/ml/network/analyze",
            "batch_detect": "/api/ml/batch-detect",
            "health": "/health",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "models_loaded": True,
        "explainer_ready": True,
        "network_analyzer_ready": True,
        "service": "ML Engine Enhanced"
    }

@app.post("/api/ml/detect/explained", response_model=EnhancedDetectionResponse)
async def detect_with_explanation(data: DeviceTelemetry):
    """
    Anomaly detection WITH SHAP explanations
    """
    try:
        # 1. Standard detection
        features = engineer_features(data)
        features_scaled = scaler.transform(features)

        iso_model = ensemble["isolation_forest"]
        rf_model = ensemble["random_forest"]
        svm_model = ensemble["one_class_svm"]

        iso_raw = iso_model.predict(features_scaled)[0]
        rf_label = rf_model.predict(features_scaled)[0]
        svm_raw = svm_model.predict(features_scaled)[0]

        rf_raw = -1 if rf_label == "Anomaly" else 1

        model_votes = {
            "isolation_forest": "Anomaly" if iso_raw == -1 else "Normal",
            "random_forest": rf_label,
            "one_class_svm": "Anomaly" if svm_raw == -1 else "Normal",
        }

        votes = [iso_raw, rf_raw, svm_raw]
        anomaly_votes = sum(1 for v in votes if v == -1)
        is_anomaly = anomaly_votes >= 2
        confidence = anomaly_votes / 3.0

        threat_type = classify_threat_type(data, is_anomaly)
        risk_score = calculate_risk_score(data, confidence, is_anomaly)
        severity = get_severity(risk_score)
        actions = get_recommended_actions(risk_score, threat_type)

        # 2. Generate SHAP explanation
        telemetry_dict = data.dict()
        shap_explanation = explainer.explain_detection(telemetry_dict)

        # 3. Combined explanation
        if is_anomaly:
            explanation = shap_explanation['explanation']
        else:
            explanation = f"Device {data.device_id} operating normally. " + shap_explanation['explanation']

        logger.info(
            f"Explained Detection: {data.device_id} - Anomaly: {is_anomaly}, "
            f"Risk: {risk_score}, Top Factor: {shap_explanation['top_contributing_factors'][0]['feature']}"
        )

        return EnhancedDetectionResponse(
            device_id=data.device_id,
            is_anomaly=is_anomaly,
            confidence_score=round(confidence, 3),
            risk_score=risk_score,
            threat_type=threat_type,
            threat_severity=severity,
            recommended_actions=actions,
            explanation=explanation,
            model_votes=model_votes,
            shap_explanation=shap_explanation['shap_summary'],
            top_contributing_factors=shap_explanation['top_contributing_factors']
        )

    except Exception as e:
        logger.error(f"Error in explained detection: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")

@app.post("/api/ml/network/analyze")
async def analyze_network(request: NetworkAnalysisRequest):
    """
    Perform network behavior graph analysis
    Detects: Botnets, lateral movement, coordinated attacks
    """
    try:
        # Convert telemetry to DataFrame
        data_dicts = [tel.dict() for tel in request.telemetry_data]
        df = pd.DataFrame(data_dicts)
        
        # Add timestamp and label columns if not present
        if 'timestamp' not in df.columns:
            df['timestamp'] = pd.Timestamp.now()
        if 'label' not in df.columns:
            df['label'] = 'Unknown'
        
        # Analyze network
        analysis = network_analyzer.analyze_network(df)

        # ✅ normalize graph naming for frontend
        graph = analysis.get("graph", {})
        graph["edges"] = graph.pop("links", [])  # frontend expects edges

        return {
            "success": True,
            "analysis": {
                **analysis,
                "graph": graph
            },
            "devices_analyzed": len(df),
            "timestamp": pd.Timestamp.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Network analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Network analysis error: {str(e)}")

@app.post("/api/ml/detect")
async def detect_anomaly(data: DeviceTelemetry):
    """
    Standard anomaly detection (backward compatible)
    """
    try:
        features = engineer_features(data)
        features_scaled = scaler.transform(features)

        iso_model = ensemble["isolation_forest"]
        rf_model = ensemble["random_forest"]
        svm_model = ensemble["one_class_svm"]

        iso_raw = iso_model.predict(features_scaled)[0]
        rf_label = rf_model.predict(features_scaled)[0]
        svm_raw = svm_model.predict(features_scaled)[0]

        rf_raw = -1 if rf_label == "Anomaly" else 1

        model_votes = {
            "isolation_forest": "Anomaly" if iso_raw == -1 else "Normal",
            "random_forest": rf_label,
            "one_class_svm": "Anomaly" if svm_raw == -1 else "Normal",
        }

        votes = [iso_raw, rf_raw, svm_raw]
        anomaly_votes = sum(1 for v in votes if v == -1)
        is_anomaly = anomaly_votes >= 2
        confidence = anomaly_votes / 3.0

        threat_type = classify_threat_type(data, is_anomaly)
        risk_score = calculate_risk_score(data, confidence, is_anomaly)
        severity = get_severity(risk_score)
        actions = get_recommended_actions(risk_score, threat_type)

        if is_anomaly:
            explanation = (
                f"Device {data.device_id} exhibits anomalous behavior. "
                f"CPU: {data.cpu_usage:.1f}%, Packet rate: {data.packet_rate} pps, "
                f"Failed auth: {data.failed_auth_attempts}. "
                f"Models anomaly votes: {anomaly_votes}/3 (ISO + RF + SVM)."
            )
        else:
            explanation = (
                f"Device {data.device_id} operating normally. "
                f"All three models mostly agree with normal behavior."
            )

        return {
            "device_id": data.device_id,
            "is_anomaly": is_anomaly,
            "confidence_score": round(confidence, 3),
            "risk_score": risk_score,
            "threat_type": threat_type,
            "threat_severity": severity,
            "recommended_actions": actions,
            "explanation": explanation,
            "model_votes": model_votes,
        }

    except Exception as e:
        logger.error(f"Error in detection: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")


app.include_router(agent_router, prefix="/api")

# ============================================================================
# STARTUP
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("=" * 80)
    logger.info("🚀 IoT Security ML Engine - ENHANCED VERSION")
    logger.info("=" * 80)
    logger.info("✅ Ensemble models loaded")
    logger.info("✅ Explainable AI (SHAP) ready")
    logger.info("✅ Network Graph Analyzer ready")
    logger.info("✅ API ready on http://localhost:8000")
    logger.info("📖 Documentation: http://localhost:8000/docs")
    logger.info("=" * 80)
    logger.info("NEW ENDPOINTS:")
    logger.info("  - /api/ml/detect/explained (with SHAP explanations)")
    logger.info("  - /api/ml/network/analyze (network behavior analysis)")
    logger.info("=" * 80)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")