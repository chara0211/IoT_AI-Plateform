"""
FastAPI ML Service - IoT Anomaly Detection
Uses the ensemble model for production-grade detection

Author: Wafaa EL HADCHI
Port: 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import numpy as np
from typing import List, Dict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="IoT Security ML Engine",
    description="Real-time anomaly detection for IoT devices",
    version="1.0.0"
)

# CORS middleware (allow frontend to call this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# LOAD MODELS
# ============================================================================

try:
    # Load ensemble model
    ensemble = joblib.load('models/ensemble_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    logger.info("✅ Models loaded successfully")
    logger.info(f"   - Isolation Forest: {ensemble['isolation_forest']}")
    logger.info(f"   - Random Forest: {ensemble['random_forest']}")
    logger.info(f"   - One-Class SVM: {ensemble['one_class_svm']}")
except Exception as e:
    logger.error(f"❌ Error loading models: {e}")
    raise

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class DeviceTelemetry(BaseModel):
    """IoT device telemetry data"""
    device_id: str = Field(..., description="Unique device identifier")
    device_type: str = Field(..., description="Device type (camera, sensor, etc)")
    cpu_usage: float = Field(..., ge=0, le=100, description="CPU usage percentage")
    memory_usage: float = Field(..., ge=0, le=100, description="Memory usage percentage")
    network_in_kb: int = Field(..., ge=0, description="Network input in KB")
    network_out_kb: int = Field(..., ge=0, description="Network output in KB")
    packet_rate: int = Field(..., ge=0, description="Packets per second")
    avg_response_time_ms: float = Field(..., ge=0, description="Average response time in ms")
    service_access_count: int = Field(..., ge=0, description="Number of service accesses")
    failed_auth_attempts: int = Field(..., ge=0, description="Failed authentication attempts")
    is_encrypted: int = Field(..., ge=0, le=1, description="Traffic encrypted (0 or 1)")
    geo_location_variation: float = Field(..., ge=0, description="Geographic location variation")

    class Config:
        json_schema_extra = {
            "example": {
                "device_id": "camera_01",
                "device_type": "camera",
                "cpu_usage": 85.5,
                "memory_usage": 72.3,
                "network_in_kb": 1200,
                "network_out_kb": 800,
                "packet_rate": 950,
                "avg_response_time_ms": 250.5,
                "service_access_count": 5,
                "failed_auth_attempts": 3,
                "is_encrypted": 0,
                "geo_location_variation": 12.5
            }
        }

class DetectionResponse(BaseModel):
    """Anomaly detection response"""
    device_id: str
    is_anomaly: bool
    confidence_score: float = Field(..., description="Detection confidence (0-1)")
    risk_score: int = Field(..., ge=0, le=100, description="Risk level (0-100)")
    threat_type: str = Field(..., description="Type of threat detected")
    threat_severity: str = Field(..., description="Severity level")
    recommended_actions: List[str] = Field(..., description="Suggested actions")
    explanation: str = Field(..., description="Human-readable explanation")
    model_votes: Dict[str, str] = Field(..., description="Individual model predictions")

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
    
    # DoS attack indicators
    if data.cpu_usage > 70 and data.packet_rate > 800:
        return "DDoS Attack"
    
    # Injection attack indicators
    if data.failed_auth_attempts > 7:
        return "Code Injection / Credential Stuffing"
    
    # Spoofing indicators
    if data.geo_location_variation > 15:
        return "Location Spoofing / Identity Theft"
    
    # Data exfiltration
    if data.network_out_kb > data.network_in_kb * 3:
        return "Data Exfiltration"
    
    # Botnet recruitment
    if data.cpu_usage > 75 and data.packet_rate > 600:
        return "Botnet Recruitment"
    
    return "Unknown Anomaly"

def calculate_risk_score(data: DeviceTelemetry, ml_confidence: float, is_anomaly: bool) -> int:
    """Context-aware risk scoring (0-100)"""
    if not is_anomaly:
        return 0
    
    risk = 0
    
    # CPU-based risk (max 25 points)
    if data.cpu_usage > 80:
        risk += 25
    elif data.cpu_usage > 60:
        risk += 15
    elif data.cpu_usage > 40:
        risk += 5
    
    # Network-based risk (max 25 points)
    if data.packet_rate > 1000:
        risk += 25
    elif data.packet_rate > 700:
        risk += 15
    elif data.packet_rate > 400:
        risk += 5
    
    # Auth failure risk (max 25 points)
    if data.failed_auth_attempts > 10:
        risk += 25
    elif data.failed_auth_attempts > 5:
        risk += 15
    elif data.failed_auth_attempts > 2:
        risk += 5
    
    # ML confidence (max 25 points)
    risk += int(ml_confidence * 25)
    
    return min(int(risk), 100)

def get_recommended_actions(risk_score: int, threat_type: str) -> List[str]:
    """Get actions based on risk level"""
    if risk_score >= 80:
        return [
            " CRITICAL: Isolate device from network immediately",
            "Block all traffic to/from this device",
            "Capture network traffic for forensic analysis",
            "Alert security team and escalate",
            "Initiate incident response protocol"
        ]
    elif risk_score >= 60:
        return [
            " HIGH: Restrict device network access",
            "Enable enhanced monitoring",
            "Alert administrator",
            "Review device logs",
            "Prepare for potential isolation"
        ]
    elif risk_score >= 40:
        return [
            " MEDIUM: Flag for security review",
            "Increase monitoring frequency",
            "Log all device activities",
            "Notify system administrator"
        ]
    else:
        return [
            "ℹ LOW: Continue monitoring",
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
# API ENDPOINTS
# ============================================================================

@app.get("/")
def root():
    """Root endpoint"""
    return {
        "service": "IoT Security ML Engine",
        "version": "1.0.0",
        "status": "operational",
        "models": "ensemble (Isolation Forest + Random Forest + One-Class SVM)",
        "endpoints": {
            "detect": "/api/ml/detect",
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
        "service": "ML Engine"
    }

@app.post("/api/ml/detect", response_model=DetectionResponse)
async def detect_anomaly(data: DeviceTelemetry):
    """
    Main anomaly detection endpoint
    
    This endpoint receives IoT device telemetry and returns:
    - Whether the device behavior is anomalous
    - Risk score (0-100)
    - Threat classification
    - Recommended actions
    """
    try:
        # Engineer features
        features = engineer_features(data)
        
        # Scale features
        features_scaled = scaler.transform(features)
        
        # Get predictions from all 3 models
        iso_pred = ensemble['isolation_forest'].predict(features_scaled)[0]
        rf_pred = ensemble['random_forest'].predict(features_scaled)[0]
        svm_pred = ensemble['one_class_svm'].predict(features_scaled)[0]
        
        # Record model votes
        model_votes = {
            "isolation_forest": "Anomaly" if iso_pred == -1 else "Normal",
            "random_forest": rf_pred,
            "one_class_svm": "Anomaly" if svm_pred == -1 else "Normal"
        }
        
        # Ensemble decision (majority vote)
        votes = [iso_pred, -1 if rf_pred == 'Anomaly' else 1, svm_pred]
        anomaly_votes = sum([1 for v in votes if v == -1])
        is_anomaly = anomaly_votes >= 2  # 2 out of 3
        
        # Calculate confidence (proportion of anomaly votes)
        confidence = anomaly_votes / 3.0
        
        # Classify threat type
        threat_type = classify_threat_type(data, is_anomaly)
        
        # Calculate risk score
        risk_score = calculate_risk_score(data, confidence, is_anomaly)
        
        # Determine severity
        severity = get_severity(risk_score)
        
        # Get recommended actions
        actions = get_recommended_actions(risk_score, threat_type)
        
        # Generate explanation
        if is_anomaly:
            explanation = (
                f"Device {data.device_id} exhibits anomalous behavior. "
                f"CPU: {data.cpu_usage:.1f}%, Packet rate: {data.packet_rate} pps, "
                f"Failed auth: {data.failed_auth_attempts}. "
                f"Models voted: {anomaly_votes}/3 for anomaly."
            )
        else:
            explanation = f"Device {data.device_id} operating normally. All metrics within expected ranges."
        
        # Log detection
        logger.info(f"Detection: {data.device_id} - Anomaly: {is_anomaly}, Risk: {risk_score}, Type: {threat_type}")
        
        return DetectionResponse(
            device_id=data.device_id,
            is_anomaly=is_anomaly,
            confidence_score=round(confidence, 3),
            risk_score=risk_score,
            threat_type=threat_type,
            threat_severity=severity,
            recommended_actions=actions,
            explanation=explanation,
            model_votes=model_votes
        )
        
    except Exception as e:
        logger.error(f"Error in detection: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")

@app.post("/api/ml/batch-detect")
async def batch_detect(devices: List[DeviceTelemetry]):
    """
    Batch anomaly detection for multiple devices
    """
    results = []
    for device in devices:
        try:
            result = await detect_anomaly(device)
            results.append(result)
        except Exception as e:
            logger.error(f"Error processing {device.device_id}: {e}")
            results.append({
                "device_id": device.device_id,
                "error": str(e)
            })
    
    return {
        "total": len(devices),
        "processed": len(results),
        "results": results
    }

# ============================================================================
# STARTUP
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("=" * 80)
    logger.info("🚀 IoT Security ML Engine Starting...")
    logger.info("=" * 80)
    logger.info(f"✅ Models loaded successfully")
    logger.info(f"✅ Ensemble voting system active")
    logger.info(f"✅ API ready on http://localhost:8000")
    logger.info(f"📖 Documentation: http://localhost:8000/docs")
    logger.info("=" * 80)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
