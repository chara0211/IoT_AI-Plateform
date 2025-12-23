// backend/src/index.ts
import express from "express";
import cors from "cors";
import http from "http";
import { PrismaClient } from "@prisma/client";
import {
  detectAnomalyFromML,
  detectWithExplanation,
  analyzeNetwork,
  checkMlEngineHealth,
} from "./services/mlClient";
import { startMqttSubscriber } from "./mqtt/subscriber";
import { initSocket } from "./realtime/socket";

const app = express();
const prisma = new PrismaClient();

// Middleware
app.use(cors());
app.use(express.json());

// ============================================================================
// ✅ AUTO-CLEANUP (RUNS EVERY HOUR)
// ============================================================================

async function autoCleanup() {
  try {
    const hoursAgo = new Date();
    hoursAgo.setHours(hoursAgo.getHours() - 48);

    const deleted = await prisma.detection.deleteMany({
      where: {
        createdAt: {
          lt: hoursAgo,
        },
      },
    });

    if (deleted.count > 0) {
      console.log(`🗑️  Auto-cleanup: Deleted ${deleted.count} old detections (>48h)`);
    }
  } catch (e) {
    console.error("❌ Auto-cleanup failed:", e);
  }
}

// Run cleanup every hour
setInterval(autoCleanup, 60 * 60 * 1000);

// Run once on startup
autoCleanup();

// ============================================================================
// HEALTH & STATUS
// ============================================================================

app.get("/health", async (_req, res) => {
  try {
    // Check database
    await prisma.$queryRaw`SELECT 1`;

    // Check ML engine
    const mlHealth = await checkMlEngineHealth();

    res.json({
      status: "healthy",
      database: "connected",
      ml_engine: mlHealth.status,
      service: "backend-api",
    });
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      error: String(error),
    });
  }
});

// ============================================================================
// DETECTION ENDPOINTS
// ============================================================================

// Standard detection (backward compatible)
app.post("/api/telemetry", async (req, res) => {
  try {
    const telemetry = req.body;

    // Remove any extra fields
    const { attack_label, timestamp, ...cleanTelemetry } = telemetry;

    // Call ML engine
    const ml = await detectAnomalyFromML(cleanTelemetry);

    // Save to database
    const saved = await prisma.detection.create({
      data: {
        deviceId: ml.device_id,
        deviceType: cleanTelemetry.device_type ?? null,
        isAnomaly: ml.is_anomaly,
        confidenceScore: ml.confidence_score,
        riskScore: ml.risk_score,
        threatType: ml.threat_type,
        threatSeverity: ml.threat_severity,
        explanation: ml.explanation,
        modelVotes: ml.model_votes,
        recommendedActions: ml.recommended_actions,
        rawTelemetry: cleanTelemetry,
      },
    });

    console.log(
      `✅ Detection saved: ${ml.device_id} | Anomaly: ${ml.is_anomaly} | Risk: ${ml.risk_score}`
    );

    res.json({
      detection_id: saved.id,
      ...ml,
    });
  } catch (e) {
    console.error("❌ Detection failed:", e);
    res.status(500).json({ error: "Detection failed", details: String(e) });
  }
});

// 🆕 Detection with SHAP explanation
app.post("/api/telemetry/explained", async (req, res) => {
  try {
    const telemetry = req.body;
    const { attack_label, timestamp, ...cleanTelemetry } = telemetry;

    // Call ML engine with explanation
    const ml = await detectWithExplanation(cleanTelemetry);

    // Save to database
    const saved = await prisma.detection.create({
      data: {
        deviceId: ml.device_id,
        deviceType: cleanTelemetry.device_type ?? null,
        isAnomaly: ml.is_anomaly,
        confidenceScore: ml.confidence_score,
        riskScore: ml.risk_score,
        threatType: ml.threat_type,
        threatSeverity: ml.threat_severity,
        explanation: ml.explanation,
        modelVotes: ml.model_votes,
        recommendedActions: ml.recommended_actions,
        rawTelemetry: {
          ...cleanTelemetry,
          shap_explanation: ml.shap_explanation,
          top_factors: ml.top_contributing_factors,
        },
      },
    });

    console.log(
      `✅ Explained detection: ${ml.device_id} | Top factor: ${ml.shap_explanation?.most_important_feature}`
    );

    res.json({
      detection_id: saved.id,
      ...ml,
    });
  } catch (e) {
    console.error("❌ Explained detection failed:", e);
    res.status(500).json({
      error: "Explained detection failed",
      details: String(e),
    });
  }
});

// ============================================================================
// QUERY ENDPOINTS
// ============================================================================

// ✅ Get detections with filters (OPTIMIZED)
app.get("/api/detections", async (req, res) => {
  try {
    const {
      limit = "1000",  // ✅ Reasonable default limit
      deviceId,
      severity,
      isAnomaly,
      startDate,
      endDate,
    } = req.query;

    const where: any = {};

    if (deviceId) where.deviceId = String(deviceId);
    if (severity) where.threatSeverity = String(severity);

    if (isAnomaly !== undefined) {
      where.isAnomaly = isAnomaly === "true";
    }

    // ✅ DEFAULT: Only last 48 hours if no date range specified
    if (!startDate && !endDate) {
      const fortyEightHoursAgo = new Date();
      fortyEightHoursAgo.setHours(fortyEightHoursAgo.getHours() - 48);
      where.createdAt = { gte: fortyEightHoursAgo };
    } else if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(String(startDate));
      if (endDate) where.createdAt.lte = new Date(String(endDate));
    }

    const detections = await prisma.detection.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: parseInt(limit as string, 10),  // ✅ Apply limit
    });

    res.json(detections);
  } catch (e) {
    console.error("❌ Error fetching detections:", e);
    res.status(500).json({ error: "Failed to fetch detections" });
  }
});

// Get single detection with details
app.get("/api/detections/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }

    const detection = await prisma.detection.findUnique({ where: { id } });
    if (!detection) return res.status(404).json({ error: "Detection not found" });

    res.json(detection);
  } catch (e) {
    console.error("❌ Error fetching detection by id:", e);
    res.status(500).json({ error: "Failed to fetch detection" });
  }
});

// 🆕 Get recent anomalies with explanations
app.get("/api/anomalies/recent", async (req, res) => {
  try {
    const { limit = "10" } = req.query;

    const anomalies = await prisma.detection.findMany({
      where: { isAnomaly: true },
      orderBy: { createdAt: "desc" },
      take: parseInt(limit as string, 10),
    });

    res.json(anomalies);
  } catch (e) {
    console.error("❌ Error fetching recent anomalies:", e);
    res.status(500).json({ error: "Failed to fetch anomalies" });
  }
});

// ============================================================================
// STATISTICS ENDPOINTS
// ============================================================================

// Summary statistics
app.get("/api/stats/summary", async (_req, res) => {
  try {
    const total = await prisma.detection.count();
    const anomalies = await prisma.detection.count({ where: { isAnomaly: true } });
    const critical = await prisma.detection.count({ where: { threatSeverity: "CRITICAL" } });
    const high = await prisma.detection.count({ where: { threatSeverity: "HIGH" } });

    res.json({
      total_detections: total,
      anomaly_count: anomalies,
      normal_count: total - anomalies,
      anomaly_ratio: total ? anomalies / total : 0,
      critical_incidents: critical,
      high_incidents: high,
    });
  } catch (e) {
    console.error("❌ Error fetching stats:", e);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// 🆕 Threat distribution
app.get("/api/stats/threats", async (_req, res) => {
  try {
    const threats = await prisma.detection.groupBy({
      by: ["threatType"],
      where: { isAnomaly: true },
      _count: true,
    });

    res.json(threats);
  } catch (e) {
    console.error("❌ Error fetching threat stats:", e);
    res.status(500).json({ error: "Failed to fetch threat stats" });
  }
});

// 🆕 Timeline data (hourly)
app.get("/api/stats/timeline", async (req, res) => {
  try {
    const { hours = "24" } = req.query;
    const hoursAgo = new Date();
    hoursAgo.setHours(hoursAgo.getHours() - parseInt(hours as string, 10));

    const detections = await prisma.detection.findMany({
      where: {
        createdAt: { gte: hoursAgo },
      },
      orderBy: { createdAt: "asc" },
      select: {
        createdAt: true,
        isAnomaly: true,
        threatSeverity: true,
      },
    });

    res.json(detections);
  } catch (e) {
    console.error("❌ Error fetching timeline:", e);
    res.status(500).json({ error: "Failed to fetch timeline" });
  }
});

// ============================================================================
// 🆕 NETWORK ANALYSIS ENDPOINTS
// ============================================================================

// Analyze network behavior
app.post("/api/network/analyze", async (req, res) => {
  try {
    const { devices } = req.body;

    if (!devices || !Array.isArray(devices)) {
      return res.status(400).json({ error: "devices array required" });
    }

    const analysis = await analyzeNetwork(devices);

    console.log(
      `✅ Network analysis: ${analysis.devices_analyzed} devices | Health: ${analysis.analysis.network_summary.health_score}`
    );

    res.json(analysis);
  } catch (e) {
    console.error("❌ Network analysis failed:", e);
    res.status(500).json({ error: "Network analysis failed", details: String(e) });
  }
});

// Get current network status (from recent detections)
app.get("/api/network/status", async (req, res) => {
  try {
    const { minutes = "60" } = req.query;
    const minutesAgo = new Date();
    minutesAgo.setMinutes(minutesAgo.getMinutes() - parseInt(minutes as string, 10));

    const recentDetections = await prisma.detection.findMany({
      where: {
        createdAt: { gte: minutesAgo },
      },
      select: {
        deviceId: true,
        deviceType: true,
        isAnomaly: true,
        riskScore: true,
        rawTelemetry: true,
      },
    });

    const devices = recentDetections.map((d) => d.rawTelemetry as any);

    if (devices.length === 0) {
      return res.json({
        message: "No recent device activity",
        devices_count: 0,
      });
    }

    const analysis = await analyzeNetwork(devices);
    res.json(analysis);
  } catch (e) {
    console.error("❌ Network status failed:", e);
    res.status(500).json({ error: "Network status failed", details: String(e) });
  }
});

// ============================================================================
// START SERVER (HTTP + SOCKET.IO)
// ============================================================================

const PORT = process.env.PORT || 5000;

// Create HTTP server so Socket.IO can attach
const httpServer = http.createServer(app);

// Init WebSocket server
initSocket(httpServer);

// Start MQTT subscriber (will emit via sockets if you wired it)
startMqttSubscriber();

httpServer.listen(PORT, () => {
  console.log(` Backend server running on http://localhost:${PORT}`);
  console.log(` ML Engine URL: ${process.env.ML_BASE_URL || "http://localhost:8000"}`);
  console.log(" Endpoints:");
  console.log("  - POST /api/telemetry (standard detection)");
  console.log("  - POST /api/telemetry/explained (with SHAP) ");
  console.log("  - POST /api/network/analyze (network analysis) ");
  console.log("  - GET  /api/network/status (current network) ");
  console.log("  - GET  /api/detections (optimized with 48h default) ");
  console.log("  - GET  /api/stats/summary");
  console.log("  - GET  /api/stats/threats ");
  console.log("  - GET  /api/stats/timeline ");
  console.log("🗑️  Auto-cleanup: Running every hour (deletes data >48h)");
});