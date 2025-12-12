// backend/src/mqtt/subscriber.ts
import mqtt from "mqtt";
import { PrismaClient } from "@prisma/client";
import { detectAnomalyFromML, analyzeNetwork } from "../services/mlClient";
import { io } from "../realtime/socket";

const prisma = new PrismaClient();

const MQTT_URL = process.env.MQTT_URL || "mqtt://localhost:1883";
const MQTT_TOPIC = process.env.MQTT_TOPIC || "devices/+/telemetry";

// store recent telemetry for network analysis batching
const recentTelemetry: any[] = [];
const MAX_BUFFER = 200;

// ----------------------------------------
// Simple throttle (no lodash needed)
// ----------------------------------------
function throttleFn<T extends (...args: any[]) => void>(fn: T, waitMs: number) {
  let last = 0;
  let timer: NodeJS.Timeout | null = null;

  return (...args: Parameters<T>) => {
    const now = Date.now();
    const remaining = waitMs - (now - last);

    if (remaining <= 0) {
      last = now;
      fn(...args);
      return;
    }

    if (!timer) {
      timer = setTimeout(() => {
        last = Date.now();
        timer = null;
        fn(...args);
      }, remaining);
    }
  };
}

// throttle network analysis so you don’t call ML too often
const emitNetworkUpdate = throttleFn(async () => {
  try {
    if (!io) return; // socket not initialized
    if (recentTelemetry.length < 3) return;

    const snapshot = recentTelemetry.slice(-80); // last 80 messages
    const analysis = await analyzeNetwork(snapshot);

    io.emit("network:update", analysis);
  } catch (e) {
    console.error("❌ network analysis emit failed:", e);
  }
}, 5000); // every 5s max

export function startMqttSubscriber() {
  const client = mqtt.connect(MQTT_URL);

  client.on("connect", () => {
    console.log("✅ MQTT connected:", MQTT_URL);
    client.subscribe(MQTT_TOPIC, () => {
      console.log("✅ Subscribed to:", MQTT_TOPIC);
    });
  });

  client.on("message", async (_topic, message) => {
    try {
      const telemetry = JSON.parse(message.toString());

      // keep telemetry buffer (for network analysis)
      recentTelemetry.push(telemetry);
      if (recentTelemetry.length > MAX_BUFFER) recentTelemetry.shift();

      // call ML detection
      const ml = await detectAnomalyFromML(telemetry);

      // save in DB
      const saved = await prisma.detection.create({
        data: {
          deviceId: ml.device_id,
          deviceType: telemetry.device_type ?? null,
          isAnomaly: ml.is_anomaly,
          confidenceScore: ml.confidence_score,
          riskScore: ml.risk_score,
          threatType: ml.threat_type,
          threatSeverity: ml.threat_severity,
          explanation: ml.explanation,
          modelVotes: ml.model_votes,
          recommendedActions: ml.recommended_actions,
          rawTelemetry: telemetry,
        },
      });

      // 🔥 emit live detection event
      if (io) {
        io.emit("detection:new", {
          id: saved.id,
          deviceId: saved.deviceId,
          deviceType: saved.deviceType,
          isAnomaly: saved.isAnomaly,
          confidenceScore: saved.confidenceScore,
          riskScore: saved.riskScore,
          threatType: saved.threatType,
          threatSeverity: saved.threatSeverity,
          explanation: saved.explanation,
          rawTelemetry: saved.rawTelemetry,
          createdAt: saved.createdAt,
        });
      }

      // 🔥 emit network analysis (throttled)
      emitNetworkUpdate();
    } catch (err) {
      console.error("❌ MQTT message error:", err);
    }
  });
}
