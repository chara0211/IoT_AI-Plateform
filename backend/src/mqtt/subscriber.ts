// backend/src/mqtt/subscriber.ts
import mqtt from "mqtt";
import { PrismaClient } from "@prisma/client";
import { detectAnomalyFromML, analyzeNetwork } from "../services/mlClient";
import { io } from "../realtime/socket";

const prisma = new PrismaClient();

const MQTT_URL = process.env.MQTT_URL || "mqtt://localhost:1883";
const MQTT_TOPIC = process.env.MQTT_TOPIC || "devices/+/telemetry";

// ============================================================================
// 1) DB BATCH BUFFER (createMany)
// ============================================================================
const dbBuffer: any[] = [];
const DB_BATCH_SIZE = Number(process.env.DB_BATCH_SIZE || 100); // 100 rows/insert
const DB_FLUSH_MS = Number(process.env.DB_FLUSH_MS || 1000);    // flush every 1s
let flushInProgress = false;

async function flushDbBuffer() {
  if (flushInProgress) return;
  if (dbBuffer.length === 0) return;

  flushInProgress = true;
  try {
    const chunk = dbBuffer.splice(0, DB_BATCH_SIZE);

    await prisma.detection.createMany({
      data: chunk,
    });
  } catch (e) {
    console.error("❌ DB batch insert failed:", e);
  } finally {
    flushInProgress = false;
  }
}

// flush on interval
setInterval(() => {
  flushDbBuffer();
}, DB_FLUSH_MS);

// also flush when stopping
process.on("SIGINT", async () => {
  console.log("🛑 SIGINT: flushing DB buffer...");
  await flushDbBuffer();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  console.log("🛑 SIGTERM: flushing DB buffer...");
  await flushDbBuffer();
  process.exit(0);
});

// ============================================================================
// 2) NETWORK ANALYSIS BUFFER (already in your code)
// ============================================================================
const recentTelemetry: any[] = [];
const MAX_TELEMETRY_BUFFER = Number(process.env.MAX_TELEMETRY_BUFFER || 200);

// throttle helper
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
    if (!io) return;
    if (recentTelemetry.length < 3) return;

    const snapshot = recentTelemetry.slice(-80);
    const analysis = await analyzeNetwork(snapshot);
    io.emit("network:update", analysis);
  } catch (e) {
    console.error("❌ network analysis emit failed:", e);
  }
}, 5000);

// ============================================================================
// 3) CONCURRENCY LIMITER (WHERE TO ADD YOUR QUEUE/PUMP)
// ============================================================================
let inFlight = 0;
const MAX_IN_FLIGHT = Number(process.env.MAX_IN_FLIGHT || 10);
const queue: Buffer[] = [];

async function handleMessage(buf: Buffer) {
  const telemetry = JSON.parse(buf.toString());

  // keep telemetry buffer for network analysis
  recentTelemetry.push(telemetry);
  if (recentTelemetry.length > MAX_TELEMETRY_BUFFER) recentTelemetry.shift();

  // ML call
  const ml = await detectAnomalyFromML(telemetry);

  // OPTIONAL: store raw only for anomaly/high risk (reduces DB size a lot)
  const storeRaw = ml.is_anomaly || ml.risk_score >= 40;

  // push to DB buffer (batch insert later)
  dbBuffer.push({
    deviceId: ml.device_id,
    deviceType: telemetry.device_type ?? null,
    isAnomaly: ml.is_anomaly,
    confidenceScore: ml.confidence_score,
    riskScore: ml.risk_score,
    threatType: ml.threat_type,
    threatSeverity: ml.threat_severity,
    explanation: ml.explanation,
    modelVotes: ml.model_votes,
    recommendedActions: ml.recommended_actions, // Json in Prisma schema
    rawTelemetry: storeRaw ? telemetry : null,
  });

  // flush early if buffer grows too big
  if (dbBuffer.length >= DB_BATCH_SIZE * 3) {
    flushDbBuffer();
  }

  // live websocket emit (don’t wait for DB)
  if (io) {
    io.emit("detection:new", {
      id: `${Date.now()}-${ml.device_id}`, // temp id
      deviceId: ml.device_id,
      deviceType: telemetry.device_type ?? null,
      isAnomaly: ml.is_anomaly,
      confidenceScore: ml.confidence_score,
      riskScore: ml.risk_score,
      threatType: ml.threat_type,
      threatSeverity: ml.threat_severity,
      explanation: ml.explanation,
      rawTelemetry: storeRaw ? telemetry : null,
      createdAt: new Date(),
    });
  }

  // throttled network update
  emitNetworkUpdate();
}

async function pump() {
  while (inFlight < MAX_IN_FLIGHT && queue.length > 0) {
    const msg = queue.shift()!;
    inFlight++;

    handleMessage(msg)
      .catch((e) => console.error("❌ handleMessage failed:", e))
      .finally(() => {
        inFlight--;
        pump();
      });
  }
}

// ============================================================================
// START MQTT SUBSCRIBER
// ============================================================================
export function startMqttSubscriber() {
  const client = mqtt.connect(MQTT_URL);

  client.on("connect", () => {
    console.log(" MQTT connected:", MQTT_URL);
    client.subscribe(MQTT_TOPIC, () => console.log("✅ Subscribed to:", MQTT_TOPIC));
  });

  client.on("message", async (_topic, message) => {
    //  THIS IS WHERE YOU ADD IT:
    queue.push(message);
    pump();
  });
}
