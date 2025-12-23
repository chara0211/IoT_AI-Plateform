from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List, Optional, Literal, Tuple
from datetime import datetime
import json
import os
import re
import asyncio

import asyncpg
from dotenv import load_dotenv

from llm_client import llm_generate, LLMError

# Load .env (works even if you run app.py from ml-engine root)
load_dotenv()

router = APIRouter(prefix="/agent", tags=["agent"])

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

# Choose provider (default: gemini if key exists, else openai)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "").strip().lower()
if not LLM_PROVIDER:
    LLM_PROVIDER = "gemini" if GEMINI_API_KEY else "openai"

# IMPORTANT: use a current model id by default
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL missing in .env")

_POOL: Optional[asyncpg.pool.Pool] = None
_POOL_LOCK = asyncio.Lock()

# -----------------------------------------------------------------------------
# Request body
# -----------------------------------------------------------------------------
class AskBody(BaseModel):
    query: str
    minutes: Optional[int] = 60     # live window
    top_k: Optional[int] = 10       # top suspects
    include_raw: Optional[bool] = False


# -----------------------------------------------------------------------------
# DB pool
# -----------------------------------------------------------------------------
async def get_pool() -> asyncpg.pool.Pool:
    global _POOL

    # NOTE: avoid touching private _closed unless necessary
    if _POOL is not None:
        return _POOL

    async with _POOL_LOCK:
        if _POOL is None:
            _POOL = await asyncpg.create_pool(
                dsn=DATABASE_URL,
                min_size=1,
                max_size=5,
                command_timeout=30,
                max_inactive_connection_lifetime=60,
            )
            async with _POOL.acquire() as conn:
                await conn.execute("SELECT 1")

    return _POOL


async def fetch(sql: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetch(sql, *args)


async def fetchrow(sql: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(sql, *args)


# -----------------------------------------------------------------------------
# Telemetry comm_target extractor from Prisma rawTelemetry JSON
# -----------------------------------------------------------------------------
COMM_TARGET_EXPR = """
COALESCE(
  "rawTelemetry"->>'comm_target',
  "rawTelemetry"->>'commTarget',
  "rawTelemetry"->>'target',
  "rawTelemetry"->>'dst',
  "rawTelemetry"->>'destination',
  "rawTelemetry"->>'dest',
  "rawTelemetry"->>'to',
  "rawTelemetry"->>'ip_dst',
  "rawTelemetry"->>'device_target'
)
"""


# -----------------------------------------------------------------------------
# Tooling (real DB)
# -----------------------------------------------------------------------------
async def tool_top_suspicious(minutes: int, limit: int) -> List[Dict[str, Any]]:
    q = """
    SELECT
      "deviceId", "deviceType", "riskScore", "threatType", "threatSeverity",
      "confidenceScore", "createdAt", "explanation"
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
      AND "isAnomaly" = TRUE
    ORDER BY "riskScore" DESC, "createdAt" DESC
    LIMIT $2
    """
    rows = await fetch(q, minutes, limit)
    out = []
    for r in rows:
        out.append({
            "deviceId": r["deviceId"],
            "deviceType": r["deviceType"],
            "riskScore": int(r["riskScore"]),
            "threatType": r["threatType"],
            "threatSeverity": r["threatSeverity"],
            "confidenceScore": float(r["confidenceScore"]),
            "createdAt": r["createdAt"].isoformat(),
            "explanation": (r["explanation"] or "")[:240],
        })
    return out


async def tool_top_suspicious_filtered(minutes: int, limit: int, threat_type: str) -> List[Dict[str, Any]]:
    q = """
    SELECT
      "deviceId", "deviceType", "riskScore", "threatType", "threatSeverity",
      "confidenceScore", "createdAt", "explanation"
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
      AND "isAnomaly" = TRUE
      AND "threatType" = $3
    ORDER BY "riskScore" DESC, "createdAt" DESC
    LIMIT $2
    """
    rows = await fetch(q, minutes, limit, threat_type)
    out = []
    for r in rows:
        out.append({
            "deviceId": r["deviceId"],
            "deviceType": r["deviceType"],
            "riskScore": int(r["riskScore"]),
            "threatType": r["threatType"],
            "threatSeverity": r["threatSeverity"],
            "confidenceScore": float(r["confidenceScore"]),
            "createdAt": r["createdAt"].isoformat(),
            "explanation": (r["explanation"] or "")[:240],
        })
    return out


async def tool_network_stats(minutes: int) -> Dict[str, Any]:
    q = """
    SELECT
      COUNT(DISTINCT "deviceId") AS nodes,
      COUNT(DISTINCT CASE WHEN "isAnomaly" = TRUE THEN "deviceId" END) AS anomalous,
      COUNT(DISTINCT CASE WHEN "threatSeverity" = 'CRITICAL' THEN "deviceId" END) AS critical
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
    """
    r = await fetchrow(q, minutes)
    return {
        "nodes": int((r and r["nodes"]) or 0),
        "anomalous": int((r and r["anomalous"]) or 0),
        "critical": int((r and r["critical"]) or 0),
    }


async def tool_network_links(minutes: int) -> int:
    q = f"""
    SELECT
      COUNT(DISTINCT ("deviceId" || '->' || ({COMM_TARGET_EXPR}))) AS links
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
      AND ({COMM_TARGET_EXPR}) IS NOT NULL
      AND ({COMM_TARGET_EXPR}) <> ''
    """
    r = await fetchrow(q, minutes)
    return int((r and r["links"]) or 0)


async def tool_attack_patterns(minutes: int) -> List[Dict[str, Any]]:
    q = """
    SELECT
      "threatType",
      COUNT(*) AS cnt,
      COUNT(DISTINCT "deviceId") AS devices,
      AVG("riskScore") AS avg_risk,
      MAX("riskScore") AS max_risk
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
      AND "isAnomaly" = TRUE
    GROUP BY "threatType"
    ORDER BY cnt DESC
    LIMIT 10
    """
    rows = await fetch(q, minutes)
    out = []
    for r in rows:
        out.append({
            "threatType": r["threatType"],
            "count": int(r["cnt"]),
            "affectedDevices": int(r["devices"]),
            "avgRisk": round(float(r["avg_risk"] or 0.0), 2),
            "maxRisk": int(r["max_risk"] or 0),
        })
    return out


async def tool_device_focus(device_id: str, minutes: int, include_raw: bool) -> Dict[str, Any]:
    q = """
    SELECT
      "createdAt", "riskScore", "threatType", "threatSeverity", "isAnomaly",
      "confidenceScore", "deviceType", "explanation", "rawTelemetry"
    FROM "Detection"
    WHERE "deviceId" = $1
      AND "createdAt" >= NOW() - ($2::int * INTERVAL '1 minute')
    ORDER BY "createdAt" DESC
    LIMIT 20
    """
    rows = await fetch(q, device_id, minutes)

    recent = []
    for r in rows[:10]:
        obj = {
            "createdAt": r["createdAt"].isoformat(),
            "riskScore": int(r["riskScore"]),
            "threatType": r["threatType"],
            "threatSeverity": r["threatSeverity"],
            "isAnomaly": bool(r["isAnomaly"]),
            "confidenceScore": float(r["confidenceScore"]),
            "explanation": (r["explanation"] or "")[:240],
        }
        if include_raw:
            obj["rawTelemetry"] = r["rawTelemetry"]
        recent.append(obj)

    qn = f"""
    SELECT DISTINCT ({COMM_TARGET_EXPR}) AS neighbor
    FROM "Detection"
    WHERE "deviceId" = $1
      AND "createdAt" >= NOW() - ($2::int * INTERVAL '1 minute')
      AND ({COMM_TARGET_EXPR}) IS NOT NULL
      AND ({COMM_TARGET_EXPR}) <> ''
    LIMIT 30
    """
    nei = await fetch(qn, device_id, minutes)
    neighbors = [x["neighbor"] for x in nei if x.get("neighbor")]

    return {
        "deviceId": device_id,
        "deviceType": (rows[0]["deviceType"] if rows else None),
        "recentDetections": recent,
        "neighbors": neighbors[:20],
    }


async def tool_botnet_candidates(minutes: int) -> Dict[str, Any]:
    """
    Simple heuristic: suspicious C2 if anomalous with high risk and talks to many distinct targets.
    """
    q = f"""
    SELECT
      "deviceId",
      MAX("riskScore") AS max_risk,
      COUNT(DISTINCT ({COMM_TARGET_EXPR})) AS out_degree
    FROM "Detection"
    WHERE "createdAt" >= NOW() - ($1::int * INTERVAL '1 minute')
      AND "isAnomaly" = TRUE
      AND "riskScore" >= 70
      AND ({COMM_TARGET_EXPR}) IS NOT NULL
      AND ({COMM_TARGET_EXPR}) <> ''
    GROUP BY "deviceId"
    HAVING COUNT(DISTINCT ({COMM_TARGET_EXPR})) >= 3
    ORDER BY MAX("riskScore") DESC, COUNT(DISTINCT ({COMM_TARGET_EXPR})) DESC
    LIMIT 5
    """
    rows = await fetch(q, minutes)
    candidates = []
    for r in rows:
        max_risk = int(r["max_risk"] or 0)
        out_deg = int(r["out_degree"] or 0)
        score = min(1.0, (max_risk / 100.0) * 0.7 + min(out_deg / 10.0, 1.0) * 0.3)
        candidates.append({
            "deviceId": r["deviceId"],
            "score": round(score, 3),
            "outDegree": out_deg,
            "riskScore": max_risk,
        })

    return {
        "botnetDetected": len(candidates) > 0,
        "c2Candidates": candidates,
        "confidence": 0.85 if candidates else 0.0,
    }


# -----------------------------------------------------------------------------
# Intent detection (FIX for “same response” problem)
# -----------------------------------------------------------------------------
Intent = Literal["device", "ddos", "botnet", "global"]
DEVICE_RE = re.compile(r"\b(?:camera|sensor|smart_light|thermostat)_[0-9]+\b", re.IGNORECASE)

def extract_device_id(query: str) -> Optional[str]:
    m = DEVICE_RE.search(query or "")
    return m.group(0) if m else None

def detect_intent(query: str) -> Tuple[Intent, Optional[str]]:
    q = (query or "").strip().lower()

    did = extract_device_id(q)
    if did:
        return "device", did

    if any(k in q for k in ["ddos", "flood"]):
        return "ddos", None

    if any(k in q for k in ["botnet", "c2", "command", "control"]):
        return "botnet", None

    return "global", None


# -----------------------------------------------------------------------------
# Prompt
# -----------------------------------------------------------------------------
SYSTEM_PROMPT = """
You are a senior SOC analyst for an IoT security platform.
Write concise, professional security analysis with clear reasoning.
No emojis.

Rules:
- Use ONLY the provided JSON context.
- Match the user's language.
- If intent == "device": focus ONLY on the device; do not output global summary.
- If intent == "ddos": focus on DDoS evidence, impacted devices, mitigations.
- If intent == "botnet": focus on botnet/C2 evidence and next investigation steps.
- If intent == "global": give full SOC summary.
"""

def build_user_prompt(query: str, context: Dict[str, Any]) -> str:
    return f"""
User query:
{query}

Context JSON:
{json.dumps(context, ensure_ascii=False, indent=2)}
"""


def fallback_answer(query: str, ctx: Dict[str, Any]) -> str:
    intent = ctx.get("intent", "global")
    lines = []
    lines.append(f"SOC analysis based on live database window ({ctx.get('time_window_minutes')} minutes).")
    lines.append("")

    # Global fallback
    if intent == "global":
        gs = ctx.get("graphStats", {})
        sus = ctx.get("suspiciousDevices", [])
        bot = ctx.get("botnet", {})

        lines.append("Network state:")
        lines.append(f"- Devices observed: {gs.get('nodes', 0)}")
        lines.append(f"- Devices with anomalies: {gs.get('anomalous', 0)}")
        lines.append(f"- Devices marked CRITICAL: {gs.get('critical', 0)}")
        lines.append(f"- Observed connections: {gs.get('links', 0)}")
        lines.append("")

        lines.append("Top suspicious devices:")
        if sus:
            for i, d in enumerate(sus[:5], 1):
                lines.append(f"{i}. {d['deviceId']} | risk={d['riskScore']} | {d['threatType']} | {d['threatSeverity']} | {d['createdAt']}")
        else:
            lines.append("No anomalies found in the selected window.")
        lines.append("")

        lines.append("Botnet assessment:")
        if bot.get("botnetDetected"):
            lines.append(f"- Botnet suspected (confidence {bot.get('confidence')}).")
            for c in bot.get("c2Candidates", [])[:3]:
                lines.append(f"- Candidate C2: {c['deviceId']} | score={c['score']} | outDegree={c['outDegree']} | risk={c['riskScore']}")
        else:
            lines.append("- No clear botnet evidence in the selected window (based on connection heuristic).")
        lines.append("")

        lines.append("Recommended actions:")
        lines.append("1. Investigate the highest risk devices first. Isolate CRITICAL, restrict egress for HIGH.")
        lines.append("2. Validate telemetry fields and ensure comm_target is present to enable topology reconstruction.")
        lines.append("3. Correlate with authentication failures, DNS/HTTP egress logs, and rate limiting signals.")
        return "\n".join(lines)

    # Device fallback
    if intent == "device":
        focus = ctx.get("deviceFocus") or {}
        lines.append("Device focus:")
        lines.append(f"- Device: {focus.get('deviceId')} ({focus.get('deviceType') or 'Unknown'})")
        for e in (focus.get("recentDetections") or [])[:8]:
            lines.append(f"  - {e['createdAt']} | risk={e['riskScore']} | {e['threatType']} | {e['threatSeverity']}")
        if focus.get("neighbors"):
            lines.append(f"- Observed targets/neighbors: {', '.join(focus['neighbors'][:10])}")
        return "\n".join(lines)

    # DDoS fallback
    if intent == "ddos":
        dd = ctx.get("ddos") or {}
        top = dd.get("topDevices") or []
        lines.append("DDoS activity:")
        if top:
            for i, d in enumerate(top[:8], 1):
                lines.append(f"{i}. {d['deviceId']} | risk={d['riskScore']} | {d['threatSeverity']} | {d['createdAt']}")
        else:
            lines.append("No DDoS detections found in this window.")
        return "\n".join(lines)

    # Botnet fallback
    bot = ctx.get("botnet") or {}
    lines.append("Botnet assessment:")
    if bot.get("botnetDetected"):
        lines.append(f"- Botnet suspected (confidence {bot.get('confidence')}).")
        for c in bot.get("c2Candidates", [])[:5]:
            lines.append(f"- Candidate C2: {c['deviceId']} | score={c['score']} | outDegree={c['outDegree']} | risk={c['riskScore']}")
    else:
        lines.append("- No clear botnet evidence in the selected window.")
    return "\n".join(lines)


def strip_emojis(text: str) -> str:
    return re.sub(r"[\U00010000-\U0010ffff]", "", text)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@router.post("/ask")
async def ask(body: AskBody):
    query = (body.query or "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="query required")

    minutes = int(body.minutes or 60)
    top_k = int(body.top_k or 10)
    include_raw = bool(body.include_raw)

    intent, device_id = detect_intent(query)

    ctx: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "time_window_minutes": minutes,
        "intent": intent,
    }
    tools_used: List[str] = []

    # DEVICE intent
    if intent == "device" and device_id:
        device_focus = await tool_device_focus(device_id, minutes, include_raw)
        tools_used.append("db.device_focus")

        # small context only
        gs = await tool_network_stats(minutes)
        tools_used.append("db.network_stats")

        ctx.update({
            "deviceFocus": device_focus,
            "graphStats": gs,
        })

    # DDoS intent
    elif intent == "ddos":
        top_ddos = await tool_top_suspicious_filtered(minutes, top_k, "DDoS Attack")
        tools_used.append("db.top_suspicious_filtered")

        patterns = await tool_attack_patterns(minutes)
        tools_used.append("db.attack_patterns")

        ctx.update({
            "ddos": {
                "topDevices": top_ddos,
                "patterns": patterns,
            }
        })

    # Botnet intent
    elif intent == "botnet":
        botnet = await tool_botnet_candidates(minutes)
        tools_used.append("db.botnet_candidates")

        links = await tool_network_links(minutes)
        tools_used.append("db.network_links")

        gs = await tool_network_stats(minutes)
        tools_used.append("db.network_stats")

        ctx.update({
            "botnet": botnet,
            "graphStats": {**gs, "links": links},
        })

    # Global intent (default)
    else:
        suspicious = await tool_top_suspicious(minutes, top_k)
        gs = await tool_network_stats(minutes)
        links = await tool_network_links(minutes)
        patterns_24h = await tool_attack_patterns(1440)
        botnet = await tool_botnet_candidates(minutes)

        tools_used.extend([
            "db.top_suspicious",
            "db.network_stats",
            "db.network_links",
            "db.attack_patterns_24h",
            "db.botnet_candidates",
        ])

        ctx.update({
            "graphStats": {**gs, "links": links},
            "suspiciousDevices": suspicious,
            "botnet": botnet,
            "attackPatterns24h": patterns_24h,
            "deviceFocus": None,
        })

    cfg = {
        "gemini_api_key": GEMINI_API_KEY,
        "gemini_model": GEMINI_MODEL,
        "openai_api_key": OPENAI_API_KEY,
        "openai_model": OPENAI_MODEL,
    }

    try:
        answer = await llm_generate(
            provider=LLM_PROVIDER,
            cfg=cfg,
            system=SYSTEM_PROMPT,
            user=build_user_prompt(query, ctx),
        )
        answer = strip_emojis(answer).strip()
        return {"answer": answer, "context": ctx, "tools_used": tools_used, "mode": LLM_PROVIDER}

    except LLMError as e:
        return {
            "answer": fallback_answer(query, ctx),
            "context": ctx,
            "tools_used": tools_used,
            "mode": f"{LLM_PROVIDER}_fallback",
            "llm_error": str(e),
        }


@router.get("/health")
async def health():
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")
        return {
            "status": "healthy",
            "db": "connected",
            "llm_provider": LLM_PROVIDER,
            "gemini_model": GEMINI_MODEL,
            "openai_model": OPENAI_MODEL,
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
