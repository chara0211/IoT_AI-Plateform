import { NextResponse } from "next/server";

const BACKEND_HTTP =
  process.env.NEXT_PUBLIC_ML_ENGINE_HTTP_URL || "http://localhost:8000";

export async function POST(req: Request) {
  try {
    const body = await req.json();

    const query = String(body?.query ?? "").trim();
    const minutes = Number(body?.minutes ?? 60);
    const top_k = Number(body?.top_k ?? 10);
    const include_raw = Boolean(body?.include_raw ?? false);

    if (!query) {
      return NextResponse.json({ error: "query required" }, { status: 400 });
    }

    // ✅ ml-engine includes agent router under /api
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 45_000);

    const r = await fetch(`${BACKEND_HTTP}/api/agent/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, minutes, top_k, include_raw }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    const text = await r.text();
    return new NextResponse(text, {
      status: r.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e: any) {
    const msg =
      e?.name === "AbortError" ? "Backend timeout" : (e?.message ?? "server error");
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
