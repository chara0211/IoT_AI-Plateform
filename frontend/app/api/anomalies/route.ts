import { NextResponse } from "next/server";

const BACKEND_HTTP =
  process.env.NEXT_PUBLIC_ML_ENGINE_HTTP_URL || "http://localhost:8000";

export async function GET(req: Request) {
  try {
    const url = new URL(req.url);
    const qs = url.searchParams.toString();

    const r = await fetch(`${BACKEND_HTTP}/api/anomalies?${qs}`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
    });

    const text = await r.text();
    return new NextResponse(text, {
      status: r.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message ?? "server error" }, { status: 500 });
  }
}
