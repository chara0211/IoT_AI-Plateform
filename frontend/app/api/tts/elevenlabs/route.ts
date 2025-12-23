import { NextResponse } from "next/server";

const ELEVEN_API_KEY = process.env.ELEVENLABS_API_KEY || "";
const DEFAULT_VOICE_ID = process.env.ELEVENLABS_VOICE_ID || "";

export async function POST(req: Request) {
  try {
    if (!ELEVEN_API_KEY) {
      return NextResponse.json({ error: "ELEVENLABS_API_KEY missing" }, { status: 500 });
    }
    if (!DEFAULT_VOICE_ID) {
      return NextResponse.json({ error: "ELEVENLABS_VOICE_ID missing" }, { status: 500 });
    }

    const body = await req.json();
    const text = String(body?.text ?? "").trim();
    const voice_id = String(body?.voice_id ?? DEFAULT_VOICE_ID).trim();

    if (!text) return NextResponse.json({ error: "text required" }, { status: 400 });

    const r = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voice_id}/stream`, {
      method: "POST",
      headers: {
        "xi-api-key": ELEVEN_API_KEY,
        "Content-Type": "application/json",
        "Accept": "audio/mpeg",
      },
      body: JSON.stringify({
        text,
        voice_settings: {
          stability: 0.45,
          similarity_boost: 0.8,
          style: 0.2,
          use_speaker_boost: true,
        },
      }),
    });

    if (!r.ok) {
      const err = await r.text();
      return NextResponse.json({ error: err }, { status: r.status });
    }

    // Return audio stream
    return new NextResponse(r.body, {
      status: 200,
      headers: {
        "Content-Type": "audio/mpeg",
        "Cache-Control": "no-store",
      },
    });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message ?? "server error" }, { status: 500 });
  }
}
