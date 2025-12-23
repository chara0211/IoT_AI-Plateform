"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Mic,
  MicOff,
  Send,
  Loader2,
  Bot,
  Volume2,
  VolumeX,
  Pause,
  Play,
  Square,
} from "lucide-react";

type AgentResponse = {
  answer: string;
  context?: {
    intent?: "device" | "ddos" | "botnet" | "global";
    time_window_minutes?: number;
    suspiciousDevices?: Array<{
      deviceId: string;
      riskScore?: number;
      threatType?: string;
      threatSeverity?: string;
    }>;
    botnet?: any;
    graphStats?: any;
    deviceFocus?: any;
    ddos?: any;
  };
  tools_used?: string[];
  mode?: string;
  llm_error?: string;
};

type Msg = {
  id: string;
  role: "user" | "assistant";
  text: string;
  ts: number;
};

declare global {
  interface Window {
    webkitSpeechRecognition?: any;
    SpeechRecognition?: any;
  }
}

export default function SocAgentVoice() {
  const [messages, setMessages] = useState<Msg[]>([
    {
      id: "hello",
      role: "assistant",
      text:
        "Salut ! Exemples:\n- “Explique l’activité DDoS détectée”\n- “Analyse camera_01 en détail”\n- “Y a-t-il un botnet ?”",
      ts: Date.now(),
    },
  ]);

  const [input, setInput] = useState("");
  const [listening, setListening] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const [loading, setLoading] = useState(false);
  const [ttsLoading, setTtsLoading] = useState(false);

  // Controls
  const [minutes, setMinutes] = useState<number>(1440);
  const [topK, setTopK] = useState<number>(10);
  const [includeRaw, setIncludeRaw] = useState<boolean>(false);

  // Speech recognition refs
  const recognitionRef = useRef<any>(null);
  const finalTranscriptRef = useRef<string>("");

  // UI refs
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // Audio refs (ElevenLabs)
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const audioUrlRef = useRef<string>(""); // keep last blob url for cleanup
  const [audioState, setAudioState] = useState<"idle" | "playing" | "paused">("idle");

  const canUseSpeech = useMemo(() => {
    return typeof window !== "undefined" && (!!window.SpeechRecognition || !!window.webkitSpeechRecognition);
  }, []);

  // --- Audio helpers
  const stopAudio = () => {
    const a = audioRef.current;
    if (!a) return;
    a.pause();
    a.currentTime = 0;
    setAudioState("idle");
  };

  const pauseAudio = () => {
    const a = audioRef.current;
    if (!a) return;
    a.pause();
    setAudioState("paused");
  };

  const resumeAudio = async () => {
    const a = audioRef.current;
    if (!a) return;
    try {
      await a.play();
      setAudioState("playing");
    } catch {
      // ignore autoplay restrictions etc.
    }
  };

  const setAndPlayBlob = async (blob: Blob) => {
    // cleanup old blob URL
    if (audioUrlRef.current) {
      URL.revokeObjectURL(audioUrlRef.current);
      audioUrlRef.current = "";
    }

    const url = URL.createObjectURL(blob);
    audioUrlRef.current = url;

    const a = audioRef.current;
    if (!a) return;

    a.src = url;
    a.currentTime = 0;

    try {
      await a.play();
      setAudioState("playing");
    } catch {
      // if autoplay blocked, keep ready
      setAudioState("paused");
    }
  };

  // --- ElevenLabs TTS (server route)
  const speakElevenLabs = async (text: string) => {
    if (!voiceEnabled) return;

    // Option: avoid huge texts
    const t = (text || "").trim();
    if (!t) return;

    setTtsLoading(true);
    try {
      // stop previous audio before speaking new
      stopAudio();

      const r = await fetch("/api/tts/elevenlabs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: t }),
      });

      if (!r.ok) {
        const j = await r.json().catch(() => null);
        throw new Error(j?.error ?? "TTS error");
      }

      const blob = await r.blob(); // audio/mpeg
      await setAndPlayBlob(blob);
    } finally {
      setTtsLoading(false);
    }
  };

  // ---- STT init
  useEffect(() => {
    if (!canUseSpeech) return;

    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    const rec = new SR();
    rec.continuous = true;
    rec.interimResults = true;
    rec.lang = "fr-FR";

    rec.onresult = (event: any) => {
      let interim = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcript = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          finalTranscriptRef.current += transcript + " ";
        } else {
          interim += transcript;
        }
      }
      setInput((finalTranscriptRef.current + interim).trim());
    };

    rec.onerror = () => setListening(false);
    rec.onend = () => setListening(false);

    recognitionRef.current = rec;
  }, [canUseSpeech]);

  const startListening = () => {
    if (!recognitionRef.current) return;
    finalTranscriptRef.current = "";
    setInput("");
    setListening(true);
    recognitionRef.current.start();
  };

  const stopListening = () => {
    if (!recognitionRef.current) return;
    setListening(false);
    recognitionRef.current.stop();
  };

  const addMsg = (role: Msg["role"], text: string) => {
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}-${Math.random()}`, role, text, ts: Date.now() },
    ]);
  };

  // Auto-scroll on new message
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [messages, loading]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopAudio();
      if (audioUrlRef.current) URL.revokeObjectURL(audioUrlRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const askAgent = async (q: string) => {
    const query = q.trim();
    if (!query) return;

    // stop any playing audio as soon as new request starts
    stopAudio();

    addMsg("user", query);
    setLoading(true);

    try {
      const res = await fetch("/api/agent/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query,
          minutes,
          top_k: topK,
          include_raw: includeRaw,
        }),
      });

      const data = (await res.json()) as any;

      if (!res.ok) {
        throw new Error(data?.error ?? data?.detail ?? "Agent error");
      }

      const parsed = data as AgentResponse;
      const answer = parsed.answer || "Je n'ai pas pu générer une réponse.";

      addMsg("assistant", answer);

      // ✅ ElevenLabs voice
      await speakElevenLabs(answer);
    } catch (e: any) {
      addMsg("assistant", `❌ Erreur agent: ${e?.message ?? "unknown"}`);
    } finally {
      setLoading(false);
    }
  };

  const onSend = async () => {
    const q = input;
    setInput("");
    finalTranscriptRef.current = "";
    if (listening) stopListening();
    await askAgent(q);
  };

  return (
    <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-white/10 bg-slate-900/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-cyan-500/20 border border-cyan-500/30 grid place-items-center">
            <Bot className="w-5 h-5 text-cyan-300" />
          </div>
          <div>
            <div className="text-white font-bold">SOC Agent + Voice (ElevenLabs)</div>
            <div className="text-xs text-gray-400">STT → Agent → ElevenLabs TTS</div>
          </div>
        </div>

        <button
          onClick={() => setVoiceEnabled((v) => !v)}
          className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-colors"
          title={voiceEnabled ? "Désactiver la voix" : "Activer la voix"}
        >
          {voiceEnabled ? (
            <Volume2 className="w-4 h-4 text-gray-200" />
          ) : (
            <VolumeX className="w-4 h-4 text-gray-200" />
          )}
        </button>
      </div>

      {/* Controls */}
      <div className="px-4 py-3 border-b border-white/10 bg-slate-900/30">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
            className="px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-sm text-white"
            title="Time window"
          >
            <option value={60}>Last 60 min</option>
            <option value={360}>Last 6h</option>
            <option value={720}>Last 12h</option>
            <option value={1440}>Last 24h</option>
            <option value={10080}>Last 7d</option>
          </select>

          <select
            value={topK}
            onChange={(e) => setTopK(Number(e.target.value))}
            className="px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-sm text-white"
            title="Top K"
          >
            <option value={5}>Top 5</option>
            <option value={10}>Top 10</option>
            <option value={20}>Top 20</option>
          </select>

          <label className="flex items-center gap-2 text-xs text-gray-300 select-none">
            <input
              type="checkbox"
              checked={includeRaw}
              onChange={(e) => setIncludeRaw(e.target.checked)}
              className="accent-cyan-400"
            />
            include_raw
          </label>

          {/* Audio controls */}
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={pauseAudio}
              disabled={audioState !== "playing"}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 disabled:opacity-40"
              title="Pause"
            >
              <Pause className="w-4 h-4 text-gray-200" />
            </button>

            <button
              onClick={resumeAudio}
              disabled={audioState !== "paused"}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 disabled:opacity-40"
              title="Resume"
            >
              <Play className="w-4 h-4 text-gray-200" />
            </button>

            <button
              onClick={stopAudio}
              disabled={audioState === "idle"}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 disabled:opacity-40"
              title="Stop"
            >
              <Square className="w-4 h-4 text-gray-200" />
            </button>
          </div>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="p-4 max-h-[360px] overflow-y-auto space-y-3 custom-scrollbar">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`rounded-xl border p-3 text-sm ${
              m.role === "user"
                ? "ml-10 bg-white/5 border-white/10 text-gray-200"
                : "mr-10 bg-cyan-500/10 border-cyan-500/20 text-gray-100"
            }`}
          >
            <div className="text-[11px] opacity-60 mb-1">
              {m.role === "user" ? "You" : "Agent"} • {new Date(m.ts).toLocaleTimeString()}
            </div>
            <div className="leading-relaxed whitespace-pre-wrap">{m.text}</div>
          </div>
        ))}

        {(loading || ttsLoading) && (
          <div className="mr-10 rounded-xl border p-3 text-sm bg-cyan-500/10 border-cyan-500/20 text-gray-100">
            <div className="text-[11px] opacity-60 mb-1">Agent • …</div>
            <div className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>{loading ? "Analyse en cours…" : "Génération audio…"}</span>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="px-4 py-4 border-t border-white/10 bg-slate-900/40">
        <div className="flex items-center gap-2">
          <button
            onClick={() => (listening ? stopListening() : startListening())}
            disabled={!canUseSpeech}
            className={`p-2.5 rounded-xl border transition-all ${
              listening
                ? "bg-red-500/20 border-red-500/30 text-red-200"
                : "bg-white/5 border-white/10 text-gray-200 hover:bg-white/10"
            } ${!canUseSpeech ? "opacity-40 cursor-not-allowed" : ""}`}
            title={!canUseSpeech ? "SpeechRecognition indisponible sur ce navigateur" : "Micro"}
          >
            {listening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
          </button>

          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='Ex: "Explique DDoS" / "Analyse camera_01"'
            className="flex-1 px-4 py-3 rounded-xl bg-black/40 border border-white/10 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-cyan-500/50"
            onKeyDown={(e) => e.key === "Enter" && onSend()}
          />

          <button
            onClick={onSend}
            disabled={loading}
            className="px-4 py-3 rounded-xl bg-cyan-500/20 text-cyan-200 border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            <span className="text-sm font-semibold">Send</span>
          </button>
        </div>

        {!canUseSpeech && (
          <div className="mt-2 text-xs text-amber-300/80">
            ⚠️ Speech-to-text: utilise Chrome/Edge (Web Speech API).
          </div>
        )}
      </div>

      {/* Hidden audio element */}
      <audio
        ref={audioRef}
        onEnded={() => setAudioState("idle")}
        onPlay={() => setAudioState("playing")}
        onPause={() => {
          // pause triggers also when ended; keep ended handled above
          if (audioRef.current && audioRef.current.currentTime > 0 && !audioRef.current.ended) {
            setAudioState("paused");
          }
        }}
      />
    </div>
  );
}
