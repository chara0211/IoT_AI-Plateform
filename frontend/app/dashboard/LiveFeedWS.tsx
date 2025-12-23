"use client";

import React, { useEffect, useState } from "react";
import { socket } from "@/lib/socket";
import { Bot } from "lucide-react";
import SocAgentVoice from "./SocAgentVoice";

function GlassPanel({
  title,
  subtitle,
  badge,
  icon,
  children,
  large,
}: {
  title: string;
  subtitle?: string;
  badge: number;
  icon?: React.ReactNode;
  children: React.ReactNode;
  large?: boolean;
}) {
  return (
    <div
      className={`rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/50 via-slate-800/50 to-slate-900/50 ${
        large ? "p-8" : "p-6"
      } hover:border-white/20 transition-all backdrop-blur-xl shadow-2xl shadow-black/50`}
    >
      <div className="mb-5 flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2.5 text-lg font-bold text-white">
            <span className="text-cyan-400">{icon}</span>
            {title}
          </div>
          {subtitle && <div className="mt-1.5 text-sm text-gray-400">{subtitle}</div>}
        </div>
        <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 text-sm font-black text-slate-900 shadow-lg shadow-amber-500/30">
          {badge}
        </div>
      </div>
      {children}
    </div>
  );
}

export default function LiveFeedWS({ initial }: { initial: any[] }) {
  const [items, setItems] = useState<any[]>(initial ?? []);
  const [seenKeys, setSeenKeys] = useState<Set<string>>(new Set());

  useEffect(() => {
    const onNew = (d: any) => {
      // ✅ Generate a truly unique key
      const timestamp = Date.now();
      const random = Math.random().toString(36).substr(2, 9);
      const uniqueKey = `${d?.deviceId ?? 'device'}-${timestamp}-${random}`;
      
      // ✅ Only add if we haven't seen this key
      setSeenKeys(prev => {
        const newSet = new Set(prev);
        newSet.add(uniqueKey);
        return newSet;
      });

      // ✅ Add the detection with its unique key
      const newItem = { 
        ...d, 
        _feedKey: uniqueKey,
        _timestamp: timestamp 
      };
      
      setItems((prev) => {
        // Remove any potential duplicates
        const filteredPrev = prev.filter(item => item._feedKey !== uniqueKey);
        return [newItem, ...filteredPrev].slice(0, 20);
      });
    };

    socket.on("detection:new", onNew);
    return () => {
      socket.off("detection:new", onNew);
    };
  }, []);

  return (
    <div className="space-y-4">
      {/* Feed */}
      <div className="rounded-sm bg-black/40 border border-white/10 p-3 max-h-[380px] overflow-y-auto">
        <div className="text-xs text-gray-400 mb-2">live • websocket</div>

        <div className="space-y-2">
          {items.map((d, idx) => {
            // ✅ Always use the guaranteed unique key
            const key = d._feedKey ?? `${d?.deviceId ?? 'device'}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${idx}`;

            return (
              <div
                key={key}
                className="rounded-sm border border-white/10 bg-black/20 px-3 py-2"
              >
                <div className="flex items-center justify-between">
                  <div className="text-sm font-medium text-gray-100">{d?.deviceId ?? "Unknown"}</div>
                  <div className="text-xs text-gray-500">
                    {d?.createdAt ? new Date(d.createdAt).toLocaleTimeString() : "now"}
                  </div>
                </div>

                <div className="mt-1 flex items-center gap-2 text-xs">
                  <span
                    className={[
                      "px-2 py-0.5 rounded border",
                      d?.isAnomaly
                        ? "bg-red-500/15 text-red-200 border-red-500/25"
                        : "bg-green-500/10 text-green-200 border-green-500/20",
                    ].join(" ")}
                  >
                    {d?.isAnomaly ? "Anomaly" : "Normal"}
                  </span>

                  <span className="text-gray-400">{d?.threatType ?? "—"}</span>

                  <span className="ml-auto text-orange-200 font-semibold">{d?.riskScore ?? 0}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* SOC Agent Panel OUTSIDE scroll */}
      <GlassPanel
        title="SOC Agent"
        subtitle="Ask by voice • Explain by voice"
        badge={8}
        icon={<Bot className="h-4 w-4" />}
      >
        <SocAgentVoice />
      </GlassPanel>
    </div>
  );
}