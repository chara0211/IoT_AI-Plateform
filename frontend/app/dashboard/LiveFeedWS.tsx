"use client";

import React, { useEffect, useState } from "react";
import { socket } from "@/lib/socket";

export default function LiveFeedWS({ initial }: { initial: any[] }) {
  const [items, setItems] = useState<any[]>(initial);

  useEffect(() => {
    const onNew = (d: any) => {
      setItems((prev) => [d, ...prev].slice(0, 20));
    };

    socket.on("detection:new", onNew);
    return () => {
      socket.off("detection:new", onNew);
    };
  }, []);

  return (
    <div className="rounded-sm bg-black/40 border border-white/10 p-3 max-h-[380px] overflow-y-auto">
      <div className="text-xs text-gray-400 mb-2">live • websocket</div>
      <div className="space-y-2">
        {items.map((d) => (
          <div key={d.id} className="rounded-sm border border-white/10 bg-black/20 px-3 py-2">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium text-gray-100">{d.deviceId}</div>
              <div className="text-xs text-gray-500">
                {new Date(d.createdAt).toLocaleTimeString()}
              </div>
            </div>
            <div className="mt-1 flex items-center gap-2 text-xs">
              <span
                className={[
                  "px-2 py-0.5 rounded border",
                  d.isAnomaly
                    ? "bg-red-500/15 text-red-200 border-red-500/25"
                    : "bg-green-500/10 text-green-200 border-green-500/20",
                ].join(" ")}
              >
                {d.isAnomaly ? "Anomaly" : "Normal"}
              </span>
              <span className="text-gray-400">{d.threatType}</span>
              <span className="ml-auto text-orange-200 font-semibold">{d.riskScore}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
