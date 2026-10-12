"use client";

import React, { useEffect, useState } from "react";
import { getMetrics, MetricsResponse } from "@/lib/api";

export default function SingleScreenMetricsPage() {
  const [data, setData] = useState<MetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getMetrics()
      .then((res) => setData(res))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="h-full flex flex-col gap-3 overflow-hidden">
      {/* 1. Header Bar */}
      <div className="flex-shrink-0 p-3 bg-[#18181B] border border-[#27272A] rounded-lg flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-[#FAFAFA] flex items-center gap-2">
            📊 Model Accuracy & Benchmark Comparisons
          </h1>
          <p className="text-xs text-[#A1A1AA]">
            Tested against 4,000+ benchmark agent trajectories across multi-class distributions.
          </p>
        </div>
        <span className="text-xs font-mono font-medium text-[#34D399] bg-[#064E3B]/30 border border-[#065F46] px-2.5 py-1 rounded">
          4-Model Ensemble Active
        </span>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center text-sm text-[#71717A]">
          Loading benchmarks...
        </div>
      ) : !data || !data.available ? (
        <div className="flex-1 flex items-center justify-center text-sm text-[#71717A]">
          Metrics report currently unavailable.
        </div>
      ) : (
        <div className="flex-1 min-h-0 flex flex-col gap-3 overflow-hidden">
          {/* 2. Top Overview 4 Bento Cards */}
          <div className="flex-shrink-0 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(data.models).map(([name, m]) => (
              <div
                key={name}
                className="p-3.5 bg-[#18181B] border border-[#27272A] rounded-lg space-y-2.5 shadow-sm"
              >
                <div className="flex items-center justify-between pb-1.5 border-b border-[#222226]">
                  <span className="font-bold text-sm text-[#FAFAFA] capitalize">
                    {name.replace("_", " ")}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 bg-[#121215] border border-[#27272A] rounded text-[#A1A1AA]">
                    {m.latency_ms} ms
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#A1A1AA]">Overall Score (F1):</span>
                    <span className="text-[#FAFAFA] font-bold text-sm">
                      {(m.f1 * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#A1A1AA]">Few False Alarms (Prec):</span>
                    <span className="text-[#FAFAFA] font-bold">
                      {(m.precision * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#A1A1AA]">Catches Threats (Recall):</span>
                    <span className="text-[#FAFAFA] font-bold">
                      {(m.recall * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between pt-1 border-t border-[#222226]">
                    <span className="text-[#71717A]">AUROC:</span>
                    <span className="text-[#34D399] font-bold font-mono">
                      {(m.auroc * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* 3. Lower Comparison Matrix (Fills height without page scroll) */}
          <div className="flex-1 min-h-0 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col overflow-hidden">
            <div className="px-4 py-2.5 bg-[#121215] border-b border-[#27272A] text-xs font-bold text-[#A1A1AA] flex-shrink-0">
              SIDE-BY-SIDE BENCHMARK MATRIX
            </div>

            <div className="flex-1 overflow-y-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-[#09090B] text-[#71717A] uppercase text-xs border-b border-[#27272A] sticky top-0">
                  <tr>
                    <th className="px-4 py-3">Model Architecture</th>
                    <th className="px-4 py-3">Overall F1</th>
                    <th className="px-4 py-3">Precision</th>
                    <th className="px-4 py-3">Recall</th>
                    <th className="px-4 py-3">AUROC Reliability</th>
                    <th className="px-4 py-3">Inference Speed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222226]">
                  {Object.entries(data.models).map(([name, m]) => (
                    <tr key={name} className="hover:bg-[#121215]/50 transition-colors">
                      <td className="px-4 py-3.5 font-bold text-[#FAFAFA] capitalize">
                        {name.replace("_", " ")}
                      </td>
                      <td className="px-4 py-3.5 text-[#E4E4E7] font-semibold">{(m.f1 * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3.5 text-[#E4E4E7]">{(m.precision * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3.5 text-[#E4E4E7]">{(m.recall * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3.5 text-[#34D399] font-bold font-mono">{(m.auroc * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3.5 text-[#A1A1AA] font-mono">{m.latency_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
