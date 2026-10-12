"use client";

import React, { useState, useEffect } from "react";
import {
  analyzePlan,
  getScenarios,
  AnalyzeResponse,
  Scenario,
} from "@/lib/api";

export default function SingleScreenMonitorPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenarioName, setSelectedScenarioName] = useState("");
  const [planJson, setPlanJson] = useState(
    JSON.stringify(
      {
        steps: [
          {
            tool_name: "database_query",
            arguments: { query: "SELECT id, title FROM projects WHERE id = 7" },
            permissions_required: ["database:read"],
            side_effect_class: "read",
            destination: "internal",
            data_sensitivity: "public",
            reversible: true,
            estimated_cost: 0.05,
          },
        ],
      },
      null,
      2
    )
  );

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [viewMode, setViewMode] = useState<"cards" | "json">("cards");

  useEffect(() => {
    getScenarios().then((list) => {
      setScenarios(list);
      try {
        const initialPlan = JSON.parse(planJson);
        analyzePlan(initialPlan).then((res) => setResult(res));
      } catch {
        // no-op
      }
    });
  }, []);

  const handleSelectScenario = (name: string) => {
    setSelectedScenarioName(name);
    const found = scenarios.find((s) => s.name === name);
    if (found) {
      const formatted = JSON.stringify(found.plan, null, 2);
      setPlanJson(formatted);
      setLoading(true);
      setErrorMsg("");
      analyzePlan(found.plan)
        .then((res) => setResult(res))
        .catch((err) => setErrorMsg(err.message))
        .finally(() => setLoading(false));
    }
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setErrorMsg("");
    try {
      const parsed = JSON.parse(planJson);
      const res = await analyzePlan(parsed);
      setResult(res);
    } catch (e: any) {
      setErrorMsg(`Plan format error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  let parsedSteps: any[] = [];
  try {
    const parsed = JSON.parse(planJson);
    if (Array.isArray(parsed?.steps)) {
      parsedSteps = parsed.steps;
    } else if (Array.isArray(parsed)) {
      parsedSteps = parsed;
    }
  } catch {
    parsedSteps = [];
  }

  const getActionBadge = (action: string) => {
    switch (action) {
      case "ALLOW":
        return {
          pill: "bg-[#064E3B]/50 text-[#34D399] border-[#065F46]",
          label: "ALLOW (SAFE)",
          icon: "✓",
          desc: "Plan cleared by all 9 safety rules & ML ensemble.",
        };
      case "CONFIRM":
        return {
          pill: "bg-[#78350F]/50 text-[#FBBF24] border-[#92400E]",
          label: "NEEDS APPROVAL",
          icon: "⚠️",
          desc: "Sensitive action. Requires administrator confirmation.",
        };
      case "REVISE":
        return {
          pill: "bg-[#7C2D12]/50 text-[#FB923C] border-[#9A3412]",
          label: "REVISE PARAMETERS",
          icon: "↻",
          desc: "Unusual parameters. Please adjust the arguments.",
        };
      case "BLOCK":
      default:
        return {
          pill: "bg-[#881337]/50 text-[#FB7185] border-[#9F1239]",
          label: "BLOCKED (DANGEROUS)",
          icon: "✕",
          desc: "Dangerous command stopped before execution.",
        };
    }
  };

  const actionInfo = result ? getActionBadge(result.action) : null;

  return (
    <div className="h-full flex flex-col gap-3 overflow-hidden">
      {/* 1. Top Action Control Bar */}
      <div className="flex-shrink-0 flex flex-wrap items-center justify-between gap-3 p-3 bg-[#121215] border border-[#27272A] rounded-lg">
        <div className="flex items-center gap-3">
          <span className="text-sm font-semibold text-[#FAFAFA]">Select Scenario:</span>
          <select
            value={selectedScenarioName}
            onChange={(e) => handleSelectScenario(e.target.value)}
            className="text-sm bg-[#18181B] border border-[#27272A] text-[#E4E4E7] rounded-md px-3 py-1.5 focus:outline-none focus:border-[#3F3F46] font-medium"
          >
            <option value="">Custom Action Plan</option>
            {scenarios.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())} [{s.expected_decision}]
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setViewMode(viewMode === "cards" ? "json" : "cards")}
            className="text-sm font-medium text-[#A1A1AA] hover:text-[#FAFAFA] bg-[#18181B] border border-[#27272A] px-3 py-1.5 rounded-md transition-colors"
          >
            {viewMode === "cards" ? "View Raw JSON" : "View Step Cards"}
          </button>
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="text-sm font-bold bg-[#FAFAFA] hover:bg-white text-[#09090B] px-5 py-1.5 rounded-md transition-colors flex items-center gap-2 shadow-sm"
          >
            {loading ? (
              <>
                <span className="animate-spin inline-block w-3.5 h-3.5 border-2 border-slate-900 border-t-transparent rounded-full" />
                Scanning...
              </>
            ) : (
              <>
                <span>⚡</span> Scan Plan Now
              </>
            )}
          </button>
        </div>
      </div>

      {/* 2. Top Banner: Large Decision HUD & Key Metrics */}
      <div className="flex-shrink-0 grid grid-cols-1 md:grid-cols-12 gap-3">
        {/* Verdict Badge & Rationale */}
        <div className="md:col-span-8 p-4 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs uppercase font-bold tracking-wider text-[#71717A]">
              Safety Interception Verdict
            </span>
            <span className="text-xs font-mono text-[#71717A]">
              Audit ID: <strong className="text-[#A1A1AA] font-normal">{result?.audit_id || "inline"}</strong>
            </span>
          </div>

          <div className="flex items-center gap-3.5 my-1">
            <span
              className={`text-2xl font-black font-mono px-4 py-1.5 rounded-md border tracking-wide flex items-center gap-2 ${
                actionInfo?.pill || "bg-[#18181B] text-[#71717A] border-[#27272A]"
              }`}
            >
              <span>{actionInfo?.icon}</span>
              <span>{actionInfo?.label || "READY"}</span>
            </span>
            <span className="text-sm text-[#A1A1AA]">
              {actionInfo?.desc || "Choose a scenario or click Scan."}
            </span>
          </div>

          <div className="text-sm text-[#E4E4E7] pt-2 border-t border-[#222226] truncate">
            <span className="font-semibold text-[#A1A1AA]">Rationale: </span>
            {result?.rationale || "Ready to evaluate."}
          </div>
        </div>

        {/* Risk Percentage & Stats */}
        <div className="md:col-span-4 p-4 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col justify-between">
          <div className="flex items-baseline justify-between">
            <div>
              <span className="text-xs uppercase font-bold tracking-wider text-[#71717A] block">
                Calculated Risk
              </span>
              <div className="text-3xl font-mono font-black text-[#FAFAFA] mt-0.5">
                {result ? (result.risk_score * 100).toFixed(1) : "0.0"}%
              </div>
            </div>
            <div className="text-right">
              <span className="text-xs uppercase font-bold tracking-wider text-[#71717A] block">
                Latency
              </span>
              <div className="text-xl font-mono font-bold text-[#A1A1AA] mt-1">
                {result ? `${result.latency_ms.toFixed(1)}ms` : "0ms"}
              </div>
            </div>
          </div>

          <div className="text-xs font-mono text-[#71717A] pt-2 border-t border-[#222226] flex justify-between">
            <span>Critical Violations: <strong className="text-[#FAFAFA] font-bold text-sm">{result?.critical_violations ?? 0}</strong></span>
            <span>Rules Active: <strong className="text-[#34D399] font-bold">9 Active</strong></span>
          </div>
        </div>
      </div>

      {/* 3. Lower Workspace: Split Panel that fills the remaining viewport without page scroll */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3 overflow-hidden">
        {/* Left Column: Tool Steps (Scrolls strictly inside container) */}
        <div className="lg:col-span-7 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col overflow-hidden">
          <div className="px-4 py-2.5 bg-[#121215] border-b border-[#27272A] flex items-center justify-between flex-shrink-0">
            <span className="text-sm font-bold text-[#FAFAFA]">
              Action Plan Steps ({parsedSteps.length})
            </span>
            <span className="text-xs text-[#71717A]">
              {viewMode === "cards" ? "Structured View" : "JSON Code"}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
            {viewMode === "cards" ? (
              parsedSteps.length === 0 ? (
                <div className="text-center py-12 text-sm text-[#71717A]">
                  No tool calls found in plan.
                </div>
              ) : (
                parsedSteps.map((step, idx) => (
                  <div
                    key={idx}
                    className="bg-[#121215] border border-[#27272A] rounded-md p-3 text-sm space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold bg-[#18181B] border border-[#27272A] text-[#A1A1AA] w-6 h-6 rounded flex items-center justify-center">
                          #{idx + 1}
                        </span>
                        <span className="font-bold text-[#FAFAFA] text-sm">
                          {step.tool_name || "Custom Action"}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 text-xs">
                        {step.destination && (
                          <span
                            className={`px-2 py-0.5 rounded border ${
                              step.destination === "external"
                                ? "bg-[#881337]/40 text-[#FB7185] border-[#9F1239]"
                                : "bg-[#18181B] text-[#A1A1AA] border-[#27272A]"
                            }`}
                          >
                            Dest: {step.destination}
                          </span>
                        )}
                        {step.data_sensitivity && (
                          <span
                            className={`px-2 py-0.5 rounded border ${
                              ["secret", "restricted", "confidential"].includes(step.data_sensitivity)
                                ? "bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]"
                                : "bg-[#18181B] text-[#A1A1AA] border-[#27272A]"
                            }`}
                          >
                            Sensitivity: {step.data_sensitivity}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="bg-[#09090B] rounded p-2 text-xs font-mono text-[#A1A1AA] border border-[#222226] overflow-x-auto">
                      <pre className="text-xs leading-relaxed">
                        {JSON.stringify(step.arguments || {}, null, 2)}
                      </pre>
                    </div>

                    <div className="flex items-center justify-between text-xs text-[#71717A] pt-1">
                      <span>Side Effect: <strong className="text-[#A1A1AA] font-normal">{step.side_effect_class || "read"}</strong></span>
                      <span>Permissions: <strong className="text-[#A1A1AA] font-normal">{step.permissions_required?.join(", ") || "none"}</strong></span>
                    </div>
                  </div>
                ))
              )
            ) : (
              <textarea
                value={planJson}
                onChange={(e) => setPlanJson(e.target.value)}
                className="w-full h-full min-h-[220px] bg-[#09090B] text-[#E4E4E7] font-mono text-sm p-3 rounded border border-[#27272A] focus:outline-none focus:border-[#3F3F46] resize-none"
                spellCheck={false}
              />
            )}
          </div>

          {errorMsg && (
            <div className="p-2 bg-[#881337]/40 border-t border-[#9F1239] text-[#FB7185] text-xs font-semibold">
              {errorMsg}
            </div>
          )}
        </div>

        {/* Right Column: Rule Hits, Drivers & ML Voting (Fills remaining height) */}
        <div className="lg:col-span-5 flex flex-col gap-3 overflow-hidden">
          {/* Rules Card */}
          <div className="p-3.5 bg-[#18181B] border border-[#27272A] rounded-lg flex-shrink-0">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-[#FAFAFA]">
                Security Rules Triggered
              </span>
              <span className="text-xs text-[#71717A]">
                {result?.rule_hits?.length || 0} Hits
              </span>
            </div>

            {result?.rule_hits && result.rule_hits.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {result.rule_hits.map((rule, idx) => (
                  <span
                    key={idx}
                    className="text-xs font-bold bg-[#881337]/40 text-[#FB7185] border border-[#9F1239] px-2.5 py-1 rounded"
                  >
                    ● {rule}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-xs text-[#34D399] font-medium py-1">
                ✓ All 9 safety rules passed with zero violations.
              </div>
            )}
          </div>

          {/* Top Feature Drivers */}
          <div className="p-3.5 bg-[#18181B] border border-[#27272A] rounded-lg flex-1 overflow-y-auto">
            <span className="text-sm font-bold text-[#FAFAFA] block mb-2">
              Risk Driver Contributions
            </span>
            {result?.feature_contributions && Object.keys(result.feature_contributions).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(result.feature_contributions).slice(0, 4).map(([feat, w], idx) => {
                  const width = Math.min(100, Math.max(10, w * 100));
                  return (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-[#A1A1AA]">{feat.replace(/_/g, " ")}</span>
                        <span className="text-[#FAFAFA] font-bold">+{w.toFixed(3)}</span>
                      </div>
                      <div className="w-full h-1.5 bg-[#121215] rounded border border-[#27272A] overflow-hidden">
                        <div className="h-full bg-[#A1A1AA] rounded" style={{ width: `${width}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-[#71717A] py-2">No elevated risk factors detected.</div>
            )}
          </div>

          {/* 4-Model Ensemble Grid */}
          <div className="p-3.5 bg-[#18181B] border border-[#27272A] rounded-lg flex-shrink-0">
            <span className="text-sm font-bold text-[#FAFAFA] block mb-2">
              AI Model Consensus
            </span>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2 bg-[#121215] border border-[#27272A] rounded">
                <span className="text-[#71717A] block text-[11px]">Random Forest</span>
                <span className="font-bold text-sm text-[#FAFAFA] mt-0.5 block">
                  {result?.model_votes?.rf_prob !== undefined ? `${(result.model_votes.rf_prob * 100).toFixed(1)}%` : "0.0%"}
                </span>
              </div>
              <div className="p-2 bg-[#121215] border border-[#27272A] rounded">
                <span className="text-[#71717A] block text-[11px]">XGBoost</span>
                <span className="font-bold text-sm text-[#FAFAFA] mt-0.5 block">
                  {result?.model_votes?.xgb_prob !== undefined ? `${(result.model_votes.xgb_prob * 100).toFixed(1)}%` : "0.0%"}
                </span>
              </div>
              <div className="p-2 bg-[#121215] border border-[#27272A] rounded">
                <span className="text-[#71717A] block text-[11px]">Decision Tree</span>
                <span className="font-bold text-sm text-[#FAFAFA] mt-0.5 block">
                  {result?.model_votes?.dt_prob !== undefined ? `${(result.model_votes.dt_prob * 100).toFixed(1)}%` : "0.0%"}
                </span>
              </div>
              <div className="p-2 bg-[#121215] border border-[#27272A] rounded">
                <span className="text-[#71717A] block text-[11px]">Anomaly Detector</span>
                <span className={`font-bold text-sm mt-0.5 block ${result?.model_votes?.iso_flag ? "text-[#FB7185]" : "text-[#34D399]"}`}>
                  {result?.model_votes?.iso_flag ? "Anomaly" : "Normal"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
