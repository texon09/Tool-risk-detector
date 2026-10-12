/**
 * API client library for Next.js frontend interfacing with FastAPI Risk Detection API.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface AnalyzeResponse {
  action: "ALLOW" | "CONFIRM" | "REVISE" | "BLOCK";
  decision?: string;
  risk_score: number;
  score?: number;
  critical_violations: number;
  rule_hits: string[];
  rationale: string;
  feature_contributions: Record<string, number>;
  model_votes: {
    rf_prob?: number;
    xgb_prob?: number;
    dt_prob?: number;
    iso_flag?: number | boolean;
  };
  latency_ms: number;
  audit_id: string;
}

export interface Scenario {
  name: string;
  description: string;
  plan: Record<string, any>;
  expected_decision: "ALLOW" | "CONFIRM" | "REVISE" | "BLOCK";
}

export interface ModelMetrics {
  f1: number;
  precision: number;
  recall: number;
  auroc: number;
  latency_ms: number;
}

export interface MetricsResponse {
  available: boolean;
  models: Record<string, ModelMetrics>;
  detail?: string;
}

export interface AuditRecord {
  id: number;
  audit_id: string;
  trajectory_id: string;
  timestamp: string;
  prev_hash: string;
  current_hash: string;
  payload: string;
  decision: string;
  rationale: string;
}

export interface AuditVerifyResponse {
  valid: boolean;
  broken_at_id?: string | null;
  reason: string;
}

export async function analyzePlan(
  plan: Record<string, any>,
  context?: Record<string, any>,
  mcp_meta?: Record<string, any>
): Promise<AnalyzeResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plan, context: context || {}, mcp_meta }),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err: any) {
    // Fail-closed in UI if backend is unreachable
    return {
      action: "BLOCK",
      decision: "BLOCK",
      risk_score: 1.0,
      score: 1.0,
      critical_violations: 1,
      rule_hits: ["backend_connection_error"],
      rationale: `Fail-closed: could not connect to risk engine (${err.message})`,
      feature_contributions: {},
      model_votes: {},
      latency_ms: 0,
      audit_id: "ui-fail-closed",
    };
  }
}

export async function getScenarios(): Promise<Scenario[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/scenarios`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.scenarios || [];
  } catch {
    return [];
  }
}

export async function getMetrics(): Promise<MetricsResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/metrics`);
    if (!res.ok) return { available: false, models: {} };
    return await res.json();
  } catch {
    return { available: false, models: {} };
  }
}

export async function getAuditLog(
  limit: number = 50,
  offset: number = 0
): Promise<AuditRecord[]> {
  try {
    const res = await fetch(
      `${API_BASE_URL}/api/audit?limit=${limit}&offset=${offset}`
    );
    if (!res.ok) return [];
    const data = await res.json();
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.logs)) return data.logs;
    return [];
  } catch {
    return [];
  }
}

export async function verifyAuditChain(): Promise<AuditVerifyResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/audit/verify`, {
      method: "POST",
    });
    if (!res.ok) return { valid: false, reason: "Verification failed" };
    return await res.json();
  } catch (err: any) {
    return { valid: false, reason: `Connection error: ${err.message}` };
  }
}
