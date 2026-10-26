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

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export interface ApiKey {
  id: string;
  key_prefix: string;
  label: string;
  created_at: string;
  revoked: number;
}

export function getStoredSessionToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("planguard_session_token");
}

export function setStoredSessionToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) {
    localStorage.setItem("planguard_session_token", token);
  } else {
    localStorage.removeItem("planguard_session_token");
  }
}

export async function signup(email: string, password: string): Promise<{ user: User; session_token: string }> {
  const res = await fetch(`${API_BASE_URL}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Signup failed" }));
    throw new Error(err.detail || "Signup failed");
  }
  const data = await res.json();
  setStoredSessionToken(data.session_token);
  return data;
}

export async function login(email: string, password: string): Promise<{ user: User; session_token: string }> {
  const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Login failed" }));
    throw new Error(err.detail || "Login failed");
  }
  const data = await res.json();
  setStoredSessionToken(data.session_token);
  return data;
}

export async function getCurrentUser(): Promise<User | null> {
  const token = getStoredSessionToken();
  if (!token) return null;
  try {
    const res = await fetch(`${API_BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      setStoredSessionToken(null);
      return null;
    }
    const data = await res.json();
    return data.user;
  } catch {
    return null;
  }
}

export async function listApiKeys(): Promise<ApiKey[]> {
  const token = getStoredSessionToken();
  if (!token) return [];
  try {
    const res = await fetch(`${API_BASE_URL}/api/keys`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.keys || [];
  } catch {
    return [];
  }
}

export async function createApiKey(label: string): Promise<{ id: string; api_key: string; key_prefix: string; label: string }> {
  const token = getStoredSessionToken();
  if (!token) throw new Error("Authentication required");
  const res = await fetch(`${API_BASE_URL}/api/keys`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ label }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to create key" }));
    throw new Error(err.detail || "Failed to create key");
  }
  return await res.json();
}

export async function revokeApiKey(keyId: string): Promise<boolean> {
  const token = getStoredSessionToken();
  if (!token) return false;
  try {
    const res = await fetch(`${API_BASE_URL}/api/keys/${keyId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function getAuditLog(
  limit: number = 50,
  offset: number = 0,
  id?: string | null
): Promise<AuditRecord[]> {
  try {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (id) {
      params.append("id", id);
    }
    const token = getStoredSessionToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(`${API_BASE_URL}/api/audit?${params.toString()}`, {
      headers,
    });
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
