// Thin typed wrapper over the SentinelGuard Dashboard REST API.
//
// This is the ONLY place in the frontend that constructs fetch() calls
// to the backend. Every page/component goes through these functions —
// no component builds its own request or duplicates API logic. All
// business logic (scoring, baseline comparison, report generation)
// lives in the dashboard backend; this file only shapes HTTP calls.

import type {
  BaselineComparisonResponse,
  FindingRecord,
  HealthResponse,
  Report,
  ReportFormat,
  ScanSummary,
  SecurityScoreResponse,
  ServerInfo,
  TokenResponse,
  UserResponse,
} from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `Request to ${path} failed with status ${response.status}`;
    try {
      const body = await response.json();
      if (body?.detail) {
        message = body.detail;
      }
    } catch {
      // response had no JSON body — keep the generic message
    }
    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

// ── Auth ──────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set("username", email);
  body.set("password", password);

  const response = await fetch(`${API_BASE_URL}/api/v1/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    let message = "Invalid email or password";
    try {
      const errBody = await response.json();
      if (errBody?.detail) message = errBody.detail;
    } catch {
      // ignore
    }
    throw new ApiError(response.status, message);
  }

  return (await response.json()) as TokenResponse;
}

export function getMe(token: string): Promise<UserResponse> {
  return request<UserResponse>("/api/v1/auth/me", {}, token);
}

// ── Health ────────────────────────────────────────────────────────────────

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/v1/health");
}

// ── Servers ───────────────────────────────────────────────────────────────

export function listServers(token: string): Promise<ServerInfo[]> {
  return request<ServerInfo[]>("/api/v1/servers", {}, token);
}

export function getServer(token: string, serverId: string): Promise<ServerInfo> {
  return request<ServerInfo>(`/api/v1/servers/${serverId}`, {}, token);
}

export function getServerScans(token: string, serverId: string): Promise<ScanSummary[]> {
  return request<ScanSummary[]>(`/api/v1/servers/${serverId}/scans`, {}, token);
}

// ── Scores ────────────────────────────────────────────────────────────────

export function getServerScore(
  token: string,
  serverId: string,
  scanId?: string
): Promise<SecurityScoreResponse> {
  const query = scanId ? `?scan_id=${scanId}` : "";
  return request<SecurityScoreResponse>(`/api/v1/servers/${serverId}/score${query}`, {}, token);
}

// ── Baseline ──────────────────────────────────────────────────────────────

export function getServerBaseline(
  token: string,
  serverId: string,
  category?: string
): Promise<BaselineComparisonResponse> {
  const query = category ? `?category=${category}` : "";
  return request<BaselineComparisonResponse>(
    `/api/v1/servers/${serverId}/baseline${query}`,
    {},
    token
  );
}

// ── Findings ──────────────────────────────────────────────────────────────

export interface FindingFilters {
  server_id?: string;
  severity?: string;
  category?: string;
  status?: string;
}

export function listFindings(
  token: string,
  filters: FindingFilters = {}
): Promise<FindingRecord[]> {
  const params = new URLSearchParams();
  if (filters.server_id) params.set("server_id", filters.server_id);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.category) params.set("category", filters.category);
  if (filters.status) params.set("status", filters.status);
  const query = params.toString() ? `?${params.toString()}` : "";
  return request<FindingRecord[]>(`/api/v1/findings${query}`, {}, token);
}

export function getFinding(token: string, findingId: string): Promise<FindingRecord> {
  return request<FindingRecord>(`/api/v1/findings/${findingId}`, {}, token);
}

// ── Reports ───────────────────────────────────────────────────────────────

export function getServerReport(
  token: string,
  serverId: string,
  format: ReportFormat,
  scanId?: string
): Promise<Report> {
  const params = new URLSearchParams({ format });
  if (scanId) params.set("scan_id", scanId);
  return request<Report>(`/api/v1/servers/${serverId}/report?${params.toString()}`, {}, token);
}
