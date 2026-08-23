// Types mirroring the SentinelGuard Dashboard REST API response shapes.
// This file intentionally contains no logic — only shape definitions —
// so the frontend never duplicates business logic that belongs in the
// dashboard backend.

export type Distro = "ubuntu" | "debian" | "fedora" | "rocky" | "centos" | "unknown";
export type ServerStatus = "online" | "offline" | "stale";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type GuardianCategory =
  | "permission"
  | "ownership"
  | "ssh"
  | "sudo"
  | "cron"
  | "secret"
  | "docker"
  | "firewall"
  | "kernel";
export type FindingStatus = "open" | "resolved" | "accepted_risk" | "false_positive";
export type ScanStatus = "running" | "completed" | "failed" | "partial";
export type ReportFormat = "executive" | "technical" | "json" | "markdown";

export interface ServerInfo {
  id: string;
  hostname: string;
  ip_address: string | null;
  distro: Distro;
  distro_version: string | null;
  agent_version: string;
  status: ServerStatus;
  last_seen_at: string | null;
  created_at: string;
}

export interface ScanSummary {
  id: string;
  server_id: string;
  started_at: string;
  completed_at: string;
  status: ScanStatus;
  agent_version: string;
}

export interface FindingRecord {
  id: string;
  scan_id: string;
  server_id: string;
  check_id: string;
  module: GuardianCategory;
  title: string;
  severity: Severity;
  description: string;
  why_it_matters: string;
  attack_scenario: string;
  recommendation: string;
  current_value: string | null;
  expected_value: string | null;
  status: FindingStatus;
  created_at: string;
}

export interface CategoryScore {
  category: GuardianCategory;
  score: number;
  weight: number;
}

export interface SecurityScore {
  scan_id: string;
  overall_score: number;
  category_scores: CategoryScore[];
  computed_at: string;
}

export interface SecurityScoreResponse {
  available: boolean;
  score: SecurityScore | null;
  message: string | null;
  total_checks: number | null;
  passed_checks: number | null;
  failed_checks: number | null;
  baseline_version: string | null;
}

export interface BaselineComparisonItem {
  category: string;
  rule: string;
  current_value: string | null;
  expected_value: string | null;
  matches_baseline: boolean;
}

export interface BaselineComparisonResponse {
  available: boolean;
  server_id: string;
  distro: string;
  comparisons: BaselineComparisonItem[];
  message: string | null;
}

export interface Report {
  server_id: string;
  scan_id: string;
  format: ReportFormat;
  generated_at: string;
  content: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface UserResponse {
  id: string;
  email: string;
  role: string;
}

export interface HealthResponse {
  status: string;
  database: string;
}

export interface ApiErrorBody {
  detail: string;
}
