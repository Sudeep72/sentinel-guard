"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState, ErrorState } from "@/components/Layout";
import { ScoreGauge } from "@/components/ScoreGauge";
import { CategoryScoreCard } from "@/components/CategoryScoreCard";
import { SeverityChart } from "@/components/SeverityChart";
import { ServerStatusBadge } from "@/components/Badges";
import { useAuth } from "@/lib/auth-context";
import { listServers, listFindings, getServerScore, getServerScans, ApiError } from "@/lib/api-client";
import { formatDate } from "@/lib/severity";
import type { CategoryScore, FindingRecord, ScanSummary, ServerInfo } from "@/lib/types";

interface FleetData {
  servers: ServerInfo[];
  overallScore: number | null;
  categoryScores: CategoryScore[];
  findings: FindingRecord[];
  recentScans: { server: ServerInfo; scan: ScanSummary }[];
}

export default function DashboardPage() {
  const { token } = useAuth();
  const [data, setData] = useState<FleetData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    async function load() {
      try {
        const servers = await listServers(token!);
        const findings = await listFindings(token!);

        const scores = await Promise.all(
          servers.map((s) =>
            getServerScore(token!, s.id).catch(() => ({
              available: false,
              score: null,
              message: null,
              total_checks: null,
              passed_checks: null,
              failed_checks: null,
              baseline_version: null,
            }))
          )
        );

        const scansPerServer = await Promise.all(
          servers.map((s) => getServerScans(token!, s.id).catch(() => [] as ScanSummary[]))
        );
        const recentScans = servers
          .map((server, idx) => {
            const scans = scansPerServer[idx];
            return scans.length > 0 ? { server, scan: scans[0] } : null;
          })
          .filter((entry): entry is { server: ServerInfo; scan: ScanSummary } => entry !== null)
          .sort((a, b) => (a.scan.completed_at < b.scan.completed_at ? 1 : -1))
          .slice(0, 8);

        const availableScores = scores.filter((s) => s.available && s.score);
        const overallScore =
          availableScores.length > 0
            ? availableScores.reduce((sum, s) => sum + (s.score?.overall_score ?? 0), 0) /
              availableScores.length
            : null;

        const categoryMap = new Map<string, { total: number; weight: number; count: number }>();
        for (const s of availableScores) {
          for (const cat of s.score?.category_scores ?? []) {
            const entry = categoryMap.get(cat.category) ?? { total: 0, weight: cat.weight, count: 0 };
            entry.total += cat.score;
            entry.count += 1;
            categoryMap.set(cat.category, entry);
          }
        }
        const categoryScores: CategoryScore[] = Array.from(categoryMap.entries()).map(
          ([category, { total, weight, count }]) => ({
            category: category as CategoryScore["category"],
            score: total / count,
            weight,
          })
        );

        if (!cancelled) {
          setData({ servers, overallScore, categoryScores, findings, recentScans });
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to load dashboard data.");
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const criticalCount = useMemo(
    () => data?.findings.filter((f) => f.severity === "critical").length ?? 0,
    [data]
  );
  const highCount = useMemo(
    () => data?.findings.filter((f) => f.severity === "high").length ?? 0,
    [data]
  );

  return (
    <AppShell>
      <PageHeader
        title="Dashboard"
        subtitle="Fleet-wide security posture across all registered servers"
      />

      {error && <ErrorState message={error} />}
      {!data && !error && <LoadingState label="Loading fleet data…" />}

      {data && (
        <div className="space-y-8">
          {data.servers.length === 0 ? (
            <Card>
              <p className="text-sm text-ink-300">
                No servers registered yet. Register an agent via{" "}
                <code className="font-mono text-xs text-ink-500">POST /api/v1/agents/register</code>{" "}
                to get started.
              </p>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <Card className="flex flex-col items-center justify-center lg:col-span-1">
                {data.overallScore !== null ? (
                  <ScoreGauge score={data.overallScore} label="Fleet Average" />
                ) : (
                  <p className="py-8 text-sm text-ink-500">No scores computed yet.</p>
                )}
              </Card>

              <Card className="lg:col-span-2">
                <h2 className="mb-4 text-sm font-medium text-ink-300">Severity Breakdown</h2>
                <SeverityChart findings={data.findings} />
                <div className="mt-4 flex gap-4 text-xs text-ink-500">
                  <span>{data.servers.length} servers</span>
                  <span>{data.findings.length} total findings</span>
                  <span className="text-severity-critical">{criticalCount} critical</span>
                  <span className="text-severity-high">{highCount} high</span>
                </div>
              </Card>
            </div>
          )}

          {data.categoryScores.length > 0 && (
            <div>
              <h2 className="mb-3 text-sm font-medium text-ink-300">Category Scores (fleet average)</h2>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                {data.categoryScores.map((cat) => (
                  <CategoryScoreCard key={cat.category} {...cat} />
                ))}
              </div>
            </div>
          )}

          <div>
            <h2 className="mb-3 text-sm font-medium text-ink-300">Recent Scans</h2>
            {data.recentScans.length === 0 ? (
              <Card>
                <p className="text-sm text-ink-500">No scans submitted yet.</p>
              </Card>
            ) : (
              <div className="overflow-hidden rounded-lg border border-base-600 bg-base-800 shadow-panel">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-base-600 text-xs uppercase tracking-wide text-ink-500">
                      <th className="px-4 py-3 font-medium">Server</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium">Scan Status</th>
                      <th className="px-4 py-3 font-medium">Completed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recentScans.map(({ server, scan }) => (
                      <tr key={scan.id} className="border-b border-base-700 last:border-0">
                        <td className="px-4 py-3">
                          <Link
                            href={`/servers/${server.id}`}
                            className="text-ink-100 hover:text-signal-400"
                          >
                            {server.hostname}
                          </Link>
                        </td>
                        <td className="px-4 py-3">
                          <ServerStatusBadge status={server.status} />
                        </td>
                        <td className="px-4 py-3 text-ink-500">{scan.status}</td>
                        <td className="px-4 py-3 text-xs text-ink-500">
                          {formatDate(scan.completed_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </AppShell>
  );
}
