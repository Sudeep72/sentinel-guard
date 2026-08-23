"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState, ErrorState } from "@/components/Layout";
import { ScoreGauge } from "@/components/ScoreGauge";
import { CategoryScoreCard } from "@/components/CategoryScoreCard";
import { FindingsTable } from "@/components/FindingsTable";
import { BaselineComparisonTable } from "@/components/BaselineComparisonTable";
import { ServerStatusBadge } from "@/components/Badges";
import { useAuth } from "@/lib/auth-context";
import {
  getServer,
  getServerScore,
  getServerScans,
  getServerBaseline,
  listFindings,
  getServerReport,
  ApiError,
} from "@/lib/api-client";
import { formatCategory, formatDate } from "@/lib/severity";
import type {
  BaselineComparisonResponse,
  FindingRecord,
  ScanSummary,
  SecurityScoreResponse,
  ServerInfo,
} from "@/lib/types";

type Tab = "findings" | "baseline" | "scans";

export default function ServerDetailPage() {
  const { token } = useAuth();
  const params = useParams<{ id: string }>();
  const serverId = params.id;

  const [server, setServer] = useState<ServerInfo | null>(null);
  const [score, setScore] = useState<SecurityScoreResponse | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [baseline, setBaseline] = useState<BaselineComparisonResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (!token || !serverId) return;
    let cancelled = false;

    async function load() {
      try {
        const [serverData, scoreData, scansData, findingsData, baselineData] = await Promise.all([
          getServer(token!, serverId),
          getServerScore(token!, serverId).catch(() => null),
          getServerScans(token!, serverId),
          listFindings(token!, { server_id: serverId }),
          getServerBaseline(token!, serverId).catch(() => null),
        ]);
        if (!cancelled) {
          setServer(serverData);
          setScore(scoreData);
          setScans(scansData);
          setFindings(findingsData);
          setBaseline(baselineData);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to load server details.");
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [token, serverId]);

  async function handleDownload(format: "executive" | "technical" | "markdown" | "json") {
    if (!token) return;
    setDownloading(true);
    try {
      const report = await getServerReport(token, serverId, format);
      const blob = new Blob([report.content], {
        type: format === "json" ? "application/json" : "text/markdown",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinelguard-${server?.hostname ?? "report"}-${format}.${
        format === "json" ? "json" : "md"
      }`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to generate report.");
    } finally {
      setDownloading(false);
    }
  }

  if (error) {
    return (
      <AppShell>
        <ErrorState message={error} />
      </AppShell>
    );
  }

  if (!server) {
    return (
      <AppShell>
        <LoadingState label="Loading server…" />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <PageHeader
        title={server.hostname}
        subtitle={`${formatCategory(server.distro)} ${server.distro_version ?? ""} · agent v${server.agent_version}`}
        actions={
          <div className="flex gap-2">
            {(["executive", "technical", "markdown", "json"] as const).map((format) => (
              <button
                key={format}
                onClick={() => handleDownload(format)}
                disabled={downloading}
                className="rounded-md border border-base-600 px-3 py-1.5 text-xs text-ink-300 transition-colors hover:border-signal-600 hover:text-signal-400 disabled:opacity-50"
              >
                {format}
              </button>
            ))}
          </div>
        }
      />

      <div className="mb-6 flex items-center gap-3">
        <ServerStatusBadge status={server.status} />
        <span className="text-xs text-ink-500">Last seen {formatDate(server.last_seen_at)}</span>
      </div>

      <div className="mb-8 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="flex flex-col items-center justify-center lg:col-span-1">
          {score?.available && score.score ? (
            <ScoreGauge score={score.score.overall_score} />
          ) : (
            <p className="py-8 text-center text-sm text-ink-500">
              {score?.message ?? "No score computed yet."}
            </p>
          )}
          {score?.available && (
            <p className="mt-2 text-xs text-ink-500">
              {score.passed_checks}/{score.total_checks} checks passed
            </p>
          )}
        </Card>

        <div className="lg:col-span-2">
          {score?.available && score.score ? (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {score.score.category_scores.map((cat) => (
                <CategoryScoreCard key={cat.category} {...cat} />
              ))}
            </div>
          ) : (
            <Card>
              <p className="text-sm text-ink-500">Category scores will appear after the first scan.</p>
            </Card>
          )}
        </div>
      </div>

      <div className="mb-4 flex gap-1 border-b border-base-600">
        {(
          [
            ["findings", `Findings (${findings.length})`],
            ["baseline", "Baseline Comparison"],
            ["scans", `Scan History (${scans.length})`],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`border-b-2 px-4 py-2 text-sm transition-colors ${
              tab === key
                ? "border-signal-500 text-ink-100"
                : "border-transparent text-ink-500 hover:text-ink-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "findings" && <FindingsTable findings={findings} />}

      {tab === "baseline" &&
        (baseline?.available ? (
          <BaselineComparisonTable items={baseline.comparisons} />
        ) : (
          <Card>
            <p className="text-sm text-ink-500">{baseline?.message ?? "Baseline data unavailable."}</p>
          </Card>
        ))}

      {tab === "scans" && (
        <div className="overflow-hidden rounded-lg border border-base-600 bg-base-800 shadow-panel">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-base-600 text-xs uppercase tracking-wide text-ink-500">
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Started</th>
                <th className="px-4 py-3 font-medium">Completed</th>
                <th className="px-4 py-3 font-medium">Agent Version</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-b border-base-700 last:border-0">
                  <td className="px-4 py-3 text-ink-300">{scan.status}</td>
                  <td className="px-4 py-3 text-xs text-ink-500">{formatDate(scan.started_at)}</td>
                  <td className="px-4 py-3 text-xs text-ink-500">{formatDate(scan.completed_at)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-ink-500">{scan.agent_version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppShell>
  );
}
