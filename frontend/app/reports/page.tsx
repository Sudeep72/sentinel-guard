"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState, ErrorState } from "@/components/Layout";
import { useAuth } from "@/lib/auth-context";
import { listServers, getServerReport, ApiError } from "@/lib/api-client";
import type { ReportFormat, ServerInfo } from "@/lib/types";

const FORMATS: { value: ReportFormat; label: string; description: string }[] = [
  { value: "executive", label: "Executive", description: "High-level summary for non-technical stakeholders" },
  { value: "technical", label: "Technical", description: "Full detail: attack scenarios, baseline deviations" },
  { value: "markdown", label: "Markdown", description: "Full technical detail as portable Markdown" },
  { value: "json", label: "JSON", description: "Structured data for tooling and automation" },
];

export default function ReportsPage() {
  const { token } = useAuth();
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [selectedServer, setSelectedServer] = useState("");
  const [format, setFormat] = useState<ReportFormat>("executive");
  const [preview, setPreview] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    listServers(token)
      .then((data) => {
        setServers(data);
        if (data.length > 0) setSelectedServer(data[0].id);
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load servers."));
  }, [token]);

  async function handleGenerate() {
    if (!token || !selectedServer) return;
    setGenerating(true);
    setError(null);
    setPreview(null);
    try {
      const report = await getServerReport(token, selectedServer, format);
      setPreview(report.content);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to generate report.");
    } finally {
      setGenerating(false);
    }
  }

  function handleDownload() {
    if (!preview) return;
    const server = servers.find((s) => s.id === selectedServer);
    const blob = new Blob([preview], {
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
  }

  return (
    <AppShell>
      <PageHeader title="Reports" subtitle="Generate and download security reports per server" />

      <Card className="mb-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-xs text-ink-500">Server</label>
            <select
              value={selectedServer}
              onChange={(e) => setSelectedServer(e.target.value)}
              className="w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 text-sm text-ink-100 outline-none focus:border-signal-500"
            >
              {servers.length === 0 && <option value="">No servers registered</option>}
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.hostname}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs text-ink-500">Format</label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as ReportFormat)}
              className="w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 text-sm text-ink-100 outline-none focus:border-signal-500"
            >
              {FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <p className="mt-3 text-xs text-ink-500">
          {FORMATS.find((f) => f.value === format)?.description}
        </p>

        <div className="mt-5 flex gap-3">
          <button
            onClick={handleGenerate}
            disabled={!selectedServer || generating}
            className="rounded-md bg-signal-500 px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-signal-400 disabled:opacity-50"
          >
            {generating ? "Generating…" : "Generate report"}
          </button>
          {preview && (
            <button
              onClick={handleDownload}
              className="rounded-md border border-base-600 px-4 py-2 text-sm text-ink-300 transition-colors hover:border-signal-600 hover:text-signal-400"
            >
              Download
            </button>
          )}
        </div>
      </Card>

      {error && <ErrorState message={error} />}
      {generating && <LoadingState label="Generating report…" />}

      {preview && (
        <Card>
          <pre className="max-h-[600px] overflow-auto whitespace-pre-wrap font-mono text-xs text-ink-300">
            {preview}
          </pre>
        </Card>
      )}
    </AppShell>
  );
}
