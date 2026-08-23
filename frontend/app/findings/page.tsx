"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { PageHeader, LoadingState, ErrorState } from "@/components/Layout";
import { FindingsTable } from "@/components/FindingsTable";
import { useAuth } from "@/lib/auth-context";
import { listFindings, listServers, ApiError } from "@/lib/api-client";
import { SEVERITY_ORDER, SEVERITY_LABELS, formatCategory } from "@/lib/severity";
import type { FindingRecord, GuardianCategory, ServerInfo } from "@/lib/types";

const CATEGORIES: GuardianCategory[] = [
  "permission",
  "ownership",
  "ssh",
  "sudo",
  "cron",
  "secret",
  "docker",
  "firewall",
  "kernel",
];

export default function FindingsPage() {
  const { token } = useAuth();
  const [findings, setFindings] = useState<FindingRecord[] | null>(null);
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [serverId, setServerId] = useState("");

  useEffect(() => {
    if (!token) return;
    listServers(token).then(setServers).catch(() => undefined);
  }, [token]);

  useEffect(() => {
    if (!token) return;
    setFindings(null);
    listFindings(token, {
      severity: severity || undefined,
      category: category || undefined,
      server_id: serverId || undefined,
    })
      .then(setFindings)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Failed to load findings.")
      );
  }, [token, severity, category, serverId]);

  return (
    <AppShell>
      <PageHeader title="Findings" subtitle="All security findings across the fleet, filterable" />

      <div className="mb-6 flex flex-wrap gap-3">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-md border border-base-600 bg-base-800 px-3 py-2 text-sm text-ink-300 outline-none focus:border-signal-500"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABELS[s]}
            </option>
          ))}
        </select>

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-md border border-base-600 bg-base-800 px-3 py-2 text-sm text-ink-300 outline-none focus:border-signal-500"
        >
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {formatCategory(c)}
            </option>
          ))}
        </select>

        <select
          value={serverId}
          onChange={(e) => setServerId(e.target.value)}
          className="rounded-md border border-base-600 bg-base-800 px-3 py-2 text-sm text-ink-300 outline-none focus:border-signal-500"
        >
          <option value="">All servers</option>
          {servers.map((s) => (
            <option key={s.id} value={s.id}>
              {s.hostname}
            </option>
          ))}
        </select>
      </div>

      {error && <ErrorState message={error} />}
      {!findings && !error && <LoadingState label="Loading findings…" />}
      {findings && <FindingsTable findings={findings} showServerColumn={!serverId} />}
    </AppShell>
  );
}
