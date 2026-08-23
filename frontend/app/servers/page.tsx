"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState, ErrorState, EmptyState } from "@/components/Layout";
import { ServerStatusBadge } from "@/components/Badges";
import { useAuth } from "@/lib/auth-context";
import { listServers, ApiError } from "@/lib/api-client";
import { formatCategory, formatDate } from "@/lib/severity";
import type { ServerInfo } from "@/lib/types";

export default function ServersPage() {
  const { token } = useAuth();
  const [servers, setServers] = useState<ServerInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    listServers(token)
      .then(setServers)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Failed to load servers.")
      );
  }, [token]);

  return (
    <AppShell>
      <PageHeader title="Servers" subtitle="Every host registered to this SentinelGuard fleet" />

      {error && <ErrorState message={error} />}
      {!servers && !error && <LoadingState label="Loading servers…" />}

      {servers && servers.length === 0 && (
        <EmptyState message="No servers registered yet. Register an agent via POST /api/v1/agents/register." />
      )}

      {servers && servers.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {servers.map((server) => (
            <Link key={server.id} href={`/servers/${server.id}`}>
              <Card className="h-full transition-colors hover:border-signal-600">
                <div className="mb-3 flex items-center justify-between">
                  <h3 className="font-medium text-ink-100">{server.hostname}</h3>
                  <ServerStatusBadge status={server.status} />
                </div>
                <dl className="space-y-1 text-xs text-ink-500">
                  <div className="flex justify-between">
                    <dt>Distro</dt>
                    <dd className="text-ink-300">
                      {formatCategory(server.distro)} {server.distro_version}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Agent</dt>
                    <dd className="font-mono text-ink-300">{server.agent_version}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Last seen</dt>
                    <dd className="text-ink-300">{formatDate(server.last_seen_at)}</dd>
                  </div>
                </dl>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </AppShell>
  );
}
