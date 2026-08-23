"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState } from "@/components/Layout";
import { useAuth } from "@/lib/auth-context";
import { getHealth } from "@/lib/api-client";
import type { HealthResponse } from "@/lib/types";

export default function SettingsPage() {
  const { user } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: "unreachable", database: "unknown" }));
  }, []);

  return (
    <AppShell>
      <PageHeader title="Settings" subtitle="Account, dashboard, and agent registration info" />

      <div className="space-y-6">
        <Card>
          <h2 className="mb-3 text-sm font-medium text-ink-300">Account</h2>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between border-b border-base-700 pb-2">
              <dt className="text-ink-500">Email</dt>
              <dd className="text-ink-100">{user?.email ?? "—"}</dd>
            </div>
            <div className="flex justify-between pb-1">
              <dt className="text-ink-500">Role</dt>
              <dd className="capitalize text-ink-100">{user?.role ?? "—"}</dd>
            </div>
          </dl>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-medium text-ink-300">Dashboard Health</h2>
          {!health ? (
            <LoadingState label="Checking…" />
          ) : (
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between border-b border-base-700 pb-2">
                <dt className="text-ink-500">API status</dt>
                <dd
                  className={health.status === "ok" ? "text-success" : "text-severity-critical"}
                >
                  {health.status}
                </dd>
              </div>
              <div className="flex justify-between pb-1">
                <dt className="text-ink-500">Database</dt>
                <dd
                  className={
                    health.database === "ok" ? "text-success" : "text-severity-critical"
                  }
                >
                  {health.database}
                </dd>
              </div>
            </dl>
          )}
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-medium text-ink-300">Register a new agent</h2>
          <p className="mb-3 text-sm text-ink-500">
            Agents register themselves via the REST API. Run this on the target host after
            installing the SentinelGuard agent:
          </p>
          <pre className="overflow-x-auto rounded-md border border-base-600 bg-base-900 p-3 font-mono text-xs text-ink-300">
{`curl -X POST ${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/api/v1/agents/register \\
  -H "Content-Type: application/json" \\
  -d '{"hostname": "myserver", "distro": "ubuntu", \\
       "distro_version": "24.04", "agent_version": "0.1.0"}'`}
          </pre>
          <p className="mt-3 text-sm text-ink-500">
            The response includes an API key shown only once — set it as{" "}
            <code className="font-mono text-xs text-ink-300">SENTINELGUARD_API_KEY</code> on the
            agent, then run{" "}
            <code className="font-mono text-xs text-ink-300">sentinelguard-agent scan --submit</code>.
          </p>
        </Card>
      </div>
    </AppShell>
  );
}
