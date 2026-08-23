"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { PageHeader, Card, LoadingState, ErrorState } from "@/components/Layout";
import { SeverityBadge } from "@/components/Badges";
import { useAuth } from "@/lib/auth-context";
import { getFinding, ApiError } from "@/lib/api-client";
import { formatCategory, formatDate } from "@/lib/severity";
import type { FindingRecord } from "@/lib/types";

export default function FindingDetailPage() {
  const { token } = useAuth();
  const params = useParams<{ id: string }>();
  const [finding, setFinding] = useState<FindingRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token || !params.id) return;
    getFinding(token, params.id)
      .then(setFinding)
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load finding."));
  }, [token, params.id]);

  if (error) {
    return (
      <AppShell>
        <ErrorState message={error} />
      </AppShell>
    );
  }

  if (!finding) {
    return (
      <AppShell>
        <LoadingState label="Loading finding…" />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <PageHeader
        title={finding.title}
        subtitle={`${finding.check_id} · ${formatCategory(finding.module)} · detected ${formatDate(finding.created_at)}`}
      />

      <div className="mb-6">
        <SeverityBadge severity={finding.severity} />
      </div>

      <div className="space-y-4">
        <Card>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-500">
            Description
          </h2>
          <p className="text-sm text-ink-100">{finding.description}</p>
        </Card>

        <Card>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-500">
            Why it matters
          </h2>
          <p className="text-sm text-ink-100">{finding.why_it_matters}</p>
        </Card>

        <Card>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-500">
            Attack scenario
          </h2>
          <p className="text-sm text-ink-100">{finding.attack_scenario}</p>
        </Card>

        {(finding.current_value !== null || finding.expected_value !== null) && (
          <Card>
            <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-ink-500">
              Values
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="mb-1 text-xs text-ink-700">Current</p>
                <p className="font-mono text-sm text-severity-critical">
                  {finding.current_value ?? "—"}
                </p>
              </div>
              <div>
                <p className="mb-1 text-xs text-ink-700">Expected</p>
                <p className="font-mono text-sm text-success">{finding.expected_value ?? "—"}</p>
              </div>
            </div>
          </Card>
        )}

        <Card className="border-signal-600/40 bg-signal-500/5">
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-signal-400">
            Recommendation
          </h2>
          <p className="text-sm text-ink-100">{finding.recommendation}</p>
        </Card>
      </div>
    </AppShell>
  );
}
