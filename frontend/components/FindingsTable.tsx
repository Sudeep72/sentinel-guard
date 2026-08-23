import Link from "next/link";
import { SeverityBadge } from "./Badges";
import { formatCategory, formatDate } from "@/lib/severity";
import type { FindingRecord } from "@/lib/types";

interface FindingsTableProps {
  findings: FindingRecord[];
  showServerColumn?: boolean;
}

export function FindingsTable({ findings, showServerColumn = false }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-base-600 bg-base-800 p-8 text-center text-sm text-ink-500">
        No findings match the current filters.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-base-600 bg-base-800 shadow-panel">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-base-600 text-xs uppercase tracking-wide text-ink-500">
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">Check</th>
            <th className="px-4 py-3 font-medium">Category</th>
            <th className="px-4 py-3 font-medium">Title</th>
            {showServerColumn && <th className="px-4 py-3 font-medium">Server</th>}
            <th className="px-4 py-3 font-medium">Detected</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              key={finding.id}
              className="border-b border-base-700 last:border-0 hover:bg-base-700/50"
            >
              <td className="px-4 py-3">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="px-4 py-3 font-mono text-xs text-ink-300">{finding.check_id}</td>
              <td className="px-4 py-3 text-ink-500">{formatCategory(finding.module)}</td>
              <td className="px-4 py-3">
                <Link href={`/findings/${finding.id}`} className="text-ink-100 hover:text-signal-400">
                  {finding.title}
                </Link>
              </td>
              {showServerColumn && (
                <td className="px-4 py-3 font-mono text-xs text-ink-500">
                  {finding.server_id.slice(0, 8)}
                </td>
              )}
              <td className="px-4 py-3 text-xs text-ink-500">{formatDate(finding.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
