import { SEVERITY_COLORS, SEVERITY_LABELS } from "@/lib/severity";
import type { ServerStatus, Severity } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLORS[severity];
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium"
      style={{ backgroundColor: `${color}22`, color }}
    >
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

const STATUS_STYLES: Record<ServerStatus, string> = {
  online: "bg-success/15 text-success",
  offline: "bg-ink-700/20 text-ink-500",
  stale: "bg-severity-medium/15 text-severity-medium",
};

export function ServerStatusBadge({ status }: { status: ServerStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${STATUS_STYLES[status]}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          status === "online" ? "bg-success" : status === "stale" ? "bg-severity-medium" : "bg-ink-500"
        }`}
      />
      {status}
    </span>
  );
}
