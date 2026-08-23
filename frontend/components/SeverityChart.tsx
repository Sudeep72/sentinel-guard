import { SEVERITY_COLORS, SEVERITY_LABELS, SEVERITY_ORDER } from "@/lib/severity";
import type { FindingRecord } from "@/lib/types";

interface SeverityChartProps {
  findings: FindingRecord[];
}

/** A simple horizontal bar chart of finding counts per severity. */
export function SeverityChart({ findings }: SeverityChartProps) {
  const counts: Record<string, number> = {};
  for (const severity of SEVERITY_ORDER) counts[severity] = 0;
  for (const finding of findings) counts[finding.severity] += 1;

  const max = Math.max(1, ...Object.values(counts));

  return (
    <div className="space-y-3">
      {SEVERITY_ORDER.map((severity) => {
        const count = counts[severity];
        const widthPct = (count / max) * 100;
        return (
          <div key={severity} className="flex items-center gap-3">
            <span className="w-16 shrink-0 text-xs text-ink-500">{SEVERITY_LABELS[severity]}</span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-base-700">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${widthPct}%`,
                  backgroundColor: SEVERITY_COLORS[severity],
                }}
              />
            </div>
            <span className="w-6 shrink-0 text-right font-mono text-xs text-ink-300">{count}</span>
          </div>
        );
      })}
    </div>
  );
}
