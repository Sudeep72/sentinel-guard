import { formatCategory } from "@/lib/severity";
import type { BaselineComparisonItem } from "@/lib/types";

export function BaselineComparisonTable({ items }: { items: BaselineComparisonItem[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-ink-500">No baseline rules available for this server.</p>;
  }

  return (
    <div className="overflow-hidden rounded-lg border border-base-600 bg-base-800 shadow-panel">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-base-600 text-xs uppercase tracking-wide text-ink-500">
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Category</th>
            <th className="px-4 py-3 font-medium">Rule</th>
            <th className="px-4 py-3 font-medium">Current</th>
            <th className="px-4 py-3 font-medium">Expected</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, idx) => (
            <tr
              key={`${item.category}-${item.rule}-${idx}`}
              className="border-b border-base-700 last:border-0"
            >
              <td className="px-4 py-3">
                {item.matches_baseline ? (
                  <span className="inline-flex items-center gap-1.5 text-xs text-success">
                    <span className="h-1.5 w-1.5 rounded-full bg-success" />
                    Pass
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs text-severity-critical">
                    <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
                    Fail
                  </span>
                )}
              </td>
              <td className="px-4 py-3 text-ink-500">{formatCategory(item.category)}</td>
              <td className="px-4 py-3 font-mono text-xs text-ink-300">{item.rule}</td>
              <td className="px-4 py-3 font-mono text-xs text-ink-300">
                {item.current_value ?? "—"}
              </td>
              <td className="px-4 py-3 font-mono text-xs text-ink-500">
                {item.expected_value ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
