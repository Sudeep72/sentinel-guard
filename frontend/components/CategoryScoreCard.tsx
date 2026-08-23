import { formatCategory, scoreColor } from "@/lib/severity";
import type { CategoryScore } from "@/lib/types";

export function CategoryScoreCard({ category, score, weight }: CategoryScore) {
  const color = scoreColor(score);
  return (
    <div className="rounded-lg border border-base-600 bg-base-800 p-4 shadow-panel">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs uppercase tracking-wide text-ink-500">
          {formatCategory(category)}
        </span>
        <span className="text-[10px] text-ink-700">weight {(weight * 100).toFixed(0)}%</span>
      </div>
      <div className="mt-2 flex items-baseline gap-1">
        <span className="font-mono text-2xl font-bold" style={{ color }}>
          {score.toFixed(0)}
        </span>
        <span className="text-xs text-ink-700">/100</span>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-base-700">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${Math.max(0, Math.min(100, score))}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}
