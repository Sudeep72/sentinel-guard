import { scoreColor, scoreLabel } from "@/lib/severity";

interface ScoreGaugeProps {
  score: number;
  size?: number;
  label?: string;
}

/**
 * A circular arc gauge showing the overall security score.
 *
 * This is the dashboard's signature visual element — used on both the
 * Dashboard overview and Server Detail pages so a score always renders
 * identically no matter where it appears.
 */
export function ScoreGauge({ score, size = 180, label = "Overall Score" }: ScoreGaugeProps) {
  const clamped = Math.max(0, Math.min(100, score));
  const radius = size / 2 - 12;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);
  const color = scoreColor(clamped);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#232936"
          strokeWidth={12}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={12}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text
          x="50%"
          y="48%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="font-mono font-bold"
          fill="#E4E7EC"
          fontSize={size * 0.22}
        >
          {clamped.toFixed(0)}
        </text>
        <text
          x="50%"
          y="66%"
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#8B93A7"
          fontSize={size * 0.07}
        >
          / 100
        </text>
      </svg>
      <p className="mt-2 text-sm font-medium text-ink-300">{label}</p>
      <p className="text-xs" style={{ color }}>
        {scoreLabel(clamped)}
      </p>
    </div>
  );
}
