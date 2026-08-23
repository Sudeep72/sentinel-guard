# SentinelGuard Dashboard (Web UI)

Next.js 14 (App Router) frontend for the SentinelGuard Dashboard. Consumes
the existing REST API exclusively — see [ARCHITECTURE.md](../ARCHITECTURE.md)
section 6. No business logic is duplicated here: scoring, baseline
comparison, and report generation all happen server-side; this app only
renders what the API returns.

## Pages

| Route | Purpose |
|---|---|
| `/login` | Sign in (JWT stored in localStorage) |
| `/dashboard` | Fleet-wide overview: average score, category scores, severity chart, recent scans |
| `/servers` | List of registered servers |
| `/servers/[id]` | Server detail: score gauge, category scores, findings, baseline comparison, scan history, report download |
| `/findings` | Fleet-wide findings table with severity/category/server filters |
| `/findings/[id]` | Full finding detail (why it matters, attack scenario, recommendation) |
| `/reports` | Generate/preview/download a report for any server in any format |
| `/settings` | Account info, API health, agent registration instructions |

## Local development

```bash
npm install
cp .env.example .env.local   # point at your running dashboard API
npm run dev
```

Requires the dashboard backend running (see `../dashboard/README.md`)
and at least one admin user registered.

## Design system

Dark operations-console aesthetic — deliberately not a generic light
SaaS template, since this is a security tool meant to be glanced at on
a second monitor. Key tokens (see `tailwind.config.js`):

- **Severity colors** drive the entire visual language: critical (red),
  high (orange), medium (yellow), low (blue), info (gray) — used
  consistently across badges, charts, and score gauges.
- **Monospace** (JetBrains Mono) for anything technical: check IDs,
  hostnames, config values, raw scores.
- **Signal blue** (`#4F8CFF`) as the single accent color for
  interactive elements and the active-nav indicator.
- **Score Gauge** (`components/ScoreGauge.tsx`) is the signature visual
  element — a circular arc gauge colored by score threshold, reused on
  both the Dashboard and Server Detail pages.

## Building

```bash
npm run lint    # ESLint (next/core-web-vitals)
npm run build   # Production build + TypeScript check
```

## API client

`lib/api-client.ts` is the *only* file that constructs requests to the
dashboard backend. Every page imports typed functions from it rather
than calling `fetch()` directly, so the request shape for each endpoint
is defined once.
