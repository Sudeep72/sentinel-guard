# modules/

Server-side Guardian analyzers. Each subfolder interprets the raw facts
an agent collector sends and turns them into `Finding` records (title,
severity, why it matters, attack scenario, recommendation) by comparing
against `app/baselines/`. `registry.py` (Phase 8) is the plugin
registration point that lets future modules (vulnerability scanning,
compliance, etc.) register without touching core scan/scoring logic.

One subfolder per Guardian, populated in Phases 8–16.
