# Contributing to SentinelGuard

Thanks for your interest in contributing. SentinelGuard is early-stage
and being built deliberately, phase by phase — please read this before
opening a PR.

## Before you start

1. Check [ROADMAP.md](./ROADMAP.md) to confirm what's in scope for the
   current version. PRs implementing out-of-scope features (see the
   "explicitly out of scope" table) will be asked to wait for the
   relevant version's build phase.
2. Check open issues/PRs to avoid duplicate work.
3. For anything non-trivial, open an issue first to discuss approach
   before writing code.

## Development setup

Setup instructions will be added here once the agent and dashboard have
runnable scaffolding (tracked in the implementation phases). In the
interim, see `agent/`, `dashboard/`, and `frontend/` for the current
folder layout and per-directory READMEs describing intended contents.

## Code standards

- **Python**: type hints required on all public functions; formatted
  with Black, linted with Ruff, type-checked with MyPy.
- **TypeScript/React**: functional components, Tailwind for styling.
- **Tests**: every new module ships with unit tests. No PR merges
  without tests for the code it adds.
- **Docstrings**: every public function/class gets a docstring
  explaining purpose, args, and return value.
- **No hardcoded values**: configuration goes through environment
  variables / settings objects, never inline constants for things like
  paths, URLs, or credentials.

## Commit style

Conventional, imperative-mood commit subjects, e.g.:

```
feat(agent): implement SSH Guardian collector
fix(dashboard): correct category score rounding
docs: update MCP tool contract for compare_to_baseline
test(agent): add unit tests for permission guardian
```

## Pull requests

- Keep PRs scoped to a single logical change.
- Fill out the PR template completely.
- CI (Ruff, Black, MyPy, Pytest) must pass before review.
- At least one maintainer approval required before merge (see
  CODEOWNERS).

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For security
vulnerabilities, do **not** open a public issue — see
[SECURITY.md](./SECURITY.md).

## Code of Conduct

By participating, you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).
