## Summary

What does this PR change and why?

## Scope check

- [ ] This change is within v1 scope per [ROADMAP.md](../ROADMAP.md)
      (not one of the explicitly deferred features)
- [ ] This change follows the approved [ARCHITECTURE.md](../ARCHITECTURE.md)
      design (or explicitly proposes an architecture change, flagged below)

## Type of change

- [ ] Bug fix
- [ ] New feature (Guardian, MCP tool, API endpoint, UI page, etc.)
- [ ] Documentation
- [ ] Refactor (no behavior change)
- [ ] CI/tooling

## How was this tested?

Describe the tests added/run. Include coverage of edge cases where
relevant (e.g. for Guardians: multiple distros, missing files,
permission-denied scenarios).

## Checklist

- [ ] Code has type hints (Python) / types (TypeScript)
- [ ] Public functions/classes have docstrings
- [ ] New code has unit tests
- [ ] `ruff`, `black --check`, `mypy` pass locally (Python changes)
- [ ] `npm run lint` and `npm run build` pass locally (frontend changes)
- [ ] Updated relevant docs (README/ARCHITECTURE/CHANGELOG) if behavior
      or structure changed
- [ ] No hardcoded values (paths, URLs, credentials) — configuration
      goes through environment variables / settings

## Related issues

Closes #
