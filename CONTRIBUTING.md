# Contributing to NetSentinel

NetSentinel is a defensive network-monitoring project. Contributions should improve reliability, detection quality, operator safety, or developer experience without weakening security controls.

## Before opening a pull request

1. Create a focused branch from `main` or from the smallest relevant feature branch.
2. Keep each commit independently meaningful: implementation, tests, documentation, CI/configuration, refactoring, observability, security hardening, or release engineering.
3. Add or update tests for behavior changes and update the relevant documentation.
4. Run the narrowest useful checks locally before expanding to the full suite.
5. Do not commit secrets, packet payloads containing sensitive data, generated reports, local databases, or environment files.

## Local checks

```bash
python -m ruff check .
python -m pytest
python scripts/check_secrets.py .
```

For changes touching Docker, also run the local image build and confirm that the health check succeeds. For detection changes, include boundary tests for invalid configuration, expiry, bounded state, privacy, and false-positive behavior where applicable.

## Detection and security expectations

- Prefer fail-closed validation for policy and configuration boundaries.
- Keep observability aggregate-only unless a field is explicitly required for investigation.
- Treat external enrichment as untrusted input and preserve provenance for fresh results.
- Never bypass `pip-audit`, secret scanning, container scanning, or required CI checks to make a pull request green.
- Explain operational risk, rollback considerations, and compatibility impact in the pull request body.

## Pull request checklist

A good pull request includes:

- a concise problem statement;
- the design and security impact;
- focused commits with clear messages;
- tests and commands run;
- documentation updates;
- known risks and follow-up work;
- an explicit merge policy.

Use a normal merge or rebase strategy that preserves valuable commits. Avoid squash-merging work that is intentionally split for review and attribution.
