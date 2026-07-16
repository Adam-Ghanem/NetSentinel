# NetSentinel Professionalization Roadmap

This roadmap prioritizes small, reviewable changes that move NetSentinel from an educational prototype toward a credible portfolio-grade NDR/SOC platform. Each item should ship with tests, documentation, and a focused pull request.

## P0 — Quality and Safety Foundations

1. **Automated quality gate** — add focused unit tests, linting, and GitHub Actions; expand coverage module by module.
2. **Configuration validation and secrets hygiene** — typed settings, startup validation, `.env.example`, safe defaults, and secret scanning.
3. **Dependency reproducibility and scanning** — pin runtime dependencies, add update policy, vulnerability scanning, and SBOM generation.
4. **Database reliability** — transactional error handling, schema migration strategy, deterministic test database fixtures, and backup guidance.
5. **Docker reliability** — non-root container, health checks, graceful shutdown, persistent volumes, and reproducible builds.

## P1 — Detection and SOC Workflow

6. **Typed detection interfaces** — explicit packet, rule, alert, and enrichment models with validated boundaries.
7. **Stateful detection engine** — reliable time windows, bounded state, deduplication, suppression, and deterministic tests.
8. **Detection engineering content** — realistic sample traffic, rule metadata, severity rationale, false-positive guidance, and MITRE ATT&CK mappings.
9. **Alert enrichment** — normalized IOC context, cache expiry, provider failure handling, confidence fields, and evidence provenance.
10. **Incident workflow** — alert-to-case linking, status transitions, ownership, notes, evidence, and audit history.

## P2 — API, Observability, and Performance

11. **Service boundary/API quality** — separate collection, detection, persistence, and UI concerns; add versioned schemas and consistent errors.
12. **Structured logging** — correlation IDs, safe field redaction, actionable event names, and configurable output.
13. **Health and readiness checks** — database, rule loading, storage, and optional provider status.
14. **Metrics** — ingestion rate, parse failures, alert counts, rule latency, enrichment latency, and queue/backpressure signals.
15. **Performance controls** — bounded queues, batch writes, indexes, profiling fixtures, and documented capacity limits.

## P3 — Product and Release Readiness

16. **Dashboard workflow polish** — realistic demo data, investigation-first navigation, empty/error/loading states, and accessibility checks.
17. **Integration tests** — PCAP-to-alert, alert-to-case, report generation, and container smoke tests.
18. **Documentation set** — architecture diagram, threat model, deployment guide, detection authoring guide, troubleshooting, and screenshots.
19. **Contributor experience** — Makefile/task runner, pre-commit hooks, contribution guide, issue/PR templates, and local test commands.
20. **Release process** — semantic versioning, changelog, release checklist, signed/tagged releases, and published artifacts.

## Current Focus

The first delivered slice establishes a parser quality gate with deterministic tests and CI on supported Python versions. The next recommended item is configuration validation and secrets hygiene because configuration failures and accidental credential exposure are high-impact risks for a security project.
