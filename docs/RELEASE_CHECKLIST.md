# NetSentinel release checklist

Use this checklist for a tagged release or a portfolio milestone. The goal is to make the release reproducible, reviewable, and safe to demonstrate.

## Change review

- [ ] The release scope is documented in `CHANGELOG.md` or the pull request body.
- [ ] All feature and security changes are merged through focused pull requests.
- [ ] Valuable commits remain visible; do not squash commits that represent separate reviewable work.
- [ ] Migration or configuration changes include operator notes and rollback guidance.

## Automated verification

- [ ] Ruff and the complete pytest suite pass.
- [ ] Secret-hygiene scanning passes.
- [ ] Dependency audit passes without unexplained suppressions.
- [ ] SBOM generation completes.
- [ ] Container build, health check, and security scan pass.
- [ ] Detection contract checks pass on every supported Python version.

## Runtime smoke checks

- [ ] The dashboard starts with safe defaults and rejects invalid production configuration.
- [ ] Database readiness and migration checks pass in a clean environment.
- [ ] A representative sample packet/PCAP workflow produces expected sanitized alerts.
- [ ] Report generation and alert/case workflows do not expose credentials or raw payloads.

## Publication

- [ ] Version and release notes are updated.
- [ ] The release commit is tagged using the repository's versioning policy.
- [ ] Build artifacts and SBOM evidence are attached or linked.
- [ ] Known limitations and next roadmap items are listed.
- [ ] Post-release monitoring and rollback owner are identified.
