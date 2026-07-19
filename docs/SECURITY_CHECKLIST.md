# NetSentinel Security Checklist

Use this checklist before merging changes or publishing a release.

## Secrets and configuration

- [ ] No passwords, API keys, private keys, tokens, or connection strings are committed.
- [ ] Sensitive values are loaded from environment variables or a secrets manager.
- [ ] Example configuration files contain placeholders only.
- [ ] Debug mode is disabled in production.

## Dependencies

- [ ] Dependencies are pinned or constrained to reviewed versions.
- [ ] Known-vulnerability checks have been run.
- [ ] Unused dependencies have been removed.
- [ ] Dependency updates are reviewed before merging.

## Input and network safety

- [ ] External input is validated before use.
- [ ] File paths are normalized and restricted to approved locations.
- [ ] Timeouts and size limits are configured for network requests.
- [ ] Error messages do not expose sensitive internal details.

## Logging and monitoring

- [ ] Logs do not contain credentials, tokens, or personal data.
- [ ] Security-relevant actions are logged with useful context.
- [ ] Log rotation and retention are configured.
- [ ] Alerts have clear severity and remediation guidance.

## Release review

- [ ] Automated tests pass.
- [ ] Security-sensitive changes received manual review.
- [ ] Documentation reflects the current behavior.
- [ ] A rollback plan exists for production changes.
