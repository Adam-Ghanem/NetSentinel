# Detection rule lifecycle metadata

NetSentinel rules can carry stable lifecycle metadata without changing their matching semantics.

## Metadata

```yaml
rule_id: netsentinel.unusual-port
version: 3
status: active
owner: detection-team
last_reviewed_at: "2026-08-01T12:00:00Z"
```

- `rule_id` is a stable 3–64 character identifier using lowercase letters, digits, `.`, `_`, and `-`.
- `version` is a positive integer and should be incremented when the rule's detection logic or operational meaning changes.
- `status` is currently `active` or `deprecated`.
- `owner` identifies the accountable detection maintainer or team.
- `last_reviewed_at` records review evidence and must include an explicit timezone.

Lifecycle metadata is optional for existing rules so the contract can be adopted incrementally. Once a stable `rule_id` is supplied, `owner` and `last_reviewed_at` are mandatory. This prevents a rule from claiming durable identity without accountable ownership and review evidence.

## Review expectations

1. Keep `rule_id` stable across content edits so alert and analytics consumers can correlate the same rule.
2. Increment `version` when detection semantics change; documentation-only edits do not require a version change.
3. Use `deprecated` before removing a rule so operators have an explicit lifecycle signal during rollout.
4. Update `last_reviewed_at` during each detection-content review and keep the timestamp in UTC or another explicit timezone.
5. Treat ownership as operational accountability, not as an authorization mechanism; repository review and CI remain required for rule changes.

Lifecycle metadata does not itself disable deprecated rules yet. Runtime lifecycle enforcement is intentionally a separate change so rule inventory, authoring, and evaluation semantics can be introduced and tested independently.
