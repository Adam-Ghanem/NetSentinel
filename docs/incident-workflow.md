# Incident Workflow Foundation

NetSentinel persists investigation cases separately from alerts while keeping the originating alert identifier as an immutable evidence link.

## Case creation

`CaseManager.create_case_from_alert()` requires a persisted alert identifier and a non-empty title. Titles are normalized and bounded to 200 characters. New cases start in `Open` state and inherit the alert severity supplied by the caller.

The database foreign-key contract prevents a case from linking to an alert that does not exist. Case identity and the originating alert link are not mutable through the normal update API.

## Reviewed statuses

The current workflow accepts four explicit states:

- `Open`
- `In Progress`
- `Resolved`
- `Closed`

Unknown free-form states are rejected so dashboards and downstream automation can rely on a stable lifecycle vocabulary.

## Analyst notes

Analyst notes are appended rather than silently replacing prior notes. The combined notes field is bounded to 10,000 characters to keep the local case record predictable. This is a foundation, not a complete audit log: author identity, per-note timestamps, and immutable note history remain future work.

## Persistence behavior

`DatabaseManager` now provides transactional `insert_case()`, `get_case()`, and `update_case()` methods. Updates are restricted to reviewed mutable fields (`title`, `analyst_notes`, `status`, `severity`, and `tags`). Attempts to mutate case identity or the originating alert link are rejected.

## Verification

The focused `Case Contracts` workflow runs Ruff plus the database and case workflow tests on Python 3.10 and 3.12. It covers:

- alert-to-case foreign-key persistence;
- case lookup and updates;
- immutable identity enforcement;
- reviewed status transitions;
- title validation;
- analyst-note append semantics;
- unknown-case behavior.

## Remaining work

The next incident-workflow slices should be shipped independently and with migrations where required:

1. case ownership and assignment;
2. immutable case event/audit history;
3. structured evidence attachments;
4. dashboard actions that create cases directly from alerts;
5. authorization boundaries for case mutation;
6. alert-to-case and case-to-report integration tests.
