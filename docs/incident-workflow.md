# Incident Workflow Foundation

NetSentinel persists investigation cases separately from alerts while keeping the originating alert identifier as an immutable evidence link.

## Case creation

`CaseManager.create_case_from_alert()` requires a persisted alert identifier and a non-empty title. Titles are normalized and bounded to 200 characters. New cases start in `Open` state and inherit the alert severity supplied by the caller.

The database foreign-key contract prevents a case from linking to an alert that does not exist. Case identity and the originating alert link are not mutable through the normal update API.

Every audited case mutation accepts an `actor`. Existing callers remain compatible through the explicit `system` actor default, while analyst-facing integrations should pass the authenticated username or service identity.

## Reviewed statuses

The current workflow accepts four explicit states:

- `Open`
- `In Progress`
- `Resolved`
- `Closed`

Unknown free-form states are rejected so dashboards and downstream automation can rely on a stable lifecycle vocabulary. Repeating the current state is treated as a no-op and does not create audit noise.

## Ownership

Cases may be assigned to one analyst/service identity through `CaseManager.assign_owner()`. Owner values are normalized, indexed, and bounded to 128 characters. `None` or blank input unassigns the case. Reassigning a case to its existing owner is a no-op.

Ownership is operational metadata, not an authorization decision. A later authorization layer must verify whether the current principal is permitted to mutate a case.

## Analyst notes

Analyst notes are appended rather than silently replacing prior notes. The combined notes field is bounded to 10,000 characters to keep the local case record predictable.

Audit events intentionally do not duplicate note contents. A `case.note_added` event records only the appended note length, reducing the chance that sensitive investigation text is copied into multiple persistence surfaces.

## Immutable audit history

Case creation, status changes, owner changes, and note appends create rows in `case_audit_events`. Each event has a unique event ID, case ID, bounded event type, bounded actor identity, before/after metadata, and creation time.

Case state and its audit event are written in the same database transaction. If audit persistence fails, the case mutation is rolled back. The normal database API exposes history reads but no update/delete method for audit rows.

History reads are oldest-first and bounded through the shared database limit contract. The default history read is limited to 500 rows and the global maximum remains 10,000.

## Persistence and migration behavior

`DatabaseManager` provides transactional case CRUD plus `insert_case_with_event()`, `update_case_with_event()`, and `get_case_history()` for audited workflow mutations. Case updates remain restricted to reviewed mutable fields.

Alembic revision `0002_case_audit_ownership` adds the indexed case owner column and the audit-event table. Downgrade is deliberately blocked because dropping the revision would destroy investigation evidence.

Local development schema bootstrapping also adds the owner column to older SQLite databases while `Base.metadata.create_all()` creates the new audit table. Production deployments must continue using Alembic rather than schema auto-creation.

## Verification

The focused `Case Contracts` workflow runs Ruff plus database, case workflow, and audit tests on Python 3.10 and 3.12. It covers:

- alert-to-case foreign-key persistence;
- immutable identity enforcement;
- reviewed status transitions and no-op suppression;
- bounded owner assignment and unassignment;
- transactional audit history;
- chronological bounded history reads;
- actor validation;
- note-content minimization in audit metadata;
- unknown-case behavior.

## Remaining work

The next incident-workflow slices should be shipped independently and with migrations where required:

1. structured evidence references and integrity metadata;
2. dashboard actions that create cases directly from alerts;
3. authenticated authorization boundaries for case mutation;
4. owner/status filtering and investigation queues;
5. alert-to-case and case-to-report integration tests;
6. retention/export policy for long-lived audit evidence.
