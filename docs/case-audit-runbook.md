# Case Audit and Ownership Runbook

This runbook describes how analysts and maintainers should use NetSentinel case ownership and audit history in authorized defensive environments.

## Assignment workflow

1. Create a case from a persisted alert and pass the authenticated analyst or service identity as `actor`.
2. Assign a single current owner with `CaseManager.assign_owner()`.
3. Move the case through the reviewed lifecycle (`Open`, `In Progress`, `Resolved`, `Closed`).
4. Append analyst notes rather than replacing prior narrative.
5. Review `get_case_history()` when validating who changed ownership or state.

Blank ownership intentionally means unassigned. Ownership is not authorization; callers must still enforce access control before invoking a mutation.

## Audit evidence expectations

The audit table is append-only through the supported application API. It records case creation, owner changes, status changes, and note additions. Case state and its corresponding event are committed in one transaction so a failed audit write cannot leave an unaudited state change.

Audit rows intentionally store only bounded metadata. Analyst note text is not copied into audit history; note events contain the appended character count instead.

## Triage checks

When a case appears inconsistent:

- confirm the originating alert still exists;
- inspect history oldest-first;
- verify the latest owner/status event matches the case row;
- verify no unexpected event type or actor appears;
- use `case_workflow_metrics()` only for aggregate workload checks, not evidence review.

A repeated request to assign the existing owner or set the existing status is a no-op and should not create a new event.

## Privacy boundary

Do not expose raw audit rows through unauthenticated metrics endpoints. Actor identities and case IDs are investigation metadata. The aggregate workflow metrics intentionally expose only counts for total/owned/unowned cases, lifecycle states, and total audit events.

## Retention and export

The current implementation does not delete audit evidence automatically. Before deploying beyond a lab, define retention requirements, backup behavior, export controls, and access logging appropriate to the environment.

Do not implement destructive downgrade or bulk audit deletion merely to simplify schema rollback. The Alembic migration deliberately blocks downgrade because it would destroy evidence.

## Failure response

If an audited mutation raises a database error, treat the operation as failed and retry only after the storage problem is understood. The transaction boundary rolls back both the case update and audit event.

If database health reports the audit table missing after deployment, stop case mutations and apply the reviewed Alembic migration before resuming analyst workflow.

## Verification

The `Case Contracts` GitHub Actions workflow covers ownership, audit transaction semantics, event ordering, privacy minimization, no-op suppression, bounded history reads, and aggregate metrics on Python 3.10 and 3.12.
