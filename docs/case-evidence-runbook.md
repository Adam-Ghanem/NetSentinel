# Structured Case Evidence Runbook

NetSentinel case evidence is an append-only investigation record. It stores bounded metadata that helps an analyst explain what was reviewed without turning audit history into a second copy of sensitive evidence.

## Evidence contract

Each record has a generated `evidence_id`, owning `case_id`, evidence type, source, reference, optional summary, analyst identity, and creation time. Required text fields are normalized before persistence and every field is bounded to prevent unbounded case growth.

Evidence is intentionally append-only. Corrections should be added as new evidence with a new reference and a summary explaining the superseded item. There are no update or delete methods in the case workflow boundary.

## Audit behavior

Adding evidence and its `case.evidence_added` audit event happens in one database transaction. The audit event contains only the generated evidence ID and evidence type. It does not copy the evidence reference or analyst summary into audit history.

This split keeps the audit trail useful while reducing accidental propagation of investigation-sensitive content.

## Operational guidance

Prefer stable references such as hashes, immutable object identifiers, saved-query identifiers, or evidence-store handles. Do not place credentials, authentication tokens, raw packet payloads, or secrets in the reference or summary fields.

When evidence must be removed for legal, privacy, or retention reasons, treat that as a governed data-lifecycle operation outside the normal case API. The application deliberately provides no analyst-facing delete path.

## Failure handling

If case lookup fails, no evidence or audit event is written. If either evidence persistence or audit persistence raises inside the transaction, both changes roll back together.

Schema migration `0003_case_structured_evidence` creates the evidence table and indexes. Its downgrade is intentionally blocked because a downgrade would destroy investigation evidence.
