# Reviewed Scanner Allowlisting

NetSentinel can exempt explicitly approved vulnerability scanners from unique-port scan detection without creating broad or permanent blind spots.

## Safety model

Each approval must include:

- one exact host or a narrowly scoped network;
- a timezone-aware expiry timestamp;
- a human-readable operational reason;
- a change, ticket, or authorization reference.

IPv4 networks broader than `/28` and IPv6 networks broader than `/120` are rejected. Overlapping entries are rejected, and one policy may contain at most 64 entries. These limits keep approvals reviewable and prevent a convenience allowlist from becoming an uncontrolled detection exclusion.

## Fail-closed behavior

Expired entries no longer bypass detection. Invalid addresses, broad networks, naive timestamps, unknown fields, overlapping entries, and excessive cardinality fail validation rather than being silently accepted.

Allowlisting happens before event-window state is created. Traffic from an active approved scanner therefore does not consume detector capacity or trigger port-scan alerts. An expired approval is processed normally by the detector.

## Audit and privacy

Runtime snapshots expose only aggregate values:

- checks;
- allowed decisions;
- expired matches;
- configured entry count.

They do not expose scanner addresses, network ranges, reasons, ticket references, ports, or packet contents. The reviewed policy remains the authoritative source for those details.

## Operational procedure

1. Confirm the scanner owner, source address, target scope, and maintenance window.
2. Use an exact host whenever possible. Use a small network only when the scanner source cannot be represented safely as one address.
3. Set expiry to the end of the approved activity, not an indefinite future date.
4. Record a valid change or authorization reference.
5. Review aggregate `expired_matches` after the window. A non-zero value indicates traffic continued after authorization expired and should be investigated.
6. Remove obsolete entries from the versioned policy even though expiry already fails closed.

## Current limitations

- Policy loading from a signed deployment artifact is not implemented yet.
- Decisions and counters are process-local and reset on restart.
- Multiple detector workers do not share allowlist counters.
- Allowlisting applies only to bounded unique-port scan detection; it does not suppress unrelated detection rules.
