# Periodic Network Beacon Detection

NetSentinel includes a bounded detector for regular outbound-style TCP connection attempts whose cadence is consistent enough to warrant command-and-control investigation.

## Decision model

A packet is eligible only when all of the following are true:

- protocol is TCP;
- source and destination IP addresses are present;
- destination port is present;
- the TCP flags contain SYN and do not contain ACK.

State is keyed by `(source_ip, destination_ip, destination_port)`. The detector stores monotonic observation timestamps, calculates adjacent inter-arrival intervals over the most recent configured observations, and requires:

- at least the configured minimum number of connections;
- every adjacent interval to meet the minimum interval duration;
- interval population variance to remain at or below the configured maximum.

A match therefore represents regular timing evidence, not proof that a destination is malicious or that an application-layer C2 protocol exists.

## Runtime integration

`DetectionEngine` converts a match into a typed `AlertRecord` with:

- alert type `Periodic Network Beacon`;
- severity `High`;
- MITRE ATT&CK technique `T1071`;
- validated source and destination addresses;
- evidence containing connection count, destination port, mean interval, and observation window;
- a 300-second duplicate-suppression cooldown before persistence.

The analyst guidance is to verify whether the destination and cadence belong to approved software and, when they do not, inspect both endpoint and destination for command-and-control behavior.

## Default policy

The default policy requires five eligible connections inside a 600-second window. Adjacent intervals must be at least ten seconds, with population variance no greater than `4.0` seconds squared.

State is bounded by:

- at most 10,000 tracked flows;
- at most 100 observations retained per flow;
- deterministic sliding-window expiry;
- least-recently-used flow eviction under cardinality pressure.

The policy is immutable after validation, and `max_events_per_flow` must be at least `min_connections`.

## False-positive guidance

Regular timing is common in legitimate software. Likely benign sources include:

- endpoint management agents;
- telemetry and metrics exporters;
- health checks and service discovery;
- update clients;
- backup agents;
- VPN or security products;
- scheduled application polling.

Analysts should correlate cadence with asset role, process identity, destination reputation, DNS history, TLS or HTTP metadata, change windows, and approved software inventories before escalating.

## Limitations

This detector currently observes TCP SYN cadence only. It does not:

- inspect application payloads;
- detect DNS-only beaconing;
- identify jittered or intentionally irregular C2 reliably;
- prove successful TCP handshakes;
- correlate the same logical service across multiple destination IP addresses.

Future detector-specific work should be based on measured false-positive data rather than silently widening this decision model.

## Observability and privacy

The metrics snapshot exports aggregate bounded-state counters only: tracked flows/events, expired events, evicted flows, dropped events, and cardinality-limited events. It does not export IP addresses, ports, raw timestamps, or packet payloads.

## Verification

Focused tests cover:

- stable-interval matching;
- rejection of irregular cadence;
- rejection of rapid bursts;
- protocol and flag filtering;
- expiry and bounded flow state;
- invalid policy rejection;
- typed engine alert persistence;
- sanitized metrics integration.

The Detection Contracts workflow runs these contracts on Python 3.10 and 3.12.

## Distributed deployments

Beacon state is process-local and clears on restart. Horizontal deployments need deterministic traffic partitioning or an explicitly designed shared-state backend before treating process-local cadence evidence as globally complete.
