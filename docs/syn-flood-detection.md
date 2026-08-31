# TCP SYN Flood Detection

NetSentinel includes a bounded stateful detector for repeated TCP SYN traffic from one source to one destination service within a sliding time window.

## Decision model

A packet is eligible only when all of the following are true:

- protocol is TCP;
- source and destination IP addresses are present;
- destination port is present;
- the TCP flags contain SYN and do not contain ACK.

State is keyed by `(source_ip, destination_ip, destination_port)`. Every eligible SYN contributes one event to that flow. A match is produced only when the configured SYN threshold is reached exactly, so the detector does not emit a new decision for every later packet in the same window.

This is packet-rate evidence, not a completed-handshake counter. Retransmissions and deliberately generated SYN traffic can contribute to the observed count.

## Runtime integration

`DetectionEngine` evaluates the detector after packet validation and before declarative YAML rules. A match becomes a typed `AlertRecord` with:

- alert type `TCP SYN Flood`;
- severity `High`;
- MITRE ATT&CK technique `T1498`;
- the validated source and destination addresses;
- evidence containing the observed SYN count, destination port, and configured window;
- a 60-second duplicate-suppression cooldown before persistence.

The recommended analyst action is to validate whether the burst is expected, inspect upstream connection rates, and apply rate limiting or filtering when availability is at risk.

## Default policy

The default policy requires 100 eligible SYN packets within ten seconds for one source/destination/service flow.

State is bounded by:

- at most 10,000 tracked flows;
- at most 1,000 events retained per flow;
- deterministic sliding-window expiry;
- least-recently-used flow eviction under cardinality pressure.

The policy is immutable after validation. `max_events_per_flow` must always be at least the configured threshold so the detector cannot silently discard evidence needed to reach a decision.

## False-positive guidance

Legitimate traffic can resemble a SYN flood during:

- approved load or resilience testing;
- high-volume reverse-proxy or gateway traffic;
- aggressive monitoring or synthetic checks;
- scanner activity;
- retransmission bursts caused by packet loss or impaired upstream networks.

Analysts should correlate the alert with connection completion rates, service health, packet loss, asset role, maintenance windows, and known testing activity before treating it as malicious denial-of-service traffic.

## Observability and privacy

The detector exposes only aggregate bounded-state counters through `DetectionEngine.metrics_snapshot()`: tracked flows, tracked events, expired events, evicted flows, dropped events, and cardinality-limited events. Flow identifiers, IP addresses, destination ports, and packet payloads are not exported through this metrics surface.

## Verification

Focused tests cover:

- threshold crossing;
- SYN/ACK and non-TCP filtering;
- per-destination-service flow isolation;
- deterministic expiry;
- bounded flow capacity;
- invalid policy rejection;
- typed alert persistence through `DetectionEngine`;
- sanitized process-local metrics.

The Detection Contracts workflow runs these contracts on Python 3.10 and 3.12.

## Distributed deployments

Detector state is process-local and is cleared on restart. Multi-sensor or horizontally scaled deployments need explicit traffic partitioning or a shared-state design before interpreting counts as globally complete SYN rates.
