# Unique Destination-Port Scan Detection

NetSentinel includes a bounded detector for TCP SYN traffic that reaches multiple unique destination ports on the same destination host within a sliding time window.

## Decision model

A packet is eligible only when all of the following are true:

- protocol is TCP;
- source and destination IP addresses are present;
- destination port is present;
- the TCP flags contain SYN and do not contain ACK.

State is keyed by `(source_ip, destination_ip)`. Repeated packets to the same destination port do not increase the unique-port count. A detection result is produced only when the configured threshold is crossed exactly, which avoids repeated results for every later port in the same window.

## Runtime integration

`DetectionEngine` evaluates the bounded detector after packet validation and before declarative YAML rules. A match is converted into a typed `AlertRecord` with:

- alert type `Unique Destination Port Scan`;
- severity `High`;
- MITRE ATT&CK technique `T1046`;
- source and destination addresses from the validated packet;
- sanitized evidence containing only the unique-port count and time-window duration;
- a 60-second duplicate-suppression cooldown before persistence.

The alert is persisted through the same validated database boundary used by other detections. The component does not store packet payloads, and its evidence does not include the individual destination ports.

## Safety properties

- Uses a monotonic clock for deterministic expiry.
- Limits the maximum number of tracked source/destination pairs.
- Limits events stored for each pair.
- Evicts least-recently-used keys under cardinality pressure.
- Exposes aggregate metrics without IP addresses, ports, or packet payloads.
- Keeps process-local state only and clears it on restart.
- Emits only at threshold crossing, then relies on the shared suppression boundary.

## Default policy

The detector defaults to five unique destination ports in ten seconds. Operators should tune thresholds only from validated evidence because vulnerability scanners, monitoring systems, and administrative discovery tools can legitimately contact many ports.

Approved scanners should be identified through operational context rather than silently excluding broad address ranges. Analysts should validate asset ownership, change windows, scanner identity, and destination role before closing an alert as expected activity.

## Verification

Focused tests cover:

- no persistence before threshold;
- typed alert persistence at threshold;
- duplicate destination-port handling;
- isolation between source addresses;
- protocol and TCP flag filtering;
- expiry and bounded-state behavior in the detector component.

The Detection Contracts workflow runs the detector and engine-integration suites on Python 3.10 and 3.12.

## Distributed deployments

State is not shared across workers or sensors. Horizontal deployments need an explicitly designed shared-state backend or deterministic traffic partitioning before relying on globally complete scan counts. Until then, port-scan metrics and decisions must be interpreted as process-local evidence.
