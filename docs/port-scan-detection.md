# Unique Destination-Port Scan Detection

NetSentinel includes a bounded detector component for TCP SYN traffic that reaches multiple unique destination ports on the same destination host within a sliding time window.

## Decision model

A packet is eligible only when all of the following are true:

- protocol is TCP;
- source and destination IP addresses are present;
- destination port is present;
- the TCP flags contain SYN and do not contain ACK.

State is keyed by `(source_ip, destination_ip)`. Repeated packets to the same destination port do not increase the unique-port count. A detection result is produced only when the configured threshold is crossed exactly, which avoids repeated results for every later port in the same window. Alert suppression remains a separate responsibility when this component is wired into persistence.

## Safety properties

- Uses a monotonic clock for deterministic expiry.
- Limits the maximum number of tracked source/destination pairs.
- Limits events stored for each pair.
- Evicts least-recently-used keys under cardinality pressure.
- Exposes aggregate metrics without IP addresses, ports, or packet payloads.
- Keeps process-local state only and clears it on restart.

## Default policy

The component defaults to five unique destination ports in ten seconds, matching the reviewed `Port Scan Detection` rule policy. Operators should tune thresholds only from validated evidence because vulnerability scanners, monitoring systems, and administrative discovery tools can legitimately contact many ports.

## Current integration boundary

The detector is intentionally isolated from alert persistence in this change. This allows its expiry, cardinality, and false-positive behavior to be verified independently before replacing the existing aggregate-statistics rule path. The next integration step should route a match through the typed `AlertRecord` and existing per-rule suppression policy with MITRE ATT&CK technique `T1046`.

## Distributed deployments

State is not shared across workers or sensors. Horizontal deployments need an explicitly designed shared-state backend or deterministic traffic partitioning before relying on globally complete scan counts.
