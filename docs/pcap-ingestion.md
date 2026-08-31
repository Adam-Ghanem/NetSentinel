# Bounded PCAP Ingestion

NetSentinel's reviewed PCAP ingestion service is designed to process untrusted capture files with explicit resource boundaries instead of loading an entire capture into memory.

## Security boundaries

The default `PcapIngestionPolicy` applies three independent limits:

- upload size: 64 MiB;
- packets processed: 100,000;
- tolerated packet parse failures: 100.

All limits are positive integers and are validated when the policy is created. A capture larger than the upload budget is rejected before packet parsing. Packet processing uses Scapy's streaming `PcapReader`, and malformed packets still consume the packet-processing budget so they cannot bypass the cap.

Uploaded file-like objects can be staged with `ingest_uploaded_capture()`. The upload is copied to a temporary file in bounded chunks, the byte limit is enforced while streaming, and the temporary file is removed in a `finally` block after success or failure.

## Failure semantics

Packet parser `TypeError` and `ValueError` failures consume the parse-error budget and skip the malformed packet. Once the budget is exceeded, ingestion fails closed with `PcapIngestionError`.

Database persistence failures are not reclassified as parse failures. They propagate to the caller so storage outages, schema faults, or validation errors are visible and cannot silently turn into packet skips.

## Result contract

Successful ingestion returns `PcapIngestionResult` with:

- `processed_packets`: packets consumed from the reader;
- `stored_packets`: packet metadata records successfully persisted;
- `parse_errors`: malformed packets skipped within policy;
- `truncated`: whether the packet budget stopped processing before EOF.

These values are aggregate operational evidence and do not include packet payloads, source addresses, destination addresses, or other high-cardinality labels.

## CLI usage

Use the bounded ingestion CLI for local or controlled workflows:

```bash
python scripts/ingest_pcap.py capture.pcap
```

Optional reviewed overrides:

```bash
python scripts/ingest_pcap.py capture.pcapng \
  --database-url sqlite:///netsentinel.db \
  --max-upload-mib 32 \
  --max-packets 50000 \
  --max-parse-errors 50
```

Treat increased limits as resource-policy changes. Review memory, disk, database throughput, capture provenance, and operational need before raising them.

## Current integration status

The bounded service and CLI are independent of the legacy Streamlit upload helper so they can be tested and reviewed without coupling ingestion policy to UI code. The dashboard should be migrated to `ingest_uploaded_capture()` in a separate UI-focused change after this contract is green; until then, operators who need the reviewed bounded path should use the CLI/service directly.

## Verification

The dedicated `PCAP Ingestion Contracts` GitHub Actions workflow runs Ruff and focused pytest coverage on Python 3.10 and 3.12. The repository's existing supply-chain and container security workflows remain required before merge.
