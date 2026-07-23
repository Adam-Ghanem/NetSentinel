# Detection Contract Boundaries

NetSentinel validates packet metadata, YAML rules, and alert payloads at component boundaries before detection logic or persistence uses them. The contracts live in `app/contracts.py` and use Pydantic models with unknown fields rejected by default.

## Packet metadata

`PacketMetadata` is the normalized output of `app.parser.parse_packet`.

The model enforces:

- timezone-capable `datetime` timestamps;
- valid IPv4 or IPv6 strings when addresses are present;
- ports in the range `0..65535`;
- non-negative packet sizes;
- normalized uppercase protocol names;
- a stable set of supported metadata fields.

The parser still returns a dictionary for compatibility with the existing analyzer, dashboard, and database code. That dictionary is produced only after `PacketMetadata` validation succeeds.

## Detection rules

`DetectionRule` validates each YAML rule during startup. Invalid rules are logged and skipped rather than reaching the evaluation loop in an ambiguous state.

A rule must provide:

- a non-empty name and description;
- one supported severity: `Low`, `Medium`, `High`, or `Critical`;
- at least one detection condition;
- valid ports and positive thresholds;
- valid regular expressions;
- a MITRE ATT&CK technique identifier such as `T1046` or `T1557.001` when mapped.

Unknown fields fail validation. Add a field to the contract and implement its evaluation semantics before adding it to production rule content.

## Alert persistence

`AlertRecord` is the only alert payload shape produced by `DetectionEngine`. It validates network addresses, severity, description length, and MITRE technique syntax before the payload reaches `DatabaseManager.insert_alert`.

The current database boundary expects primitive dictionaries, so `AlertRecord.to_persistence_dict()` preserves the existing schema while converting the severity enum to its stored string value.

## Authoring and review policy

When changing detection data structures:

1. Update the relevant contract first.
2. Add positive and negative validation tests.
3. Update parser, rule evaluation, or alert persistence code to consume the typed model.
4. Keep compatibility adapters explicit and temporary.
5. Run the focused checks below.

```bash
python -m ruff check app/contracts.py app/parser.py app/rules_engine.py app/detection_engine.py tests/test_detection_contracts.py tests/test_rules_engine_contracts.py tests/test_detection_engine_contracts.py tests/test_parser.py
python -m pytest tests/test_detection_contracts.py tests/test_rules_engine_contracts.py tests/test_detection_engine_contracts.py tests/test_parser.py
```

## Current limitations

The contracts validate structure and individual values. They do not yet provide bounded state windows, alert deduplication, suppression, rule lifecycle metadata, confidence scoring, or evidence provenance. Those capabilities belong to the next stateful detection-engine slice.
