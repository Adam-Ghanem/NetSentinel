from scripts.ingest_pcap import build_parser


def test_pcap_cli_defaults_are_bounded():
    args = build_parser().parse_args(["capture.pcap"])

    assert args.max_upload_mib == 64
    assert args.max_packets == 100_000
    assert args.max_parse_errors == 100


def test_pcap_cli_accepts_reviewed_boundary_overrides():
    args = build_parser().parse_args(
        [
            "capture.pcapng",
            "--database-url",
            "sqlite:///:memory:",
            "--max-upload-mib",
            "16",
            "--max-packets",
            "25000",
            "--max-parse-errors",
            "25",
        ]
    )

    assert args.capture == "capture.pcapng"
    assert args.database_url == "sqlite:///:memory:"
    assert args.max_upload_mib == 16
    assert args.max_packets == 25_000
    assert args.max_parse_errors == 25
