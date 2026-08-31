#!/usr/bin/env python3

import argparse
import json

from app.database import DatabaseManager
from app.pcap_ingestion import PcapIngestionPolicy, ingest_pcap_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely stream packet metadata from a PCAP/PCAPNG file into NetSentinel."
    )
    parser.add_argument("capture", help="Path to the capture file")
    parser.add_argument("--database-url", help="Override the configured database URL")
    parser.add_argument("--max-upload-mib", type=int, default=64)
    parser.add_argument("--max-packets", type=int, default=100_000)
    parser.add_argument("--max-parse-errors", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    policy = PcapIngestionPolicy(
        max_upload_bytes=args.max_upload_mib * 1024 * 1024,
        max_packets=args.max_packets,
        max_parse_errors=args.max_parse_errors,
    )
    database = DatabaseManager(db_url=args.database_url) if args.database_url else DatabaseManager()
    result = ingest_pcap_file(args.capture, database, policy=policy)
    print(
        json.dumps(
            {
                "processed_packets": result.processed_packets,
                "stored_packets": result.stored_packets,
                "parse_errors": result.parse_errors,
                "truncated": result.truncated,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
