"""Command-line interface for Floppy Audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from floppy_audit import __version__
from floppy_audit.audit import (
    AuditError,
    audit_export,
    download_export,
    render_html,
    write_bytes,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify one DID's records in a Technocore room export."
    )
    parser.add_argument("room", help="Technocore room name")
    parser.add_argument("--did", required=True, help="Ed25519 did:key to find and verify")
    parser.add_argument("--base-url", default="https://technocore.chat")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--archive", type=Path, help="save the exact raw JSONL export")
    parser.add_argument(
        "--json-output", type=Path, default=Path("floppy-audit.json")
    )
    parser.add_argument(
        "--html-output", type=Path, default=Path("floppy-audit.html")
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw_export, generation = download_export(
            args.room, args.base_url, args.timeout
        )
        report = audit_export(raw_export, args.room, args.did)
        report["source"] = f"{args.base_url.rstrip('/')}/r/{args.room}/export"
        report["room_generation"] = generation
        write_bytes(
            args.json_output,
            (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode(),
        )
        write_bytes(args.html_output, render_html(report).encode())
        if args.archive:
            write_bytes(args.archive, raw_export)
    except AuditError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"audited {report['counts']['records']} records; found "
        f"{report['target']['valid']} valid and {report['target']['invalid']} "
        f"invalid for {args.did}"
    )
    print(args.json_output.resolve())
    print(args.html_output.resolve())
    if args.archive:
        print(args.archive.resolve())
    if not report["target"]["records"]:
        return 3
    return 2 if report["target"]["invalid"] else 0
