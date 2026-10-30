#!/usr/bin/env python3
"""BusyBrains OSINT — Institutional and Web Intelligence."""

import argparse
import json
import sys

from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import app


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def collect_institutional_page(url):
    """
    Collect text from a public HTTPS webpage.

    Network restrictions and response-size limits are inherited
    from the existing BusyBrains OSINT web collector.
    """

    title, text = app.collect_public_page(url)

    return {
        "module": "BusyBrains OSINT Institutional Intelligence",
        "collected_at": utc_now(),
        "source_url": url,
        "page_title": title,
        "extracted_text": text,
        "collection_method": "Public HTTPS webpage",
        "limitations": [
            "Only information returned by the webpage is collected.",
            "The page content may change over time.",
            "Information should be verified against its source.",
            "This module does not authenticate institutional claims.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Collect publicly accessible institutional webpage text."
        )
    )

    parser.add_argument(
        "--case",
        type=int,
        required=True,
        help="Existing investigation ID",
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Public HTTPS webpage to examine",
    )

    parser.add_argument(
        "--institution",
        required=True,
        help="Institution name for the evidence record",
    )

    args = parser.parse_args()

    institution = args.institution.strip()

    if not institution:
        parser.error("--institution cannot be empty")

    try:
        app.initialize_database()
        app.get_case(args.case)

        result = collect_institutional_page(args.url)
        result["institution"] = institution

        finding_id = app.add_finding(
            args.case,
            "institutional-intelligence",
            f"Institutional webpage: {institution}",
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            ),
            args.url,
        )

        print(json.dumps(result, indent=2, ensure_ascii=False))
        print()
        print(f"Investigation ID: {args.case}")
        print(f"Finding ID: {finding_id}")

    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
