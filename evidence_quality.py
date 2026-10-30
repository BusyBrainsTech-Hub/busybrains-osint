#!/usr/bin/env python3
"""Evidence quality and analyst assessment tools for BusyBrains OSINT."""

import argparse
import sqlite3
import sys
from datetime import datetime, timezone

import app as core

CLASSIFICATIONS = (
    "observed_fact",
    "analyst_assessment",
    "unverified_lead",
)

CONFIDENCE_LEVELS = ("high", "medium", "low")

SOURCE_REVIEWS = (
    "verified",
    "needs_verification",
    "not_applicable",
)


def connect():
    db = sqlite3.connect(str(core.DB_PATH))
    db.row_factory = sqlite3.Row
    return db


def initialise():
    core.initialize_database()
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS finding_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE,
                classification TEXT NOT NULL,
                confidence TEXT NOT NULL,
                source_review TEXT NOT NULL,
                rationale TEXT NOT NULL,
                analyst TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)
        db.commit()


def get_finding(finding_id):
    with connect() as db:
        row = db.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()

    if row is None:
        raise ValueError(f"Finding {finding_id} does not exist.")
    return dict(row)


def save_assessment(args):
    finding = get_finding(args.finding)

    if not args.rationale.strip():
        raise ValueError("Rationale cannot be empty.")

    if not args.analyst.strip():
        raise ValueError("Analyst label cannot be empty.")

    if args.source_review == "verified" and not finding.get("source_url"):
        raise ValueError(
            "This finding has no recorded source URL. "
            "Use --source-review needs_verification or not_applicable."
        )

    assessed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connect() as db:
        db.execute("""
            INSERT INTO finding_assessments (
                finding_id, classification, confidence,
                source_review, rationale, analyst, assessed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                classification = excluded.classification,
                confidence = excluded.confidence,
                source_review = excluded.source_review,
                rationale = excluded.rationale,
                analyst = excluded.analyst,
                assessed_at = excluded.assessed_at
        """, (
            args.finding,
            args.classification,
            args.confidence,
            args.source_review,
            args.rationale.strip(),
            args.analyst.strip(),
            assessed_at,
        ))
        db.commit()

    print(f"Assessment saved for finding #{args.finding}")
    print(f"Classification: {args.classification}")
    print(f"Confidence: {args.confidence}")
    print(f"Source review: {args.source_review}")
    print(f"Analyst: {args.analyst}")
    print(f"Assessed at: {assessed_at}")
    print("Original finding preserved.")


def list_assessments(case_id):
    with connect() as db:
        rows = db.execute("""
            SELECT
                f.id AS finding_id,
                f.title,
                f.category,
                f.source_url,
                f.collected_at,
                a.classification,
                a.confidence,
                a.source_review,
                a.rationale,
                a.analyst,
                a.assessed_at
            FROM findings AS f
            LEFT JOIN finding_assessments AS a
                ON a.finding_id = f.id
            WHERE f.case_id = ?
            ORDER BY f.id DESC
        """, (case_id,)).fetchall()

    if not rows:
        print(f"No findings found for case #{case_id}.")
        return

    print(f"Evidence quality review — case #{case_id}")
    print("=" * 72)

    for row in rows:
        item = dict(row)
        print(f"\nFinding #{item['finding_id']}: {item['title']}")
        print(f"  Category:       {item['category']}")
        print(f"  Source URL:     {item['source_url'] or 'MISSING'}")
        print(f"  Collected:      {item['collected_at'] or 'NOT RECORDED'}")

        if item["classification"]:
            print(f"  Classification: {item['classification']}")
            print(f"  Confidence:     {item['confidence']}")
            print(f"  Source review:  {item['source_review']}")
            print(f"  Rationale:      {item['rationale']}")
            print(f"  Analyst:        {item['analyst']}")
            print(f"  Assessed at:    {item['assessed_at']}")
        else:
            print("  Assessment:     NOT REVIEWED")
            print(
                "  Action:         Review this finding before relying on it."
            )


def show_summary(case_id):
    with connect() as db:
        row = db.execute("""
            SELECT
                COUNT(f.id) AS total,
                SUM(CASE WHEN a.finding_id IS NOT NULL THEN 1 ELSE 0 END)
                    AS reviewed,
                SUM(CASE WHEN a.finding_id IS NULL THEN 1 ELSE 0 END)
                    AS unreviewed,
                SUM(CASE WHEN a.source_review = 'needs_verification'
                    THEN 1 ELSE 0 END) AS needs_verification,
                SUM(CASE WHEN a.confidence = 'low'
                    THEN 1 ELSE 0 END) AS low_confidence
            FROM findings AS f
            LEFT JOIN finding_assessments AS a
                ON a.finding_id = f.id
            WHERE f.case_id = ?
        """, (case_id,)).fetchone()

    print(f"Evidence quality summary — case #{case_id}")
    print(f"Total findings:            {row['total'] or 0}")
    print(f"Reviewed:                  {row['reviewed'] or 0}")
    print(f"Awaiting review:           {row['unreviewed'] or 0}")
    print(f"Needs source verification: {row['needs_verification'] or 0}")
    print(f"Low-confidence findings:   {row['low_confidence'] or 0}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="busybrains-quality",
        description="Review evidence quality for BusyBrains OSINT findings.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    assess = commands.add_parser(
        "assess",
        help="Record or update an assessment for a finding",
    )
    assess.add_argument("--finding", type=int, required=True)
    assess.add_argument(
        "--classification",
        choices=CLASSIFICATIONS,
        required=True,
    )
    assess.add_argument(
        "--confidence",
        choices=CONFIDENCE_LEVELS,
        required=True,
    )
    assess.add_argument(
        "--source-review",
        choices=SOURCE_REVIEWS,
        required=True,
    )
    assess.add_argument("--rationale", required=True)
    assess.add_argument("--analyst", default="BusyBrains analyst")

    listing = commands.add_parser(
        "list",
        help="List findings and their evidence assessments for a case",
    )
    listing.add_argument("--case", type=int, required=True)

    summary = commands.add_parser(
        "summary",
        help="Show evidence-review coverage for a case",
    )
    summary.add_argument("--case", type=int, required=True)

    commands.add_parser("init", help="Initialize the assessment table")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        initialise()

        if args.command == "init":
            print("Evidence-quality storage is ready.")
        elif args.command == "assess":
            save_assessment(args)
        elif args.command == "list":
            core.get_case(args.case)
            list_assessments(args.case)
        elif args.command == "summary":
            core.get_case(args.case)
            show_summary(args.case)

    except (ValueError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
