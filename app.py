#!/usr/bin/env python3
"""
BusyBrains OSINT
Public-source intelligence collection and case management.

Initial release:
- Investigation management
- SQLite evidence storage
- Public HTTPS page collection
- JSON and CSV report exports
- Local logging and self-tests

This application is designed to run using Python's standard library.
"""

import argparse
import csv
import html
import ipaddress
import json
import logging
import re
import socket
import sqlite3
import sys

from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

APP_NAME = "BusyBrains OSINT"
VERSION = "0.1.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "storage"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = DATA_DIR / "busybrains_osint.db"

MAX_PAGE_BYTES = 1_000_000
REQUEST_TIMEOUT = 10


def timestamp():
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def prepare_directories():
    """Create only the directories belonging to this application."""
    for directory in (DATA_DIR, LOG_DIR, REPORT_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def setup_logging():
    prepare_directories()

    logging.basicConfig(
        filename=LOG_DIR / "busybrains_osint.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )


def connect_db():
    prepare_directories()

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                source_url TEXT NOT NULL DEFAULT '',
                collected_at TEXT NOT NULL,
                FOREIGN KEY(case_id)
                    REFERENCES cases(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_case_id
            ON findings(case_id);
            """
        )

    logging.info("Database initialized.")


class PageTextParser(HTMLParser):
    """Extract readable text and a page title from HTML."""

    def __init__(self):
        super().__init__()
        self.in_title = False
        self.in_ignored_section = 0
        self.title_parts = []
        self.text_parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

        if tag.lower() in ("script", "style", "noscript", "svg"):
            self.in_ignored_section += 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

        if tag.lower() in ("script", "style", "noscript", "svg"):
            self.in_ignored_section = max(
                0, self.in_ignored_section - 1
            )

    def handle_data(self, data):
        text = data.strip()

        if not text:
            return

        if self.in_title:
            self.title_parts.append(text)

        if not self.in_ignored_section:
            self.text_parts.append(text)

    @property
    def title(self):
        return " ".join(self.title_parts).strip() or "Untitled page"

    @property
    def text(self):
        return " ".join(self.text_parts).strip()


def validate_public_https_url(url):
    """
    Allow public HTTPS URLs only.

    Reject local hostnames, private/reserved IPs, credentials,
    unsupported schemes, and names that cannot be resolved.
    """

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL must contain a hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    if parsed.port not in (None, 443):
        raise ValueError("Only the standard HTTPS port 443 is allowed.")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost targets are not allowed.")

    if hostname.endswith(".local"):
        raise ValueError("Local network hostnames are not allowed.")

    try:
        ip = ipaddress.ip_address(hostname)
        addresses = [ip]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                443,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(
                f"Could not resolve hostname: {exc}"
            ) from exc

        addresses = [
            ipaddress.ip_address(record[4][0].split("%")[0])
            for record in records
        ]

    if not addresses:
        raise ValueError("No usable IP addresses were found.")

    for address in addresses:
        if not address.is_global:
            raise ValueError(
                "The hostname resolves to a non-public IP address."
            )

    return parsed


class NoRedirectHandler(HTTPRedirectHandler):
    """Do not automatically follow redirects to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect_public_page(url):
    """Fetch a bounded amount of text from a public HTTPS page."""

    parsed = validate_public_https_url(url)

    request = Request(
        url,
        headers={
            "User-Agent": "BusyBrainsOSINT/0.1 (+public-source-research)",
            "Accept": "text/html,text/plain;q=0.9",
        },
        method="GET",
    )

    opener = build_opener(NoRedirectHandler())

    try:
        with opener.open(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:
            content_type = response.headers.get_content_type()

            if content_type not in (
                "text/html",
                "text/plain",
                "application/xhtml+xml",
            ):
                raise ValueError(
                    f"Unsupported content type: {content_type}"
                )

            data = response.read(MAX_PAGE_BYTES + 1)

            if len(data) > MAX_PAGE_BYTES:
                raise ValueError(
                    "Page exceeds the 1 MB collection limit."
                )

            charset = response.headers.get_content_charset() or "utf-8"
            decoded = data.decode(charset, errors="replace")

    except HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            raise ValueError(
                "The page redirected. Check the destination manually "
                "and submit its public HTTPS URL separately."
            ) from exc

        raise ValueError(f"HTTP request failed: {exc.code}") from exc

    except URLError as exc:
        raise ValueError(f"Unable to fetch page: {exc.reason}") from exc

    if content_type == "text/plain":
        title = parsed.hostname
        text = decoded
    else:
        parser = PageTextParser()
        parser.feed(decoded)

        title = parser.title
        text = parser.text

    # Keep evidence compact and remove control characters.
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    text = "".join(
        char for char in text
        if char.isprintable() or char == "\t"
    )

    return title[:300], text[:12000]


def create_case(name, purpose):
    name = name.strip()

    if not name:
        raise ValueError("Case name cannot be empty.")

    with connect_db() as db:
        cursor = db.execute(
            """
            INSERT INTO cases (name, purpose, created_at)
            VALUES (?, ?, ?)
            """,
            (name, purpose.strip(), timestamp()),
        )

        case_id = cursor.lastrowid

    logging.info("Created case %s", case_id)
    return case_id


def list_cases():
    with connect_db() as db:
        return db.execute(
            """
            SELECT
                c.id,
                c.name,
                c.purpose,
                c.created_at,
                COUNT(f.id) AS finding_count
            FROM cases c
            LEFT JOIN findings f ON f.case_id = c.id
            GROUP BY c.id
            ORDER BY c.id DESC
            """
        ).fetchall()


def get_case(case_id):
    with connect_db() as db:
        row = db.execute(
            "SELECT * FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()

    if row is None:
        raise ValueError(f"Case {case_id} does not exist.")

    return row


def add_finding(case_id, category, title, content, source_url=""):
    get_case(case_id)

    if not category.strip() or not title.strip():
        raise ValueError("Category and title are required.")

    if not content.strip():
        raise ValueError("Finding content cannot be empty.")

    with connect_db() as db:
        cursor = db.execute(
            """
            INSERT INTO findings (
                case_id,
                category,
                title,
                content,
                source_url,
                collected_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                category.strip(),
                title.strip(),
                content.strip(),
                source_url.strip(),
                timestamp(),
            ),
        )

        finding_id = cursor.lastrowid

    logging.info(
        "Added finding %s to case %s",
        finding_id,
        case_id,
    )

    return finding_id


def list_findings(case_id):
    get_case(case_id)

    with connect_db() as db:
        return db.execute(
            """
            SELECT *
            FROM findings
            WHERE case_id = ?
            ORDER BY id DESC
            """,
            (case_id,),
        ).fetchall()


def export_report(case_id, fmt):
    case = get_case(case_id)
    findings = list_findings(case_id)

    safe_name = re.sub(
        r"[^A-Za-z0-9_-]+",
        "_",
        case["name"],
    ).strip("_")[:60] or "case"

    output = REPORT_DIR / (
        f"case_{case_id}_{safe_name}.{fmt}"
    )

    report = {
        "application": APP_NAME,
        "version": VERSION,
        "generated_at": timestamp(),
        "case": dict(case),
        "findings": [dict(row) for row in findings],
    }

    if fmt == "json":
        output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    elif fmt == "csv":
        with output.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "id",
                    "case_id",
                    "category",
                    "title",
                    "content",
                    "source_url",
                    "collected_at",
                ],
            )

            writer.writeheader()
            writer.writerows(report["findings"])

    elif fmt == "html":
        case_data = dict(case)

        def escape(value):
            return html.escape(str(value if value is not None else ""))

        finding_cards = []
        for item in report["findings"]:
            source_url = item.get("source_url") or ""
            source_html = ""

            if source_url:
                safe_url = escape(source_url)
                source_html = (
                    f'<p class="source"><strong>Source:</strong> '
                    f'<a href="{safe_url}" rel="noopener noreferrer">'
                    f'{safe_url}</a></p>'
                )

            finding_cards.append(
                f"""
                <article class="finding">
                  <div class="finding-meta">
                    <span class="badge">{escape(item.get("category", "Uncategorised"))}</span>
                    <span>Finding #{escape(item.get("id", ""))}</span>
                  </div>
                  <h3>{escape(item.get("title", "Untitled finding"))}</h3>
                  <p class="content">{escape(item.get("content", "")).replace(chr(10), "<br>")}</p>
                  {source_html}
                  <p class="timestamp">Collected: {escape(item.get("collected_at", "Not recorded"))}</p>
                </article>
                """
            )

        findings_html = "\n".join(finding_cards)
        if not findings_html:
            findings_html = '<p class="empty">No findings have been recorded for this case.</p>'

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(case_data.get("name", "Investigation"))} — BusyBrains OSINT</title>
<style>
:root {{
  --navy: #101c35;
  --navy-light: #1b2d4f;
  --gold: #d6ad55;
  --ink: #202938;
  --muted: #647084;
  --paper: #ffffff;
  --background: #f1f4f8;
  --border: #dce2eb;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--background);
  color: var(--ink);
  font: 15px/1.65 Arial, Helvetica, sans-serif;
}}
header {{
  background: linear-gradient(120deg, var(--navy), var(--navy-light));
  color: white;
  padding: 36px 24px;
  border-bottom: 5px solid var(--gold);
}}
.wrap {{ max-width: 1050px; margin: 0 auto; }}
.brand {{ color: var(--gold); font-weight: 700; letter-spacing: 2px; }}
header h1 {{ margin: 10px 0; line-height: 1.2; overflow-wrap: anywhere; }}
header p {{ color: #e0e6f0; margin: 5px 0; }}
main {{ max-width: 1050px; margin: 28px auto; padding: 0 20px; }}
.panel, .finding {{
  background: var(--paper);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 22px;
  margin-bottom: 18px;
  box-shadow: 0 3px 12px rgba(16, 28, 53, .05);
}}
h2 {{ color: var(--navy); margin-top: 0; }}
h3 {{ color: var(--navy); margin: 12px 0; overflow-wrap: anywhere; }}
.summary-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 12px;
}}
.stat {{ background: #f7f8fb; padding: 15px; border-radius: 8px; }}
.stat strong {{ display: block; color: var(--navy); font-size: 1.35rem; }}
.muted, .timestamp {{ color: var(--muted); font-size: .9rem; }}
.badge {{
  display: inline-block; background: #fff3d5; color: #60460b;
  border: 1px solid #ead39b; border-radius: 20px;
  padding: 3px 10px; font-size: .8rem; font-weight: 700;
}}
.finding-meta {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }}
.content {{ white-space: normal; overflow-wrap: anywhere; }}
.source {{ overflow-wrap: anywhere; }}
a {{ color: #174f91; }}
.notice {{ border-left: 4px solid var(--gold); background: #fffaf0; }}
.empty {{ color: var(--muted); }}
footer {{ max-width: 1050px; margin: 20px auto; padding: 20px; color: var(--muted); font-size: .85rem; }}
button {{
  border: 0; border-radius: 6px; padding: 10px 15px; cursor: pointer;
  color: white; background: var(--navy);
}}
@media print {{
  body {{ background: white; }}
  header {{ background: var(--navy) !important; print-color-adjust: exact; }}
  main {{ max-width: none; margin: 15px 0; padding: 0; }}
  .panel, .finding {{ box-shadow: none; break-inside: avoid; }}
  .no-print {{ display: none !important; }}
  a {{ color: inherit; text-decoration: none; }}
}}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div class="brand">BUSYBRAINS TECH-HUB · OSINT</div>
    <h1>{escape(case_data.get("name", "Investigation"))}</h1>
    <p>Investigation Report · Case #{escape(case_data.get("id", ""))}</p>
    <p>Generated: {escape(report["generated_at"])}</p>
  </div>
</header>
<main>
  <div class="panel no-print">
    <button onclick="window.print()">Print / Save as PDF</button>
  </div>
  <section class="panel">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="stat"><strong>{len(report["findings"])}</strong>Recorded findings</div>
      <div class="stat"><strong>{escape(case_data.get("created_at", "Not recorded"))}</strong>Case created</div>
      <div class="stat"><strong>{escape(report["version"])}</strong>Application version</div>
    </div>
    <h3>Investigation purpose</h3>
    <p>{escape(case_data.get("purpose", "") or "No purpose was recorded for this case.")}</p>
  </section>
  <section>
    <h2>Investigation Findings</h2>
    {findings_html}
  </section>
  <section class="panel notice">
    <h2>Scope and Limitations</h2>
    <p>This report summarises information recorded in BusyBrains OSINT at the time of generation. Public-source observations may be incomplete, outdated, affected by access restrictions, or incorrectly attributed. A reachable profile or domain does not by itself establish identity, ownership, or affiliation. Independently verify material claims before relying on them.</p>
    <p>Use only for lawful research and investigations within your authorisation. This report does not certify the accuracy of the underlying sources.</p>
  </section>
</main>
<footer>
  BusyBrains Tech-Hub · BusyBrains OSINT · Version {escape(report["version"])}<br>
  Confidentiality and distribution should be determined by the case owner.
</footer>
</body>
</html>
"""
        output.write_text(page, encoding="utf-8")
        # Append the evidence-quality register without altering original findings.
        try:
            with connect_db() as db:
                assessment_rows = db.execute(
                    """
                    SELECT f.id AS finding_id, f.title,
                           a.classification, a.confidence,
                           a.source_review, a.rationale,
                           a.analyst, a.assessed_at
                    FROM findings AS f
                    LEFT JOIN finding_assessments AS a
                      ON a.finding_id = f.id
                    WHERE f.case_id = ?
                    ORDER BY f.id DESC
                    """,
                    (case_id,),
                ).fetchall()

            review_items = []
            for item in assessment_rows:
                item = dict(item)
                if item.get("classification"):
                    status = (
                        f'<span class="badge">'
                        f'{html.escape(str(item["classification"]))}</span>'
                    )
                    details = (
                        f'<p><strong>Confidence:</strong> '
                        f'{html.escape(str(item["confidence"]))}</p>'
                        f'<p><strong>Source review:</strong> '
                        f'{html.escape(str(item["source_review"]))}</p>'
                        f'<p><strong>Rationale:</strong> '
                        f'{html.escape(str(item["rationale"]))}</p>'
                        f'<p class="timestamp">Analyst: '
                        f'{html.escape(str(item["analyst"]))} · Assessed: '
                        f'{html.escape(str(item["assessed_at"]))}</p>'
                    )
                else:
                    status = (
                        '<span class="badge">NOT REVIEWED</span>'
                    )
                    details = (
                        '<p>Review the source and record an assessment '
                        'before relying on this finding.</p>'
                    )

                review_items.append(
                    '<article class="finding">'
                    f'<h3>Finding #{html.escape(str(item["finding_id"]))}: '
                    f'{html.escape(str(item["title"] or "Untitled"))}</h3>'
                    f'{status}{details}</article>'
                )

            review_section = (
                '<section class="panel">'
                '<h2>Evidence Quality Review</h2>'
                '<p>Analyst-recorded assessments are separate from the '
                'original findings. An assessment does not independently '
                'verify the underlying claim.</p>'
                + "".join(review_items)
                + '</section>'
            )

            generated_page = output.read_text(encoding="utf-8")
            if "</main>" in generated_page:
                generated_page = generated_page.replace(
                    "</main>", review_section + "</main>", 1
                )
                output.write_text(generated_page, encoding="utf-8")
        except sqlite3.OperationalError:
            # Keep exports functional if assessment storage has not been initialized.
            logging.warning("Evidence assessment table unavailable during export.")

    logging.info("Exported report to %s", output)
    return output


def run_self_test():
    """Check core database operations without network requests."""

    initialize_database()

    case_id = create_case(
        "BusyBrains OSINT Self-Test",
        "Automated local application test.",
    )

    finding_id = add_finding(
        case_id,
        "self-test",
        "Database test",
        "SQLite storage is functioning.",
        "local://self-test",
    )

    findings = list_findings(case_id)

    if not any(row["id"] == finding_id for row in findings):
        raise RuntimeError("Finding verification failed.")

    json_path = export_report(case_id, "json")
    csv_path = export_report(case_id, "csv")

    assert json_path.is_file()
    assert csv_path.is_file()

    # Remove only this self-test case and its associated evidence.
    with connect_db() as db:
        db.execute(
            "DELETE FROM findings WHERE case_id = ?",
            (case_id,),
        )
        db.execute(
            "DELETE FROM cases WHERE id = ?",
            (case_id,),
        )

    json_path.unlink(missing_ok=True)
    csv_path.unlink(missing_ok=True)

    print("PASS: Database initialization")
    print("PASS: Case creation")
    print("PASS: Finding storage and retrieval")
    print("PASS: JSON report export")
    print("PASS: CSV report export")
    print("PASS: Self-test cleanup")
    print()
    print("BusyBrains OSINT core is working.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="busybrains-osint",
        description=(
            "BusyBrains OSINT — public-source intelligence "
            "and investigation management"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    commands.add_parser(
        "init",
        help="Initialize the local database",
    )

    commands.add_parser(
        "self-test",
        help="Test the local application",
    )

    case_parser = commands.add_parser(
        "case",
        help="Manage investigation cases",
    )

    case_commands = case_parser.add_subparsers(
        dest="case_command",
        required=True,
    )

    create_parser = case_commands.add_parser(
        "create",
        help="Create an investigation case",
    )

    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--purpose", default="")

    case_commands.add_parser(
        "list",
        help="List investigation cases",
    )

    finding_parser = commands.add_parser(
        "finding",
        help="Manage investigation findings",
    )

    finding_commands = finding_parser.add_subparsers(
        dest="finding_command",
        required=True,
    )

    add_parser = finding_commands.add_parser(
        "add",
        help="Add a manual finding",
    )

    add_parser.add_argument("--case", type=int, required=True)
    add_parser.add_argument("--category", required=True)
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--content", required=True)
    add_parser.add_argument("--source", default="")

    list_parser = finding_commands.add_parser(
        "list",
        help="List findings in a case",
    )

    list_parser.add_argument("--case", type=int, required=True)

    collect_parser = commands.add_parser(
        "collect-url",
        help="Collect text from a public HTTPS page",
    )

    collect_parser.add_argument("--case", type=int, required=True)
    collect_parser.add_argument("--url", required=True)
    domain_parser = commands.add_parser(
        "domain",
        help="Assess public DNS and HTTPS certificate information",
    )
    domain_parser.add_argument("--case", type=int, required=True)
    domain_parser.add_argument("--domain", required=True)

    username_parser = commands.add_parser(
        "username",
        help="Check public profile URL availability",
    )
    username_parser.add_argument("--case", type=int, required=True)
    username_parser.add_argument("--username", required=True)

    institution_parser = commands.add_parser(
        "institution",
        help="Collect text from a public institutional webpage",
    )
    institution_parser.add_argument("--case", type=int, required=True)
    institution_parser.add_argument("--url", required=True)
    institution_parser.add_argument("--institution", required=True)
    export_parser = commands.add_parser(
        "export",
        help="Export a case report",
    )

    export_parser.add_argument("--case", type=int, required=True)
    export_parser.add_argument(
        "--format",
        choices=("json", "csv", "html"),
        required=True,
    )

    return parser


def main():
    prepare_directories()
    setup_logging()

    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "init":
            initialize_database()
            print(f"{APP_NAME} database initialized.")
            print(f"Database: {DB_PATH}")

        elif args.command == "self-test":
            run_self_test()

        elif args.command == "case":
            initialize_database()

            if args.case_command == "create":
                case_id = create_case(args.name, args.purpose)
                print(f"Case created successfully. ID: {case_id}")

            elif args.case_command == "list":
                cases = list_cases()

                if not cases:
                    print("No investigation cases found.")
                else:
                    for case in cases:
                        print(
                            f"ID: {case['id']} | "
                            f"Name: {case['name']} | "
                            f"Findings: {case['finding_count']} | "
                            f"Created: {case['created_at']}"
                        )

        elif args.command == "finding":
            initialize_database()

            if args.finding_command == "add":
                finding_id = add_finding(
                    args.case,
                    args.category,
                    args.title,
                    args.content,
                    args.source,
                )

                print(f"Finding saved. ID: {finding_id}")

            elif args.finding_command == "list":
                findings = list_findings(args.case)

                if not findings:
                    print("No findings recorded for this case.")
                else:
                    for finding in findings:
                        print(
                            f"\nFinding ID: {finding['id']}\n"
                            f"Category: {finding['category']}\n"
                            f"Title: {finding['title']}\n"
                            f"Content: {finding['content']}\n"
                            f"Source: {finding['source_url']}\n"
                            f"Collected: {finding['collected_at']}"
                        )

        elif args.command == "collect-url":
            initialize_database()
            get_case(args.case)

            title, content = collect_public_page(args.url)

            if not content:
                content = "The page returned no extractable text."

            finding_id = add_finding(
                args.case,
                "public-web",
                title,
                content,
                args.url,
            )

            print("Public page collected successfully.")
            print(f"Finding ID: {finding_id}")
            print(f"Page title: {title}")
            print(f"Stored in case: {args.case}")
        elif args.command in ("domain", "username", "institution"):
            import subprocess

            if args.command == "domain":
                module_command = [
                    sys.executable,
                    str(BASE_DIR / "modules" / "domain_intel.py"),
                    "--case", str(args.case),
                    "--domain", args.domain,
                ]
            elif args.command == "username":
                module_command = [
                    sys.executable,
                    str(BASE_DIR / "modules" / "username_intel.py"),
                    "--case", str(args.case),
                    "--username", args.username,
                ]
            else:
                module_command = [
                    sys.executable,
                    str(BASE_DIR / "modules" / "institution_intel.py"),
                    "--case", str(args.case),
                    "--url", args.url,
                    "--institution", args.institution,
                ]

            completed = subprocess.run(
                module_command,
                cwd=BASE_DIR,
                check=False,
            )
            return completed.returncode

        elif args.command == "export":
            initialize_database()
            output = export_report(args.case, args.format)
            print(f"Report exported: {output}")

        return 0

    except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
        logging.error("Operation failed: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
