#!/usr/bin/env python3

import argparse
import csv
import html
import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "storage" / "busybrains_osint.db"
REPORT_DIR = BASE_DIR / "reports"


def extract_json_objects(content):
    """Extract JSON objects embedded in finding content."""
    objects = []

    try:
        value = json.loads(content)
        if isinstance(value, dict):
            objects.append(value)
    except (ValueError, TypeError):
        pass

    for match in re.finditer(r'\{.*\}', content, re.DOTALL):
        try:
            value = json.loads(match.group())
            if isinstance(value, dict):
                objects.append(value)
        except (ValueError, TypeError):
            continue

    return objects


def flatten_json(value, prefix=""):
    result = {}

    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            result.update(flatten_json(item, name))
    elif isinstance(value, list):
        result[prefix] = json.dumps(value, sort_keys=True)
    else:
        result[prefix] = str(value)

    return result


def identify_observation(row):
    title = row["title"]
    category = row["category"]
    content = row["content"]

    if category == "social_profile_check":
        match = re.search(
            r"Public profile URL check:\s*(.*?)\s*/\s*(.*)",
            title,
            re.IGNORECASE,
        )
        if not match:
            return None

        platform = match.group(1).strip().lower()
        username = match.group(2).strip().lower()

        fields = {}

        for label, pattern in [
            ("classification", r"Classification:\s*([^\n]+)"),
            ("http_status", r"HTTP status:\s*([^\n]+)"),
            ("final_url", r"Final URL:\s*([^\n]+)"),
        ]:
            found = re.search(pattern, content, re.IGNORECASE)
            if found:
                fields[label] = found.group(1).strip()

        return {
            "key": f"social:{platform}:{username}",
            "entity": f"{platform} / {username}",
            "type": "Social profile observation",
            "fields": fields,
        }

    if category in ("domain-intelligence", "domain_intelligence"):
        match = re.search(
            r"(?:domain intelligence|domain assessment):\s*(\S+)",
            title,
            re.IGNORECASE,
        )
        if not match:
            return None

        domain = match.group(1).strip().lower().rstrip(".")
        fields = {}

        for obj in extract_json_objects(content):
            fields.update(flatten_json(obj))

        for label, pattern in [
            ("tls_version", r"TLS(?: version)?:\s*([^\n]+)"),
            ("certificate_issuer", r"Issuer:\s*([^\n]+)"),
            ("certificate_expiry", r"(?:Not after|Expiry|Expires):\s*([^\n]+)"),
        ]:
            found = re.search(pattern, content, re.IGNORECASE)
            if found:
                fields[label] = found.group(1).strip()

        if not fields:
            fields["observation"] = content[:1000]

        return {
            "key": f"domain:{domain}",
            "entity": domain,
            "type": "Domain observation",
            "fields": fields,
        }

    return None


def load_observations(case_id):
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found: {DB_PATH}")

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT id, case_id, category, title, content,
               source_url, collected_at
        FROM findings
        WHERE case_id = ?
        ORDER BY collected_at ASC, id ASC
        """,
        (case_id,),
    ).fetchall()

    case = connection.execute(
        "SELECT id, name, purpose, created_at FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()

    connection.close()

    if case is None:
        raise ValueError(f"Case {case_id} does not exist.")

    observations = []

    for row in rows:
        parsed = identify_observation(row)
        if parsed is None:
            continue

        parsed.update({
            "finding_id": row["id"],
            "case_id": row["case_id"],
            "category": row["category"],
            "title": row["title"],
            "source_url": row["source_url"],
            "collected_at": row["collected_at"],
        })

        observations.append(parsed)

    return dict(case), observations, len(rows)


def normalize_observation_fields(observation):
    """Normalize equivalent fields across different collector formats."""
    fields = dict(observation["fields"])

    ignored = {
        "application",
        "case_id",
        "checked_at",
        "collected_at",
        "generated_at",
        "module",
        "limitations",
        "type",
        "hostname",
        "domain",
        "dns.address_count",
    }

    normalized = {}

    for name, value in fields.items():
        if name in ignored or value in (None, "", "None"):
            continue

        canonical = name

        aliases = {
            "dns.resolved_addresses": "resolved_addresses",
            "dns_records.A": "dns.A",
            "dns_records.AAAA": "dns.AAAA",
            "dns_records.MX": "dns.MX",
            "dns_records.NS": "dns.NS",
            "dns_records.TXT": "dns.TXT",
            "dns_records.CNAME": "dns.CNAME",
            "https_certificate.connected_ip": "tls.connected_ip",
            "https_certificate.tls_version": "tls.version",
            "https_certificate.cipher": "tls.cipher",
            "https_certificate.subject": "tls.subject",
            "https_certificate.issuer": "tls.issuer",
            "https_certificate.not_before": "tls.not_before",
            "https_certificate.not_after": "tls.not_after",
            "https_certificate.serial_number": "tls.serial_number",
            "https_certificate.sha256_fingerprint": "tls.sha256_fingerprint",
            "https_certificate.subject_alt_names": "tls.subject_alt_names",
        }

        canonical = aliases.get(canonical, canonical)
        normalized[canonical] = value

    return normalized


def compare_observations(observations):
    grouped = defaultdict(list)

    for observation in observations:
        grouped[observation["key"]].append(observation)

    comparisons = []

    for key, history in grouped.items():
        history.sort(
            key=lambda item: (item["collected_at"], item["finding_id"])
        )

        if len(history) < 2:
            continue

        previous = history[-2]
        current = history[-1]

        previous_fields = normalize_observation_fields(previous)
        current_fields = normalize_observation_fields(current)

        # Compare only fields observed in both records.
        # A missing field is not evidence that something disappeared.
        common_fields = sorted(
            set(previous_fields) & set(current_fields)
        )

        changes = []

        for field in common_fields:
            old = previous_fields[field]
            new = current_fields[field]

            if old != new:
                change = {
                    "field": field,
                    "previous": old,
                    "current": new,
                }

                if field == "resolved_addresses" or field.startswith("dns."):
                    try:
                        old_records = set(json.loads(old))
                        new_records = set(json.loads(new))
                        change["added"] = sorted(new_records - old_records)
                        change["removed"] = sorted(old_records - new_records)
                    except (ValueError, TypeError):
                        pass

                changes.append(change)

        comparisons.append({
            "key": key,
            "entity": current["entity"],
            "type": current["type"],
            "previous_finding_id": previous["finding_id"],
            "current_finding_id": current["finding_id"],
            "previous_date": previous["collected_at"],
            "current_date": current["collected_at"],
            "observation_count": len(history),
            "compared_fields": common_fields,
            "changes": changes,
            "status": (
                "CHANGE DETECTED" if changes
                else "NO CHANGE DETECTED" if common_fields
                else "INSUFFICIENT COMPARABLE DATA"
            ),
        })

    return comparisons


def write_reports(case, observations, comparisons, total_findings):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"case_{case['id']}_historical_{stamp}"

    changed = sum(item["status"] == "CHANGE DETECTED" for item in comparisons)
    unchanged = sum(item["status"] == "NO CHANGE DETECTED" for item in comparisons)
    insufficient = sum(
        item["status"] == "INSUFFICIENT COMPARABLE DATA"
        for item in comparisons
    )

    report = {
        "application": "BusyBrains OSINT",
        "module": "Historical Intelligence Engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "summary": {
            "total_database_findings": total_findings,
            "historical_observations_supported": len(observations),
            "entities_compared": len(comparisons),
            "entities_with_detected_changes": changed,
            "entities_without_detected_changes": unchanged,
            "entities_with_insufficient_comparable_data": insufficient,
        },
        "comparisons": comparisons,
        "observations": observations,
        "limitations": [
            "Only supported social-profile and domain observations are compared.",
            "HTTP responses do not prove account ownership or identity.",
            "A changed HTTP status does not prove an account was created or deleted.",
            "Differences are observed data changes, not proof of their cause.",
            "Only the two most recent observations per entity are compared.",
        ],
    }

    json_path = REPORT_DIR / f"{prefix}.json"
    csv_path = REPORT_DIR / f"{prefix}.csv"
    html_path = REPORT_DIR / f"{prefix}.html"

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "entity",
                "type",
                "status",
                "previous_finding_id",
                "current_finding_id",
                "previous_date",
                "current_date",
                "observation_count",
                "changes",
            ],
        )
        writer.writeheader()

        for item in comparisons:
            writer.writerow({
                **{
                    key: item[key]
                    for key in writer.fieldnames
                    if key != "changes"
                },
                "changes": json.dumps(item["changes"], ensure_ascii=False),
            })

    rows = []

    for item in comparisons:
        changes = item["changes"]

        change_html = "".join(
            "<li><strong>{}</strong>: {} → {}</li>".format(
                html.escape(change["field"]),
                html.escape(str(change["previous"])),
                html.escape(str(change["current"])),
            )
            for change in changes
        ) or "<li>No field differences detected.</li>"

        rows.append(
            "<tr>"
            f"<td>{html.escape(item['entity'])}</td>"
            f"<td>{html.escape(item['type'])}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['previous_date'])}</td>"
            f"<td>{html.escape(item['current_date'])}</td>"
            f"<td><ul>{change_html}</ul></td>"
            "</tr>"
        )

    summary = report["summary"]

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BusyBrains OSINT - Historical Intelligence</title>
<style>
body {{ background:#081426; color:#e8edf5; font-family:Arial,sans-serif;
       margin:0; padding:28px; }}
h1 {{ color:#d9b45b; }}
.card {{ background:#12243d; padding:18px; margin:12px 0;
         border-radius:9px; }}
table {{ width:100%; border-collapse:collapse; background:#12243d; }}
th {{ background:#203958; color:#e6c46f; }}
th,td {{ padding:12px; border:1px solid #30445e;
         text-align:left; vertical-align:top; }}
.warning {{ color:#e6c46f; }}
small {{ color:#aab8cb; }}
</style>
</head>
<body>
<h1>BusyBrains OSINT</h1>
<h2>Historical Intelligence Report</h2>
<p>Case #{case['id']}: {html.escape(case['name'])}</p>
<p><small>Generated: {html.escape(report['generated_at'])}</small></p>
<div class="card">
<h3>Investigation Summary</h3>
<p>Database findings: {summary['total_database_findings']}</p>
<p>Supported historical observations: {summary['historical_observations_supported']}</p>
<p>Entities compared: {summary['entities_compared']}</p>
<p>Entities with detected changes: {summary['entities_with_detected_changes']}</p>
<p>Entities without detected changes: {summary['entities_without_detected_changes']}</p>
</div>
<h3>Latest Observation Comparisons</h3>
<table>
<thead><tr><th>Entity</th><th>Type</th><th>Result</th>
<th>Previous</th><th>Current</th><th>Differences</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="6">No entities have two supported observations yet.</td></tr>'}</tbody>
</table>
<div class="card warning">
<h3>Analyst Caution</h3>
<p>Detected differences are changes in recorded observations.
They do not establish why a change occurred. HTTP status codes alone
do not establish account existence, ownership, identity, or deletion.</p>
<p>Only the two most recent observations for each supported entity
are compared in this report.</p>
</div>
</body>
</html>
"""

    html_path.write_text(page, encoding="utf-8")

    return json_path, csv_path, html_path, summary


def main():
    parser = argparse.ArgumentParser(
        description="Compare historical OSINT observations without modifying evidence."
    )
    parser.add_argument("--case", type=int, required=True, help="Case ID")
    args = parser.parse_args()

    try:
        case, observations, total = load_observations(args.case)
        comparisons = compare_observations(observations)

        paths = write_reports(case, observations, comparisons, total)
        json_path, csv_path, html_path, summary = paths

        print("\nBUSYBRAINS OSINT - HISTORICAL INTELLIGENCE")
        print("=" * 48)
        print(f"Case: {case['id']} - {case['name']}")
        print(f"Database findings: {total}")
        print(f"Supported observations: {len(observations)}")
        print(f"Entities compared: {summary['entities_compared']}")
        print(f"Changes detected: {summary['entities_with_detected_changes']}")
        print("\nREPORTS CREATED")
        print(f"JSON: {json_path}")
        print(f"CSV:  {csv_path}")
        print(f"HTML: {html_path}")
        print("\nDatabase findings were not modified.")

    except (ValueError, FileNotFoundError, sqlite3.Error) as error:
        print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
