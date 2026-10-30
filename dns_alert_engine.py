#!/usr/bin/env python3
"""BusyBrains OSINT - DNS and TLS Change Alert Engine."""

import argparse
import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

import historical_intelligence as historical

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

DNS_LABELS = {
    "dns.A": "IPv4 address record",
    "dns.AAAA": "IPv6 address record",
    "dns.MX": "Mail routing record",
    "dns.NS": "Nameserver record",
    "dns.TXT": "DNS text record",
    "dns.CNAME": "Canonical name record",
    "resolved_addresses": "Resolved IP addresses",
}

def record_sets(change):
    """Return added and removed values from a comparison."""
    if "added" in change or "removed" in change:
        return change.get("added", []), change.get("removed", [])

    try:
        old = json.loads(change["previous"])
        new = json.loads(change["current"])

        if not isinstance(old, list) or not isinstance(new, list):
            return [], []

        old_set = set(map(str, old))
        new_set = set(map(str, new))
        return sorted(new_set - old_set), sorted(old_set - new_set)
    except (KeyError, TypeError, ValueError):
        return [], []


def classify_change(change):
    field = change.get("field", "")
    added, removed = record_sets(change)

    alert_type = "Configuration change"
    severity = "LOW"
    recommendation = (
        "Review the change against the domain owner's approved "
        "infrastructure configuration."
    )

    if field in ("dns.NS",):
        alert_type = "Nameserver configuration change"
        severity = "HIGH"
        recommendation = (
            "Verify the nameserver change with the domain owner and "
            "authoritative DNS provider."
        )

    elif field == "dns.MX":
        alert_type = "Mail routing configuration change"
        severity = "MEDIUM"
        recommendation = (
            "Verify the mail routing change with the authorized "
            "domain administrator. Check for service disruption."
        )

    elif field in ("dns.A", "dns.AAAA", "resolved_addresses"):
        alert_type = "IP address configuration change"
        severity = "MEDIUM" if removed else "LOW"
        recommendation = (
            "Verify new and removed addresses against approved hosting, "
            "CDN and infrastructure changes."
        )

    elif field == "dns.CNAME":
        alert_type = "CNAME configuration change"
        severity = "MEDIUM"
        recommendation = (
            "Verify the new alias target and confirm it is controlled "
            "by the domain owner."
        )

    elif field == "dns.TXT":
        alert_type = "DNS TXT policy or verification change"
        severity = "MEDIUM"
        recommendation = (
            "Review SPF, DKIM, DMARC and domain-verification values "
            "with the authorized administrator."
        )

    elif field == "tls.sha256_fingerprint":
        alert_type = "TLS certificate fingerprint change"
        severity = "HIGH"
        recommendation = (
            "Verify the replacement certificate, issuer, subject and "
            "deployment with the authorized certificate administrator."
        )

    elif field in ("tls.issuer", "tls.subject", "tls.serial_number"):
        alert_type = "TLS certificate identity change"
        severity = "HIGH"
        recommendation = (
            "Validate the certificate chain and certificate identity "
            "against the expected certificate deployment."
        )

    elif field in ("tls.not_after", "tls.not_before"):
        alert_type = "TLS certificate validity date change"
        severity = "MEDIUM"
        recommendation = (
            "Check certificate renewal and deployment records."
        )

    elif field in ("tls.version", "tls.cipher"):
        alert_type = "TLS security configuration change"
        severity = "MEDIUM"
        recommendation = (
            "Review the TLS protocol and cipher configuration against "
            "the organization's security baseline."
        )

    return {
        "alert_type": alert_type,
        "severity": severity,
        "field": field,
        "added": added,
        "removed": removed,
        "previous": change.get("previous"),
        "current": change.get("current"),
        "recommendation": recommendation,
    }


def build_alerts(case_id):
    case, observations, total = historical.load_observations(case_id)
    comparisons = historical.compare_observations(observations)

    alerts = []

    for comparison in comparisons:
        for change in comparison.get("changes", []):
            alert = classify_change(change)

            alert.update({
                "case_id": case_id,
                "case_name": case["name"],
                "entity": comparison["entity"],
                "previous_finding_id": comparison["previous_finding_id"],
                "current_finding_id": comparison["current_finding_id"],
                "previous_date": comparison["previous_date"],
                "current_date": comparison["current_date"],
                "status": "REQUIRES REVIEW",
                "interpretation": (
                    "Observed configuration difference. This is an "
                    "investigative lead, not proof of compromise."
                ),
            })

            alerts.append(alert)

    return case, total, comparisons, alerts


def write_reports(case, total, comparisons, alerts):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"case_{case['id']}_dns_alerts_{stamp}"

    counts = {
        level: sum(a["severity"] == level for a in alerts)
        for level in ("HIGH", "MEDIUM", "LOW", "INFO")
    }

    report = {
        "application": "BusyBrains OSINT",
        "module": "DNS Change Alert Engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "summary": {
            "total_database_findings": total,
            "entities_compared": len(comparisons),
            "total_alerts": len(alerts),
            "severity_counts": counts,
        },
        "alerts": alerts,
        "limitations": [
            "Alerts represent observed differences, not confirmed incidents.",
            "Severity is a review priority, not a probability of compromise.",
            "Only the latest two supported observations per entity are compared.",
            "A missing field is not interpreted as a deleted DNS record.",
            "Verify changes with authoritative sources and the domain owner.",
        ],
    }

    json_path = REPORT_DIR / f"{prefix}.json"
    csv_path = REPORT_DIR / f"{prefix}.csv"
    html_path = REPORT_DIR / f"{prefix}.html"

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    columns = [
        "severity", "alert_type", "entity", "field",
        "previous_finding_id", "current_finding_id",
        "previous", "current", "added", "removed",
        "recommendation",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()

        for alert in alerts:
            row = dict(alert)
            for key in ("added", "removed"):
                row[key] = json.dumps(row.get(key, []), ensure_ascii=False)
            writer.writerow({key: row.get(key, "") for key in columns})

    rows = []

    for alert in alerts:
        rows.append(
            "<tr>"
            f"<td>{html.escape(alert['severity'])}</td>"
            f"<td>{html.escape(alert['alert_type'])}</td>"
            f"<td>{html.escape(alert['entity'])}</td>"
            f"<td>{html.escape(alert['field'])}</td>"
            f"<td>{html.escape(str(alert['previous']))}</td>"
            f"<td>{html.escape(str(alert['current']))}</td>"
            f"<td>{html.escape(alert['recommendation'])}</td>"
            "</tr>"
        )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BusyBrains OSINT - DNS Alerts</title>
<style>
body {{background:#081426;color:#e8edf5;font-family:Arial,sans-serif;padding:25px}}
h1 {{color:#d9b45b}}
.card {{background:#12243d;padding:18px;margin:12px 0;border-radius:9px}}
table {{width:100%;border-collapse:collapse;background:#12243d}}
th {{background:#203958;color:#e6c46f}}
th,td {{padding:12px;border:1px solid #30445e;text-align:left;vertical-align:top}}
small {{color:#aab8cb}}
</style>
</head>
<body>
<h1>BUSYBRAINS OSINT</h1>
<h2>DNS Change Alert Report</h2>
<div class="card">
<p>Case #{case['id']}: {html.escape(case['name'])}</p>
<p>Database findings: {total}</p>
<p>Total alerts: {len(alerts)}</p>
<p>HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']}
| LOW: {counts['LOW']} | INFO: {counts['INFO']}</p>
<p><small>Generated: {html.escape(report['generated_at'])}</small></p>
</div>
<table>
<thead><tr><th>Severity</th><th>Alert</th><th>Entity</th>
<th>Field</th><th>Previous</th><th>Current</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7">No configuration changes detected.</td></tr>'}</tbody>
</table>
<div class="card">
<p>Alerts identify observed differences and do not prove compromise.
Verify findings with authoritative sources and the domain owner.</p>
</div>
</body>
</html>
"""

    html_path.write_text(page, encoding="utf-8")
    return json_path, csv_path, html_path, counts


def main():
    parser = argparse.ArgumentParser(
        description="Generate DNS and TLS configuration change alerts."
    )
    parser.add_argument("--case", type=int, required=True)
    args = parser.parse_args()

    try:
        case, total, comparisons, alerts = build_alerts(args.case)
        paths = write_reports(case, total, comparisons, alerts)
        json_path, csv_path, html_path, counts = paths

        print("\nBUSYBRAINS OSINT - DNS CHANGE ALERT ENGINE")
        print("=" * 48)
        print(f"Case: {case['id']} - {case['name']}")
        print(f"Entities compared: {len(comparisons)}")
        print(f"Total alerts: {len(alerts)}")
        print(
            "Severity: "
            f"HIGH={counts['HIGH']} "
            f"MEDIUM={counts['MEDIUM']} "
            f"LOW={counts['LOW']} INFO={counts['INFO']}"
        )
        print("\nREPORTS CREATED")
        print(f"JSON: {json_path}")
        print(f"CSV:  {csv_path}")
        print(f"HTML: {html_path}")
        print("\nDatabase findings were not modified.")

    except (ValueError, FileNotFoundError) as error:
        print(f"ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
