#!/usr/bin/env python3
"""Read-only evidence correlation and review summary for BusyBrains OSINT."""

import html
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "storage" / "busybrains_osint.db"


def esc(value):
    return html.escape(str(value or ""), quote=True)


def dashboard_body(case_id=2):
    """Render a read-only analysis of existing findings."""
    if not DB_PATH.exists():
        return "<h2>Investigation Intelligence</h2><p>Database not found.</p>"

    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    try:
        case = con.execute(
            "SELECT id, name, purpose FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()

        if case is None:
            return (
                "<h2>Investigation Intelligence</h2>"
                f"<p>Case #{int(case_id)} was not found.</p>"
            )

        rows = con.execute("""
            SELECT
                f.id, f.category, f.title, f.content,
                f.source_url, f.collected_at,
                (SELECT a.classification
                 FROM finding_assessments a
                 WHERE a.finding_id = f.id
                 ORDER BY a.assessed_at DESC, a.id DESC LIMIT 1
                ) AS classification,
                (SELECT a.confidence
                 FROM finding_assessments a
                 WHERE a.finding_id = f.id
                 ORDER BY a.assessed_at DESC, a.id DESC LIMIT 1
                ) AS confidence,
                (SELECT a.source_review
                 FROM finding_assessments a
                 WHERE a.finding_id = f.id
                 ORDER BY a.assessed_at DESC, a.id DESC LIMIT 1
                ) AS source_review
            FROM findings f
            WHERE f.case_id = ?
            ORDER BY f.id
        """, (case_id,)).fetchall()
    finally:
        con.close()

    host_map = defaultdict(list)
    username_map = defaultdict(list)
    review_queue = []

    for row in rows:
        source = row["source_url"] or ""
        try:
            host = (urlsplit(source).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""

        if host:
            host_map[host].append(row)

        # Extract only usernames explicitly recorded in known finding-title formats.
        title = row["title"] or ""
        match = re.search(
            r"(?:Public profile URL check:\s*[^/]+/\s*|"
            r"Public username checks:\s*)([A-Za-z0-9_.-]{1,64})",
            title,
            re.IGNORECASE,
        )
        if match:
            username_map[match.group(1).casefold()].append(row)

        if (
            not row["classification"]
            or not row["confidence"]
            or not row["source_review"]
            or row["source_review"] == "needs_verification"
        ):
            review_queue.append(row)

    correlations = []

    for host, matches in sorted(host_map.items()):
        if len(matches) > 1:
            correlations.append({
                "kind": "Shared source host",
                "indicator": host,
                "records": matches,
                "explanation": (
                    "Multiple findings reference this host. "
                    "This may reflect a shared source, not a shared identity."
                ),
            })

    for username, matches in sorted(username_map.items()):
        if len(matches) > 1:
            correlations.append({
                "kind": "Repeated username",
                "indicator": username,
                "records": matches,
                "explanation": (
                    "The same username string appears in multiple records. "
                    "This alone does not establish common ownership."
                ),
            })

    parts = [
        "<h2>Investigation Intelligence</h2>",
        f"<p><strong>Case:</strong> {esc(case['name'])} "
        f"(#{int(case_id)})</p>",
        "<p>Read-only analysis of recorded findings. "
        "No database records were changed.</p>",
        '<div class="stats">',
        f'<div class="stat"><strong>{len(rows)}</strong>'
        "<span>Total findings</span></div>",
        f'<div class="stat"><strong>{len(review_queue)}</strong>'
        "<span>Needs review</span></div>",
        f'<div class="stat"><strong>{len(correlations)}</strong>'
        "<span>Potential correlations</span></div>",
        "</div>",
        "<h3>Evidence review queue</h3>",
    ]

    if review_queue:
        parts.append(
            "<p>Prioritize these records for source review and assessment.</p>"
            "<table><thead><tr><th>ID</th><th>Category</th>"
            "<th>Finding</th><th>Review status</th></tr></thead><tbody>"
        )
        for row in review_queue:
            status = row["source_review"] or "unassessed"
            parts.append(
                f"<tr><td>{row['id']}</td>"
                f"<td>{esc(row['category'])}</td>"
                f"<td>{esc(row['title'])}</td>"
                f"<td>{esc(status)}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append("<p>No findings currently meet the review-queue criteria.</p>")

    parts.append("<h3>Potential correlations</h3>")

    if correlations:
        parts.append(
            "<table><thead><tr><th>Match type</th><th>Indicator</th>"
            "<th>Finding IDs</th><th>Interpretation</th></tr></thead><tbody>"
        )
        for item in correlations:
            ids = ", ".join(str(row["id"]) for row in item["records"])
            parts.append(
                f"<tr><td>{esc(item['kind'])}</td>"
                f"<td>{esc(item['indicator'])}</td>"
                f"<td>{esc(ids)}</td>"
                f"<td>{esc(item['explanation'])}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append(
            "<p>No repeated usernames or source hosts were identified "
            "by these basic matching rules.</p>"
        )

    parts.extend([
        "<h3>Case actions</h3>",
        f'<p><a class="button" href="/case?id={int(case_id)}">'
        "Open case</a> ",
        f'<a class="button" href="/export?case={int(case_id)}&amp;format=html">'
        "Export HTML report</a> ",
        f'<a class="button" href="/export?case={int(case_id)}&amp;format=json">'
        "Export JSON</a></p>",
        "<p><strong>Important:</strong> These are candidate correlations, "
        "not verified identity matches. Confirm relevant claims against "
        "independent sources before relying on them.</p>",
    ])

    return "\n".join(parts)
