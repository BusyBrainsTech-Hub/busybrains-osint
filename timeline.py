#!/usr/bin/env python3
"""Create a read-only HTML timeline from existing BusyBrains OSINT records."""
import argparse
import html
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = ROOT / "storage" / "busybrains_osint.db"
REPORTS = ROOT / "reports"


def columns(conn, table):
    return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]


def pick(cols, *options):
    mapping = {c.lower(): c for c in cols}
    return next((mapping[o.lower()] for o in options if o.lower() in mapping), None)


def ident(name):
    return '"' + name.replace('"', '""') + '"'


def main():
    parser = argparse.ArgumentParser(description="Generate an HTML case timeline.")
    parser.add_argument("--case", type=int, required=True)
    args = parser.parse_args()

    if not DB.is_file():
        parser.error(f"Database not found: {DB}")

    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        cases_table = next(
            (t for t in ("cases", "investigation_cases", "osint_cases") if t in tables),
            None,
        )
        findings_table = next(
            (t for t in ("findings", "case_findings", "osint_findings") if t in tables),
            None,
        )
        if not cases_table or not findings_table:
            parser.error("Could not identify case/findings tables; database was not changed.")

        cc = columns(conn, cases_table)
        case_id = pick(cc, "id", "case_id")
        case_name_col = pick(cc, "name", "title", "case_name")
        if not case_id:
            parser.error("Could not identify the case ID column.")

        case = conn.execute(
            f"SELECT * FROM {ident(cases_table)} WHERE {ident(case_id)}=?",
            (args.case,),
        ).fetchone()
        if case is None:
            parser.error(f"Case {args.case} was not found.")
        case_name = str(case[case_name_col]) if case_name_col else f"Case {args.case}"

        fc = columns(conn, findings_table)
        fid_col = pick(fc, "id", "finding_id")
        fcase_col = pick(fc, "case_id", "case", "investigation_id")
        if not fid_col or not fcase_col:
            parser.error("Could not identify finding ID/case columns.")

        findings = conn.execute(
            f"SELECT * FROM {ident(findings_table)} WHERE {ident(fcase_col)}=?",
            (args.case,),
        ).fetchall()

        assessments = {}
        if "finding_assessments" in tables and findings:
            ac = columns(conn, "finding_assessments")
            aid = pick(ac, "finding_id")
            if aid:
                ids = [row[fid_col] for row in findings]
                placeholders = ",".join("?" for _ in ids)
                for row in conn.execute(
                    f"SELECT * FROM finding_assessments WHERE {ident(aid)} IN ({placeholders})",
                    ids,
                ):
                    assessments[row[aid]] = dict(row)

    date_col = pick(fc, "created_at", "timestamp", "created", "date", "observed_at")
    title_col = pick(fc, "title", "name", "subject")
    category_col = pick(fc, "category", "type", "finding_type")
    content_col = pick(fc, "content", "description", "details", "summary", "value")
    source_col = pick(fc, "source_url", "source", "url", "source_uri")

    events = []

    def add_event(date, kind, title, category, content, source, fid):
        events.append({
            "sort": date if date != "Date not recorded" else "",
            "date": date, "kind": kind, "title": title,
            "category": category, "content": content,
            "source": source, "id": fid,
        })

    for row in findings:
        fid = row[fid_col]
        value = lambda col, default: (
            str(row[col]) if col and row[col] not in (None, "") else default
        )
        date = value(date_col, "Date not recorded")
        add_event(
            date, "Finding", value(title_col, f"Finding #{fid}"),
            value(category_col, "Finding"),
            value(content_col, "No details recorded."),
            value(source_col, ""), fid,
        )

        assessment = assessments.get(fid)
        if assessment:
            def avalue(*names):
                col = pick(list(assessment.keys()), *names)
                return str(assessment[col]) if col and assessment[col] not in (None, "") else "Not recorded"

            add_event(
                avalue("assessed_at", "updated_at", "created_at", "timestamp"),
                "Evidence assessment", f"Assessment for finding #{fid}",
                avalue("classification"),
                "Confidence: " + avalue("confidence")
                + ". Source review: " + avalue("source_review")
                + ". Rationale: " + avalue("rationale"),
                "", fid,
            )

    events.sort(key=lambda e: (e["sort"], int(e["id"])))
    cards = []

    for event in events:
        source_html = ""
        if event["source"].startswith(("https://", "http://")):
            url = html.escape(event["source"], quote=True)
            source_html = (
                f'<p><strong>Source:</strong> '
                f'<a href="{url}" rel="noopener noreferrer">{url}</a></p>'
            )
        cards.append(
            '<article class="event">'
            f'<div class="date">{html.escape(event["date"])}</div>'
            f'<div class="kind">{html.escape(event["kind"])}</div>'
            f'<h2>{html.escape(event["title"])}</h2>'
            f'<p><strong>Category / classification:</strong> {html.escape(event["category"])}</p>'
            f'<p>{html.escape(event["content"])}</p>{source_html}'
            f'<p class="ref">Finding ID: {html.escape(str(event["id"]))}</p>'
            '</article>'
        )

    if not cards:
        cards.append(
            '<article class="event"><h2>No findings recorded</h2>'
            '<p>This case has no findings to display.</p></article>'
        )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Investigation Timeline — Case {args.case}</title>
<style>
:root{{--navy:#101b35;--gold:#d6ad55;--paper:#f4f6fa;--ink:#202a3b;--muted:#667085}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 system-ui,sans-serif}}
header{{background:var(--navy);color:white;padding:30px max(22px,calc((100% - 960px)/2));border-bottom:5px solid var(--gold)}}
header h1{{margin:0}}header p{{margin:5px 0;color:#e4e8f0}}
main{{max-width:960px;margin:28px auto;padding:0 18px}}
.notice{{background:#fff8e7;border-left:4px solid var(--gold);padding:14px;margin-bottom:20px}}
.event{{background:white;border:1px solid #e1e6ef;border-radius:10px;padding:20px;margin-bottom:16px;overflow-wrap:anywhere}}
.date{{color:var(--muted);font-size:.9rem}}.kind{{display:inline-block;background:#eef1f7;padding:3px 9px;border-radius:20px;margin:7px 0;font-size:.85rem}}
h2{{font-size:1.2rem;margin:5px 0 12px}}.ref{{font-size:.85rem;color:var(--muted)}}a{{color:#164d91}}
footer{{text-align:center;color:var(--muted);padding:25px}}
</style></head><body>
<header><h1>Investigation Timeline</h1>
<p>{html.escape(case_name)} · Case #{args.case}</p><p>Generated {generated}</p></header>
<main><div class="notice"><strong>Evidence handling:</strong>
This report reflects records stored in the local case database. Missing dates are not invented.
Chronological order does not prove a claim is true; independently verify sources and assessments.</div>
{''.join(cards)}</main>
<footer>BusyBrains Tech-Hub · BusyBrains OSINT · Local report</footer>
</body></html>"""

    REPORTS.mkdir(parents=True, exist_ok=True)
    output = REPORTS / f"case_{args.case}_timeline.html"
    output.write_text(page, encoding="utf-8")
    print(f"Timeline report created: {output}")
    print(f"Case: {args.case} — {case_name}")
    print(f"Events included: {len(events)}")


if __name__ == "__main__":
    main()
