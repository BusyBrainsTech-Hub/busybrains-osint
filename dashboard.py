import time
#!/usr/bin/env python3
"""Local-only web dashboard for BusyBrains OSINT."""

import html
from html import escape as esc
import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from scan_launcher import render_launcher, run_scan
from investigation_intelligence import dashboard_body as investigation_dashboard_body
from pathlib import Path

import app as core
import evidence_quality as quality
import historical_intelligence as historical
import dns_alert_engine as dns_alerts

HOST = "127.0.0.1"
PORT = 8787

NAVY = "#101c35"
GOLD = "#d6ad55"


def esc(value):
    return html.escape(str(value if value is not None else ""))


def layout(title, body):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | BusyBrains OSINT</title>
<style>
:root {{
  --navy: {NAVY};
  --gold: {GOLD};
  --ink: #202938;
  --muted: #647084;
  --line: #dce2eb;
  --bg: #f2f5f9;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink);
       font: 15px/1.6 Arial, Helvetica, sans-serif; }}
header {{ background: var(--navy); color: white;
          border-bottom: 5px solid var(--gold); padding: 22px 24px; }}
.wrap {{ max-width: 1120px; margin: auto; }}
.brand {{ color: var(--gold); font-weight: bold; letter-spacing: 2px; }}
header h1 {{ margin: 8px 0 2px; }}
header p {{ margin: 0; color: #dbe3ef; }}
nav {{ margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }}
nav a {{ color: white; text-decoration: none; padding: 7px 11px;
         border: 1px solid #46536b; border-radius: 6px; }}
main {{ max-width: 1120px; margin: 26px auto; padding: 0 18px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
         gap: 15px; }}
.card, .panel {{ background: white; border: 1px solid var(--line);
                 border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
.card {{ box-shadow: 0 3px 12px #101c350b; }}
h2, h3 {{ color: var(--navy); margin-top: 0; }}
.metric {{ font-size: 30px; font-weight: bold; color: var(--navy); }}
.muted {{ color: var(--muted); font-size: 13px; }}
a {{ color: #174f91; overflow-wrap: anywhere; }}
.button {{ display: inline-block; background: var(--navy); color: white;
           text-decoration: none; padding: 9px 13px; border-radius: 6px;
           margin: 3px 4px 3px 0; }}
.button.gold {{ background: #fff3d5; color: #60460b;
                 border: 1px solid #ead39b; }}
input {{ width: 100%; max-width: 520px; padding: 12px;
         border: 1px solid #cbd3df; border-radius: 7px; margin-bottom: 16px; }}
table {{ border-collapse: collapse; width: 100%; background: white; }}
th, td {{ text-align: left; padding: 11px; border-bottom: 1px solid var(--line);
          vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #eaf0f7; color: var(--navy); }}
.table-wrap {{ overflow-x: auto; }}
.badge {{ display: inline-block; padding: 3px 9px; border-radius: 20px;
          background: #fff3d5; border: 1px solid #ead39b; color: #60460b;
          font-size: 12px; }}
.notice {{ border-left: 4px solid var(--gold); }}
footer {{ text-align: center; padding: 24px; color: var(--muted); font-size: 12px; }}
@media(max-width:650px) {{
  th, td {{ padding: 8px; font-size: 13px; }}
}}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div class="brand">BUSYBRAINS TECH-HUB</div>
    <h1>OSINT Investigation Workspace</h1>
    <p>Public-source research · Case management · Evidence review</p>
    <nav>
      <a href="/">Dashboard</a>
      <a href="/health">System status</a>
      <a href="/social">Social Intelligence</a>
      <a href="/scans">Unified Scan Launcher</a>
      <a href="/intel">Unified Intelligence</a>
      <a href="/investigation">Investigation Intelligence</a>
      <a href="/history">Historical Intelligence</a>
      <a href="/alerts">DNS &amp; TLS Alerts</a>
    </nav>
  </div>
</header>
<main class="wrap">{body}</main>
<footer>BusyBrains OSINT {esc(core.VERSION)} · Local workspace · {HOST}:{PORT}</footer>
</body>
</html>"""


def dashboard_page():
    cases = [dict(c) for c in core.list_cases()]
    total_findings = sum(int(c.get("finding_count", 0) or 0) for c in cases)

    with quality.connect() as db:
        review_stats = db.execute("""
            SELECT COUNT(f.id) AS total,
                   COUNT(a.finding_id) AS reviewed
            FROM findings AS f
            LEFT JOIN finding_assessments AS a
              ON a.finding_id = f.id
        """).fetchone()
    reviewed_count = int(review_stats["reviewed"] or 0)

    cards = []
    for case in cases:
        case_id = int(case["id"])
        cards.append(f"""
        <article class="card case-card"
                 data-search="{esc((case.get('name','') + ' ' + case.get('purpose','')).lower())}">
          <div class="badge">CASE #{case_id}</div>
          <h3>{esc(case.get('name', 'Untitled case'))}</h3>
          <p>{esc(case.get('purpose') or 'No investigation purpose recorded.')}</p>
          <p class="muted">Created: {esc(case.get('created_at', 'Not recorded'))}</p>
          <p><strong>{int(case.get('finding_count', 0) or 0)}</strong> findings</p>
          <a class="button" href="/case?id={case_id}">Open investigation</a>
        </article>
        """)

    case_cards = "\n".join(cards) if cards else (
        '<div class="panel">No cases found. Create one using the CLI:<br>'
        '<code>./busybrains-osint case create --name "New Investigation" '
        '--purpose "Describe the authorised research purpose"</code></div>'
    )

    body = f"""
    <section class="grid">
      <div class="card"><div class="muted">Investigation cases</div>
        <div class="metric">{len(cases)}</div></div>
      <div class="card"><div class="muted">Recorded findings</div>
        <div class="metric">{total_findings}</div></div>
      <div class="card"><div class="muted">Application version</div>
        <div class="metric">{esc(core.VERSION)}</div></div>
      <div class="card"><div class="muted">Findings assessed</div>
        <div class="metric">{reviewed_count} / {int(review_stats["total"] or 0)}</div>
        <div class="muted">Review coverage</div></div>
    </section>
    <section class="panel">
      <h2>Investigation cases</h2>
      <input id="caseSearch" type="search" placeholder="Search cases by name or purpose…"
             aria-label="Search cases">
      <div class="grid" id="caseGrid">{case_cards}</div>
      <p id="noMatches" class="muted" hidden>No matching cases.</p>
    </section>
    <section class="panel notice">
      <h3>Responsible research</h3>
      Use this workspace for lawful public-source research and investigations
      within your authorisation. Validate important claims against their original
      sources; a profile match alone does not establish identity or ownership.
    </section>
    <script>
    const input = document.getElementById('caseSearch');
    input.addEventListener('input', () => {{
      const query = input.value.toLowerCase().trim();
      let visible = 0;
      document.querySelectorAll('.case-card').forEach(card => {{
        const match = card.dataset.search.includes(query);
        card.hidden = !match;
        if (match) visible++;
      }});
      document.getElementById('noMatches').hidden = visible !== 0;
    }});
    </script>
    """
    return layout("Dashboard", body)


def case_page(case_id):
    case = dict(core.get_case(case_id))
    findings = [dict(row) for row in core.list_findings(case_id)]

    with quality.connect() as db:
        assessment_rows = db.execute("""
            SELECT a.*
            FROM finding_assessments AS a
            JOIN findings AS f ON f.id = a.finding_id
            WHERE f.case_id = ?
        """, (case_id,)).fetchall()
    assessments = {
        int(row["finding_id"]): dict(row) for row in assessment_rows
    }

    rows = []
    for item in findings:
        assessment = assessments.get(int(item["id"]))
        if assessment:
            assessment_html = (
                f'<span class="badge">{esc(assessment["classification"])}</span>'
                f'<p><strong>Confidence:</strong> {esc(assessment["confidence"])}</p>'
                f'<p><strong>Source review:</strong> {esc(assessment["source_review"])}</p>'
                f'<p class="muted">{esc(assessment["rationale"])}</p>'
            )
        else:
            assessment_html = (
                '<span class="badge">NOT REVIEWED</span>'
                '<p class="muted">Run busybrains-quality assess to review.</p>'
            )

        source = item.get("source_url") or ""
        source_link = ""
        if source:
            parsed = urlparse(source)
            if parsed.scheme in ("https", "http") and parsed.netloc:
                source_link = (
                    f'<a href="{esc(source)}" target="_blank" '
                    f'rel="noopener noreferrer">{esc(source)}</a>'
                )
            else:
                source_link = esc(source)

        rows.append(f"""
        <tr>
          <td>{esc(item.get('id'))}</td>
          <td><span class="badge">{esc(item.get('category'))}</span></td>
          <td><strong>{esc(item.get('title'))}</strong><br>
              <span>{esc(item.get('content'))}</span></td>
          <td>{source_link or '<span class="muted">Not recorded</span>'}</td>
          <td>{esc(item.get('collected_at') or 'Not recorded')}</td>
          <td>{assessment_html}</td>
        </tr>
        """)

    table_rows = "\n".join(rows) or (
        '<tr><td colspan="5">No findings recorded for this case yet.</td></tr>'
    )

    body = f"""
    <p><a href="/">← Back to dashboard</a></p>
    <section class="panel">
      <span class="badge">CASE #{int(case["id"])}</span>
      <h2>{esc(case.get("name", "Untitled case"))}</h2>
      <p>{esc(case.get("purpose") or "No purpose recorded.")}</p>
      <p class="muted">Created: {esc(case.get("created_at", "Not recorded"))}</p>
      <p><strong>{len(findings)}</strong> findings in this case</p>
      <h3>Export investigation report</h3>
      <a class="button" href="/export?case={case_id}&format=html">HTML report</a>
      <a class="button gold" href="/export?case={case_id}&format=json">JSON data</a>
      <a class="button gold" href="/export?case={case_id}&format=csv">CSV data</a>
    </section>
    <section class="panel">
      <h2>Findings register</h2>
      <input id="findingSearch" type="search"
             placeholder="Search findings, categories, and sources…"
             aria-label="Search findings">
      <div class="table-wrap">
      <table id="findingsTable">
        <thead><tr><th>ID</th><th>Category</th><th>Finding</th>
        <th>Source</th><th>Collected</th><th>Evidence assessment</th></tr></thead>
        <tbody>{table_rows}</tbody>
      </table>
      </div>
      <p id="noFindings" class="muted" hidden>No findings match your search.</p>
    </section>
    """
    body += """
    <script>
    const search = document.getElementById('findingSearch');
    search.addEventListener('input', () => {
      const query = search.value.toLowerCase().trim();
      let visible = 0;
      document.querySelectorAll('#findingsTable tbody tr').forEach(row => {
        const match = row.innerText.toLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible++;
      });
      document.getElementById('noFindings').hidden = visible !== 0;
    });
    </script>
    """
    return layout(case.get("name", "Case"), body)




def historical_intelligence_page(case_id):
    cases = [dict(item) for item in core.list_cases()]

    if not cases:
        return layout(
            "Historical Intelligence",
            "<section class='panel'><h2>No cases available</h2>"
            "<p>Create a case before running historical comparisons.</p></section>",
        )

    valid_ids = {int(item["id"]) for item in cases}
    if case_id not in valid_ids:
        raise ValueError("Selected case does not exist.")

    case, observations, total_findings = historical.load_observations(case_id)
    comparisons = historical.compare_observations(observations)

    changed = sum(item["status"] == "CHANGE DETECTED" for item in comparisons)
    unchanged = sum(item["status"] == "NO CHANGE DETECTED" for item in comparisons)
    insufficient = sum(
        item["status"] == "INSUFFICIENT COMPARABLE DATA"
        for item in comparisons
    )

    options = "".join(
        f'<option value="{int(item["id"])}" '
        f'{"selected" if int(item["id"]) == case_id else ""}>'
        f'Case #{int(item["id"])} — {esc(item.get("name", ""))}</option>'
        for item in cases
    )

    rows = []
    for item in comparisons:
        status = item["status"]
        badge = (
            "CHANGE DETECTED" if status == "CHANGE DETECTED"
            else "NO CHANGE DETECTED" if status == "NO CHANGE DETECTED"
            else "INSUFFICIENT COMPARABLE DATA"
        )

        changes = item.get("changes", [])
        if changes:
            detail_items = []
            for change in changes:
                item_html = (
                    "<li><strong>" + esc(change["field"]) + ":</strong> "
                )

                if "added" in change or "removed" in change:
                    added = change.get("added", [])
                    removed = change.get("removed", [])
                    item_html += (
                        "<br><span class='muted'>Added:</span> "
                        + esc(", ".join(added) if added else "None")
                        + "<br><span class='muted'>Removed:</span> "
                        + esc(", ".join(removed) if removed else "None")
                    )
                else:
                    item_html += (
                        "<br><span class='muted'>Previous:</span> "
                        + esc(change["previous"])
                        + "<br><span class='muted'>Current:</span> "
                        + esc(change["current"])
                    )

                item_html += "</li>"
                detail_items.append(item_html)

            details = "<ul>" + "".join(detail_items) + "</ul>"
        elif item.get("compared_fields"):
            details = (
                "<p class='muted'>Compared fields: "
                + esc(", ".join(item["compared_fields"]))
                + ". No differences found.</p>"
            )
        else:
            details = (
                "<p class='muted'>The two observations have no shared "
                "comparable fields. No conclusion can be drawn.</p>"
            )

        rows.append(
            "<tr>"
            f"<td><strong>{esc(item['entity'])}</strong><br>"
            f"<span class='muted'>{esc(item['type'])}</span></td>"
            f"<td><span class='badge'>{esc(badge)}</span></td>"
            f"<td>{esc(item['previous_finding_id'])} → "
            f"{esc(item['current_finding_id'])}</td>"
            f"<td>{esc(item['previous_date'])}<br>→ "
            f"{esc(item['current_date'])}</td>"
            f"<td>{len(item.get('compared_fields', []))}</td>"
            f"<td>{details}</td>"
            "</tr>"
        )

    table_rows = "".join(rows) or (
        "<tr><td colspan='6'>No entities have two or more supported "
        "historical observations yet.</td></tr>"
    )

    body = f"""
    <section class="panel">
      <h2>Historical Intelligence</h2>
      <p>Compare supported observations collected at different times
      within an investigation case.</p>
      <form method="get" action="/history">
        <label for="case">Select investigation case</label><br>
        <select id="case" name="case"
          style="width:100%;max-width:520px;padding:12px;margin:12px 0">
          {options}
        </select>
        <br><button class="button" type="submit">Compare case history</button>
      </form>
      <p class="muted">Case #{int(case["id"])}:
      {esc(case.get("name", ""))}</p>
    </section>

    <section class="grid">
      <div class="card"><div class="muted">Database findings</div>
        <div class="metric">{total_findings}</div></div>
      <div class="card"><div class="muted">Supported observations</div>
        <div class="metric">{len(observations)}</div></div>
      <div class="card"><div class="muted">Changes detected</div>
        <div class="metric">{changed}</div></div>
      <div class="card"><div class="muted">No change detected</div>
        <div class="metric">{unchanged}</div></div>
      <div class="card"><div class="muted">Insufficient data</div>
        <div class="metric">{insufficient}</div></div>
    </section>

    <section class="panel">
      <h2>Historical comparison results</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Entity</th><th>Status</th><th>Findings</th>
            <th>Observation dates</th><th>Fields compared</th><th>Details</th>
          </tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="panel notice">
      <h3>Interpretation and limitations</h3>
      <p>Only fields present in both observations are compared.
      A missing field is not evidence that information disappeared.</p>
      <p>A detected difference is an investigative lead, not proof
      of identity, ownership, wrongdoing, or causation. Verify original
      sources before relying on a conclusion.</p>
      <p class="muted">This dashboard view is read-only. It does not
      modify findings or case records.</p>
    </section>
    """
    return layout("Historical Intelligence", body)



def dns_alerts_page(case_id):
    cases = [dict(item) for item in core.list_cases()]

    if not cases:
        return layout(
            "DNS & TLS Alerts",
            "<section class='panel'><h2>No cases available</h2>"
            "<p>Create an investigation case before reviewing alerts.</p></section>",
        )

    valid_ids = {int(item["id"]) for item in cases}
    if case_id not in valid_ids:
        raise ValueError("Selected case does not exist.")

    case, total, comparisons, alerts = dns_alerts.build_alerts(case_id)

    counts = {
        level: sum(item["severity"] == level for item in alerts)
        for level in ("HIGH", "MEDIUM", "LOW", "INFO")
    }

    options = "".join(
        f'<option value="{int(item["id"])}" '
        f'{"selected" if int(item["id"]) == case_id else ""}>'
        f'Case #{int(item["id"])} — {esc(item.get("name", ""))}</option>'
        for item in cases
    )

    rows = []
    for alert in alerts:
        previous = json.dumps(
            alert.get("previous"), ensure_ascii=False
        )
        current = json.dumps(
            alert.get("current"), ensure_ascii=False
        )
        added = json.dumps(
            alert.get("added", []), ensure_ascii=False
        )
        removed = json.dumps(
            alert.get("removed", []), ensure_ascii=False
        )

        rows.append(f"""
        <tr>
          <td><strong>{esc(alert["severity"])}</strong></td>
          <td>{esc(alert["alert_type"])}</td>
          <td>{esc(alert["entity"])}</td>
          <td>{esc(alert["field"])}</td>
          <td>{esc(previous)}</td>
          <td>{esc(current)}</td>
          <td>{esc(added)}</td>
          <td>{esc(removed)}</td>
          <td>{esc(alert["recommendation"])}</td>
        </tr>
        """)

    table_rows = "".join(rows) or (
        "<tr><td colspan='9'>No DNS or TLS configuration changes "
        "detected between the latest comparable observations.</td></tr>"
    )

    body = f"""
    <section class="panel">
      <h2>DNS &amp; TLS Change Alerts</h2>
      <p>Review observed DNS record and TLS certificate changes
      across supported historical observations.</p>

      <form method="get" action="/alerts">
        <label for="case">Select investigation case</label><br>
        <select id="case" name="case"
          style="width:100%;max-width:520px;padding:12px;margin:12px 0">
          {options}
        </select>
        <br><button class="button" type="submit">Review alerts</button>
      </form>

      <p class="muted">Case #{int(case["id"])}:
      {esc(case.get("name", ""))}</p>
    </section>

    <section class="grid">
      <div class="card"><div class="muted">Database findings</div>
        <div class="metric">{total}</div></div>
      <div class="card"><div class="muted">Entities compared</div>
        <div class="metric">{len(comparisons)}</div></div>
      <div class="card"><div class="muted">Total alerts</div>
        <div class="metric">{len(alerts)}</div></div>
      <div class="card"><div class="muted">HIGH</div>
        <div class="metric">{counts["HIGH"]}</div></div>
      <div class="card"><div class="muted">MEDIUM</div>
        <div class="metric">{counts["MEDIUM"]}</div></div>
      <div class="card"><div class="muted">LOW</div>
        <div class="metric">{counts["LOW"]}</div></div>
      <div class="card"><div class="muted">INFO</div>
        <div class="metric">{counts["INFO"]}</div></div>
    </section>

    <section class="panel">
      <h2>Alert review results</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Severity</th><th>Alert type</th><th>Entity</th>
            <th>Field</th><th>Previous value</th><th>Current value</th>
            <th>Added</th><th>Removed</th><th>Recommendation</th>
          </tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h3>Interpretation and limitations</h3>
      <p>Alerts identify observed configuration differences. They are
      investigative leads, not proof of compromise.</p>
      <p>Severity represents review priority, not probability of attack.
      Verify changes with authoritative sources and the domain owner.</p>
      <p class="muted">This dashboard page is read-only. It does not
      modify findings or case records.</p>
    </section>
    """

    return layout("DNS & TLS Alerts", body)


def social_intelligence_page():
    reports_dir = Path(__file__).resolve().parent / "reports"
    report_files = sorted(
        reports_dir.glob("social_scan_*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    panels = []
    for report_path in report_files[:10]:
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            rendered = esc(json.dumps(data, indent=2, ensure_ascii=False))
            if len(rendered) > 16000:
                rendered = rendered[:16000] + "\n... report truncated ..."
            panels.append(
                "<section class='panel'><h3>" + esc(report_path.name) +
                "</h3><details><summary>View report</summary>"
                "<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>" +
                rendered + "</pre></details></section>"
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            panels.append(
                "<section class='panel'><p>" +
                esc(f"Could not read {report_path.name}: {exc}") +
                "</p></section>"
            )

    report_content = "\n".join(panels) or (
        "<section class='panel'><p>No social scan reports yet.</p></section>"
    )

    body = f"""
    <p><a href="/">← Back to dashboard</a></p>

    <section class="panel notice">
      <h2>Social Intelligence</h2>
      <p>Check candidate public profile URLs across supported platforms.</p>
      <p class="muted">
        These checks use public profile URLs only. HTTP responses are
        preliminary signals, not identity verification. No private account
        access, login bypass, or private-content collection is performed.
      </p>
    </section>

    <section class="panel">
      <h3>New public profile search</h3>
      <form method="POST" action="/social">
        <label><strong>Investigation case ID</strong></label><br>
        <input name="case_id" type="number" min="1" value="2" required
          style="width:100%;max-width:420px;padding:10px"><br><br>

        <label><strong>Username or handle</strong></label><br>
        <input name="username" type="text" maxlength="64"
          placeholder="Example: Possiblinkz" required
          style="width:100%;max-width:420px;padding:10px"><br><br>

        <label><strong>Platforms</strong></label><br>
        <input name="platforms" type="text" value="all"
          placeholder="all or github,reddit,instagram"
          style="width:100%;max-width:420px;padding:10px">
        <p class="muted">
          Enter <code>all</code> or comma-separated platform keys.
          Example: <code>github,reddit,devto</code>.
        </p>

        <button class="button" type="submit">Run Social Intelligence Search</button>
      </form>
    </section>

    <section class="panel">
      <h3>Supported platforms</h3>
      <p>25 public profile URL patterns are available.</p>
      <p><code>./busybrains-social --list</code></p>
    </section>

    <h2>Recent social scan reports ({len(report_files)})</h2>
    {report_content}
    """
    return layout("Social Intelligence", body)


def unified_intelligence_page():
    body = """
    <p><a href="/">← Back to dashboard</a></p>
    <section class="panel notice">
      <h2>Unified Intelligence</h2>
      <p>Run a public-source check and attach its report to an investigation case.</p>
      <p class="muted">Use only accounts, contact details and systems you own or
      are explicitly authorized to investigate. Results are leads, not proof
      of identity or ownership.</p>
    </section>
    <section class="panel">
      <form method="POST" action="/intel">
        <label><strong>Investigation case ID</strong></label><br>
        <input name="case_id" type="number" min="1" value="2" required>
        <label><strong>Search type</strong></label><br>
        <select name="search_type" required
          style="width:100%;max-width:520px;padding:12px;margin-bottom:16px">
          <option value="username">Username / public profiles</option>
          <option value="email">Email syntax and mail records</option>
          <option value="phone">Phone number validation</option>
          <option value="domain">Domain DNS resolution</option>
        </select><br>
        <label><strong>Search value</strong></label><br>
        <input name="search_value" type="text" maxlength="254"
          placeholder="Username, email, phone or domain" required>
        <label><strong>Platforms (username searches only)</strong></label><br>
        <input name="platforms" type="text" value="all"
          placeholder="all or github,reddit,x">
        <label><strong>Phone region (phone searches only)</strong></label><br>
        <input name="region" type="text" value="NG" maxlength="2">
        <p><button class="button" type="submit">Run intelligence search</button></p>
      </form>
    </section>
    <section class="panel">
      <h3>Search coverage</h3>
      <ul>
        <li>Username: public profile URL availability across the platform registry.</li>
        <li>Email: syntax check and MX lookup when DNS support is installed.</li>
        <li>Phone: numbering-plan validation when the optional library is installed.</li>
        <li>Domain: basic DNS address resolution.</li>
      </ul>
      <p class="muted">Reports are saved as JSON and consolidated findings
      are attached to the selected case. No mailbox login, private account
      access, subscriber lookup or location tracking is performed.</p>
    </section>
    """
    return layout("Unified Intelligence", body)


def investigation_intelligence_page():
    return layout(
        "Investigation Intelligence",
        investigation_dashboard_body(2),
    )


def scan_launcher_page():
    return layout("Unified Scan Launcher", render_launcher())


def evidence_review_page(case_id):
    core.get_case(case_id)
    findings = core.list_findings(case_id)

    conn = quality.connect()
    try:
        assessments = {
            row["finding_id"]: dict(row)
            for row in conn.execute(
                "SELECT * FROM finding_assessments"
            ).fetchall()
        }
    finally:
        conn.close()

    rows = []
    for finding in findings:
        item = dict(finding)
        fid = int(item["id"])
        title = esc(str(item.get("title", "Untitled finding")))
        category = esc(str(item.get("category", "Uncategorised")))
        assessment = assessments.get(fid)

        if assessment:
            current = (
                "<p><strong>Current assessment:</strong> "
                + esc(assessment["classification"])
                + " / " + esc(assessment["confidence"])
                + " / " + esc(assessment["source_review"])
                + "</p><p><strong>Rationale:</strong> "
                + esc(assessment["rationale"]) + "</p>"
            )
            button_text = "Update assessment"
        else:
            current = "<p><strong>Status:</strong> Awaiting review</p>"
            button_text = "Save assessment"

        rows.append(
            "<section class='card' style='margin:16px 0;padding:18px'>"
            f"<h3>Finding #{fid}: {title}</h3>"
            f"<p><strong>Category:</strong> {category}</p>"
            f"{current}"
            "<form method='POST' action='/review'>"
            f"<input type='hidden' name='case_id' value='{case_id}'>"
            f"<input type='hidden' name='finding_id' value='{fid}'>"
            "<label>Classification</label>"
            "<select name='classification' required>"
            "<option value='observed_fact'>Observed fact</option>"
            "<option value='analyst_assessment'>Analyst assessment</option>"
            "<option value='unverified_lead' selected>Unverified lead</option>"
            "</select>"
            "<label>Confidence</label>"
            "<select name='confidence' required>"
            "<option value='high'>High</option>"
            "<option value='medium' selected>Medium</option>"
            "<option value='low'>Low</option>"
            "</select>"
            "<label>Source review</label>"
            "<select name='source_review' required>"
            "<option value='verified'>Verified</option>"
            "<option value='needs_verification' selected>Needs verification</option>"
            "<option value='not_applicable'>Not applicable</option>"
            "</select>"
            "<label>Analyst</label>"
            "<input name='analyst' maxlength='100' "
            "value='BusyBrains analyst' required>"
            "<label>Review rationale</label>"
            "<textarea name='rationale' maxlength='4000' "
            "rows='3' required placeholder='Explain what the evidence supports, "
            "what remains uncertain, and what should be checked.'></textarea>"
            f"<button type='submit'>{button_text}</button>"
            "</form></section>"
        )

    content = (
        f"<h2>Evidence Review — Case #{case_id}</h2>"
        "<p>Assess each finding separately. A reachable profile or matching "
        "username is not proof of identity or ownership.</p>"
        + ("".join(rows) if rows else "<p>No findings in this case.</p>")
        + f"<p><a class='button' href='/investigation'>Investigation Intelligence</a> "
        f"<a class='button' href='/case?id={case_id}'>View Case</a></p>"
    )
    return layout("Evidence Review", content)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "BusyBrainsOSINTDashboard/1.0"

    def send_page(self, body, status=200, content_type="text/html; charset=utf-8"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)


    def do_POST(self):
        from urllib.parse import parse_qs, urlparse

        request_path = urlparse(self.path).path

        if request_path == "/review":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16384:
                    self.send_error(413, "Invalid form size")
                    return

                raw = self.rfile.read(length).decode("utf-8")
                parsed_form = parse_qs(raw, keep_blank_values=True)
                form = {key: values[0] for key, values in parsed_form.items()}

                import argparse
                case_id = int(form.get("case_id", "0"))
                finding_id = int(form.get("finding_id", "0"))

                core.get_case(case_id)
                finding = quality.get_finding(finding_id)
                if int(finding["case_id"]) != case_id:
                    raise ValueError("That finding does not belong to this case.")

                classification = form.get("classification", "")
                confidence = form.get("confidence", "")
                source_review = form.get("source_review", "")

                if classification not in quality.CLASSIFICATIONS:
                    raise ValueError("Invalid classification.")
                if confidence not in quality.CONFIDENCE_LEVELS:
                    raise ValueError("Invalid confidence level.")
                if source_review not in quality.SOURCE_REVIEWS:
                    raise ValueError("Invalid source review value.")

                rationale = form.get("rationale", "").strip()
                analyst = form.get("analyst", "").strip()
                if not rationale or len(rationale) > 4000:
                    raise ValueError("Enter a rationale of 1–4000 characters.")
                if not analyst or len(analyst) > 100:
                    raise ValueError("Enter an analyst name of 1–100 characters.")

                quality.save_assessment(argparse.Namespace(
                    finding=finding_id,
                    classification=classification,
                    confidence=confidence,
                    source_review=source_review,
                    rationale=rationale,
                    analyst=analyst,
                ))

                self.send_response(303)
                self.send_header("Location", f"/review?case={case_id}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            except (ValueError, TypeError, KeyError) as exc:
                self.send_page(
                    layout("Review Validation", "<h2>Assessment not saved</h2>"
                    f"<p>{esc(str(exc))}</p><p><a href='/investigation'>Return to investigation</a></p>"),
                    400,
                )
                return
            except Exception:
                self.send_page(
                    layout("Review Error", "<h2>Assessment could not be saved</h2>"
                    "<p>Check the dashboard terminal for details.</p>"),
                    500,
                )
                return

        if request_path == "/intel":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16384:
                    self.send_error(413, "Invalid form size")
                    return

                raw = self.rfile.read(length).decode("utf-8")
                parsed_form = parse_qs(raw, keep_blank_values=True)
                form = {key: values[0] for key, values in parsed_form.items()}

                case_id = int(form.get("case_id", "0"))
                if case_id < 1:
                    raise ValueError("Enter a valid positive case ID.")
                core.get_case(case_id)

                search_type = form.get("search_type", "")
                value = form.get("search_value", "").strip()
                if not value:
                    raise ValueError("Enter a search value.")

                import modules.unified_intel as unified

                if search_type == "username":
                    result = unified.username_intel(
                        value, form.get("platforms", "all"), 8.0, 1.2
                    )
                elif search_type == "email":
                    result = unified.email_intel(value)
                elif search_type == "phone":
                    region = form.get("region", "NG").strip().upper() or "NG"
                    if len(region) != 2 or not region.isalpha():
                        raise ValueError("Phone region must be a two-letter code.")
                    result = unified.phone_intel(value, region)
                elif search_type == "domain":
                    result = unified.domain_intel(value)
                else:
                    raise ValueError("Choose a supported search type.")

                result["application"] = "BusyBrains OSINT"
                result["case_id"] = case_id
                result["generated_at"] = unified.now()

                reports_dir = Path(__file__).resolve().parent / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                stamp = unified.datetime.now(unified.timezone.utc).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                report_path = reports_dir / f"unified_intel_dashboard_{stamp}.json"
                report_path.write_text(
                    json.dumps(result, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                title_value = (
                    result.get("username_pattern")
                    or result.get("submitted_value")
                    or result.get("domain")
                    or value
                )
                finding_id = core.add_finding(
                    case_id,
                    f"{search_type}-intelligence",
                    f"Unified {search_type} intelligence: {title_value}",
                    json.dumps(result, indent=2, ensure_ascii=False),
                    "",
                )

                rendered = esc(json.dumps(result, indent=2, ensure_ascii=False))
                body = (
                    "<p><a href='/intel'>← New intelligence search</a></p>"
                    "<section class='panel notice'><h2>Search completed</h2>"
                    f"<p>Saved to case #{case_id}, finding #{finding_id}.</p>"
                    f"<p>JSON report: <code>{esc(report_path.name)}</code></p>"
                    f"<p><a class='button' href='/review?case={case_id}'>Review case evidence</a> "
                    f"<a class='button' href='/case?id={case_id}'>Open case</a></p></section>"
                    "<section class='panel'><h3>Result details</h3>"
                    f"<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>{rendered}</pre>"
                    "</section>"
                )
                self.send_page(layout("Unified Intelligence Results", body))
                return

            except (ValueError, TypeError, KeyError) as exc:
                self.send_page(
                    layout("Unified Intelligence",
                    "<h2>Search not completed</h2>"
                    f"<p>{esc(str(exc))}</p>"
                    "<p><a href='/intel'>Return to Unified Intelligence</a></p>"),
                    400,
                )
                return
            except Exception:
                self.send_page(
                    layout("Unified Intelligence Error",
                    "<h2>Search could not be completed</h2>"
                    "<p>Check the dashboard terminal for details.</p>"
                    "<p><a href='/intel'>Return to Unified Intelligence</a></p>"),
                    500,
                )
                return

        if request_path == "/social":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 8192:
                    self.send_error(413, "Invalid form size")
                    return

                raw = self.rfile.read(length).decode("utf-8")
                parsed_form = parse_qs(raw, keep_blank_values=True)
                form = {key: values[0] for key, values in parsed_form.items()}

                import re
                import modules.social_platforms as social

                case_id = int(form.get("case_id", "0"))
                if case_id < 1:
                    raise ValueError("Enter a valid positive case ID.")
                core.get_case(case_id)

                username = form.get("username", "").strip().lstrip("@")
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
                    raise ValueError(
                        "Username must contain 1–64 letters, digits, dots, "
                        "underscores or hyphens."
                    )

                platforms_raw = form.get("platforms", "all").strip().lower()
                if platforms_raw == "all":
                    selected = list(social.PLATFORMS)
                else:
                    selected = [
                        item.strip() for item in platforms_raw.split(",")
                        if item.strip()
                    ]
                    unknown = [
                        item for item in selected
                        if item not in social.PLATFORMS
                    ]
                    if unknown:
                        raise ValueError(
                            "Unknown platform key(s): " + ", ".join(unknown)
                        )
                    selected = list(dict.fromkeys(selected))

                if not selected:
                    raise ValueError("Select at least one platform.")

                results = []
                for index, platform in enumerate(selected):
                    result = social.check_profile(platform, username, 8.0)

                    title = (
                        f"Public profile URL check: "
                        f"{result['platform']} / {username}"
                    )
                    content = (
                        f"Classification: {result['classification']}\n"
                        f"HTTP status: {result['http_status']}\n"
                        f"Checked at: {result['checked_at']}\n"
                        f"Final URL: {result['final_url']}\n"
                        f"Assessment: {result['note']}\n"
                        "Caution: This check does not establish account "
                        "ownership or identity."
                    )

                    finding_id = core.add_finding(
                        case_id,
                        "social_profile_check",
                        title,
                        content,
                        result["url"],
                    )
                    result["saved_to_case"] = True
                    result["finding_id"] = finding_id
                    results.append(result)

                    if index < len(selected) - 1:
                        time.sleep(1.2)

                reports_dir = Path(__file__).resolve().parent / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)

                stamp = social.datetime.now(
                    social.timezone.utc
                ).strftime("%Y%m%dT%H%M%S%fZ")
                safe_name = re.sub(
                    r"[^A-Za-z0-9._-]", "_", username
                )[:64]
                base = reports_dir / f"social_scan_{safe_name}_{stamp}"

                report = {
                    "application": "BusyBrains OSINT",
                    "report_type": "public_profile_url_checks",
                    "username_pattern": username,
                    "case_id": case_id,
                    "generated_at": social.utc_now(),
                    "limitations": [
                        "A reachable URL does not prove account ownership.",
                        "An HTTP error does not prove an account is absent.",
                        "A matching username does not prove identity.",
                        "No private account access or login bypass was performed.",
                    ],
                    "results": results,
                }

                json_path = base.with_suffix(".json")
                csv_path = base.with_suffix(".csv")

                json_path.write_text(
                    json.dumps(report, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                fields = [
                    "platform", "platform_key", "username_pattern", "url",
                    "http_status", "classification", "note", "final_url",
                    "checked_at", "saved_to_case", "finding_id",
                ]
                with csv_path.open(
                    "w", newline="", encoding="utf-8"
                ) as handle:
                    writer = social.csv.DictWriter(
                        handle, fieldnames=fields, extrasaction="ignore"
                    )
                    writer.writeheader()
                    writer.writerows(results)

                rows = []
                for item in results:
                    rows.append(
                        "<tr>"
                        f"<td>{esc(item['platform'])}</td>"
                        f"<td>{esc(str(item['http_status'] or 'N/A'))}</td>"
                        f"<td>{esc(item['classification'])}</td>"
                        f"<td><a href='{esc(item['url'])}' "
                        "target='_blank' rel='noopener noreferrer'>"
                        "Open source</a></td>"
                        f"<td>#{int(item['finding_id'])}</td>"
                        "</tr>"
                    )

                body = (
                    "<p><a href='/social'>← New Social Intelligence search</a></p>"
                    "<section class='panel notice'>"
                    "<h2>Social search completed</h2>"
                    f"<p>Username pattern: <strong>{esc(username)}</strong></p>"
                    f"<p>Checks completed: {len(results)}</p>"
                    f"<p>Saved to case #{case_id}.</p>"
                    f"<p>JSON report: <code>{esc(json_path.name)}</code></p>"
                    f"<p>CSV report: <code>{esc(csv_path.name)}</code></p>"
                    f"<p><a class='button' href='/review?case={case_id}'>"
                    "Review case evidence</a></p></section>"
                    "<section class='panel'><h3>Search results</h3>"
                    "<div style='overflow-x:auto'><table>"
                    "<thead><tr><th>Platform</th><th>HTTP</th>"
                    "<th>Assessment</th><th>Source</th><th>Finding</th>"
                    "</tr></thead><tbody>"
                    + "".join(rows) +
                    "</tbody></table></div></section>"
                    "<p class='muted'>Verify source pages manually. "
                    "A matching username or reachable URL is not proof "
                    "of identity or ownership.</p>"
                )
                self.send_page(layout("Social Intelligence Results", body))
                return

            except (ValueError, TypeError, KeyError) as exc:
                self.send_page(
                    layout(
                        "Social Intelligence",
                        "<h2>Search not completed</h2>"
                        f"<p>{esc(str(exc))}</p>"
                        "<p><a href='/social'>Return to Social Intelligence</a></p>",
                    ),
                    400,
                )
                return
            except Exception as exc:
                print(f"[social-intelligence] {type(exc).__name__}: {exc}")
                self.send_page(
                    layout(
                        "Social Intelligence Error",
                        "<h2>Search could not be completed</h2>"
                        "<p>Check the dashboard terminal for details.</p>"
                        "<p><a href='/social'>Return to Social Intelligence</a></p>",
                    ),
                    500,
                )
                return

        if request_path != "/scans":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid content length")
            return

        if length < 1 or length > 16384:
            self.send_error(413, "Invalid form size")
            return

        try:
            raw = self.rfile.read(length).decode("utf-8")
            parsed_form = parse_qs(raw, keep_blank_values=True)
            form = {key: values[0] for key, values in parsed_form.items()}
            code, output = run_scan(form)
            status = "Completed" if code == 0 else "Finished with warnings or errors"
            body = (
                "<h2>Scan Results</h2>"
                f"<p><strong>Status:</strong> {esc(status)}</p>"
                f"<p><strong>Exit code:</strong> {int(code)}</p>"
                f"<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>"
                f"{esc(output)}</pre>"
                "<p><a class='button' href='/scans'>Run another scan</a> "
                "<a class='button' href='/'>Dashboard</a></p>"
                "<p>Review findings and verify source evidence before relying "
                "on any conclusion.</p>"
            )
            page = layout("Scan Results", body)
            self.send_response(200)
        except ValueError as exc:
            print(f"[scan-launcher] Validation rejected submission: {exc}")
            page = layout(
                "Scan Validation",
                "<h2>Scan not started</h2><p>" + esc(exc) + "</p>"
                "<p><a href='/scans'>Return to Scan Launcher</a></p>",
            )
            self.send_response(400)
        except Exception:
            page = layout(
                "Scan Error",
                "<h2>Scan could not be completed</h2>"
                "<p>Check the terminal logs for details, then try again.</p>"
                "<p><a href='/scans'>Return to Scan Launcher</a></p>",
            )
            self.send_response(500)

        encoded = page.encode("utf-8")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/scans":
            page = scan_launcher_page()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))
            return
        query = parse_qs(parsed.query)

        try:
            if parsed.path == "/":
                self.send_page(dashboard_page())
                return

            if parsed.path == "/intel":
                self.send_page(unified_intelligence_page())
                return

            if parsed.path == "/social":
                self.send_page(social_intelligence_page())
                return

            if parsed.path == "/investigation":
                self.send_page(investigation_intelligence_page())
                return

            if parsed.path == "/history":
                case_id = int(query.get("case", ["2"])[0])
                self.send_page(historical_intelligence_page(case_id))
                return

            if parsed.path == "/alerts":
                case_id = int(query.get("case", ["2"])[0])
                self.send_page(dns_alerts_page(case_id))
                return

            if parsed.path == "/review":
                case_id = int(query.get("case", ["2"])[0])
                self.send_page(evidence_review_page(case_id))
                return

            if parsed.path == "/health":
                self.send_page(json.dumps({
                    "status": "ok",
                    "application": core.APP_NAME,
                    "version": core.VERSION,
                }, indent=2), content_type="application/json; charset=utf-8")
                return

            if parsed.path == "/case":
                case_id = int(query.get("id", ["0"])[0])
                self.send_page(case_page(case_id))
                return

            if parsed.path == "/export":
                case_id = int(query.get("case", ["0"])[0])
                fmt = query.get("format", [""])[0].lower()
                if fmt not in ("html", "json", "csv"):
                    self.send_page("Unsupported export format.", 400, "text/plain")
                    return

                output = core.export_report(case_id, fmt)
                payload = output.read_bytes()
                content_type = {
                    "html": "text/html; charset=utf-8",
                    "json": "application/json; charset=utf-8",
                    "csv": "text/csv; charset=utf-8",
                }[fmt]

                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                if fmt in ("json", "csv"):
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{output.name}"',
                    )
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_page("Not found.", 404, "text/plain; charset=utf-8")

        except (ValueError, TypeError) as exc:
            self.send_page(f"Request error: {esc(exc)}", 400)
        except Exception:
            self.send_page(
                "The request could not be completed. Check the local application logs.",
                500,
            )

    def log_message(self, fmt, *args):
        # Keep normal request logs in the terminal, without remote client details.
        print("[dashboard] " + (fmt % args))


def main():
    core.initialize_database()
    print(f"{core.APP_NAME} dashboard")
    print(f"Local address: http://{HOST}:{PORT}")
    print("Bound to localhost only; press Ctrl+C to stop.")
    try:
        HTTPServer((HOST, PORT), DashboardHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")

if __name__ == "__main__":
    main()
