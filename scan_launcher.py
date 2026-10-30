"""Unified, validated launcher for existing BusyBrains OSINT scanners."""

import html
import ipaddress
import re
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parent
DB = BASE / "storage" / "busybrains_osint.db"

PLATFORMS = {
    "github", "gitlab", "reddit", "devto", "medium",
    "linkedin", "x", "instagram", "facebook", "threads",
    "tiktok", "youtube", "bluesky", "pinterest", "twitch",
    "soundcloud", "flickr", "dribbble", "codeberg",
    "hackernews", "keybase", "telegram", "snapchat",
    "mastodon", "substack",
}


def esc(value):
    return html.escape(str(value or ""), quote=True)


def render_launcher():
    return """
    <h2>Unified Scan Launcher</h2>
    <p>Run an existing BusyBrains OSINT scanner against an investigation.</p>
    <p>Results may be saved to the selected case. Existing findings are not
    deleted by this launcher.</p>

    <form method="post" action="/scans">
      <label for="case">Investigation case ID</label><br>
      <input id="case" name="case" type="number" min="1"
             value="2" required><br><br>

      <label for="scan_type">Intelligence module</label><br>
      <select id="scan_type" name="scan_type" required>
        <option value="domain">Domain intelligence</option>
        <option value="username">Username intelligence</option>
        <option value="institution">Institutional webpage</option>
        <option value="social">Social profile checks</option>
      </select><br><br>

      <label for="domain">Domain (domain scan)</label><br>
      <input id="domain" name="domain" type="text"
             placeholder="example.com"><br><br>

      <label for="username">Username or handle</label><br>
      <input id="username" name="username" type="text"
             maxlength="64" placeholder="example_user"><br><br>

      <label for="platforms">Social platforms</label><br>
      <input id="platforms" name="platforms" type="text"
             value="github,reddit,devto,medium"
             placeholder="github,reddit or all"><br>
      <small>Used for social profile checks only.</small><br><br>

      <label for="url">Public institutional webpage URL</label><br>
      <input id="url" name="url" type="url" size="55"
             placeholder="https://example.org/about"><br><br>

      <label for="institution">Institution name</label><br>
      <input id="institution" name="institution" type="text"
             maxlength="160" placeholder="Institution name"><br><br>

      <button class="button" type="submit">Run selected scan</button>
    </form>

    <p><a href="/">Back to dashboard</a></p>
    <p><strong>Usage:</strong> Only investigate public sources you are
    authorized to assess. A reachable profile does not prove identity,
    ownership, or affiliation.</p>
    """


def check_case(case_id):
    if not DB.is_file():
        raise ValueError("The BusyBrains OSINT database was not found.")

    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT id FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Case #{case_id} does not exist.")
    finally:
        con.close()


def validate_domain(value):
    value = value.strip().rstrip(".")
    if len(value) > 253 or not re.fullmatch(
        r"(?i)(?=.{1,253}$)"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        value,
    ):
        raise ValueError("Enter a valid domain such as example.com.")
    return value


def validate_username(value):
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise ValueError(
            "Username must be 1–64 characters and contain only "
            "letters, numbers, dots, underscores or hyphens."
        )
    return value


def validate_public_https_url(value):
    value = value.strip()
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme.lower() != "https"
            or not host
            or parsed.username
            or parsed.password
            or not parsed.netloc
            or any(ch.isspace() for ch in value)
        ):
            raise ValueError
        if host.lower() == "localhost" or host.lower().endswith(".localhost"):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise ValueError
        except ValueError as exc:
            # Invalid IP literals are treated as hostnames only if they
            # actually parse as a conventional DNS name.
            if ":" in host or host.startswith("["):
                raise ValueError from exc
            if not re.fullmatch(
                r"(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host
            ):
                raise ValueError from exc
    except ValueError:
        raise ValueError(
            "Enter a valid public HTTPS URL without embedded credentials "
            "or localhost addresses."
        )
    return value


def run_scan(form):
    scan_type = (form.get("scan_type") or "").strip()
    try:
        case_id = int(form.get("case", ""))
    except (TypeError, ValueError):
        raise ValueError("Enter a valid numeric case ID.")

    if case_id < 1:
        raise ValueError("Case ID must be a positive integer.")
    check_case(case_id)

    cli = BASE / "busybrains-osint"
    social_cli = BASE / "busybrains-social"

    if scan_type == "domain":
        domain = validate_domain(form.get("domain", ""))
        command = [
            str(cli), "domain", "--case", str(case_id),
            "--domain", domain,
        ]

    elif scan_type == "username":
        username = validate_username(form.get("username", ""))
        command = [
            str(cli), "username", "--case", str(case_id),
            "--username", username,
        ]

    elif scan_type == "institution":
        url = validate_public_https_url(form.get("url", ""))
        institution = (form.get("institution") or "").strip()
        if not institution or len(institution) > 160:
            raise ValueError(
                "Enter an institution name of 1–160 characters."
            )
        command = [
            str(cli), "institution", "--case", str(case_id),
            "--url", url, "--institution", institution,
        ]

    elif scan_type == "social":
        username = validate_username(form.get("username", ""))
        raw = (form.get("platforms") or "").strip().lower()
        if raw == "all":
            platforms = "all"
        else:
            selected = [
                item.strip() for item in raw.split(",") if item.strip()
            ]
            unknown = sorted(set(selected) - PLATFORMS)
            if not selected or unknown:
                raise ValueError(
                    "Choose supported platform keys or enter 'all'. "
                    "Unknown keys: " + ", ".join(unknown)
                )
            platforms = ",".join(dict.fromkeys(selected))

        command = [
            str(social_cli), "--case", str(case_id),
            "--username", username, "--platforms", platforms,
        ]

    else:
        raise ValueError("Choose one of the four supported scan types.")

    try:
        result = subprocess.run(
            command,
            cwd=BASE,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "Scan timed out after 180 seconds."
    except OSError as exc:
        return 127, f"Could not start scanner: {exc}"

    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode, output.strip() or "(No command output.)"
