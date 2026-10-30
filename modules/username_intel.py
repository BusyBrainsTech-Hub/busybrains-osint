#!/usr/bin/env python3
"""BusyBrains OSINT — Public Username Intelligence."""

import argparse
import json
import re
import sys

from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import app


PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "DEV Community": "https://dev.to/{username}",
    "Medium": "https://medium.com/@{username}",
}

TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 16384


class NoRedirectHandler(HTTPRedirectHandler):
    """Return redirects to the caller instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_username(username):
    """Accept conservative username characters only."""

    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", username):
        raise ValueError(
            "Use a username containing only letters, digits, "
            "underscores, or hyphens (maximum 39 characters)."
        )

    return username


def classify_status(status):
    """Avoid interpreting HTTP status as definitive identity evidence."""

    if status == 200:
        return "reachable_verify_manually"

    if status == 404:
        return "not_found_response"

    if status in (401, 403, 429):
        return "restricted_or_rate_limited"

    if 300 <= status < 400:
        return "redirect_inconclusive"

    return "inconclusive"


def check_profile(platform, url):
    """Make one bounded request to a known public profile URL."""

    request = Request(
        url,
        headers={
            "User-Agent": "BusyBrainsOSINT/0.2 "
                          "(public profile availability check)",
            "Accept": "text/html",
        },
        method="GET",
    )

    opener = build_opener(NoRedirectHandler())

    result = {
        "platform": platform,
        "profile_url": url,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "http_status": None,
        "assessment": "inconclusive",
        "details": "",
    }

    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            result["http_status"] = response.status
            result["assessment"] = classify_status(response.status)

            # Read only a small response portion. The body is not saved.
            response.read(MAX_RESPONSE_BYTES)

    except HTTPError as exc:
        result["http_status"] = exc.code
        result["assessment"] = classify_status(exc.code)
        result["details"] = "The server returned an HTTP error status."

    except (URLError, TimeoutError, OSError) as exc:
        result["details"] = (
            f"Request failed: {type(exc).__name__}"
        )

    return result


def investigate_username(username):
    username = validate_username(username)
    results = []

    for platform, template in PLATFORMS.items():
        url = template.format(username=username)
        result = check_profile(platform, url)
        results.append(result)

    return {
        "module": "BusyBrains OSINT Username Intelligence",
        "username_searched": username,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "method": "Public profile URL availability checks",
        "limitations": [
            "A reachable URL does not establish account ownership.",
            "A missing response does not prove an account is absent.",
            "Platform responses can be misleading or restricted.",
            "Results require independent verification.",
        ],
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Check public profile URL availability."
    )

    parser.add_argument("--username", required=True)
    parser.add_argument("--case", required=True, type=int)

    args = parser.parse_args()

    try:
        app.initialize_database()
        app.get_case(args.case)

        report = investigate_username(args.username)

        finding_id = app.add_finding(
            args.case,
            "username-intelligence",
            f"Public username checks: {report['username_searched']}",
            json.dumps(report, indent=2, ensure_ascii=False),
            "Multiple public platform profile URLs",
        )

        print(json.dumps(report, indent=2, ensure_ascii=False))
        print()
        print(f"Saved to investigation: {args.case}")
        print(f"Finding ID: {finding_id}")

    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
