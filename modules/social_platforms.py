#!/usr/bin/env python3
"""Public profile URL checks for BusyBrains OSINT.
No login, scraping of private data, or access-control bypass.
"""

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

PLATFORMS = {
    "github": ("GitHub", "https://github.com/{u}"),
    "gitlab": ("GitLab", "https://gitlab.com/{u}"),
    "reddit": ("Reddit", "https://www.reddit.com/user/{u}/"),
    "devto": ("DEV Community", "https://dev.to/{u}"),
    "medium": ("Medium", "https://medium.com/@{u}"),
    "linkedin": ("LinkedIn", "https://www.linkedin.com/in/{u}/"),
    "x": ("X", "https://x.com/{u}"),
    "instagram": ("Instagram", "https://www.instagram.com/{u}/"),
    "facebook": ("Facebook", "https://www.facebook.com/{u}"),
    "threads": ("Threads", "https://www.threads.net/@{u}"),
    "tiktok": ("TikTok", "https://www.tiktok.com/@{u}"),
    "youtube": ("YouTube", "https://www.youtube.com/@{u}"),
    "bluesky": ("Bluesky", "https://bsky.app/profile/{u}"),
    "pinterest": ("Pinterest", "https://www.pinterest.com/{u}/"),
    "twitch": ("Twitch", "https://www.twitch.tv/{u}"),
    "soundcloud": ("SoundCloud", "https://soundcloud.com/{u}"),
    "flickr": ("Flickr", "https://www.flickr.com/people/{u}/"),
    "dribbble": ("Dribbble", "https://dribbble.com/{u}"),
    "codeberg": ("Codeberg", "https://codeberg.org/{u}"),
    "hackernews": ("Hacker News", "https://news.ycombinator.com/user?id={u}"),
    "keybase": ("Keybase", "https://keybase.io/{u}"),
    "telegram": ("Telegram", "https://t.me/{u}"),
    "snapchat": ("Snapchat", "https://www.snapchat.com/add/{u}"),
    "mastodon": ("Mastodon.social", "https://mastodon.social/@{u}"),
    "substack": ("Substack", "https://{u}.substack.com"),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def profile_url(platform, username):
    encoded = quote(username, safe="._-")
    if platform == "bluesky" and "." not in username:
        encoded += ".bsky.social"
    return PLATFORMS[platform][1].format(u=encoded)


def check_profile(platform, username, timeout):
    label = PLATFORMS[platform][0]
    url = profile_url(platform, username)
    checked = utc_now()
    request = Request(
        url,
        headers={
            "User-Agent": "BusyBrainsOSINT-PublicProfileChecker/1.0",
            "Accept": "text/html,application/xhtml+xml",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            final_url = response.geturl()
            parsed = urlparse(final_url)
            if status == 200 and any(
                marker in parsed.path.lower()
                for marker in ("/login", "/accounts/login", "/auth/")
            ):
                classification = "inconclusive"
                note = "Platform returned a login/authentication page."
            elif status == 200 and final_url.rstrip("/") != url.rstrip("/"):
                classification = "redirected_inconclusive"
                note = "The URL redirected; this does not confirm an account."
            elif status == 200:
                classification = "reachable_unconfirmed"
                note = "HTTP 200 only; profile existence and identity are unverified."
            else:
                classification = "inconclusive"
                note = f"Unexpected HTTP status: {status}."
    except HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
        if status == 404:
            classification = "not_found_response"
            note = "HTTP 404; not definitive proof that no account exists."
        elif status in (401, 403, 429):
            classification = "inconclusive"
            note = f"HTTP {status}; access restricted or rate limited."
        else:
            classification = "inconclusive"
            note = f"HTTP {status}; result cannot establish account existence."
    except (URLError, TimeoutError, OSError) as exc:
        status = None
        final_url = url
        classification = "connection_error"
        note = f"Could not check URL: {str(exc)[:180]}"

    return {
        "platform": label,
        "platform_key": platform,
        "username_pattern": username,
        "url": url,
        "http_status": status,
        "classification": classification,
        "note": note,
        "final_url": final_url,
        "checked_at": checked,
    }


def save_finding(result, case_id):
    title = f"Public profile URL check: {result['platform']} / {result['username_pattern']}"
    content = (
        f"Classification: {result['classification']}\n"
        f"HTTP status: {result['http_status']}\n"
        f"Checked at: {result['checked_at']}\n"
        f"Final URL: {result['final_url']}\n"
        f"Assessment: {result['note']}\n"
        "Caution: This URL check does not establish account ownership or identity."
    )
    command = [
        str(ROOT / "busybrains-osint"),
        "finding", "add",
        "--case", str(case_id),
        "--category", "social_profile_check",
        "--title", title,
        "--content", content,
        "--source", result["url"],
    ]
    completed = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, timeout=30
    )
    if completed.returncode:
        raise RuntimeError(
            (completed.stderr or completed.stdout or "Finding save failed").strip()
        )


def main():
    parser = argparse.ArgumentParser(
        description="Check candidate public profile URLs across social platforms."
    )
    parser.add_argument("--username", help="Candidate username or handle")
    parser.add_argument("--case", type=int, default=2, help="Existing case ID (default: 2)")
    parser.add_argument(
        "--platforms", default="all",
        help="Comma-separated platform keys, or 'all'. Use --list to see keys."
    )
    parser.add_argument("--list", action="store_true", help="List supported platforms and exit")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=1.2, help="Seconds between requests")
    parser.add_argument(
        "--no-save", action="store_true",
        help="Do not add scan results to the case database"
    )
    args = parser.parse_args()

    if args.list:
        print("Supported public-profile URL patterns:")
        for key, (label, template) in PLATFORMS.items():
            print(f"  {key:12} {label:18} {template}")
        return 0

    if not args.username:
        parser.error("--username is required unless --list is used")

    username = args.username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        parser.error("Username must be 1-64 characters: letters, digits, dot, underscore or hyphen.")

    if args.case < 1:
        parser.error("--case must be a positive integer")
    if args.timeout <= 0 or args.delay < 0:
        parser.error("--timeout must be positive and --delay cannot be negative")

    if args.platforms.strip().lower() == "all":
        selected = list(PLATFORMS)
    else:
        selected = [part.strip().lower() for part in args.platforms.split(",") if part.strip()]
        unknown = [key for key in selected if key not in PLATFORMS]
        if unknown:
            parser.error("Unknown platform key(s): " + ", ".join(unknown))
        selected = list(dict.fromkeys(selected))

    if not selected:
        parser.error("Select at least one platform.")

    results = []
    print(f"\nBusyBrains OSINT — public profile URL checks")
    print(f"Username pattern: {username}")
    print(f"Platforms selected: {len(selected)}")
    print("No private data is accessed; results may be inconclusive.\n")

    for index, platform in enumerate(selected):
        result = check_profile(platform, username, args.timeout)
        results.append(result)
        print(
            f"{result['platform']:<18} "
            f"{str(result['http_status'] or 'N/A'):<5} "
            f"{result['classification']}"
        )
        print(f"  {result['url']}")
        print(f"  {result['note']}")

        if not args.no_save:
            try:
                save_finding(result, args.case)
                result["saved_to_case"] = True
            except Exception as exc:
                result["saved_to_case"] = False
                result["save_error"] = str(exc)
                print(f"  WARNING: could not save to case {args.case}: {exc}")

        if index < len(selected) - 1 and args.delay:
            time.sleep(args.delay)

    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", username)[:64]
    base = REPORTS / f"social_scan_{safe_name}_{stamp}"

    report = {
        "application": "BusyBrains OSINT",
        "report_type": "public_profile_url_checks",
        "username_pattern": username,
        "case_id": None if args.no_save else args.case,
        "generated_at": utc_now(),
        "limitations": [
            "A reachable URL does not prove that an account exists.",
            "An HTTP error does not prove that an account is absent.",
            "A matching username does not prove identity or account ownership.",
            "No private account access, login bypass, or profile-content scraping was performed.",
        ],
        "results": results,
    }
    json_path = base.with_suffix(".json")
    csv_path = base.with_suffix(".csv")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    fields = [
        "platform", "platform_key", "username_pattern", "url",
        "http_status", "classification", "note", "final_url",
        "checked_at", "saved_to_case", "save_error",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(f"\nJSON report: {json_path.relative_to(ROOT)}")
    print(f"CSV report:  {csv_path.relative_to(ROOT)}")
    if args.no_save:
        print("Database: unchanged (--no-save selected)")
    else:
        saved = sum(bool(item.get("saved_to_case")) for item in results)
        print(f"Saved to case {args.case}: {saved}/{len(results)} checks")
    print("Reminder: manually verify sources before treating a result as evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
