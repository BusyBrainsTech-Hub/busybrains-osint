#!/usr/bin/env python3
"""BusyBrains OSINT unified public-source intelligence engine."""

import argparse
import importlib.util
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app
from modules import social_platforms


REPORTS = ROOT / "reports"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def email_intel(value):
    value = value.strip()

    if len(value) > 254 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",
        value,
    ):
        raise ValueError("Enter a syntactically valid email address.")

    domain = value.rsplit("@", 1)[1].lower()
    result = {
        "type": "email",
        "submitted_value": value,
        "domain": domain,
        "syntax": "valid",
        "mail_records": "not_checked",
        "checked_at": now(),
        "limitations": [
            "Syntax validation does not prove that a mailbox exists.",
            "No mailbox login, password check, or message was attempted.",
            "Domain mail records do not identify the mailbox owner.",
        ],
    }

    if importlib.util.find_spec("dns") is not None:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            exchanges = [
                str(answer.exchange).rstrip(".")
                for answer in answers
                if str(answer.exchange).rstrip(".")
            ]
            result["mail_records"] = exchanges
            result["mail_records_status"] = (
                "records_found" if exchanges else "no_usable_mx_records"
            )
        except Exception as exc:
            result["mail_records"] = []
            result["mail_records_status"] = type(exc).__name__
    else:
        result["mail_records_status"] = (
            "dnspython_not_installed; MX lookup unavailable"
        )

    return result


def phone_intel(value, region):
    value = value.strip()

    if not value or len(value) > 40:
        raise ValueError("Enter a phone number no longer than 40 characters.")

    result = {
        "type": "phone",
        "submitted_value": value,
        "default_region": region,
        "checked_at": now(),
    }

    if importlib.util.find_spec("phonenumbers") is None:
        result.update({
            "validation": "not_performed",
            "reason": "Optional phonenumbers library is not installed.",
            "limitations": [
                "No subscriber identity or private carrier records were queried.",
                "Number validity and ownership are not established.",
            ],
        })
        return result

    import phonenumbers

    try:
        parsed = phonenumbers.parse(value, region or None)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Phone number could not be parsed: {exc}")

    result.update({
        "validation": (
            "valid_numbering_plan"
            if phonenumbers.is_valid_number(parsed)
            else "not_validated"
        ),
        "possible": phonenumbers.is_possible_number(parsed),
        "international_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "country_calling_code": parsed.country_code,
        "region": phonenumbers.region_code_for_number(parsed),
        "number_type": str(
            phonenumbers.number_type(parsed)
        ),
        "limitations": [
            "Numbering-plan validity does not prove current service or ownership.",
            "No private subscriber information or location tracking was performed.",
        ],
    })

    return result


def domain_intel(value):
    domain = value.strip().lower().rstrip(".")

    if (
        len(domain) > 253
        or not re.fullmatch(
            r"(?=.{1,253}$)[a-z0-9]"
            r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            domain,
        )
    ):
        raise ValueError("Enter a valid domain such as example.com.")

    addresses = []
    try:
        for item in socket.getaddrinfo(domain, None):
            address = item[4][0]
            if address not in addresses:
                addresses.append(address)
    except socket.gaierror:
        pass

    return {
        "type": "domain",
        "domain": domain,
        "resolved_addresses": addresses,
        "dns_status": "resolved" if addresses else "no_addresses_returned",
        "checked_at": now(),
        "limitations": [
            "DNS resolution does not establish ownership or control.",
            "This is a basic DNS check, not a complete infrastructure assessment.",
        ],
    }


def username_intel(username, platforms, timeout, delay):
    username = username.strip().lstrip("@")

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        raise ValueError("Username must be 1–64 valid username characters.")

    if platforms == "all":
        selected = list(social_platforms.PLATFORMS)
    else:
        selected = list(dict.fromkeys(
            item.strip().lower()
            for item in platforms.split(",")
            if item.strip()
        ))

    unknown = sorted(
        set(selected) - set(social_platforms.PLATFORMS)
    )
    if unknown:
        raise ValueError("Unknown platform keys: " + ", ".join(unknown))

    if not selected:
        raise ValueError("Select at least one platform.")

    results = []
    for index, platform in enumerate(selected):
        result = social_platforms.check_profile(
            platform, username, timeout
        )
        results.append(result)

        if index < len(selected) - 1 and delay:
            time.sleep(delay)

    return {
        "type": "username",
        "username_pattern": username,
        "platforms_checked": len(results),
        "results": results,
        "checked_at": now(),
        "limitations": [
            "A reachable profile URL does not prove account ownership.",
            "A matching username does not establish that accounts share an owner.",
            "Restricted, redirected and missing responses can be inconclusive.",
            "Only public profile URL availability was checked.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="BusyBrains OSINT Unified Intelligence Search"
    )
    parser.add_argument("--case", type=int, required=True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--username")
    group.add_argument("--email")
    group.add_argument("--phone")
    group.add_argument("--domain")

    parser.add_argument("--platforms", default="all")
    parser.add_argument("--region", default="NG")
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--delay", type=float, default=1.2)
    parser.add_argument("--no-save", action="store_true")

    args = parser.parse_args()

    try:
        if args.case < 1:
            raise ValueError("Case ID must be positive.")
        if args.timeout <= 0 or args.delay < 0:
            raise ValueError("Timeout must be positive; delay cannot be negative.")

        app.initialize_database()
        app.get_case(args.case)

        if args.username:
            result = username_intel(
                args.username, args.platforms, args.timeout, args.delay
            )
        elif args.email:
            result = email_intel(args.email)
        elif args.phone:
            result = phone_intel(args.phone, args.region)
        else:
            result = domain_intel(args.domain)

        result["application"] = "BusyBrains OSINT"
        result["case_id"] = args.case
        result["generated_at"] = now()

        REPORTS.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = REPORTS / f"unified_intel_{stamp}.json"
        report_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        finding_id = None
        if not args.no_save:
            title_value = (
                result.get("username_pattern")
                or result.get("submitted_value")
                or result.get("domain")
            )
            finding_id = app.add_finding(
                args.case,
                f"{result['type']}-intelligence",
                f"Unified {result['type']} intelligence: {title_value}",
                json.dumps(result, indent=2, ensure_ascii=False),
                "",
            )

        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"\nJSON report: {report_path.relative_to(ROOT)}")
        print("Database: unchanged" if args.no_save else
              f"Saved to case #{args.case}, finding #{finding_id}")

    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
