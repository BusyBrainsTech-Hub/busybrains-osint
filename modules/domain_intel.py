#!/usr/bin/env python3
"""BusyBrains OSINT — Public Domain Intelligence Module."""

import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import sys

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import dns.resolver

import app


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value):
    """Accept a hostname or HTTPS URL and return its hostname."""

    value = value.strip()

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS domains are supported.")

    if not parsed.hostname:
        raise ValueError("A valid domain name is required.")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed.")

    if parsed.port not in (None, 443):
        raise ValueError("Only HTTPS port 443 is supported.")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise ValueError("Local hostnames are not supported.")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain.") from exc

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    labels = hostname.split(".")

    if len(labels) < 2:
        raise ValueError("Provide a fully qualified domain name.")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                char.isalnum() or char == "-"
                for char in label
            )
        ):
            raise ValueError("Invalid domain name.")

    return hostname


def resolve_public_addresses(hostname):
    """Resolve a domain and reject non-public IP addresses."""

    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"DNS resolution failed: {exc}"
        ) from exc

    addresses = sorted({
        ipaddress.ip_address(record[4][0].split("%")[0])
        for record in records
    }, key=lambda address: (address.version, int(address)))

    if not addresses:
        raise ValueError("No IP addresses were returned.")

    for address in addresses:
        if not address.is_global:
            raise ValueError(
                f"Rejected non-public IP address: {address}"
            )

    return [str(address) for address in addresses]


def collect_dns_records(hostname):
    """Collect public DNS records independently by record type."""

    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
    records = {}
    errors = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6

    for record_type in record_types:
        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                raise_on_no_answer=False,
            )

            if answer.rrset is None:
                records[record_type] = []
                continue

            values = []

            for item in answer:
                if record_type == "MX":
                    value = f"{item.preference} {item.exchange.to_text()}"
                else:
                    value = item.to_text()

                values.append(value)

            records[record_type] = sorted(set(values))

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            errors[record_type] = "Domain does not exist."

        except dns.resolver.NoAnswer:
            records[record_type] = []

        except dns.resolver.NoNameservers:
            records[record_type] = []
            errors[record_type] = "No responding nameservers."

        except dns.exception.Timeout:
            records[record_type] = []
            errors[record_type] = "DNS query timed out."

        except Exception as exc:
            records[record_type] = []
            errors[record_type] = str(exc)[:250]

    return {
        "records": records,
        "errors": errors,
    }


def inspect_certificate(hostname, addresses):
    """Inspect a verified HTTPS certificate on a public IP."""

    context = ssl.create_default_context()
    errors = []

    for address in addresses:
        family = (
            socket.AF_INET6
            if ":" in address
            else socket.AF_INET
        )

        try:
            with socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(8)
                raw.connect((address, 443))

                with context.wrap_socket(
                    raw,
                    server_hostname=hostname,
                ) as secure:
                    certificate = secure.getpeercert()
                    certificate_der = secure.getpeercert(binary_form=True)
                    certificate_fingerprint = hashlib.sha256(
                        certificate_der
                    ).hexdigest()

                    return {
                        "connected_ip": address,
                        "tls_version": secure.version(),
                        "cipher": secure.cipher()[0],
                        "subject": certificate.get("subject", ()),
                        "issuer": certificate.get("issuer", ()),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                        "serial_number": certificate.get(
                            "serialNumber"
                        ),
                        "sha256_fingerprint": certificate_fingerprint,
                        "subject_alt_names": certificate.get(
                            "subjectAltName", ()
                        ),
                    }

        except (OSError, ssl.SSLError, ValueError) as exc:
            errors.append(f"{address}: {exc}")

    raise ValueError(
        "Unable to inspect a verified HTTPS certificate. "
        + "; ".join(errors)
    )


def investigate(domain):
    hostname = normalize_domain(domain)

    result = {
        "module": "BusyBrains OSINT Domain Intelligence",
        "collected_at": utc_now(),
        "hostname": hostname,
        "dns": {},
        "https_certificate": {},
    }

    addresses = resolve_public_addresses(hostname)

    result["dns"] = {
        "resolved_addresses": addresses,
        "address_count": len(addresses),
    }

    dns_result = collect_dns_records(hostname)
    result["dns_records"] = dns_result["records"]
    result["dns_record_errors"] = dns_result["errors"]

    result["https_certificate"] = inspect_certificate(
        hostname,
        addresses,
    )

    return result


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Inspect public DNS resolution and HTTPS certificates."
        )
    )

    parser.add_argument(
        "--domain",
        required=True,
        help="Public domain, e.g. example.com",
    )

    parser.add_argument(
        "--case",
        type=int,
        required=True,
        help="Existing BusyBrains OSINT investigation ID",
    )

    args = parser.parse_args()

    try:
        app.initialize_database()
        app.get_case(args.case)

        result = investigate(args.domain)

        finding_id = app.add_finding(
            args.case,
            "domain-intelligence",
            f"Domain assessment: {result['hostname']}",
            json.dumps(result, indent=2, ensure_ascii=False),
            f"https://{result['hostname']}/",
        )

        print(json.dumps(result, indent=2, ensure_ascii=False))
        print()
        print(f"Evidence saved to investigation {args.case}.")
        print(f"Finding ID: {finding_id}")

    except (ValueError, OSError, ssl.SSLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
