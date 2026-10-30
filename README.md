# BusyBrains OSINT

**BusyBrains Tech-Hub | Open-Source Intelligence Platform**

BusyBrains OSINT is a Python-based platform for organizing
investigations, collecting permitted public-source information,
assessing public domain infrastructure, reviewing evidence,
comparing historical observations and producing structured reports.

## Features

- Investigation case and finding management.
- Public HTTPS page collection.
- Public DNS record assessment: A, AAAA, MX, NS, TXT and CNAME.
- HTTPS/TLS certificate inspection.
- Public username profile URL checks on supported platforms.
- Public institutional webpage research.
- Evidence quality assessment.
- Historical observation comparison.
- DNS and TLS change alert classification.
- Investigation timelines.
- JSON, CSV and HTML report generation.
- Local web dashboard.

## Requirements

- Ubuntu or a compatible Linux distribution.
- Python 3.10 or later.
- SQLite support through Python.
- Internet access for online collection.
- dnspython 2.8 or later, below version 3.

Install the Python dependency:

    python3 -m pip install --user -r requirements.txt

On Ubuntu systems where system-wide pip installation is restricted,
use the distribution package if available:

    sudo apt install python3-dnspython

The application itself does not require a virtual environment.

## Quick start

From the project directory:

    ./busybrains-osint init

Run the core self-test:

    ./busybrains-osint self-test

Run the complete project test suite:

    ./run-tests

Display available commands:

    ./busybrains-osint --help

## Investigation management

Create a case:

    ./busybrains-osint case create \
      --name "Example Public Research" \
      --purpose "Organize publicly available information."

List cases:

    ./busybrains-osint case list

Add a finding:

    ./busybrains-osint finding add \
      --case 1 \
      --category "website" \
      --title "Example finding" \
      --content "A manually recorded public-source observation." \
      --source "https://example.com/"

List findings:

    ./busybrains-osint finding list --case 1

## Intelligence modules

Domain and DNS/TLS assessment:

    ./busybrains-osint domain --help

Public username checks:

    ./busybrains-osint username --help

Institutional webpage research:

    ./busybrains-osint institution --help

Social platform checks:

    ./busybrains-social --help

Unified intelligence:

    ./busybrains-intel --help

## Historical intelligence and alerts

Compare historical observations:

    ./busybrains-history --case 1

Generate DNS and TLS change alerts:

    ./busybrains-alerts --case 1

Alert severity represents review priority, not proof of compromise.
Changes should be independently investigated and verified.

## Evidence and timelines

Evidence quality assessment:

    ./busybrains-quality --help

Investigation timeline:

    ./busybrains-timeline --case 1

## Web dashboard

Start the local dashboard:

    ./busybrains-dashboard

Open:

    http://127.0.0.1:8787

The dashboard is intended for local use. Do not expose it to the
public internet without appropriate authentication, access controls
and deployment security review.

## Reports and local data

Runtime data is stored locally:

- Database: `storage/busybrains_osint.db`
- Logs: `logs/`
- Generated reports: `reports/`

These directories are excluded from Git to help prevent accidental
publication of investigation records and generated data.

Back up important local investigation data securely.

## Testing

Run:

    ./run-tests

The test launcher runs the regression tests, compiles Python source
files and executes the core application self-test.

## Responsible use

Use BusyBrains OSINT only for lawful public-source research and
authorized investigations.

The application is not a substitute for human verification.
Public profile availability, DNS responses, certificate details
and automated classifications can be incomplete or change over time.

Respect privacy, applicable laws, platform terms, authorization
requirements and reasonable request limits.

Do not use the application to bypass authentication, access private
accounts, obtain credentials or collect information without
appropriate authorization.

## Project status

Current development version: **0.1.0**

This is an initial development release. Features and interfaces may
change as the project evolves.

## Maintainer

**BusyBrains Tech-Hub**

GitHub organization:
https://github.com/BusyBrainsTech-Hub
