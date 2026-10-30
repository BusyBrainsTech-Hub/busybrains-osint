#!/usr/bin/env python3
"""Non-destructive release verification for BusyBrains OSINT."""

import hashlib
import json
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CASE_ID = 2

required = [
    "app.py",
    "busybrains-osint",
    "dashboard.py",
    "busybrains-dashboard",
    "evidence_quality.py",
    "busybrains-quality",
    "timeline.py",
    "busybrains-timeline",
    "modules/social_platforms.py",
        "investigation_intelligence.py",
    "busybrains-social",
]

failed = []
passed = []


def check(name, fn):
    try:
        fn()
        passed.append(name)
        print(f"PASS  {name}")
    except Exception as exc:
        failed.append((name, str(exc)))
        print(f"FAIL  {name}: {exc}")


def run(args, timeout=45):
    result = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(
            f"Exit code {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout.strip()


def check_files():
    missing = [name for name in required if not (ROOT / name).is_file()]
    if missing:
        raise RuntimeError("Missing files: " + ", ".join(missing))


def check_python():
    import py_compile

    files = [
        ROOT / "app.py",
        ROOT / "dashboard.py",
        ROOT / "evidence_quality.py",
        ROOT / "timeline.py",
        ROOT / "modules" / "social_platforms.py",
    ]
    for path in files:
        py_compile.compile(str(path), doraise=True)


def check_core():
    output = run([str(ROOT / "busybrains-osint"), "self-test"])
    if "working" not in output.lower():
        raise RuntimeError("Core self-test did not report success.")
    print(output)


def check_cli():
    for command in (
        ["--version"],
        ["domain", "--help"],
        ["username", "--help"],
        ["institution", "--help"],
        ["export", "--help"],
    ):
        run([str(ROOT / "busybrains-osint"), *command])

    run([str(ROOT / "busybrains-quality"), "--help"])
    run([str(ROOT / "busybrains-timeline"), "--help"])
    run([str(ROOT / "busybrains-social"), "--help"])
    run([str(ROOT / "busybrains-social"), "--list"])


def check_quality():
    run([str(ROOT / "busybrains-quality"), "init"])
    output = run([
        str(ROOT / "busybrains-quality"),
        "summary",
        "--case",
        str(CASE_ID),
    ])
    if "Total findings" not in output:
        raise RuntimeError("Evidence-quality summary was incomplete.")
    print(output)


def check_exports():
    outputs = {}
    for fmt in ("json", "csv", "html"):
        output = run([
            str(ROOT / "busybrains-osint"),
            "export",
            "--case",
            str(CASE_ID),
            "--format",
            fmt,
        ])
        candidates = sorted(
            REPORTS.glob(f"case_{CASE_ID}_*.{fmt}"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise RuntimeError(f"No {fmt.upper()} report found.")
        outputs[fmt] = candidates[0]

    data = json.loads(outputs["json"].read_text(encoding="utf-8"))
    if "findings" not in data:
        raise RuntimeError("JSON report lacks findings.")

    html_report = outputs["html"].read_text(encoding="utf-8")
    if "<html" not in html_report.lower():
        raise RuntimeError("HTML report is invalid.")

    if not outputs["csv"].read_text(encoding="utf-8").strip():
        raise RuntimeError("CSV report is empty.")

    print("JSON:", outputs["json"].name)
    print("CSV: ", outputs["csv"].name)
    print("HTML:", outputs["html"].name)


def check_timeline():
    run([
        str(ROOT / "busybrains-timeline"),
        "--case",
        str(CASE_ID),
    ])
    timeline = REPORTS / f"case_{CASE_ID}_timeline.html"
    if not timeline.is_file():
        raise RuntimeError("Timeline report was not created.")
    if "Investigation Timeline" not in timeline.read_text(encoding="utf-8"):
        raise RuntimeError("Timeline content validation failed.")
    print("Timeline:", timeline.name)


def check_dashboard():
    import dashboard

    server = HTTPServer(("127.0.0.1", 0), dashboard.DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    try:
        checks = {
            "/": "Investigation Workspace",
            "/case?id=2": "Evidence assessment",
            "/health": '"status": "ok"',
            "/social": "Social Intelligence",
        }
        for route, expected in checks.items():
            with urllib.request.urlopen(base + route, timeout=8) as response:
                body = response.read().decode("utf-8")
                if response.status != 200 or expected not in body:
                    raise RuntimeError(f"Unexpected response for {route}")
            print(f"  Route OK: {route}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def create_manifest():
    excluded_parts = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
    }
    excluded_names = {
        "release_manifest.json",
        "release_check.py",
        "busybrains-check",
    }
    entries = []

    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)

        if any(part in excluded_parts for part in relative.parts):
            continue
        if path.name in excluded_names:
            continue
        if relative.parts and relative.parts[0] in {"logs"}:
            continue
        if relative.parts and relative.parts[0] == "storage":
            # Do not include the live investigation database in a release manifest.
            continue
        if "backup" in path.name.lower() or ".bak" in path.name.lower():
            continue

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({
            "file": str(relative),
            "size_bytes": path.stat().st_size,
            "sha256": digest,
        })

    manifest = {
        "application": "BusyBrains OSINT",
        "verification_time": datetime.now(timezone.utc).isoformat(),
        "purpose": "File integrity inventory; not a signed release or security certification.",
        "files": entries,
    }
    (ROOT / "release_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    print(f"Manifest entries: {len(entries)}")


def main():
    print("=" * 60)
    print("BUSYBRAINS OSINT — RELEASE VERIFICATION")
    print("=" * 60)

    check("Required project files", check_files)
    check("Python syntax", check_python)
    check("CLI command registration", check_cli)
    check("Existing application self-test", check_core)
    check("Evidence-quality storage and summary", check_quality)
    check("JSON, CSV and HTML exports", check_exports)
    check("Investigation timeline generation", check_timeline)
    check("Dashboard overview, case, health and social routes", check_dashboard)
    check("Release file manifest", create_manifest)

    print("\n" + "=" * 60)
    print(f"PASSED: {len(passed)}")
    print(f"FAILED: {len(failed)}")
    if failed:
        for name, error in failed:
            print(f"\n{name}\n{error}")
        print("\nFix the listed failures before treating this as release-ready.")
        return 1

    print("ALL RELEASE CHECKS PASSED")
    print("Existing case data was not intentionally reset or deleted.")
    print("Manifest: release_manifest.json")
    print("Start dashboard: ./busybrains-dashboard")
    print("Local URL: http://127.0.0.1:8787")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
