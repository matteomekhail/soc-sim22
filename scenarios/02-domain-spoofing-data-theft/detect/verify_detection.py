#!/usr/bin/env python3
"""
Scenario 02 - Domain Spoofing & Data Theft: Detection Verification
===================================================================
Verifies that the generated logs contain the indicators expected by
the Suricata and Wazuh rules defined for this scenario.

Usage:
    python verify_detection.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Noop:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Noop()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCENARIO_DIR   = os.path.join(os.path.dirname(__file__), "..")
LOG_DIR        = os.path.join(SCENARIO_DIR, "logs", "sample_logs")
EXPECTED_FILE  = os.path.join(os.path.dirname(__file__), "expected_alerts.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_logs(filename: str) -> list[dict]:
    """Load JSON-lines log file, returning list of dicts."""
    filepath = os.path.join(LOG_DIR, filename)
    entries = []
    if not os.path.exists(filepath):
        return entries
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                # Syslog lines are plain text
                entries.append({"_raw": line})
    return entries


def load_expected_alerts() -> dict:
    with open(EXPECTED_FILE, "r") as fh:
        return json.load(fh)


def field_match(log_entry: dict, field: str, expected_value) -> bool:
    """Check if a field in a log entry matches the expected value.
    Supports nested dotted keys and wildcard prefix (*) matching."""
    parts = field.split(".")
    val = log_entry
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        else:
            return False
        if val is None:
            return False

    val_str = str(val)
    expected_str = str(expected_value)

    if expected_str.startswith("*"):
        return val_str.endswith(expected_str[1:])
    if "/" in expected_str and expected_str.replace(".", "").replace("/", "").isdigit():
        # CIDR-style -- just check prefix
        prefix = expected_str.split("/")[0].rsplit(".", 1)[0]
        return val_str.startswith(prefix)
    # Substring match for partial values
    if expected_str in val_str:
        return True
    return val_str == expected_str


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def verify() -> None:
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"  Scenario 02: Detection Verification")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")

    # Load all logs
    log_files = [
        "attack_simulation.json",
        "phishing_emails.json",
        "phase1_domain_registration.json",
        "phase2_phishing_deploy.json",
        "phase3_phishing_emails_dns.json",
        "phase4_credential_harvesting.json",
        "phase5_data_exfiltration.json",
    ]

    all_logs: list[dict] = []
    for lf in log_files:
        loaded = load_logs(lf)
        if loaded:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Loaded {len(loaded):>4} entries from {lf}")
            all_logs.extend(loaded)
        else:
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} Missing or empty: {lf}")

    if not all_logs:
        print(f"\n  {Fore.RED}[!] No logs found. Run simulate_attack.py first.{Style.RESET_ALL}\n")
        sys.exit(1)

    print(f"\n  Total log entries loaded: {len(all_logs)}\n")

    # Load expected alerts
    expected = load_expected_alerts()
    alerts = expected.get("alerts", [])
    passed = 0
    failed = 0

    print(f"{Fore.CYAN}--- Checking Expected Alerts ---{Style.RESET_ALL}\n")

    for alert in alerts:
        alert_id = alert["alert_id"]
        description = alert["description"]
        expected_fields = alert.get("expected_fields", {})

        # Search logs for a matching entry
        found = False
        for entry in all_logs:
            if all(field_match(entry, k, v) for k, v in expected_fields.items()):
                found = True
                break

        if found:
            passed += 1
            print(f"  {Fore.GREEN}[PASS]{Style.RESET_ALL} {alert_id}: {description}")
        else:
            failed += 1
            print(f"  {Fore.RED}[FAIL]{Style.RESET_ALL} {alert_id}: {description}")
            for k, v in expected_fields.items():
                print(f"         Expected field: {k} = {v}")

    # Summary
    total = passed + failed
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"  Results: {Fore.GREEN}{passed} passed{Style.RESET_ALL}, "
          f"{Fore.RED}{failed} failed{Style.RESET_ALL} out of {total} checks")

    coverage = (passed / total * 100) if total > 0 else 0
    color = Fore.GREEN if coverage >= 80 else Fore.YELLOW if coverage >= 50 else Fore.RED
    print(f"  Detection coverage: {color}{coverage:.0f}%{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    verify()
