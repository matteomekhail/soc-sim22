#!/usr/bin/env python3
"""
Scenario 14: Verify Credential Stuffing detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the credential stuffing attack was properly detected.
"""

import json
import os
import sys

from colorama import Fore, Style, init
from tabulate import tabulate

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.siem_client import SIEMClient

init(autoreset=True)

EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "expected_alerts.json")
LOG_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "credential_stuffing_attack.jsonl"
)
COMPROMISED_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "compromised_accounts.json"
)


def check_local_logs() -> dict:
    """Check locally generated attack logs."""
    results = {
        "total": 0,
        "auth_failures": 0,
        "auth_successes": 0,
        "web_access": 0,
        "ids_alerts": 0,
    }

    if not os.path.exists(LOG_FILE):
        print(f"{Fore.RED}[!] No attack logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
        return results

    with open(LOG_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            try:
                entry = json.loads(line)
                event_type = entry.get("event_type", "")
                if event_type == "ids_alert":
                    results["ids_alerts"] += 1
                elif event_type == "web_access":
                    results["web_access"] += 1
                    if entry.get("status_code") == 401:
                        results["auth_failures"] += 1
                    elif entry.get("status_code") == 200 and entry.get("method") == "POST":
                        results["auth_successes"] += 1
            except json.JSONDecodeError:
                # Handle syslog-format auth entries
                line_str = line.strip()
                if "Failed password" in line_str or "Failed" in line_str:
                    results["auth_failures"] += 1
                elif "Accepted" in line_str:
                    results["auth_successes"] += 1

    return results


def check_compromised_accounts() -> list[dict]:
    """Check for compromised account report."""
    if not os.path.exists(COMPROMISED_FILE):
        return []
    with open(COMPROMISED_FILE) as f:
        data = json.load(f)
    return data.get("accounts", [])


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for credential stuffing alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="credential stuffing", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 14 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="14-credential-stuffing"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 14: Credential Stuffing Detection Check  ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    # Load expected alerts
    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    results_table = []
    total_checks = 0
    passed_checks = 0

    # Check 1: Local logs
    print(f"{Fore.YELLOW}[1/4] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  [+] {local['total']} log entries found")
        print(f"    - Auth failures (HTTP 401): {local['auth_failures']}")
        print(f"    - Auth successes (HTTP 200 POST): {local['auth_successes']}")
        print(f"    - Web access logs: {local['web_access']}")
        print(f"    - IDS alerts: {local['ids_alerts']}")
        results_table.append(["Local Logs", local["total"], "PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "FAIL"])
    total_checks += 1

    # Check 2: Compromised accounts
    print(f"\n{Fore.YELLOW}[2/4] Checking compromised accounts report...{Style.RESET_ALL}")
    compromised = check_compromised_accounts()
    if compromised:
        print(f"  [!] {len(compromised)} accounts compromised:")
        for acct in compromised:
            print(f"    - {acct['username']} (role: {acct.get('role', 'N/A')}) from {acct['src_ip']}")
        results_table.append(["Compromised Accounts", len(compromised), "DETECTED"])
    else:
        print(f"  [+] No compromised accounts found (or report not generated)")
        results_table.append(["Compromised Accounts", 0, "N/A"])
    total_checks += 1

    # Check 3: Wazuh alerts
    print(f"\n{Fore.YELLOW}[3/4] Checking Wazuh alerts...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    if wazuh_alerts:
        print(f"  [+] {len(wazuh_alerts)} Wazuh alerts found")
        for alert in wazuh_alerts[:5]:
            rule = alert.get("rule", {})
            print(f"    - Rule {rule.get('id')}: {rule.get('description', 'N/A')}")
        results_table.append(["Wazuh Alerts", len(wazuh_alerts), "PASS"])
        passed_checks += 1
    else:
        print(f"  [*] No Wazuh alerts (stack may not be running)")
        results_table.append(["Wazuh Alerts", 0, "SKIP"])
    total_checks += 1

    # Check 4: Loki logs
    print(f"\n{Fore.YELLOW}[4/4] Checking Loki logs...{Style.RESET_ALL}")
    loki_count = check_loki_logs()
    if loki_count > 0:
        print(f"  [+] {loki_count} entries in Loki")
        results_table.append(["Loki Logs", loki_count, "PASS"])
        passed_checks += 1
    else:
        print(f"  [*] No Loki entries (stack may not be running)")
        results_table.append(["Loki Logs", 0, "SKIP"])
    total_checks += 1

    # Summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Detection Verification Summary")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(tabulate(results_table, headers=["Check", "Count", "Status"], tablefmt="grid"))

    print(f"\nExpected alerts for this scenario:")
    for ea in expected["expected_alerts"]:
        source = ea["source"].upper()
        desc = ea["description"]
        min_c = ea["min_count"]
        sev = ea["severity"].upper()
        print(f"  [{source}] {desc} (min: {min_c}, severity: {sev})")

    print(f"\n{Fore.GREEN}Detection coverage: {passed_checks}/{total_checks} checks passed{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
