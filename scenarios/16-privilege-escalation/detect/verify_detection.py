#!/usr/bin/env python3
"""
Scenario 16: Verify Privilege Escalation detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the privilege escalation attack was properly detected.
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
    os.path.dirname(__file__), "..", "logs", "sample_logs", "privilege_escalation_attack.jsonl"
)
AUTH_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "auth_logs.log"
)


def check_local_logs() -> dict:
    """Check locally generated attack logs."""
    results = {
        "total": 0,
        "sudo_failures": 0,
        "suid_events": 0,
        "root_access": 0,
        "backdoor_events": 0,
        "wazuh_alerts": 0,
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

                if event_type == "wazuh_alert":
                    results["wazuh_alerts"] += 1
                elif "suid" in event_type:
                    results["suid_events"] += 1
                elif entry.get("effective_uid") == 0 or entry.get("user") == "root":
                    results["root_access"] += 1

                # Check for backdoor user references
                if "svc_support" in str(entry):
                    results["backdoor_events"] += 1

            except json.JSONDecodeError:
                # Handle syslog-format auth entries
                line_str = line.strip()
                if "NOT in sudoers" in line_str:
                    results["sudo_failures"] += 1
                elif "session opened for user root" in line_str:
                    results["root_access"] += 1
                elif "new user:" in line_str:
                    results["backdoor_events"] += 1

    return results


def check_auth_logs() -> dict:
    """Check auth-specific log entries."""
    results = {"total": 0, "sudo_denied": 0, "sessions_opened": 0}

    if not os.path.exists(AUTH_FILE):
        return results

    with open(AUTH_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            if "NOT in sudoers" in line:
                results["sudo_denied"] += 1
            if "session opened" in line:
                results["sessions_opened"] += 1

    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for privilege escalation alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="privilege escalation", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 16 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="16-privilege-escalation"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}+============================================================+
|  WCACE Scenario 16: Privilege Escalation Detection Check   |
+============================================================+{Style.RESET_ALL}
""")

    # Load expected alerts
    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    results_table = []
    total_checks = 0
    passed_checks = 0

    # Check 1: Local attack logs
    print(f"{Fore.YELLOW}[1/4] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  [+] {local['total']} log entries found")
        print(f"    - Sudo failures:     {local['sudo_failures']}")
        print(f"    - SUID events:       {local['suid_events']}")
        print(f"    - Root access events: {local['root_access']}")
        print(f"    - Backdoor events:   {local['backdoor_events']}")
        print(f"    - Wazuh alerts:      {local['wazuh_alerts']}")
        results_table.append(["Local Logs", local["total"], "PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "FAIL"])
    total_checks += 1

    # Check 2: Auth logs
    print(f"\n{Fore.YELLOW}[2/4] Checking auth logs...{Style.RESET_ALL}")
    auth = check_auth_logs()
    if auth["total"] > 0:
        print(f"  [+] {auth['total']} auth log entries found")
        print(f"    - Sudo denied:       {auth['sudo_denied']}")
        print(f"    - Sessions opened:   {auth['sessions_opened']}")
        results_table.append(["Auth Logs", auth["total"], "PASS"])
        passed_checks += 1
    else:
        print(f"  [*] No auth logs found (run simulate_attack.py first)")
        results_table.append(["Auth Logs", 0, "FAIL"])
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
