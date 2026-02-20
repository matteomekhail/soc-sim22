#!/usr/bin/env python3
"""
Scenario 08: Verify Phishing & Ransomware detection by SOC stack.

Checks local attack logs, FIM alerts, encryption detection, and
optionally queries Wazuh and Loki for live alert verification.
"""

import json
import os
import sys

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.siem_client import SIEMClient

init(autoreset=True)

EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "expected_alerts.json")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")
ATTACK_LOG = os.path.join(LOG_DIR, "ransomware_attack.jsonl")
FIM_LOG = os.path.join(LOG_DIR, "fim_alerts.jsonl")
EMAIL_LOG = os.path.join(LOG_DIR, "phishing_emails.json")
SANDBOX_DIR = "/tmp/wcace-sandbox/victim-files"


def banner():
    print(f"""
{Fore.CYAN}+==============================================================+
|  WCACE Scenario 08: Phishing & Ransomware Detection Verify   |
+==============================================================+{Style.RESET_ALL}
""")


def check_local_logs() -> dict:
    """Check locally generated attack logs for phishing and ransomware events."""
    results = {
        "total": 0,
        "email_events": 0,
        "ids_alerts": 0,
        "fim_alerts": 0,
        "wazuh_alerts": 0,
        "process_events": 0,
        "network_events": 0,
    }

    if not os.path.exists(ATTACK_LOG):
        print(f"  {Fore.RED}[!] No attack logs found at {ATTACK_LOG}")
        print(f"      Run attack/simulate_attack.py first.{Style.RESET_ALL}")
        return results

    with open(ATTACK_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            try:
                entry = json.loads(line)
                event_type = entry.get("event_type", "")
                if event_type == "email_received":
                    results["email_events"] += 1
                elif event_type == "ids_alert":
                    results["ids_alerts"] += 1
                elif event_type == "fim_alert":
                    results["fim_alerts"] += 1
                elif event_type == "wazuh_alert":
                    results["wazuh_alerts"] += 1
                elif event_type == "process_execution":
                    results["process_events"] += 1
                elif event_type == "network_connection":
                    results["network_events"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_fim_alerts() -> dict:
    """Check FIM alert logs for encryption-related events."""
    results = {
        "total": 0,
        "files_deleted": 0,
        "encrypted_created": 0,
        "ransom_notes": 0,
    }

    if not os.path.exists(FIM_LOG):
        return results

    with open(FIM_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            try:
                entry = json.loads(line)
                action = entry.get("action", "")
                file_path = entry.get("file_path", "")
                file_name = entry.get("file_name", "")

                if action == "deleted":
                    results["files_deleted"] += 1
                elif action == "created" and file_path.endswith(".encrypted"):
                    results["encrypted_created"] += 1
                if file_name == "RANSOM_NOTE.txt" or "RANSOM_NOTE" in file_path:
                    results["ransom_notes"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_sandbox_state() -> dict:
    """Check the current state of the sandbox directory."""
    results = {
        "exists": False,
        "encrypted_files": 0,
        "original_files": 0,
        "ransom_notes": 0,
    }

    if not os.path.exists(SANDBOX_DIR):
        return results

    results["exists"] = True

    for root, dirs, files in os.walk(SANDBOX_DIR):
        for f in files:
            if f.endswith(".encrypted"):
                results["encrypted_files"] += 1
            elif f == "RANSOM_NOTE.txt":
                results["ransom_notes"] += 1
            else:
                results["original_files"] += 1

    return results


def check_phishing_emails() -> int:
    """Count phishing emails in the email log."""
    if not os.path.exists(EMAIL_LOG):
        return 0
    count = 0
    with open(EMAIL_LOG) as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh API for ransomware-related alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="ransomware", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 08 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="08-phishing-ransomware"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    banner()

    # Load expected alerts
    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    results_table = []
    total_checks = 0
    passed_checks = 0

    # -----------------------------------------------------------------------
    # Check 1: Local attack logs
    # -----------------------------------------------------------------------
    print(f"{Fore.YELLOW}[1/5] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  [PASS] {local['total']} total log entries found")
        print(f"    - Email events:     {local['email_events']}")
        print(f"    - IDS alerts:       {local['ids_alerts']}")
        print(f"    - FIM alerts:       {local['fim_alerts']}")
        print(f"    - Wazuh alerts:     {local['wazuh_alerts']}")
        print(f"    - Process events:   {local['process_events']}")
        print(f"    - Network events:   {local['network_events']}")
        results_table.append(("Local Logs", local["total"], "PASS"))
        passed_checks += 1
    else:
        print(f"  [FAIL] No attack logs found")
        results_table.append(("Local Logs", 0, "FAIL"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 2: FIM alerts (encryption detection)
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[2/5] Checking FIM alerts for encryption activity...{Style.RESET_ALL}")
    fim = check_fim_alerts()
    if fim["total"] > 0:
        print(f"  [PASS] {fim['total']} FIM alert entries found")
        print(f"    - Files deleted:         {fim['files_deleted']}")
        print(f"    - Encrypted files made:  {fim['encrypted_created']}")
        print(f"    - Ransom notes detected: {fim['ransom_notes']}")
        results_table.append(("FIM Alerts", fim["total"], "PASS"))
        passed_checks += 1
    else:
        print(f"  [FAIL] No FIM alerts found")
        results_table.append(("FIM Alerts", 0, "FAIL"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 3: Sandbox state
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[3/5] Checking sandbox directory state...{Style.RESET_ALL}")
    sandbox = check_sandbox_state()
    if sandbox["exists"] and sandbox["encrypted_files"] > 0:
        print(f"  [PASS] Sandbox exists with encrypted files")
        print(f"    - Encrypted files: {sandbox['encrypted_files']}")
        print(f"    - Original files:  {sandbox['original_files']}")
        print(f"    - Ransom notes:    {sandbox['ransom_notes']}")
        results_table.append(("Sandbox State", sandbox["encrypted_files"], "PASS"))
        passed_checks += 1
    elif sandbox["exists"]:
        print(f"  [WARN] Sandbox exists but no encrypted files found")
        results_table.append(("Sandbox State", 0, "WARN"))
    else:
        print(f"  [FAIL] Sandbox directory does not exist at {SANDBOX_DIR}")
        results_table.append(("Sandbox State", 0, "FAIL"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 4: Wazuh alerts (live)
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[4/5] Checking Wazuh alerts...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    if wazuh_alerts:
        print(f"  [PASS] {len(wazuh_alerts)} Wazuh alerts found")
        for alert in wazuh_alerts[:5]:
            rule = alert.get("rule", {})
            print(f"    - Rule {rule.get('id')}: {rule.get('description', 'N/A')}")
        results_table.append(("Wazuh Alerts", len(wazuh_alerts), "PASS"))
        passed_checks += 1
    else:
        print(f"  [SKIP] Wazuh not available or no alerts")
        results_table.append(("Wazuh Alerts", 0, "SKIP"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 5: Loki logs
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[5/5] Checking Loki logs...{Style.RESET_ALL}")
    loki_count = check_loki_logs()
    if loki_count > 0:
        print(f"  [PASS] {loki_count} entries in Loki")
        results_table.append(("Loki Logs", loki_count, "PASS"))
        passed_checks += 1
    else:
        print(f"  [SKIP] Loki not available or no entries")
        results_table.append(("Loki Logs", 0, "SKIP"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{Fore.CYAN}{'=' * 62}")
    print(f"  Detection Verification Summary")
    print(f"{'=' * 62}{Style.RESET_ALL}")

    for check_name, count, status in results_table:
        if status == "PASS":
            color = Fore.GREEN
        elif status == "FAIL":
            color = Fore.RED
        else:
            color = Fore.YELLOW
        print(f"  {check_name:<20s}  Count: {count:<6}  {color}{status}{Style.RESET_ALL}")

    print(f"\n  Expected alerts for this scenario:")
    phishing_alerts = [a for a in expected["expected_alerts"] if a["phase"] == "phishing"]
    ransomware_alerts = [a for a in expected["expected_alerts"] if a["phase"] == "ransomware"]

    print(f"\n  {Fore.YELLOW}-- Phishing Phase --{Style.RESET_ALL}")
    for ea in phishing_alerts:
        source = ea["source"].upper()
        desc = ea["description"]
        sev = ea["severity"].upper()
        print(f"    [{source}] {desc} (severity: {sev})")

    print(f"\n  {Fore.YELLOW}-- Ransomware Phase --{Style.RESET_ALL}")
    for ea in ransomware_alerts:
        source = ea["source"].upper()
        desc = ea["description"]
        sev = ea["severity"].upper()
        print(f"    [{source}] {desc} (severity: {sev})")

    print(f"\n  {Fore.GREEN}Detection coverage: "
          f"{passed_checks}/{total_checks} checks passed{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
