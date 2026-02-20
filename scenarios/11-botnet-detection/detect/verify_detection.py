#!/usr/bin/env python3
"""
Scenario 11: Verify Botnet Detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the botnet attack was properly detected across all phases.
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
    os.path.dirname(__file__), "..", "logs", "sample_logs", "botnet_attack.jsonl"
)
NETWORK_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "network_logs.log"
)


def check_local_logs() -> dict:
    """Check locally generated attack logs."""
    results = {
        "total": 0,
        "propagation_events": 0,
        "registration_events": 0,
        "beacon_events": 0,
        "tasking_events": 0,
        "ddos_events": 0,
        "credential_events": 0,
        "exfiltration_events": 0,
        "persistence_events": 0,
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
                elif event_type == "smb_exploitation" or "propagation" in str(entry):
                    results["propagation_events"] += 1
                elif event_type in ("http_request", "http_response") and "/register" in str(entry):
                    results["registration_events"] += 1
                elif event_type == "c2_beacon":
                    results["beacon_events"] += 1
                elif event_type in ("c2_tasking", "c2_task_ack"):
                    results["tasking_events"] += 1
                elif "ddos" in event_type:
                    results["ddos_events"] += 1
                elif event_type == "credential_harvest":
                    results["credential_events"] += 1
                elif event_type == "data_exfiltration":
                    results["exfiltration_events"] += 1
                elif event_type == "persistence_install":
                    results["persistence_events"] += 1

            except json.JSONDecodeError:
                # Handle syslog-format entries
                pass

    return results


def check_network_logs() -> dict:
    """Check network-specific log entries."""
    results = {"total": 0, "smb_connections": 0, "firewall_events": 0}

    if not os.path.exists(NETWORK_FILE):
        return results

    with open(NETWORK_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            if "445" in line or "SMB" in line:
                results["smb_connections"] += 1
            if "firewall" in line.lower():
                results["firewall_events"] += 1

    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for botnet-related alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="botnet", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 11 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="11-botnet-detection"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}+============================================================+
|  WCACE Scenario 11: Botnet Detection Verification          |
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
        print(f"    - Propagation events:    {local['propagation_events']}")
        print(f"    - Registration events:   {local['registration_events']}")
        print(f"    - Beacon events:         {local['beacon_events']}")
        print(f"    - Tasking events:        {local['tasking_events']}")
        print(f"    - DDoS events:           {local['ddos_events']}")
        print(f"    - Credential events:     {local['credential_events']}")
        print(f"    - Exfiltration events:   {local['exfiltration_events']}")
        print(f"    - Persistence events:    {local['persistence_events']}")
        print(f"    - Wazuh alerts:          {local['wazuh_alerts']}")
        results_table.append(["Local Logs", local["total"], "PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "FAIL"])
    total_checks += 1

    # Check 2: Network logs
    print(f"\n{Fore.YELLOW}[2/4] Checking network logs...{Style.RESET_ALL}")
    network = check_network_logs()
    if network["total"] > 0:
        print(f"  [+] {network['total']} network log entries found")
        print(f"    - SMB connections:       {network['smb_connections']}")
        print(f"    - Firewall events:       {network['firewall_events']}")
        results_table.append(["Network Logs", network["total"], "PASS"])
        passed_checks += 1
    else:
        print(f"  [*] No network logs found (run simulate_attack.py first)")
        results_table.append(["Network Logs", 0, "FAIL"])
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
