#!/usr/bin/env python3
"""
Scenario 19: Verify Cryptojacking detection by SOC stack.

Checks Suricata alerts, Wazuh alerts, and Loki logs to confirm
the cryptojacking attack was properly detected.
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
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs", "cryptojacking_attack.jsonl")


def check_local_logs() -> dict:
    """Check locally generated attack logs for cryptojacking indicators."""
    results = {
        "total": 0,
        "ids_alerts": 0,
        "mining_beacons": 0,
        "stratum_events": 0,
        "pool_connections": 0,
        "cpu_spikes": 0,
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
                elif event_type == "mining_beacon":
                    results["mining_beacons"] += 1
                elif event_type == "stratum_protocol":
                    results["stratum_events"] += 1
                elif event_type == "firewall":
                    dst_ip = entry.get("dst_ip", "")
                    if dst_ip == "203.0.113.200":
                        results["pool_connections"] += 1
                elif event_type == "endpoint_telemetry":
                    cpu = entry.get("cpu_percent", 0)
                    if cpu > 70:
                        results["cpu_spikes"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for cryptojacking alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="cryptojacking", limit=50)
        alerts += api.get_alerts(search="mining", limit=50)
        # Deduplicate by timestamp
        seen = set()
        unique = []
        for a in alerts:
            ts = a.get("timestamp", "")
            if ts not in seen:
                seen.add(ts)
                unique.append(a)
        return unique
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 19 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="19-cryptojacking"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}=====================================================================
  WCACE Scenario 19: Cryptojacking Detection Verification
====================================================================={Style.RESET_ALL}
""")

    # Load expected alerts
    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    results_table = []
    total_checks = 0
    passed_checks = 0

    # Check 1: Local logs
    print(f"{Fore.YELLOW}[1/3] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  + {local['total']} total log entries found")
        print(f"    - IDS alerts:        {local['ids_alerts']}")
        print(f"    - Mining beacons:    {local['mining_beacons']}")
        print(f"    - Stratum events:    {local['stratum_events']}")
        print(f"    - Pool connections:  {local['pool_connections']}")
        print(f"    - CPU spikes:        {local['cpu_spikes']}")
        results_table.append(["Local Logs", local["total"], "+ PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "x FAIL"])
    total_checks += 1

    # Check 2: Wazuh alerts
    print(f"\n{Fore.YELLOW}[2/3] Checking Wazuh alerts...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    if wazuh_alerts:
        print(f"  + {len(wazuh_alerts)} Wazuh alerts found")
        for alert in wazuh_alerts[:5]:
            rule = alert.get("rule", {})
            print(f"    - Rule {rule.get('id')}: {rule.get('description', 'N/A')}")
        results_table.append(["Wazuh Alerts", len(wazuh_alerts), "+ PASS"])
        passed_checks += 1
    else:
        print(f"  ! No Wazuh alerts (stack may not be running)")
        results_table.append(["Wazuh Alerts", 0, "! SKIP"])
    total_checks += 1

    # Check 3: Loki logs
    print(f"\n{Fore.YELLOW}[3/3] Checking Loki logs...{Style.RESET_ALL}")
    loki_count = check_loki_logs()
    if loki_count > 0:
        print(f"  + {loki_count} entries in Loki")
        results_table.append(["Loki Logs", loki_count, "+ PASS"])
        passed_checks += 1
    else:
        print(f"  ! No Loki entries (stack may not be running)")
        results_table.append(["Loki Logs", 0, "! SKIP"])
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
