#!/usr/bin/env python3
"""
Scenario 18: Verify Drive-By Download detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the drive-by download attack was properly detected.
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
    os.path.dirname(__file__), "..", "logs", "sample_logs", "drive_by_download_attack.jsonl"
)
PROXY_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "proxy_logs.jsonl"
)


def check_local_logs() -> dict:
    """Check locally generated attack logs."""
    results = {
        "total": 0,
        "web_access": 0,
        "dns_queries": 0,
        "ids_alerts": 0,
        "file_creations": 0,
        "exploit_kit_probes": 0,
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

                if event_type == "web_access":
                    results["web_access"] += 1
                elif event_type == "dns_query":
                    results["dns_queries"] += 1
                elif event_type == "ids_alert":
                    results["ids_alerts"] += 1
                elif event_type == "file_creation":
                    results["file_creations"] += 1
                elif event_type == "exploit_kit_probe":
                    results["exploit_kit_probes"] += 1
                elif event_type == "wazuh_alert":
                    results["wazuh_alerts"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_proxy_logs() -> dict:
    """Check web proxy logs for exploit kit and download indicators."""
    results = {
        "total": 0,
        "exploit_kit_requests": 0,
        "download_requests": 0,
        "c2_requests": 0,
    }

    if not os.path.exists(PROXY_FILE):
        return results

    with open(PROXY_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            try:
                entry = json.loads(line)
                path = entry.get("path", "")

                if "exploitkit" in path or "clickserv" in path or "/check?p=" in path:
                    results["exploit_kit_requests"] += 1
                elif ".exe" in path or "download" in path.lower():
                    results["download_requests"] += 1
                elif "evil-cdn" in path or "checkin" in path:
                    results["c2_requests"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for drive-by download alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="drive-by", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 18 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="18-drive-by-download"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}+============================================================+
|  WCACE Scenario 18: Drive-By Download Detection Check      |
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
        print(f"    - Web access logs:     {local['web_access']}")
        print(f"    - DNS queries:         {local['dns_queries']}")
        print(f"    - IDS alerts:          {local['ids_alerts']}")
        print(f"    - File creations:      {local['file_creations']}")
        print(f"    - Exploit kit probes:  {local['exploit_kit_probes']}")
        print(f"    - Wazuh alerts:        {local['wazuh_alerts']}")
        results_table.append(["Local Logs", local["total"], "PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "FAIL"])
    total_checks += 1

    # Check 2: Proxy logs
    print(f"\n{Fore.YELLOW}[2/4] Checking proxy logs...{Style.RESET_ALL}")
    proxy = check_proxy_logs()
    if proxy["total"] > 0:
        print(f"  [+] {proxy['total']} proxy log entries found")
        print(f"    - Exploit kit requests: {proxy['exploit_kit_requests']}")
        print(f"    - Download requests:    {proxy['download_requests']}")
        print(f"    - C2 requests:          {proxy['c2_requests']}")
        results_table.append(["Proxy Logs", proxy["total"], "PASS"])
        passed_checks += 1
    else:
        print(f"  [*] No proxy logs found (run simulate_attack.py first)")
        results_table.append(["Proxy Logs", 0, "FAIL"])
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
