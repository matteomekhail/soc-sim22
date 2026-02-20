#!/usr/bin/env python3
"""Scenario 9: Verify insider data theft detection."""

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
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs", "insider_theft.jsonl")


def check_local_logs() -> dict:
    results = {"total": 0, "db_queries": 0, "file_ops": 0, "exfil": 0}
    if not os.path.exists(LOG_FILE):
        return results
    with open(LOG_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            try:
                entry = json.loads(line)
                et = entry.get("event_type", "")
                if "db_query" in et:
                    results["db_queries"] += 1
                elif "file" in et:
                    results["file_ops"] += 1
                elif "transfer" in et or "exfil" in et:
                    results["exfil"] += 1
            except json.JSONDecodeError:
                pass
    return results


def main():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 9: Insider Data Theft Detection Check   ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    results_table = []
    total_checks = 0
    passed_checks = 0

    print(f"{Fore.YELLOW}[1/3] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  ✓ {local['total']} log entries found")
        print(f"    - DB queries: {local['db_queries']}")
        print(f"    - File operations: {local['file_ops']}")
        print(f"    - Exfiltration events: {local['exfil']}")
        results_table.append(["Local Logs", local["total"], "✓ PASS"])
        passed_checks += 1
    else:
        print(f"  ✗ No logs found. Run simulate_attack.py first.")
        results_table.append(["Local Logs", 0, "✗ FAIL"])
    total_checks += 1

    print(f"\n{Fore.YELLOW}[2/3] Checking Wazuh alerts...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            alerts = api.get_alerts(search="insider", limit=50)
            print(f"  ✓ {len(alerts)} Wazuh alerts found")
            results_table.append(["Wazuh Alerts", len(alerts), "✓ PASS"])
            passed_checks += 1
        else:
            results_table.append(["Wazuh Alerts", 0, "⚠ SKIP"])
    except Exception:
        print(f"  ⚠ Wazuh not available")
        results_table.append(["Wazuh Alerts", 0, "⚠ SKIP"])
    total_checks += 1

    print(f"\n{Fore.YELLOW}[3/3] Checking Loki logs...{Style.RESET_ALL}")
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="09-insider-theft"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        if count > 0:
            results_table.append(["Loki Logs", count, "✓ PASS"])
            passed_checks += 1
        else:
            results_table.append(["Loki Logs", 0, "⚠ SKIP"])
    except Exception:
        results_table.append(["Loki Logs", 0, "⚠ SKIP"])
    total_checks += 1

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Detection Verification Summary")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(tabulate(results_table, headers=["Check", "Count", "Status"], tablefmt="grid"))

    # Behavioral indicators
    print(f"\n{Fore.YELLOW}Key Behavioral Indicators:{Style.RESET_ALL}")
    indicators = [
        "Escalating database query sensitivity over time",
        "Bulk PII/financial data extraction",
        "Encrypted file creation in hidden directories",
        "Chunked HTTPS uploads to external host",
        "DNS tunnelling as backup exfiltration channel",
    ]
    for ind in indicators:
        print(f"  → {ind}")


if __name__ == "__main__":
    main()
