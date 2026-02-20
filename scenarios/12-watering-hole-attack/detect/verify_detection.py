#!/usr/bin/env python3
"""
Scenario 12: Verify Watering Hole Attack detection by SOC stack.

Checks local attack logs for all five phases, verifies exploit and C2
indicators, and optionally queries Wazuh and Loki for live alert
verification.
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
ATTACK_LOG = os.path.join(LOG_DIR, "watering_hole_attack.jsonl")


def banner():
    print(f"""
{Fore.CYAN}+==============================================================+
|  WCACE Scenario 12: Watering Hole Attack Detection Verify    |
+==============================================================+{Style.RESET_ALL}
""")


def check_local_logs() -> dict:
    """Check locally generated attack logs for watering hole events."""
    results = {
        "total": 0,
        "web_access": 0,
        "web_modifications": 0,
        "watering_hole_visits": 0,
        "browser_exploits": 0,
        "file_downloads": 0,
        "process_executions": 0,
        "registry_modifications": 0,
        "network_connections": 0,
        "ids_alerts": 0,
        "dns_queries": 0,
        "firewall_events": 0,
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
                if event_type == "web_access":
                    results["web_access"] += 1
                elif event_type == "web_modification":
                    results["web_modifications"] += 1
                elif event_type == "watering_hole_visit":
                    results["watering_hole_visits"] += 1
                elif event_type == "browser_exploit":
                    results["browser_exploits"] += 1
                elif event_type == "file_download":
                    results["file_downloads"] += 1
                elif event_type == "process_execution":
                    results["process_executions"] += 1
                elif event_type == "registry_modification":
                    results["registry_modifications"] += 1
                elif event_type == "network_connection":
                    results["network_connections"] += 1
                elif event_type == "ids_alert":
                    results["ids_alerts"] += 1
                elif event_type == "dns_query":
                    results["dns_queries"] += 1
                elif event_type == "firewall":
                    results["firewall_events"] += 1
            except json.JSONDecodeError:
                pass

    return results


def check_phase_logs() -> dict:
    """Check individual phase log files."""
    phases = {
        "phase1_website_compromise.jsonl": 0,
        "phase2_victim_browsing.jsonl": 0,
        "phase3_browser_exploit.jsonl": 0,
        "phase4_payload_execution.jsonl": 0,
        "phase5_post_exploitation.jsonl": 0,
    }

    for fname in phases:
        fpath = os.path.join(LOG_DIR, fname)
        if os.path.exists(fpath):
            with open(fpath) as f:
                phases[fname] = sum(1 for line in f if line.strip())

    return phases


def check_exploit_indicators() -> dict:
    """Check for specific exploit and C2 indicators in logs."""
    indicators = {
        "exploit_cve_found": False,
        "c2_connections": 0,
        "registry_persistence": 0,
        "credential_harvesting": 0,
        "recon_commands": 0,
        "exploited_hosts": set(),
    }

    if not os.path.exists(ATTACK_LOG):
        return indicators

    with open(ATTACK_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                event_type = entry.get("event_type", "")

                # Check for CVE exploit
                if entry.get("vulnerability", ""):
                    indicators["exploit_cve_found"] = True

                # Check for C2 connections
                if event_type == "network_connection" and \
                   entry.get("dst_ip") == "203.0.113.100":
                    indicators["c2_connections"] += 1
                    indicators["exploited_hosts"].add(entry.get("src_ip", ""))

                # Check for registry persistence
                if event_type == "registry_modification":
                    indicators["registry_persistence"] += 1

                # Check for credential harvesting
                if "comsvcs.dll" in entry.get("command_line", "") or \
                   "MiniDump" in entry.get("command_line", "") or \
                   "lsass" in entry.get("description", ""):
                    indicators["credential_harvesting"] += 1

                # Check for recon commands
                if event_type == "process_execution" and \
                   entry.get("parent_process", "") == "msedge_update.exe":
                    indicators["recon_commands"] += 1

            except json.JSONDecodeError:
                pass

    # Convert set to count
    indicators["exploited_hosts"] = len(indicators["exploited_hosts"])
    return indicators


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh API for watering hole related alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="watering_hole", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 12 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="12-watering-hole-attack"}', limit=200)
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
        print(f"    - Web access events:      {local['web_access']}")
        print(f"    - Web modifications:       {local['web_modifications']}")
        print(f"    - Watering hole visits:    {local['watering_hole_visits']}")
        print(f"    - Browser exploits:        {local['browser_exploits']}")
        print(f"    - File downloads:          {local['file_downloads']}")
        print(f"    - Process executions:      {local['process_executions']}")
        print(f"    - Registry modifications:  {local['registry_modifications']}")
        print(f"    - Network connections:     {local['network_connections']}")
        print(f"    - IDS alerts:              {local['ids_alerts']}")
        print(f"    - DNS queries:             {local['dns_queries']}")
        print(f"    - Firewall events:         {local['firewall_events']}")
        results_table.append(("Local Logs", local["total"], "PASS"))
        passed_checks += 1
    else:
        print(f"  [FAIL] No attack logs found")
        results_table.append(("Local Logs", 0, "FAIL"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 2: Phase logs completeness
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[2/5] Checking phase log files...{Style.RESET_ALL}")
    phases = check_phase_logs()
    phases_with_data = sum(1 for v in phases.values() if v > 0)
    if phases_with_data >= 4:
        print(f"  [PASS] {phases_with_data}/5 phase logs contain data")
        for fname, count in phases.items():
            status = "OK" if count > 0 else "EMPTY"
            print(f"    - {fname:<42s} {count:>4} entries  [{status}]")
        results_table.append(("Phase Logs", phases_with_data, "PASS"))
        passed_checks += 1
    elif phases_with_data > 0:
        print(f"  [WARN] Only {phases_with_data}/5 phase logs have data")
        for fname, count in phases.items():
            print(f"    - {fname:<42s} {count:>4} entries")
        results_table.append(("Phase Logs", phases_with_data, "WARN"))
    else:
        print(f"  [FAIL] No phase logs found")
        results_table.append(("Phase Logs", 0, "FAIL"))
    total_checks += 1

    # -----------------------------------------------------------------------
    # Check 3: Exploit and C2 indicators
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[3/5] Checking exploit and C2 indicators...{Style.RESET_ALL}")
    indicators = check_exploit_indicators()
    indicator_score = sum([
        indicators["exploit_cve_found"],
        indicators["c2_connections"] > 0,
        indicators["registry_persistence"] > 0,
        indicators["credential_harvesting"] > 0,
        indicators["recon_commands"] > 0,
    ])
    if indicator_score >= 3:
        print(f"  [PASS] {indicator_score}/5 attack indicators detected")
        print(f"    - Exploit CVE found:       {'Yes' if indicators['exploit_cve_found'] else 'No'}")
        print(f"    - C2 connections:          {indicators['c2_connections']}")
        print(f"    - Registry persistence:    {indicators['registry_persistence']}")
        print(f"    - Credential harvesting:   {indicators['credential_harvesting']}")
        print(f"    - Recon commands:          {indicators['recon_commands']}")
        print(f"    - Exploited hosts:         {indicators['exploited_hosts']}")
        results_table.append(("Attack Indicators", indicator_score, "PASS"))
        passed_checks += 1
    elif indicator_score > 0:
        print(f"  [WARN] Only {indicator_score}/5 attack indicators detected")
        results_table.append(("Attack Indicators", indicator_score, "WARN"))
    else:
        print(f"  [FAIL] No attack indicators found")
        results_table.append(("Attack Indicators", 0, "FAIL"))
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

    # Show expected alerts by phase
    print(f"\n  Expected alerts for this scenario:")

    phases_display = {
        "website_compromise": "Website Compromise",
        "victim_browsing": "Victim Browsing",
        "browser_exploitation": "Browser Exploitation",
        "persistence": "Persistence",
        "c2_communication": "C2 Communication",
        "post_exploitation": "Post-Exploitation",
        "data_exfiltration": "Data Exfiltration",
        "kill_chain": "Kill Chain Correlation",
    }

    for phase_key, phase_label in phases_display.items():
        phase_alerts = [a for a in expected["expected_alerts"]
                        if a["phase"] == phase_key]
        if phase_alerts:
            print(f"\n  {Fore.YELLOW}-- {phase_label} --{Style.RESET_ALL}")
            for ea in phase_alerts:
                source = ea["source"].upper()
                desc = ea["description"]
                sev = ea["severity"].upper()
                print(f"    [{source}] {desc} (severity: {sev})")

    print(f"\n  {Fore.GREEN}Detection coverage: "
          f"{passed_checks}/{total_checks} checks passed{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
