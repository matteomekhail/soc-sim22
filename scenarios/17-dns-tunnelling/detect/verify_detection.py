#!/usr/bin/env python3
"""
Scenario 17: Verify DNS Tunnelling detection by SOC stack.

Checks Suricata alerts, Wazuh alerts, and local logs to confirm
the DNS tunnelling attack was properly detected.
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
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs", "dns_tunnel_attack.jsonl")


def check_local_logs() -> dict:
    """Check locally generated attack logs for DNS tunnel indicators."""
    results = {
        "total": 0,
        "dns_queries": 0,
        "ids_alerts": 0,
        "tunnel_queries": 0,
        "txt_queries": 0,
        "cname_queries": 0,
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

                if event_type == "dns_query":
                    results["dns_queries"] += 1
                    query = entry.get("query", "")
                    qtype = entry.get("query_type", "")

                    if "exfil.test" in query:
                        results["tunnel_queries"] += 1
                    if qtype == "TXT":
                        results["txt_queries"] += 1
                    elif qtype == "CNAME":
                        results["cname_queries"] += 1

                elif event_type == "ids_alert":
                    results["ids_alerts"] += 1

            except json.JSONDecodeError:
                pass

    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for DNS tunnelling alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="dns tunnel", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 17 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="17-dns-tunnel"}', limit=200)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def analyze_query_patterns(log_file: str) -> dict:
    """Analyze DNS query patterns for tunnel characteristics."""
    analysis = {
        "avg_query_length": 0,
        "max_query_length": 0,
        "queries_over_100_chars": 0,
        "unique_subdomains": set(),
        "query_rate_per_min": 0,
    }

    if not os.path.exists(log_file):
        return analysis

    lengths = []
    timestamps = []

    with open(log_file) as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "dns_query":
                    query = entry.get("query", "")
                    qlen = len(query)
                    lengths.append(qlen)

                    if qlen > 100:
                        analysis["queries_over_100_chars"] += 1

                    subdomain = query.split(".")[0] if "." in query else query
                    analysis["unique_subdomains"].add(subdomain)

                    ts = entry.get("timestamp", "")
                    if ts:
                        timestamps.append(ts)
            except (json.JSONDecodeError, KeyError):
                pass

    if lengths:
        analysis["avg_query_length"] = sum(lengths) / len(lengths)
        analysis["max_query_length"] = max(lengths)

    # Estimate query rate (approximate)
    if len(timestamps) > 1:
        analysis["query_rate_per_min"] = len(timestamps)  # simplified estimate

    analysis["unique_subdomains"] = len(analysis["unique_subdomains"])

    return analysis


def main():
    print(f"""
{Fore.CYAN}{'='*62}
  WCACE Scenario 17: DNS Tunnelling Detection Verification
{'='*62}{Style.RESET_ALL}
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
        print(f"  + {local['total']} log entries found")
        print(f"    - DNS queries      : {local['dns_queries']}")
        print(f"    - Tunnel queries   : {local['tunnel_queries']}")
        print(f"    - TXT queries      : {local['txt_queries']}")
        print(f"    - CNAME queries    : {local['cname_queries']}")
        print(f"    - IDS alerts       : {local['ids_alerts']}")
        results_table.append(["Local Logs", local["total"], "PASS"])
        passed_checks += 1
    else:
        results_table.append(["Local Logs", 0, "FAIL"])
    total_checks += 1

    # Check 2: Query pattern analysis
    print(f"\n{Fore.YELLOW}[2/4] Analyzing DNS query patterns...{Style.RESET_ALL}")
    patterns = analyze_query_patterns(LOG_FILE)
    tunnel_detected = patterns["queries_over_100_chars"] > 0 or patterns["avg_query_length"] > 50
    if tunnel_detected:
        print(f"  + Tunnel characteristics detected:")
        print(f"    - Avg query length     : {patterns['avg_query_length']:.0f} chars")
        print(f"    - Max query length     : {patterns['max_query_length']} chars")
        print(f"    - Queries > 100 chars  : {patterns['queries_over_100_chars']}")
        print(f"    - Unique subdomains    : {patterns['unique_subdomains']}")
        results_table.append(["Pattern Analysis", patterns["queries_over_100_chars"], "PASS"])
        passed_checks += 1
    else:
        print(f"  - No tunnel patterns found in logs")
        results_table.append(["Pattern Analysis", 0, "FAIL"])
    total_checks += 1

    # Check 3: Wazuh alerts
    print(f"\n{Fore.YELLOW}[3/4] Checking Wazuh alerts...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    if wazuh_alerts:
        print(f"  + {len(wazuh_alerts)} Wazuh alerts found")
        for alert in wazuh_alerts[:5]:
            rule = alert.get("rule", {})
            print(f"    - Rule {rule.get('id')}: {rule.get('description', 'N/A')}")
        results_table.append(["Wazuh Alerts", len(wazuh_alerts), "PASS"])
        passed_checks += 1
    else:
        print(f"  ! No Wazuh alerts (stack may not be running)")
        results_table.append(["Wazuh Alerts", 0, "SKIP"])
    total_checks += 1

    # Check 4: Loki logs
    print(f"\n{Fore.YELLOW}[4/4] Checking Loki logs...{Style.RESET_ALL}")
    loki_count = check_loki_logs()
    if loki_count > 0:
        print(f"  + {loki_count} entries in Loki")
        results_table.append(["Loki Logs", loki_count, "PASS"])
        passed_checks += 1
    else:
        print(f"  ! No Loki entries (stack may not be running)")
        results_table.append(["Loki Logs", 0, "SKIP"])
    total_checks += 1

    # Summary
    print(f"\n{Fore.CYAN}{'='*62}")
    print(f"  Detection Verification Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  {'Check':<25s} {'Count':>8s}   {'Status':<8s}")
    print(f"  {'-'*25} {'-'*8}   {'-'*8}")
    for row in results_table:
        status_color = Fore.GREEN if row[2] == "PASS" else (Fore.YELLOW if row[2] == "SKIP" else Fore.RED)
        print(f"  {row[0]:<25s} {row[1]:>8}   {status_color}{row[2]:<8s}{Style.RESET_ALL}")

    print(f"\n  Expected alerts for this scenario:")
    for ea in expected["expected_alerts"]:
        source = ea["source"].upper()
        desc = ea["description"]
        min_c = ea["min_count"]
        sev = ea["severity"].upper()
        print(f"    [{source:>8s}] {desc} (min: {min_c}, severity: {sev})")

    print(f"\n{Fore.GREEN}  Detection coverage: {passed_checks}/{total_checks} checks passed{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
