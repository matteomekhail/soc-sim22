#!/usr/bin/env python3
"""
Scenario 10: Verify APT RAT detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the Remote Access Trojan was properly detected, including
C2 beaconing interval analysis.
"""

import json
import os
import sys
import statistics

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.siem_client import SIEMClient

init(autoreset=True)

EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "expected_alerts.json")
LOG_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "apt_rat_campaign.jsonl"
)

PHASE_INDICATORS = {
    "rat_delivery": {
        "patterns": ["email_received", "xlsm", "phishing", "libreoffice"],
        "description": "RAT delivery via phishing email",
    },
    "rat_installation": {
        "patterns": ["crontab", ".bashrc", "sys_update", "RAT_INSTALL"],
        "description": "RAT installation with persistence",
    },
    "c2_beaconing": {
        "patterns": ["c2_beacon", "heartbeat", "check-update", "telemetry"],
        "description": "C2 beaconing pattern (regular interval callbacks)",
    },
    "command_execution": {
        "patterns": ["c2_command", "rat_execution", "tasking"],
        "description": "Remote command execution via C2",
    },
    "data_collection": {
        "patterns": ["keylogger", "screenshot", "rat_harvester", "rat_module"],
        "description": "Data collection (keylog, screenshots, files)",
    },
    "exfiltration": {
        "patterns": ["c2_exfiltration", "upload", "exfil"],
        "description": "Data exfiltration over C2 channel",
    },
}


def check_local_logs() -> dict:
    """Check locally generated logs for RAT indicators."""
    results = {
        "total": 0,
        "phases_detected": {},
        "beacon_intervals": [],
        "commands_executed": 0,
        "exfil_bytes": 0,
        "event_types": {},
    }

    if not os.path.exists(LOG_FILE):
        print(f"{Fore.RED}[!] No attack logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
        return results

    prev_beacon_time = None

    with open(LOG_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            line_str = line.strip()

            try:
                entry = json.loads(line_str)
                event_type = entry.get("event_type", "unknown")
                results["event_types"][event_type] = results["event_types"].get(event_type, 0) + 1

                # Track beacon intervals
                if event_type == "c2_beacon":
                    interval = entry.get("interval")
                    if interval:
                        results["beacon_intervals"].append(interval)

                # Count C2 commands
                if event_type == "c2_command":
                    results["commands_executed"] += 1

                # Track exfiltration volume
                if event_type == "c2_exfiltration":
                    results["exfil_bytes"] += entry.get("size_bytes", 0)

                # Phase detection
                entry_str = json.dumps(entry).lower()
                for phase, info in PHASE_INDICATORS.items():
                    for pattern in info["patterns"]:
                        if pattern.lower() in entry_str:
                            if phase not in results["phases_detected"]:
                                results["phases_detected"][phase] = 0
                            results["phases_detected"][phase] += 1
                            break

            except json.JSONDecodeError:
                pass

    return results


def analyze_beacon_pattern(intervals: list[int]) -> dict:
    """Analyze C2 beacon intervals for regularity (key detection indicator)."""
    if len(intervals) < 3:
        return {"regular": False, "reason": "Too few beacons"}

    mean = statistics.mean(intervals)
    stdev = statistics.stdev(intervals)
    cv = stdev / mean if mean > 0 else 0  # Coefficient of variation

    return {
        "count": len(intervals),
        "mean_interval": round(mean, 1),
        "stdev": round(stdev, 1),
        "min_interval": min(intervals),
        "max_interval": max(intervals),
        "coefficient_of_variation": round(cv, 3),
        "regular": cv < 0.15,  # CV < 15% indicates regular beaconing
        "verdict": "SUSPICIOUS (regular beaconing)" if cv < 0.15 else "INCONCLUSIVE",
    }


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for RAT-related alerts."""
    try:
        from wcace_lib.wazuh_api import WazuhAPI
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="WCACE S10", limit=50)
        return alerts
    except Exception as e:
        print(f"  [*] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 10 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="10-apt-rat"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        return sum(len(s.get("values", [])) for s in streams)
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}{'='*62}
  WCACE Scenario 10: APT Remote Access Trojan
  Detection Verification
{'='*62}{Style.RESET_ALL}
""")

    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    total_checks = 0
    passed_checks = 0

    # Check 1: Local logs
    print(f"{Fore.YELLOW}[1/4] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  [+] {local['total']} log entries found")
        print(f"  [+] C2 commands executed: {local['commands_executed']}")
        print(f"  [+] Data exfiltrated: {local['exfil_bytes'] // 1024} KB")

        print(f"\n  Event type breakdown:")
        for etype, count in sorted(local["event_types"].items(), key=lambda x: -x[1]):
            print(f"    - {etype}: {count}")

        print(f"\n  RAT phases detected:")
        detected_phases = 0
        for phase, info in PHASE_INDICATORS.items():
            count = local["phases_detected"].get(phase, 0)
            if count > 0:
                status = f"{Fore.GREEN}DETECTED ({count} indicators){Style.RESET_ALL}"
                detected_phases += 1
            else:
                status = f"{Fore.RED}NOT DETECTED{Style.RESET_ALL}"
            print(f"    - {info['description']}: {status}")

        coverage = detected_phases / len(PHASE_INDICATORS) * 100
        print(f"\n  Phase coverage: {detected_phases}/{len(PHASE_INDICATORS)} ({coverage:.0f}%)")
        passed_checks += 1
    else:
        print(f"  {Fore.RED}[!] No logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
    total_checks += 1

    # Check 2: Beacon interval analysis
    print(f"\n{Fore.YELLOW}[2/4] Analyzing C2 beacon pattern...{Style.RESET_ALL}")
    if local["beacon_intervals"]:
        analysis = analyze_beacon_pattern(local["beacon_intervals"])
        print(f"  [+] Beacons analyzed: {analysis['count']}")
        print(f"  [+] Mean interval: {analysis['mean_interval']}s")
        print(f"  [+] Std deviation: {analysis['stdev']}s")
        print(f"  [+] Min/Max: {analysis['min_interval']}s / {analysis['max_interval']}s")
        print(f"  [+] Coefficient of variation: {analysis['coefficient_of_variation']}")

        if analysis["regular"]:
            print(f"  [{Fore.RED}ALERT{Style.RESET_ALL}] {analysis['verdict']}")
            passed_checks += 1
        else:
            print(f"  [*] {analysis['verdict']}")
    else:
        print(f"  [*] No beacon data to analyze")
    total_checks += 1

    # Check 3: Wazuh
    print(f"\n{Fore.YELLOW}[3/4] Checking Wazuh alerts...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    if wazuh_alerts:
        print(f"  [+] {len(wazuh_alerts)} Wazuh alerts found")
        for alert in wazuh_alerts[:5]:
            rule = alert.get("rule", {})
            print(f"    - Rule {rule.get('id')}: {rule.get('description', 'N/A')}")
        passed_checks += 1
    else:
        print(f"  [*] No Wazuh alerts (stack may not be running)")
    total_checks += 1

    # Check 4: Loki
    print(f"\n{Fore.YELLOW}[4/4] Checking Loki logs...{Style.RESET_ALL}")
    loki_count = check_loki_logs()
    if loki_count > 0:
        print(f"  [+] {loki_count} entries in Loki")
        passed_checks += 1
    else:
        print(f"  [*] No Loki entries (stack may not be running)")
    total_checks += 1

    # Summary
    print(f"\n{Fore.CYAN}{'='*62}")
    print(f"  Detection Verification Summary")
    print(f"{'='*62}{Style.RESET_ALL}")

    print(f"\n  Expected alerts:")
    for ea in expected["expected_alerts"]:
        source = ea["source"].upper()
        desc = ea["description"]
        sev = ea["severity"].upper()
        rule_key = ea.get("rule_id") or ea.get("sid")
        print(f"    [{source}] {rule_key}: {desc} (severity: {sev})")

    print(f"\n{Fore.GREEN}  Detection checks: {passed_checks}/{total_checks} passed{Style.RESET_ALL}")
    print(f"  Next step: python3 respond/containment.py")


if __name__ == "__main__":
    main()
