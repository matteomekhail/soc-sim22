#!/usr/bin/env python3
"""
Scenario 07: Verify Zero-Day & Lateral Movement detection by SOC stack.

Checks local logs, Wazuh alerts, and Loki logs to confirm
the zero-day exploit and lateral movement were properly detected.
"""

import json
import os
import sys

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.siem_client import SIEMClient

init(autoreset=True)

EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "expected_alerts.json")
LOG_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "sample_logs", "zero_day_lateral_movement.jsonl"
)

# Attack phase indicators
PHASE_INDICATORS = {
    "zero_day_exploit": {
        "patterns": ["segfault", "SIGSEGV", "application_crash", "0x41414141", "buffer overflow"],
        "description": "Zero-day buffer overflow on API server",
    },
    "reverse_shell": {
        "patterns": ["bash -i", "reverse shell", ":4444", "outbound"],
        "description": "Reverse shell establishment",
    },
    "internal_recon": {
        "patterns": ["ifconfig", "arp -a", "ip route", "recon_results"],
        "description": "Internal network reconnaissance",
    },
    "credential_harvest": {
        "patterns": ["/etc/shadow", "id_rsa", "credential_harvest", "ssh_key"],
        "description": "Credential harvesting (shadow, SSH keys, configs)",
    },
    "lateral_ssh": {
        "patterns": ["lateral_movement_chain", "sequential SSH", "Accepted"],
        "description": "Lateral movement via SSH (sequential host compromise)",
    },
    "lateral_smb": {
        "patterns": ["smb_session", "smb_access", "C$", "ADMIN$"],
        "description": "Lateral movement via SMB (admin shares)",
    },
    "domain_compromise": {
        "patterns": ["credential_dump", "SAM database", "ldapsearch", "GPO", "SYSVOL"],
        "description": "Domain controller compromise and AD extraction",
    },
}


def check_local_logs() -> dict:
    """Check locally generated logs for attack phase indicators."""
    results = {
        "total": 0,
        "phases_detected": {},
        "compromised_hosts": set(),
        "event_types": {},
        "critical_events": 0,
    }

    if not os.path.exists(LOG_FILE):
        print(f"{Fore.RED}[!] No attack logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
        return results

    with open(LOG_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            results["total"] += 1
            line_str = line.strip()

            try:
                entry = json.loads(line_str)
                event_type = entry.get("event_type", "unknown")
                severity = entry.get("severity", "info")
                host = entry.get("host", "")

                results["event_types"][event_type] = results["event_types"].get(event_type, 0) + 1

                if severity in ("critical", "alert"):
                    results["critical_events"] += 1

                if host:
                    results["compromised_hosts"].add(host)

                # Check phase indicators
                entry_str = json.dumps(entry).lower()
                for phase, info in PHASE_INDICATORS.items():
                    for pattern in info["patterns"]:
                        if pattern.lower() in entry_str:
                            if phase not in results["phases_detected"]:
                                results["phases_detected"][phase] = 0
                            results["phases_detected"][phase] += 1
                            break

            except json.JSONDecodeError:
                for phase, info in PHASE_INDICATORS.items():
                    for pattern in info["patterns"]:
                        if pattern.lower() in line_str.lower():
                            if phase not in results["phases_detected"]:
                                results["phases_detected"][phase] = 0
                            results["phases_detected"][phase] += 1
                            break

    results["compromised_hosts"] = list(results["compromised_hosts"])
    return results


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for zero-day and lateral movement alerts."""
    try:
        from wcace_lib.wazuh_api import WazuhAPI
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="WCACE S07", limit=50)
        return alerts
    except Exception as e:
        print(f"  [*] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 07 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="07-zero-day-lateral"}', limit=100)
        streams = result.get("data", {}).get("result", [])
        return sum(len(s.get("values", [])) for s in streams)
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}{'='*62}
  WCACE Scenario 07: Zero-Day & Lateral Movement
  Detection Verification
{'='*62}{Style.RESET_ALL}
""")

    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    total_checks = 0
    passed_checks = 0

    # Check 1: Local logs
    print(f"{Fore.YELLOW}[1/3] Checking local attack logs...{Style.RESET_ALL}")
    local = check_local_logs()
    if local["total"] > 0:
        print(f"  [+] {local['total']} log entries found")
        print(f"  [+] Critical events: {local['critical_events']}")
        print(f"  [+] Hosts involved: {len(local['compromised_hosts'])}")

        print(f"\n  Event type breakdown:")
        for etype, count in sorted(local["event_types"].items(), key=lambda x: -x[1]):
            print(f"    - {etype}: {count}")

        print(f"\n  Attack phases detected:")
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

        if local["compromised_hosts"]:
            print(f"\n  Compromise chain hosts:")
            for host in sorted(local["compromised_hosts"]):
                print(f"    - {host}")

        passed_checks += 1
    else:
        print(f"  {Fore.RED}[!] No logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
    total_checks += 1

    # Check 2: Wazuh
    print(f"\n{Fore.YELLOW}[2/3] Checking Wazuh alerts...{Style.RESET_ALL}")
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

    # Check 3: Loki
    print(f"\n{Fore.YELLOW}[3/3] Checking Loki logs...{Style.RESET_ALL}")
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
