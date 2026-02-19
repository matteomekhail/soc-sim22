#!/usr/bin/env python3
"""
Scenario 13: Automated containment response for SQL injection attacks.

Actions:
1. Block attacker IP via Wazuh active response
2. Generate firewall rules
3. Alert SOC team
4. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IP

init(autoreset=True)


def block_ip_firewall(ip: str) -> str:
    """Generate firewall block rule."""
    return f"iptables -A INPUT -s {ip} -j DROP"


def generate_suricata_drop_rule(ip: str, sid: int = 9999001) -> str:
    """Generate Suricata drop rule for attacker."""
    return (f'drop http {ip} any -> $SQL_SERVERS any '
            f'(msg:"WCACE: Block SQLi attacker {ip}"; sid:{sid}; rev:1;)')


def preserve_evidence(attacker_ip: str, logs_dir: str) -> str:
    """Create evidence package."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "SQL Injection Attack",
        "attacker_ip": attacker_ip,
        "timestamp": datetime.now().isoformat(),
        "containment_actions": [
            f"Firewall rule: {block_ip_firewall(attacker_ip)}",
            f"Suricata drop rule generated",
            "Application endpoint rate-limited",
        ],
        "evidence_files": [],
    }

    # List available log files
    if os.path.exists(logs_dir):
        for f in os.listdir(logs_dir):
            evidence["evidence_files"].append(os.path.join(logs_dir, f))

    evidence_file = os.path.join(logs_dir, "incident_evidence.json")
    os.makedirs(logs_dir, exist_ok=True)
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)

    return evidence_file


def main():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 13: SQL Injection Containment Response  ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    attacker_ip = ATTACKER_IP
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Generate firewall rules
    print(f"{Fore.YELLOW}[1] Generating firewall block rules...{Style.RESET_ALL}")
    fw_rule = block_ip_firewall(attacker_ip)
    print(f"  → {fw_rule}")

    # Step 2: Generate Suricata drop rule
    print(f"\n{Fore.YELLOW}[2] Generating Suricata drop rule...{Style.RESET_ALL}")
    suricata_rule = generate_suricata_drop_rule(attacker_ip)
    print(f"  → {suricata_rule}")

    # Step 3: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[3] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  ✓ Wazuh connected - active response would block {attacker_ip}")
        else:
            print(f"  ⚠ Wazuh not available - manual block required")
    except Exception:
        print(f"  ⚠ Wazuh not available - manual block required")

    # Step 4: Preserve evidence
    print(f"\n{Fore.YELLOW}[4] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(attacker_ip, logs_dir)
    print(f"  → Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"Containment Actions Summary")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  Attacker IP:     {attacker_ip}")
    print(f"  Firewall:        Rule generated (apply manually)")
    print(f"  Suricata:        Drop rule generated")
    print(f"  Evidence:        {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
