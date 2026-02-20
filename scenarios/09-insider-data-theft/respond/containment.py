#!/usr/bin/env python3
"""Scenario 9: Automated containment for insider data theft."""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import INSIDER_USER, WORKSTATION_IPS

init(autoreset=True)


def main():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 9: Insider Data Theft Containment       ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    insider_ip = WORKSTATION_IPS[3]
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Network isolation
    print(f"{Fore.YELLOW}[1] Network Isolation{Style.RESET_ALL}")
    print(f"  → Block outbound: iptables -A OUTPUT -s {insider_ip} -j DROP")
    print(f"  → Except monitoring: iptables -I OUTPUT -s {insider_ip} -d 172.25.0.0/24 -j ACCEPT")

    # Step 2: Revoke access
    print(f"\n{Fore.YELLOW}[2] Access Revocation{Style.RESET_ALL}")
    print(f"  → Disable AD account: net user {INSIDER_USER} /active:no /domain")
    print(f"  → Revoke DB access: REVOKE ALL ON production_crm FROM '{INSIDER_USER}'")
    print(f"  → Disable VPN certificate for {INSIDER_USER}")

    # Step 3: Forensic preservation
    print(f"\n{Fore.YELLOW}[3] Forensic Preservation{Style.RESET_ALL}")
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Insider Data Theft",
        "suspect": INSIDER_USER,
        "suspect_ip": insider_ip,
        "timestamp": datetime.now().isoformat(),
        "actions_taken": [
            "Network isolation applied",
            "Database access revoked",
            "VPN access disabled",
            "Disk snapshot initiated",
        ],
        "data_at_risk": [
            "Customer PII (SSN, DOB)",
            "Payment card data",
            "Employee salary records",
            "Admin credentials",
        ],
    }
    os.makedirs(logs_dir, exist_ok=True)
    evidence_file = os.path.join(logs_dir, "insider_incident_evidence.json")
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"  → Evidence saved: {evidence_file}")

    # Step 4: Enhanced monitoring
    print(f"\n{Fore.YELLOW}[4] Enhanced Monitoring{Style.RESET_ALL}")
    print(f"  → Enable packet capture on {insider_ip}")
    print(f"  → Flag all accounts associated with {INSIDER_USER}")
    print(f"  → Monitor for lateral credential use")

    print(f"\n{Fore.GREEN}Containment actions complete. See respond/playbook.md for next steps.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
