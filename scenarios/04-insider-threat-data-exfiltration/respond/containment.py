#!/usr/bin/env python3
"""
Scenario 04: Automated containment response for insider threat data exfiltration.

Actions:
1. Disable insider's user account (AD/LDAP)
2. Revoke VPN access
3. Block exfiltration destination at firewall
4. Preserve forensic evidence
5. Generate incident report
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import (
    INSIDER_USER,
    ATTACKER_IP,
    FILE_SERVER_IP,
    VPN_SERVER_IP,
    DC_IP,
    COMPANY_DOMAIN,
)

init(autoreset=True)

LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")
INSIDER_WORKSTATION = "10.0.0.102"


def disable_user_account(user: str) -> list[str]:
    """Generate commands to disable the insider's Active Directory account.

    In a real environment, these would execute against the domain controller.
    Here we generate the commands for manual execution or playbook integration.
    """
    commands = [
        # Windows AD (PowerShell)
        f'Disable-ADAccount -Identity "{user}"',
        f'Set-ADUser -Identity "{user}" -Description "DISABLED - Security Incident {{incident_id}} - {{timestamp}}"',
        # Reset password to prevent cached credential usage
        f'Set-ADAccountPassword -Identity "{user}" -Reset -NewPassword (ConvertTo-SecureString "R4nd0m!Tmp#{datetime.now().strftime("%H%M%S")}" -AsPlainText -Force)',
        # Linux/LDAP alternative
        f"usermod -L {user}",
        f"passwd -l {user}",
    ]
    return commands


def revoke_vpn_access(user: str) -> list[str]:
    """Generate commands to revoke VPN access for the insider."""
    commands = [
        # Terminate active VPN sessions
        f"# Disconnect active VPN session for {user}",
        f'ovpn-disconnect --user "{user}" --server {VPN_SERVER_IP}',
        # Revoke VPN certificate
        f'ovpn-revoke-cert --user "{user}" --crl-update',
        # Block at firewall level
        f"iptables -A INPUT -s {INSIDER_WORKSTATION} -d {VPN_SERVER_IP} -j DROP",
        # Remove from VPN allowed group
        f'Remove-ADGroupMember -Identity "VPN-Users" -Members "{user}" -Confirm:$false',
    ]
    return commands


def block_exfil_destination(dst_ip: str) -> list[str]:
    """Generate firewall rules to block the exfiltration destination."""
    commands = [
        # Block outbound to exfil destination
        f"iptables -A OUTPUT -d {dst_ip} -j DROP",
        f"iptables -A FORWARD -d {dst_ip} -j DROP",
        # Suricata drop rule
        f'drop ip any any -> {dst_ip} any (msg:"WCACE: Block insider exfil destination {dst_ip}"; sid:9999004; rev:1;)',
        # DNS sinkhole for associated domain
        f"# Add to DNS sinkhole: storage.cloud-backup-service.test -> 127.0.0.1",
    ]
    return commands


def isolate_workstation(workstation_ip: str) -> list[str]:
    """Generate commands to network-isolate the insider's workstation."""
    commands = [
        # Block all traffic except to forensic collection server
        f"iptables -A FORWARD -s {workstation_ip} -j DROP",
        f"iptables -A FORWARD -d {workstation_ip} -j DROP",
        # Allow only forensic collection
        f"iptables -I FORWARD -s {workstation_ip} -d 10.0.0.250 -j ACCEPT",
        # VLAN reassignment (switch command)
        f"# Switch: Move port for {workstation_ip} to quarantine VLAN 999",
    ]
    return commands


def preserve_evidence(user: str, dst_ip: str) -> str:
    """Create forensic evidence package."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "incident_type": "Insider Threat - Data Exfiltration",
        "classification": "CRITICAL",
        "timestamp": datetime.now().isoformat(),
        "insider": {
            "username": user,
            "workstation_ip": INSIDER_WORKSTATION,
            "domain": COMPANY_DOMAIN,
        },
        "exfiltration": {
            "destination_ip": dst_ip,
            "protocol": "HTTPS",
            "port": 443,
        },
        "affected_systems": [
            {"host": FILE_SERVER_IP, "role": "File Server", "data_accessed": "HR, Finance, Executive shares"},
            {"host": VPN_SERVER_IP, "role": "VPN Server", "note": "After-hours connection"},
            {"host": INSIDER_WORKSTATION, "role": "Insider Workstation", "note": "Data staging location"},
        ],
        "containment_actions": [
            f"User account '{user}' disabled in Active Directory",
            "VPN access revoked and certificate invalidated",
            f"Exfiltration destination {dst_ip} blocked at firewall",
            f"Workstation {INSIDER_WORKSTATION} network-isolated",
            "File server access logs preserved",
            "Network flow data exported for analysis",
        ],
        "evidence_files": [],
        "data_at_risk": [
            "HR employee records (salaries, personal info, performance reviews)",
            "Finance documents (quarterly earnings, bank details, vendor contracts)",
            "Executive strategy documents (acquisition targets, board presentations)",
        ],
        "forensic_notes": [
            "Check /tmp on workstation for residual staging artifacts",
            "Review bash_history for compression commands",
            "Examine browser history for cloud storage uploads",
            "Check for any USB device connections during incident window",
            "Review email/chat for data sharing with external parties",
        ],
    }

    # List available log files as evidence
    if os.path.exists(LOGS_DIR):
        for f in os.listdir(LOGS_DIR):
            evidence["evidence_files"].append(os.path.join(LOGS_DIR, f))

    evidence_file = os.path.join(LOGS_DIR, "incident_evidence.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)

    return evidence_file


def main():
    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 04: Insider Threat Containment Response
  Insider:    {INSIDER_USER} ({INSIDER_WORKSTATION})
  Exfil Dest: {ATTACKER_IP}
{'='*62}{Style.RESET_ALL}
""")

    # Step 1: Disable user account
    print(f"{Fore.YELLOW}[1/5] Disabling insider user account...{Style.RESET_ALL}")
    ad_commands = disable_user_account(INSIDER_USER)
    for cmd in ad_commands:
        print(f"  -> {cmd}")
    print(f"  {Fore.GREEN}Account disable commands generated{Style.RESET_ALL}")

    # Step 2: Revoke VPN access
    print(f"\n{Fore.YELLOW}[2/5] Revoking VPN access...{Style.RESET_ALL}")
    vpn_commands = revoke_vpn_access(INSIDER_USER)
    for cmd in vpn_commands:
        print(f"  -> {cmd}")
    print(f"  {Fore.GREEN}VPN revocation commands generated{Style.RESET_ALL}")

    # Step 3: Block exfiltration destination
    print(f"\n{Fore.YELLOW}[3/5] Blocking exfiltration destination...{Style.RESET_ALL}")
    fw_commands = block_exfil_destination(ATTACKER_IP)
    for cmd in fw_commands:
        print(f"  -> {cmd}")
    print(f"  {Fore.GREEN}Firewall block rules generated{Style.RESET_ALL}")

    # Step 4: Isolate workstation
    print(f"\n{Fore.YELLOW}[4/5] Isolating insider workstation...{Style.RESET_ALL}")
    iso_commands = isolate_workstation(INSIDER_WORKSTATION)
    for cmd in iso_commands:
        print(f"  -> {cmd}")
    print(f"  {Fore.GREEN}Network isolation commands generated{Style.RESET_ALL}")

    # Step 5: Preserve evidence
    print(f"\n{Fore.YELLOW}[5/5] Preserving forensic evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(INSIDER_USER, ATTACKER_IP)
    print(f"  -> Evidence package saved to: {evidence_path}")

    # Step 6: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[*] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  Connected to Wazuh - active response available")
            print(f"  Would trigger: firewall-drop for {ATTACKER_IP}")
            print(f"  Would trigger: disable-account for {INSIDER_USER}")
        else:
            print(f"  Wazuh not available - execute commands manually")
    except Exception:
        print(f"  Wazuh not available - execute commands manually")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Insider:         {INSIDER_USER} - ACCOUNT DISABLED")
    print(f"  VPN:             Access REVOKED")
    print(f"  Firewall:        {ATTACKER_IP} BLOCKED (outbound)")
    print(f"  Workstation:     {INSIDER_WORKSTATION} ISOLATED")
    print(f"  Evidence:        {evidence_path}")
    print(f"\n  IMPORTANT: Review respond/playbook.md for full IR procedure")
    print(f"  IMPORTANT: Notify Legal, HR, and Management per policy")
    print(f"  IMPORTANT: Do NOT alert the insider until instructed by Legal")


if __name__ == "__main__":
    main()
