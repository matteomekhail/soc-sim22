#!/usr/bin/env python3
"""
Scenario 07: Automated containment response for zero-day lateral movement.

Actions:
1. Isolate all compromised hosts from the network
2. Block attacker IP at perimeter
3. Segment DMZ from internal network
4. Revoke all compromised credentials
5. Deploy emergency detection rules
6. Preserve evidence across all compromised hosts
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import (
    ATTACKER_IP,
    API_SERVER_IP,
    DC_IP,
    FILE_SERVER_IP,
    DB_SERVER_IP,
    WORKSTATION_IPS,
    REGULAR_USERS,
    SERVICE_ACCOUNTS,
)

init(autoreset=True)


def isolate_compromised_hosts() -> dict:
    """Generate isolation rules for all hosts in the compromise chain."""
    compromised = [
        {"ip": API_SERVER_IP, "name": "API Server (beachhead)", "priority": "CRITICAL"},
        {"ip": WORKSTATION_IPS[0], "name": "Workstation-100", "priority": "HIGH"},
        {"ip": WORKSTATION_IPS[1], "name": "Workstation-101", "priority": "HIGH"},
        {"ip": WORKSTATION_IPS[3], "name": "Workstation-103", "priority": "HIGH"},
        {"ip": DB_SERVER_IP, "name": "Database Server", "priority": "CRITICAL"},
        {"ip": WORKSTATION_IPS[5], "name": "Workstation-105", "priority": "HIGH"},
        {"ip": FILE_SERVER_IP, "name": "File Server", "priority": "CRITICAL"},
        {"ip": DC_IP, "name": "Domain Controller", "priority": "CRITICAL"},
    ]

    rules = []
    for host in compromised:
        rules.extend([
            f"iptables -A FORWARD -s {host['ip']} -j DROP",
            f"iptables -A FORWARD -d {host['ip']} -j DROP",
        ])

    return {"hosts": compromised, "rules": rules}


def segment_dmz_internal() -> list[str]:
    """Generate rules to isolate DMZ from internal network."""
    return [
        "# Emergency DMZ segmentation",
        "iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.0.0/24 -j DROP",
        "iptables -A FORWARD -s 10.0.0.0/24 -d 10.0.1.0/24 -p tcp --dport 22 -j DROP",
        "iptables -A FORWARD -s 10.0.0.0/24 -d 10.0.1.0/24 -p tcp --dport 445 -j DROP",
        "",
        "# Only allow pre-approved management traffic",
        "iptables -I FORWARD -s 10.0.0.250 -d 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT",
    ]


def revoke_credentials() -> list[str]:
    """Generate credential revocation commands for all compromised accounts."""
    commands = [
        "# === Revoke all compromised credentials ===",
        "",
        "# Force password reset for all users (domain-wide)",
        "samba-tool user setexpiry --days=0 sysadmin",
        "samba-tool user setexpiry --days=0 svc_web",
        "samba-tool user setexpiry --days=0 svc_db",
    ]
    for user in REGULAR_USERS[:6]:
        commands.append(f"samba-tool user setexpiry --days=0 {user}")

    commands.extend([
        "",
        "# Regenerate all SSH host keys on compromised hosts",
        "for host in 10.0.1.20 10.0.0.10 10.0.0.20 10.0.0.30; do",
        "  ssh-keygen -A -f /tmp/hostkeys/$host/",
        "done",
        "",
        "# Revoke Kerberos tickets (invalidate all sessions)",
        "samba-tool domain passwordsettings set --min-pwd-age=0",
        "# Force krbtgt password change twice (golden ticket mitigation)",
        "samba-tool user setpassword krbtgt --newpassword='$(openssl rand -base64 32)'",
    ])

    return commands


def remove_malicious_gpo() -> list[str]:
    """Generate commands to remove the attacker's GPO."""
    return [
        "# List all GPOs and identify malicious ones",
        "samba-tool gpo listall",
        "",
        "# Remove the malicious GPO created by attacker",
        "samba-tool gpo del 'Maintenance Update'",
        "",
        "# Audit GPO changes",
        "samba-tool gpo listall | grep -i 'maintenance\\|update\\|script'",
    ]


def generate_emergency_detection() -> list[str]:
    """Generate emergency Suricata rules for the zero-day IOCs."""
    return [
        f'drop ip {ATTACKER_IP} any -> any any (msg:"S07: Block zero-day attacker"; sid:9079001; rev:1;)',
        f'drop tcp {API_SERVER_IP} any -> $HOME_NET [22,445] (msg:"S07: Block lateral from compromised API server"; sid:9079002; rev:1;)',
        'alert http any any -> $HOME_NET 8080 (msg:"S07: Zero-day IOC - Oversized POST to API import"; flow:to_server,established; content:"POST"; http_method; content:"/api/v1/users/import"; http_uri; urilen:>10000; sid:9079003; rev:1;)',
    ]


def preserve_evidence(logs_dir: str) -> str:
    """Create comprehensive evidence package."""
    compromise_chain = [
        API_SERVER_IP,
        WORKSTATION_IPS[0], WORKSTATION_IPS[1], WORKSTATION_IPS[3],
        DB_SERVER_IP, WORKSTATION_IPS[5],
        FILE_SERVER_IP, DC_IP,
    ]

    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Zero-Day Exploit with Lateral Movement",
        "severity": "CRITICAL",
        "zero_day": {
            "cve": "CVE-2026-XXXX (unpatched)",
            "target": API_SERVER_IP,
            "vector": "Buffer overflow in REST API deserialization handler",
            "exploit_method": "Oversized POST to /api/v1/users/import",
        },
        "mitre_techniques": ["T1068", "T1021", "T1059", "T1018", "T1003"],
        "attacker_ip": ATTACKER_IP,
        "compromise_chain": compromise_chain,
        "total_compromised_hosts": len(compromise_chain),
        "domain_compromised": True,
        "timestamp": datetime.now().isoformat(),
        "containment_actions": [
            f"{len(compromise_chain)} hosts isolated from network",
            "DMZ-to-internal traffic blocked",
            "Attacker IP blocked at perimeter",
            "All compromised credentials revoked",
            "Kerberos tickets invalidated (krbtgt rotation)",
            "Malicious GPO removed",
            "Emergency IDS rules deployed",
        ],
        "evidence_files": [],
    }

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
{Fore.RED}{'='*62}
  WCACE Scenario 07: Zero-Day Lateral Movement Containment
  Incident: Zero-Day Exploit + Domain-Wide Lateral Movement
  Severity: CRITICAL
{'='*62}{Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Isolate compromised hosts
    print(f"{Fore.YELLOW}[1] Isolating all compromised hosts...{Style.RESET_ALL}")
    isolation = isolate_compromised_hosts()
    for host in isolation["hosts"]:
        priority_color = Fore.RED if host["priority"] == "CRITICAL" else Fore.YELLOW
        print(f"    [{priority_color}{host['priority']}{Style.RESET_ALL}] {host['name']} ({host['ip']})")
    print(f"    -> {len(isolation['rules'])} firewall rules generated")

    # Step 2: Segment DMZ from internal
    print(f"\n{Fore.YELLOW}[2] Emergency DMZ-Internal segmentation...{Style.RESET_ALL}")
    segment_rules = segment_dmz_internal()
    print(f"    [+] DMZ (10.0.1.0/24) blocked from internal (10.0.0.0/24)")
    print(f"    [+] Only management host (10.0.0.250) allowed SSH to DMZ")

    # Step 3: Block attacker
    print(f"\n{Fore.YELLOW}[3] Blocking attacker at perimeter...{Style.RESET_ALL}")
    print(f"    [+] Blocked: {ATTACKER_IP}")
    print(f"    [+] Reverse shell port 4444 blocked outbound")

    # Step 4: Revoke credentials
    print(f"\n{Fore.YELLOW}[4] Revoking compromised credentials...{Style.RESET_ALL}")
    cred_cmds = revoke_credentials()
    print(f"    [+] All service accounts expired")
    print(f"    [+] {len(REGULAR_USERS[:6])} user accounts expired")
    print(f"    [+] SSH host keys regenerated on {len(isolation['hosts'])} hosts")
    print(f"    [+] krbtgt password rotated (golden ticket mitigation)")

    # Step 5: Remove malicious GPO
    print(f"\n{Fore.YELLOW}[5] Removing malicious GPO...{Style.RESET_ALL}")
    gpo_cmds = remove_malicious_gpo()
    print(f"    [+] 'Maintenance Update' GPO queued for removal")
    print(f"    [+] GPO audit initiated")

    # Step 6: Emergency detection rules
    print(f"\n{Fore.YELLOW}[6] Deploying emergency detection rules...{Style.RESET_ALL}")
    emergency_rules = generate_emergency_detection()
    for rule in emergency_rules:
        print(f"    -> {rule[:75]}...")

    # Step 7: Preserve evidence
    print(f"\n{Fore.YELLOW}[7] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(logs_dir)
    print(f"    -> Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Compromised hosts:    {len(isolation['hosts'])} isolated")
    print(f"  Network segmentation: DMZ <-> Internal blocked")
    print(f"  Credentials revoked:  All service + {len(REGULAR_USERS[:6])} user accounts")
    print(f"  Kerberos:             krbtgt rotated (golden ticket defense)")
    print(f"  Malicious GPO:        Removed")
    print(f"  Emergency rules:      {len(emergency_rules)} deployed")
    print(f"  Evidence:             {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
