#!/usr/bin/env python3
"""
Scenario 10: Automated containment response for APT Remote Access Trojan.

Actions:
1. Kill RAT process on victim workstation
2. Remove RAT persistence mechanisms
3. Block C2 server at firewall and DNS
4. Quarantine victim workstation
5. Reset compromised credentials
6. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import (
    C2_SERVER_IP,
    C2_DOMAIN,
    WORKSTATION_IPS,
    REGULAR_USERS,
)

init(autoreset=True)

VICTIM_IP = WORKSTATION_IPS[4]  # 10.0.0.104
VICTIM_USER = REGULAR_USERS[4]  # carlos.garcia


def kill_rat_process() -> list[str]:
    """Generate commands to find and kill the RAT process."""
    return [
        "# Find RAT process",
        f"ps aux | grep -i 'sys_update\\|system_update' | grep -v grep",
        f"pgrep -f 'sys_update'",
        "",
        "# Kill RAT process and all children",
        f"pkill -9 -f 'sys_update'",
        f"pkill -9 -f '.local/share/.sys_update'",
        "",
        "# Verify process is dead",
        f"ps aux | grep -i 'sys_update' | grep -v grep",
    ]


def remove_persistence() -> list[str]:
    """Generate commands to remove RAT persistence mechanisms."""
    return [
        "# Remove RAT files",
        f"rm -rf /home/{VICTIM_USER}/.local/share/.sys_update/",
        "",
        "# Remove crontab persistence",
        f"crontab -u {VICTIM_USER} -l | grep -v 'sys_update' | crontab -u {VICTIM_USER} -",
        "",
        "# Remove .bashrc modification",
        f"sed -i '/sys_update/d' /home/{VICTIM_USER}/.bashrc",
        f"sed -i '/nohup.*sys_update/d' /home/{VICTIM_USER}/.bashrc",
        "",
        "# Check for other persistence",
        f"find /home/{VICTIM_USER} -name '*.py' -newer /home/{VICTIM_USER}/.bashrc",
        f"ls -la /home/{VICTIM_USER}/.config/autostart/",
        f"systemctl list-unit-files | grep -i update",
    ]


def block_c2_infrastructure() -> list[str]:
    """Generate rules to block C2 server and domain."""
    return [
        f"# Block C2 server IP",
        f"iptables -A OUTPUT -d {C2_SERVER_IP} -j DROP",
        f"iptables -A INPUT -s {C2_SERVER_IP} -j DROP",
        f"iptables -A FORWARD -d {C2_SERVER_IP} -j DROP",
        "",
        f"# Block C2 domain via DNS",
        f"echo '127.0.0.1 {C2_DOMAIN}' >> /etc/hosts",
        f"echo '{C2_DOMAIN}' >> /etc/pihole/blacklist.txt",
        "",
        f"# Suricata drop rule",
        f'drop ip any any -> {C2_SERVER_IP} any (msg:"WCACE S10: Block RAT C2 server"; sid:9109001; rev:1;)',
    ]


def quarantine_workstation() -> list[str]:
    """Generate rules to quarantine the victim workstation."""
    return [
        f"# Isolate victim workstation from network",
        f"iptables -A FORWARD -s {VICTIM_IP} -j DROP",
        f"iptables -A FORWARD -d {VICTIM_IP} -j DROP",
        "",
        f"# Allow only management access (for forensics)",
        f"iptables -I FORWARD -s 10.0.0.250 -d {VICTIM_IP} -p tcp --dport 22 -j ACCEPT",
        "",
        f"# Disable network shares access",
        f"iptables -A OUTPUT -s {VICTIM_IP} -p tcp --dport 445 -j DROP",
    ]


def reset_credentials() -> list[str]:
    """Generate credential reset commands."""
    return [
        f"# Force password reset for victim user",
        f"passwd --expire {VICTIM_USER}",
        "",
        f"# Regenerate SSH keys",
        f"rm -f /home/{VICTIM_USER}/.ssh/id_rsa /home/{VICTIM_USER}/.ssh/id_rsa.pub",
        f"su - {VICTIM_USER} -c 'ssh-keygen -t ed25519 -N \"\" -f ~/.ssh/id_rsa'",
        "",
        f"# Revoke any tokens/sessions",
        f"# Application-specific: revoke all active sessions for {VICTIM_USER}",
        "",
        f"# Clear browser saved passwords (may have been exfiltrated)",
        f"rm -rf /home/{VICTIM_USER}/.config/chromium/Default/'Login Data'",
        f"rm -rf /home/{VICTIM_USER}/.mozilla/firefox/*/logins.json",
    ]


def preserve_evidence(logs_dir: str) -> str:
    """Create evidence package for the incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "APT Remote Access Trojan",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1219", "T1071", "T1059", "T1053", "T1041"],
        "victim": {
            "user": VICTIM_USER,
            "ip": VICTIM_IP,
            "delivery_method": "Phishing email with trojanized .xlsm",
        },
        "c2": {
            "server_ip": C2_SERVER_IP,
            "domain": C2_DOMAIN,
            "beacon_interval": "~60 seconds",
            "protocol": "HTTPS",
        },
        "rat_details": {
            "type": "Python-based RAT",
            "install_path": f"/home/{VICTIM_USER}/.local/share/.sys_update/system_update.py",
            "persistence": ["crontab @reboot", ".bashrc modification"],
            "capabilities": ["command execution", "keylogging", "screenshot", "file harvest", "exfiltration"],
        },
        "data_compromised": [
            "Keystrokes captured",
            "Screenshots taken",
            "Documents from ~/Documents/",
            "SSH private key",
            "Browser saved credentials",
        ],
        "timestamp": datetime.now().isoformat(),
        "containment_actions": [
            "RAT process killed",
            "Persistence mechanisms removed",
            "C2 server blocked (firewall + DNS)",
            "Victim workstation quarantined",
            "Credentials reset",
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
  WCACE Scenario 10: APT RAT Containment Response
  Incident: Remote Access Trojan on {VICTIM_USER}'s workstation
  Severity: CRITICAL
{'='*62}{Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Kill RAT process
    print(f"{Fore.YELLOW}[1] Killing RAT process...{Style.RESET_ALL}")
    kill_cmds = kill_rat_process()
    print(f"    [+] RAT process kill commands generated")
    print(f"    [+] Target: python3 .sys_update/system_update.py")

    # Step 2: Remove persistence
    print(f"\n{Fore.YELLOW}[2] Removing RAT persistence mechanisms...{Style.RESET_ALL}")
    persist_cmds = remove_persistence()
    print(f"    [+] RAT files: /home/{VICTIM_USER}/.local/share/.sys_update/")
    print(f"    [+] Crontab: @reboot entry removed")
    print(f"    [+] .bashrc: malicious line removed")

    # Step 3: Block C2
    print(f"\n{Fore.YELLOW}[3] Blocking C2 infrastructure...{Style.RESET_ALL}")
    c2_rules = block_c2_infrastructure()
    print(f"    [+] C2 IP blocked: {C2_SERVER_IP}")
    print(f"    [+] C2 domain blocked: {C2_DOMAIN}")
    print(f"    [+] Suricata drop rule deployed")

    # Step 4: Quarantine workstation
    print(f"\n{Fore.YELLOW}[4] Quarantining victim workstation...{Style.RESET_ALL}")
    quarantine_rules = quarantine_workstation()
    print(f"    [+] Workstation isolated: {VICTIM_IP}")
    print(f"    [+] Management access preserved (10.0.0.250)")

    # Step 5: Reset credentials
    print(f"\n{Fore.YELLOW}[5] Resetting compromised credentials...{Style.RESET_ALL}")
    cred_cmds = reset_credentials()
    print(f"    [+] Password expired: {VICTIM_USER}")
    print(f"    [+] SSH keys regenerated")
    print(f"    [+] Browser saved passwords cleared")

    # Step 6: Preserve evidence
    print(f"\n{Fore.YELLOW}[6] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(logs_dir)
    print(f"    -> Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  RAT process:        Killed")
    print(f"  Persistence:        Crontab + .bashrc cleaned")
    print(f"  C2 blocked:         {C2_SERVER_IP} + {C2_DOMAIN}")
    print(f"  Workstation:        {VICTIM_IP} quarantined")
    print(f"  Credentials:        {VICTIM_USER} password + SSH keys reset")
    print(f"  Evidence:           {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
