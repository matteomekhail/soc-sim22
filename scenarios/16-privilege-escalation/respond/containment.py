#!/usr/bin/env python3
"""
Scenario 16: Automated containment response for privilege escalation attacks.

Actions:
1. Kill attacker SSH sessions
2. Remove backdoor user account
3. Audit and fix SUID binary permissions
4. Block attacker IP at firewall
5. Generate Suricata drop rules
6. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IP, ATTACKER_IPS

init(autoreset=True)

BACKDOOR_USER = "svc_support"
SUID_BINARIES_TO_FIX = [
    "/usr/bin/find",
    "/usr/bin/vim.basic",
    "/usr/bin/nmap",
    "/usr/bin/python3",
    "/usr/bin/env",
]


def kill_attacker_sessions(attacker_ip: str, attacker_user: str) -> list[str]:
    """Generate commands to kill attacker SSH sessions."""
    return [
        f"# Kill all SSH sessions from attacker IP",
        f"ss -K dst {attacker_ip}",
        f"# Kill all processes owned by attacker user",
        f"pkill -u {attacker_user}",
        f"# Kill any root shell spawned via SUID",
        f"pkill -f '/bin/sh -p'",
        f"# Terminate specific PTY sessions",
        f"who | grep {attacker_user} | awk '{{print $2}}' | xargs -I{{}} pkill -t {{}}",
    ]


def remove_backdoor_account(user: str) -> list[str]:
    """Generate commands to remove the backdoor account."""
    return [
        f"# Lock the backdoor account immediately",
        f"usermod -L {user}",
        f"# Expire the account",
        f"chage -E 0 {user}",
        f"# Remove SSH authorized keys",
        f"rm -f /home/{user}/.ssh/authorized_keys",
        f"# Remove sudoers entry",
        f"rm -f /etc/sudoers.d/{user}",
        f"# Delete the user account and home directory",
        f"userdel -r {user}",
        f"# Verify removal",
        f"id {user} 2>&1 || echo 'Account successfully removed'",
    ]


def audit_suid_binaries(binaries: list[str]) -> list[str]:
    """Generate commands to audit and fix SUID binary permissions."""
    commands = [
        "# Audit all SUID binaries on the system",
        "find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null",
        "",
        "# Fix misconfigured SUID binaries:",
    ]
    for binary in binaries:
        commands.append(f"chmod u-s {binary}  # Remove SUID from {binary}")
    commands.extend([
        "",
        "# Verify SUID bits removed",
        "find / -perm -4000 -type f 2>/dev/null | sort",
    ])
    return commands


def generate_firewall_rules(attacker_ip: str) -> list[str]:
    """Generate firewall rules to block attacker."""
    return [
        f"# Block attacker IP",
        f"iptables -A INPUT -s {attacker_ip} -j DROP",
        f"iptables -A OUTPUT -d {attacker_ip} -j DROP",
        f"# Block common reverse shell ports",
        f"iptables -A OUTPUT -p tcp --dport 4444:4450 -j DROP",
        f"# Log and drop suspicious outbound connections",
        f"iptables -A OUTPUT -p tcp --dport 4444 -j LOG --log-prefix 'WCACE-REVSHELL: '",
    ]


def generate_suricata_drop_rules(attacker_ip: str) -> list[str]:
    """Generate Suricata drop rules for containment."""
    return [
        f'drop ip {attacker_ip} any -> $HOME_NET any '
        f'(msg:"WCACE S16: Block privilege escalation attacker"; '
        f'sid:9169001; rev:1;)',
        f'drop tcp $HOME_NET any -> any 4444:4450 '
        f'(msg:"WCACE S16: Block reverse shell connections"; '
        f'sid:9169002; rev:1;)',
    ]


def generate_pam_hardening() -> list[str]:
    """Generate PAM configuration hardening recommendations."""
    return [
        "# /etc/security/limits.conf - limit su access",
        "* hard maxlogins 3",
        "",
        "# /etc/pam.d/su - restrict su to wheel group",
        "auth required pam_wheel.so use_uid",
        "",
        "# /etc/pam.d/sudo - add delay after failed attempts",
        "auth required pam_faildelay.so delay=4000000",
    ]


def preserve_evidence(attacker_ip: str, logs_dir: str) -> str:
    """Create evidence package for the incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Privilege Escalation Attack",
        "attacker_ip": attacker_ip,
        "attacker_user": "carlos.garcia",
        "backdoor_user": BACKDOOR_USER,
        "timestamp": datetime.now().isoformat(),
        "mitre_techniques": ["T1068", "T1548", "T1136.001"],
        "escalation_method": "SUID binary exploitation (/usr/bin/find)",
        "containment_actions": [
            "Attacker SSH sessions terminated",
            "Backdoor account locked and removed",
            "SUID binary permissions fixed",
            "Firewall rules generated to block attacker",
            "Suricata drop rules generated",
            "PAM hardening recommendations generated",
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
{Fore.RED}+============================================================+
|  WCACE Scenario 16: Privilege Escalation Containment       |
+============================================================+{Style.RESET_ALL}
""")

    attacker_ip = ATTACKER_IP
    attacker_user = "carlos.garcia"
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Kill attacker sessions
    print(f"{Fore.YELLOW}[1/7] Terminating attacker sessions...{Style.RESET_ALL}")
    kill_cmds = kill_attacker_sessions(attacker_ip, attacker_user)
    for cmd in kill_cmds:
        print(f"  {cmd}")

    # Step 2: Remove backdoor account
    print(f"\n{Fore.YELLOW}[2/7] Removing backdoor account '{BACKDOOR_USER}'...{Style.RESET_ALL}")
    remove_cmds = remove_backdoor_account(BACKDOOR_USER)
    for cmd in remove_cmds:
        print(f"  {cmd}")

    # Step 3: Audit SUID binaries
    print(f"\n{Fore.YELLOW}[3/7] Auditing and fixing SUID binaries...{Style.RESET_ALL}")
    suid_cmds = audit_suid_binaries(SUID_BINARIES_TO_FIX)
    for cmd in suid_cmds:
        print(f"  {cmd}")

    # Step 4: Firewall rules
    print(f"\n{Fore.YELLOW}[4/7] Generating firewall block rules...{Style.RESET_ALL}")
    fw_rules = generate_firewall_rules(attacker_ip)
    for rule in fw_rules:
        print(f"  {rule}")

    # Step 5: Suricata drop rules
    print(f"\n{Fore.YELLOW}[5/7] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(attacker_ip)
    for rule in suricata_rules:
        print(f"  {rule[:80]}...")

    # Step 6: PAM hardening
    print(f"\n{Fore.YELLOW}[6/7] Generating PAM hardening recommendations...{Style.RESET_ALL}")
    pam_config = generate_pam_hardening()
    for line in pam_config:
        print(f"  {line}")

    # Step 7: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[7/7] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [+] Wazuh connected - active response would block {attacker_ip}")
        else:
            print(f"  [*] Wazuh not available - manual containment required")
    except Exception:
        print(f"  [*] Wazuh not available - manual containment required")

    # Preserve evidence
    print(f"\n{Fore.YELLOW}[*] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(attacker_ip, logs_dir)
    print(f"  Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Attacker IP:        {attacker_ip}")
    print(f"  Attacker User:      {attacker_user}")
    print(f"  Backdoor Account:   {BACKDOOR_USER} (removal commands generated)")
    print(f"  SUID Binaries:      {len(SUID_BINARIES_TO_FIX)} to fix")
    print(f"  Firewall Rules:     {len(fw_rules)} rules generated")
    print(f"  Suricata Rules:     {len(suricata_rules)} drop rules generated")
    print(f"  PAM Hardening:      Configuration recommendations generated")
    print(f"  Evidence:           {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
