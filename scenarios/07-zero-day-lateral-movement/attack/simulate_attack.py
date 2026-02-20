#!/usr/bin/env python3
"""
Scenario 07: Zero-Day Exploit & Lateral Movement Simulation.

Multi-stage attack that progresses through six phases:
  Phase 1: Zero-day exploit on API server (unknown signature)
  Phase 2: Internal reconnaissance from beachhead
  Phase 3: Credential harvesting
  Phase 4: Lateral movement via SSH (sequential host compromise)
  Phase 5: Lateral movement via SMB (file server and admin shares)
  Phase 6: Domain compromise (DC access and AD data extraction)

Tier 2: Simulated approach with partial implementation.
Generates log sequences showing sequential host compromise patterns.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import (
    ATTACKER_IP,
    API_SERVER_IP,
    DC_IP,
    FILE_SERVER_IP,
    DB_SERVER_IP,
    WORKSTATION_IPS,
    ADMIN_USERS,
    REGULAR_USERS,
    SERVICE_ACCOUNTS,
    SSH_PORT,
    SMB_PORT,
    API_PORT,
    HTTP_PORT,
    COMPANY_DOMAIN,
    MITRE,
)

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Initial compromise target (API server in DMZ)
BEACHHEAD_IP = API_SERVER_IP  # 10.0.1.20

# Lateral movement targets (sequential compromise order)
LATERAL_SSH_TARGETS = [
    {"ip": WORKSTATION_IPS[0], "name": "Workstation-100", "user": REGULAR_USERS[0]},
    {"ip": WORKSTATION_IPS[1], "name": "Workstation-101", "user": REGULAR_USERS[1]},
    {"ip": WORKSTATION_IPS[3], "name": "Workstation-103", "user": REGULAR_USERS[3]},
    {"ip": DB_SERVER_IP, "name": "Database Server", "user": SERVICE_ACCOUNTS[3]},
    {"ip": WORKSTATION_IPS[5], "name": "Workstation-105", "user": REGULAR_USERS[5]},
]

LATERAL_SMB_TARGETS = [
    {"ip": FILE_SERVER_IP, "name": "File Server", "shares": ["C$", "ADMIN$", "shared"]},
    {"ip": DC_IP, "name": "Domain Controller", "shares": ["SYSVOL", "NETLOGON", "C$"]},
]

# Zero-day exploit details (fictitious)
ZERO_DAY_CVE = "CVE-2026-XXXX"
ZERO_DAY_DESC = "Buffer overflow in custom REST API deserialization handler"


def banner():
    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 07: Zero-Day Exploit & Lateral Movement
  Attacker:   {ATTACKER_IP} (external)
  Beachhead:  {BEACHHEAD_IP} (API server)
  Zero-Day:   {ZERO_DAY_CVE} ({ZERO_DAY_DESC[:40]}...)
  MITRE:      T1068 (Priv Esc Exploit), T1021 (Remote Services)
  WARNING: Educational simulation only
{'='*62}{Style.RESET_ALL}
""")


def phase_1_zero_day_exploit(log_gen: LogGenerator) -> list[str]:
    """Phase 1: Zero-day exploit against the API server.

    A crafted HTTP request triggers a buffer overflow in the API server's
    deserialization handler. No existing IDS signature matches this attack.
    The exploit spawns a reverse shell as the service account.
    """
    print(f"{Fore.CYAN}[Phase 1] Zero-Day Exploit ({ZERO_DAY_CVE}){Style.RESET_ALL}")
    print(f"  Target:  {BEACHHEAD_IP} (API server, port {API_PORT})")
    print(f"  Vector:  Buffer overflow in REST API deserialization")
    logs = []

    log_gen._base_time = datetime.now().replace(hour=3, minute=42, second=0)

    # Normal-looking API requests (blending in)
    normal_paths = ["/api/v1/users", "/api/v1/status", "/api/v1/products",
                    "/api/v1/health", "/api/v1/auth/token"]
    for path in normal_paths:
        logs.append(log_gen.web_access_log(
            ATTACKER_IP, "GET", path, 200,
            user_agent="python-requests/2.28.1"
        ))
        log_gen.advance_time(random.randint(2, 5))

    print(f"  [+] Normal API requests sent ({len(normal_paths)} endpoints)")

    # The zero-day exploit request (oversized POST with crafted payload)
    log_gen.advance_time(10)
    logs.append(log_gen.web_access_log(
        ATTACKER_IP, "POST", "/api/v1/users/import", 500,
        user_agent="python-requests/2.28.1"
    ))
    logs.append(log_gen.json_log("web_access", {
        "src_ip": ATTACKER_IP,
        "method": "POST",
        "path": "/api/v1/users/import",
        "status_code": 500,
        "content_length": 65536,
        "content_type": "application/json",
        "user_agent": "python-requests/2.28.1",
        "response_time_ms": 15234,
        "error": "Internal Server Error",
    }, severity="critical"))

    # Application crash/segfault
    logs.append(log_gen.syslog(
        "segfault at 0x41414141 ip 0x7f8a3c2d4e00 sp 0x7ffe9c3b1a80 error 14 in api-server[400000+8a000]",
        severity="critical", facility="kern", host=BEACHHEAD_IP
    ))
    logs.append(log_gen.json_log("application_crash", {
        "host": BEACHHEAD_IP,
        "process": "api-server",
        "pid": 2847,
        "signal": "SIGSEGV",
        "fault_address": "0x41414141",
        "core_dumped": True,
    }, severity="critical"))

    print(f"  [!] Exploit sent: oversized POST to /api/v1/users/import")
    print(f"  [!] API server crashed (SIGSEGV at 0x41414141)")

    # Exploit succeeds - reverse shell spawned
    log_gen.advance_time(3)
    logs.append(log_gen.json_log("process_execution", {
        "host": BEACHHEAD_IP,
        "user": "svc_web",
        "command": "/bin/bash -i",
        "parent_process": "api-server",
        "pid": random.randint(10000, 30000),
        "ppid": 2847,
    }, severity="critical"))

    # Outbound connection (reverse shell)
    logs.append(log_gen.firewall_log(
        BEACHHEAD_IP, ATTACKER_IP,
        random.randint(40000, 65535), 4444,
        action="allow", protocol="TCP"
    ))
    logs.append(log_gen.json_log("network_connection", {
        "host": BEACHHEAD_IP,
        "process": "bash",
        "src_ip": BEACHHEAD_IP,
        "dst_ip": ATTACKER_IP,
        "dst_port": 4444,
        "direction": "outbound",
        "state": "ESTABLISHED",
    }, severity="critical"))

    print(f"  [!] Reverse shell established: {BEACHHEAD_IP} -> {ATTACKER_IP}:4444")
    print(f"  [{Fore.RED}ZERO-DAY{Style.RESET_ALL}] Initial compromise via unknown vulnerability\n")

    return logs


def phase_2_internal_recon(log_gen: LogGenerator) -> list[str]:
    """Phase 2: Internal reconnaissance from the compromised API server.

    The attacker discovers the internal network topology by running
    ARP scans, internal port scans, and service enumeration.
    """
    print(f"{Fore.YELLOW}[Phase 2] Internal Network Reconnaissance{Style.RESET_ALL}")
    print(f"  Source: {BEACHHEAD_IP} (compromised API server)")
    logs = []

    log_gen.advance_time(60)

    # Host enumeration commands
    recon_commands = [
        ("ifconfig", "eth0: 10.0.1.20 netmask 255.255.255.0"),
        ("ip route", "default via 10.0.1.1 dev eth0\n10.0.0.0/24 via 10.0.1.1"),
        ("arp -a", "dc (10.0.0.10) at 00:1a:2b:3c:4d:5e\nfilesvr (10.0.0.20) at 00:1a:2b:3c:4d:5f"),
        ("cat /etc/resolv.conf", "nameserver 10.0.0.50\nsearch acmecorp.local"),
        ("cat /etc/hosts", "10.0.0.10 dc.acmecorp.local\n10.0.0.20 files.acmecorp.local"),
    ]

    for cmd, output in recon_commands:
        log_gen.advance_time(random.randint(3, 8))
        logs.append(log_gen.json_log("process_execution", {
            "host": BEACHHEAD_IP,
            "user": "svc_web",
            "command": cmd,
            "output": output,
            "parent_process": "bash",
            "pid": random.randint(10000, 30000),
        }, severity="warning"))

    print(f"  [+] Basic enumeration: {len(recon_commands)} commands executed")

    # Internal port scan (nmap-style)
    log_gen.advance_time(30)
    scan_targets = [DC_IP, FILE_SERVER_IP, DB_SERVER_IP] + WORKSTATION_IPS[:6]
    scan_ports = [SSH_PORT, 80, 443, SMB_PORT, 3389, 3306]

    for target_ip in scan_targets:
        for port in scan_ports:
            log_gen.advance_time(random.randint(0, 1))
            action = "allow" if port in [SSH_PORT, SMB_PORT, 3306] else random.choice(["allow", "deny"])
            logs.append(log_gen.firewall_log(
                BEACHHEAD_IP, target_ip,
                random.randint(40000, 65535), port,
                action=action, protocol="TCP"
            ))

    print(f"  [+] Internal scan: {len(scan_targets)} hosts x {len(scan_ports)} ports")

    # IDS alert for internal scan
    logs.append(log_gen.ids_alert(
        BEACHHEAD_IP, DC_IP,
        "Internal network scan from API server - anomalous behavior",
        sid=9070001, severity=2
    ))

    # Discovered hosts summary
    logs.append(log_gen.json_log("recon_results", {
        "host": BEACHHEAD_IP,
        "discovered_hosts": [
            {"ip": DC_IP, "hostname": "dc.acmecorp.local", "ports": [22, 445, 389]},
            {"ip": FILE_SERVER_IP, "hostname": "files.acmecorp.local", "ports": [22, 445]},
            {"ip": DB_SERVER_IP, "hostname": "db.acmecorp.local", "ports": [22, 3306]},
        ] + [
            {"ip": WORKSTATION_IPS[i], "ports": [22, 445]}
            for i in range(6)
        ],
    }, severity="warning"))

    print(f"  [+] Discovered: {len(scan_targets)} live hosts with open services")
    print(f"  [{Fore.YELLOW}RECON{Style.RESET_ALL}] Internal topology mapped\n")

    return logs


def phase_3_credential_harvest(log_gen: LogGenerator) -> list[str]:
    """Phase 3: Credential harvesting from the compromised API server.

    The attacker dumps local credentials, SSH keys, application config
    files, and attempts to crack password hashes.
    """
    print(f"{Fore.YELLOW}[Phase 3] Credential Harvesting{Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(120)

    # Dump /etc/shadow (requires privilege escalation first)
    # Use sudo abuse since svc_web has NOPASSWD sudo
    logs.append(log_gen.sudo_event("svc_web", "/bin/cat /etc/shadow", success=True))
    logs.append(log_gen.json_log("process_execution", {
        "host": BEACHHEAD_IP,
        "user": "root",
        "command": "cat /etc/shadow",
        "parent_process": "sudo",
        "pid": random.randint(10000, 30000),
    }, severity="critical"))
    print(f"  [+] /etc/shadow dumped via sudo")

    # Extract SSH keys
    log_gen.advance_time(15)
    ssh_key_locations = [
        "/home/svc_web/.ssh/id_rsa",
        "/home/svc_web/.ssh/known_hosts",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/ssh_host_rsa_key",
    ]
    for key_path in ssh_key_locations:
        logs.append(log_gen.json_log("file_access", {
            "host": BEACHHEAD_IP,
            "user": "svc_web",
            "path": key_path,
            "action": "read",
            "result": "success",
        }, severity="critical"))

    print(f"  [+] SSH keys extracted: {len(ssh_key_locations)} key files")

    # Application config with database credentials
    log_gen.advance_time(10)
    config_files = [
        "/opt/api-server/config/database.yml",
        "/opt/api-server/.env",
        "/opt/api-server/config/secrets.json",
    ]
    for cfg in config_files:
        logs.append(log_gen.json_log("file_access", {
            "host": BEACHHEAD_IP,
            "user": "svc_web",
            "path": cfg,
            "action": "read",
            "result": "success",
        }, severity="warning"))

    print(f"  [+] Application configs read: {len(config_files)} files")

    # Harvested credentials summary
    logs.append(log_gen.json_log("credential_harvest", {
        "host": BEACHHEAD_IP,
        "credentials_found": [
            {"user": "svc_web", "source": "ssh_key", "type": "private_key"},
            {"user": "root", "source": "/etc/shadow", "type": "hash", "crackable": True},
            {"user": REGULAR_USERS[0], "source": "/etc/shadow", "type": "hash", "crackable": True},
            {"user": REGULAR_USERS[1], "source": "/etc/shadow", "type": "hash", "crackable": True},
            {"user": "svc_db", "source": "database.yml", "type": "plaintext"},
            {"user": "admin", "source": "secrets.json", "type": "plaintext"},
        ],
    }, severity="critical"))

    print(f"  [!] Credentials harvested: 6 accounts (SSH keys, hashes, plaintext)")
    print(f"  [{Fore.RED}CREDS{Style.RESET_ALL}] Ready for lateral movement\n")

    return logs


def phase_4_lateral_ssh(log_gen: LogGenerator) -> list[str]:
    """Phase 4: Lateral movement via SSH.

    The attacker uses harvested credentials to SSH into multiple internal
    hosts sequentially. Each compromised host yields additional credentials
    and access to more systems.
    """
    print(f"{Fore.YELLOW}[Phase 4] Lateral Movement via SSH{Style.RESET_ALL}")
    print(f"  Pivot: {BEACHHEAD_IP} -> Internal hosts via SSH")
    logs = []

    log_gen.advance_time(180)

    compromised_chain = [BEACHHEAD_IP]

    for i, target in enumerate(LATERAL_SSH_TARGETS):
        log_gen.advance_time(random.randint(60, 300))
        src_ip = compromised_chain[-1]  # Pivot from last compromised host

        # SSH connection attempt
        logs.append(log_gen.firewall_log(
            src_ip, target["ip"],
            random.randint(40000, 65535), SSH_PORT,
            action="allow", protocol="TCP"
        ))

        # Auth failure(s) then success (realistic pattern)
        if random.random() > 0.4:
            logs.append(log_gen.auth_failure(target["user"], src_ip))
            log_gen.advance_time(3)

        logs.append(log_gen.auth_success(target["user"], src_ip))

        # Post-access enumeration on new host
        enum_commands = [
            "id", "whoami", "hostname", "ip addr show",
            "cat /etc/passwd", "ls -la /home/",
        ]
        for cmd in enum_commands:
            log_gen.advance_time(random.randint(2, 8))
            logs.append(log_gen.json_log("process_execution", {
                "host": target["ip"],
                "user": target["user"],
                "command": cmd,
                "parent_process": "sshd",
                "pid": random.randint(10000, 30000),
                "src_ip": src_ip,
            }, severity="warning"))

        # IDS alert for sequential SSH access
        logs.append(log_gen.ids_alert(
            src_ip, target["ip"],
            f"Sequential SSH lateral movement: hop {i+1} in chain",
            sid=9070002, severity=1
        ))

        compromised_chain.append(target["ip"])
        print(f"  [{i+1}/{len(LATERAL_SSH_TARGETS)}] {src_ip} -> {target['ip']} "
              f"({target['name']}) as {target['user']}")

    # Log the full compromise chain
    logs.append(log_gen.json_log("lateral_movement_chain", {
        "chain": compromised_chain,
        "method": "SSH",
        "total_hops": len(compromised_chain) - 1,
        "duration_seconds": len(compromised_chain) * 180,
    }, severity="critical"))

    print(f"  [!] Compromise chain: {' -> '.join(compromised_chain)}")
    print(f"  [{Fore.RED}LATERAL{Style.RESET_ALL}] {len(LATERAL_SSH_TARGETS)} hosts compromised via SSH\n")

    return logs


def phase_5_lateral_smb(log_gen: LogGenerator) -> list[str]:
    """Phase 5: Lateral movement via SMB.

    The attacker accesses file shares and administrative shares on the
    file server and domain controller using harvested domain credentials.
    """
    print(f"{Fore.YELLOW}[Phase 5] Lateral Movement via SMB{Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(240)

    for target in LATERAL_SMB_TARGETS:
        log_gen.advance_time(random.randint(30, 120))

        # SMB connection
        logs.append(log_gen.firewall_log(
            BEACHHEAD_IP, target["ip"],
            random.randint(40000, 65535), SMB_PORT,
            action="allow", protocol="TCP"
        ))

        # SMB authentication
        logs.append(log_gen.json_log("smb_session", {
            "src_ip": BEACHHEAD_IP,
            "dst_ip": target["ip"],
            "user": "svc_web",
            "domain": COMPANY_DOMAIN,
            "action": "session_setup",
            "result": "success",
            "ntlm_auth": True,
        }, severity="warning"))

        # Access each share
        for share in target["shares"]:
            log_gen.advance_time(random.randint(5, 15))
            logs.append(log_gen.json_log("smb_access", {
                "src_ip": BEACHHEAD_IP,
                "dst_ip": target["ip"],
                "user": "svc_web",
                "share": f"\\\\{target['ip']}\\{share}",
                "action": "tree_connect",
                "result": "success",
            }, severity="warning" if share in ["C$", "ADMIN$"] else "info"))

            # Admin share access triggers higher severity
            if share in ["C$", "ADMIN$"]:
                logs.append(log_gen.ids_alert(
                    BEACHHEAD_IP, target["ip"],
                    f"Administrative share access: \\\\{target['ip']}\\{share}",
                    sid=9070003, severity=1
                ))

            # File enumeration on share
            if share == "shared":
                files_accessed = [
                    "/shared/finance/quarterly_earnings_Q4.xlsx",
                    "/shared/executive/strategy/acquisition_targets.xlsx",
                    "/shared/hr/employee_records/salaries_2025.xlsx",
                ]
                for fpath in files_accessed:
                    logs.append(log_gen.json_log("smb_file_access", {
                        "src_ip": BEACHHEAD_IP,
                        "dst_ip": target["ip"],
                        "user": "svc_web",
                        "file": fpath,
                        "action": "read",
                        "size_bytes": random.randint(100000, 5000000),
                    }, severity="warning"))

        print(f"  [!] SMB access: {target['name']} ({target['ip']}) "
              f"- shares: {', '.join(target['shares'])}")

    print(f"  [{Fore.RED}SMB{Style.RESET_ALL}] File server and DC shares accessed\n")

    return logs


def phase_6_domain_compromise(log_gen: LogGenerator) -> list[str]:
    """Phase 6: Domain compromise -- access DC and extract AD data.

    The attacker accesses the domain controller, extracts Active Directory
    data including all user hashes (DCSync-style), and establishes
    persistence via a golden ticket.
    """
    print(f"{Fore.YELLOW}[Phase 6] Domain Compromise{Style.RESET_ALL}")
    print(f"  Target: {DC_IP} (Domain Controller)")
    logs = []

    log_gen.advance_time(300)

    # SSH to DC using cracked admin credentials
    logs.append(log_gen.auth_success("sysadmin", BEACHHEAD_IP))
    logs.append(log_gen.json_log("process_execution", {
        "host": DC_IP,
        "user": "sysadmin",
        "command": "id",
        "output": "uid=0(root) gid=0(root)",
        "parent_process": "sshd",
        "pid": random.randint(10000, 30000),
        "src_ip": BEACHHEAD_IP,
    }, severity="critical"))

    print(f"  [+] SSH to DC as sysadmin (root access)")

    # Active Directory enumeration
    ad_commands = [
        ("ldapsearch -x -b 'dc=acmecorp,dc=local' '(objectClass=user)' sAMAccountName",
         "Enumerating all AD user accounts"),
        ("ldapsearch -x -b 'dc=acmecorp,dc=local' '(objectClass=group)' cn member",
         "Enumerating AD group memberships"),
        ("ldapsearch -x -b 'dc=acmecorp,dc=local' '(memberOf=CN=Domain Admins,CN=Users,DC=acmecorp,DC=local)'",
         "Identifying Domain Admin accounts"),
        ("samba-tool domain passwordsettings show",
         "Checking domain password policy"),
        ("cat /var/lib/samba/private/sam.ldb | strings | grep -i password",
         "Extracting AD database strings"),
    ]

    for cmd, desc in ad_commands:
        log_gen.advance_time(random.randint(5, 20))
        logs.append(log_gen.json_log("process_execution", {
            "host": DC_IP,
            "user": "sysadmin",
            "command": cmd,
            "description": desc,
            "parent_process": "bash",
            "pid": random.randint(10000, 30000),
        }, severity="critical"))
        print(f"  [+] {desc}")

    # DCSync-style credential dump
    log_gen.advance_time(30)
    logs.append(log_gen.json_log("credential_dump", {
        "host": DC_IP,
        "user": "sysadmin",
        "method": "SAM database extraction",
        "accounts_dumped": len(REGULAR_USERS) + len(ADMIN_USERS) + len(SERVICE_ACCOUNTS),
        "includes_hashes": True,
        "includes_kerberos_keys": True,
    }, severity="critical"))

    logs.append(log_gen.ids_alert(
        BEACHHEAD_IP, DC_IP,
        "Domain controller compromise: mass credential extraction",
        sid=9070004, severity=1
    ))

    print(f"  [!] AD database dumped: {len(REGULAR_USERS) + len(ADMIN_USERS) + len(SERVICE_ACCOUNTS)} accounts")

    # GPO manipulation for persistence
    log_gen.advance_time(60)
    logs.append(log_gen.json_log("process_execution", {
        "host": DC_IP,
        "user": "sysadmin",
        "command": "samba-tool gpo create 'Maintenance Update' --attrs='script=\\\\dc\\SYSVOL\\scripts\\update.sh'",
        "parent_process": "bash",
        "pid": random.randint(10000, 30000),
    }, severity="critical"))

    logs.append(log_gen.ids_alert(
        BEACHHEAD_IP, DC_IP,
        "Suspicious GPO creation on domain controller",
        sid=9070005, severity=1
    ))

    print(f"  [!] Malicious GPO created for domain-wide persistence")
    print(f"  [{Fore.RED}DOMAIN COMPROMISE{Style.RESET_ALL}] Full Active Directory control achieved\n")

    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host="api-server")
    all_logs = []

    # Execute all six phases
    all_logs.extend(phase_1_zero_day_exploit(log_gen))
    all_logs.extend(phase_2_internal_recon(log_gen))
    all_logs.extend(phase_3_credential_harvest(log_gen))
    all_logs.extend(phase_4_lateral_ssh(log_gen))
    all_logs.extend(phase_5_lateral_smb(log_gen))
    all_logs.extend(phase_6_domain_compromise(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "zero_day_lateral_movement.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Summary
    print(f"{Fore.GREEN}{'='*62}")
    print(f"  Zero-Day Lateral Movement Simulation Complete")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Total log entries:  {len(all_logs)}")
    print(f"  Output file:        {log_file}")
    print(f"  Attacker:           {ATTACKER_IP}")
    print(f"  Beachhead:          {BEACHHEAD_IP} (API server)")
    print(f"  Zero-day:           {ZERO_DAY_CVE}")
    print(f"\n  Compromise chain (SSH):")
    chain = [BEACHHEAD_IP] + [t["ip"] for t in LATERAL_SSH_TARGETS]
    print(f"    {' -> '.join(chain)}")
    print(f"\n  SMB targets: {FILE_SERVER_IP} (file server), {DC_IP} (DC)")
    print(f"  Domain compromised: YES (AD database + GPO persistence)")
    print(f"\n  Next step: python3 detect/verify_detection.py")

    # Try to send to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "07-zero-day-lateral"},
            all_logs
        )
        print(f"\n  [+] Logs pushed to Loki")
    except Exception:
        print(f"\n  [*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
