#!/usr/bin/env python3
"""
Scenario 11: Botnet Detection Attack Simulation.

Full attack chain:
  Phase 1 - Bot Propagation (Worm spreads to 8 workstations via SMB)
  Phase 2 - Bot Registration (Bots check in with C2, get unique bot_id)
  Phase 3 - C2 Beaconing (Coordinated callbacks at similar intervals)
  Phase 4 - Tasking (C2 sends commands to bots)
  Phase 5 - DDoS Attack (Coordinated flood against target)
  Phase 6 - Data Theft (Credential harvesting and exfiltration)

SAFETY: No actual botnet activity is performed -- all activity is
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
    ATTACKER_IP, C2_SERVER_IP, COMPANY_DOMAIN, REGULAR_USERS,
    WORKSTATION_IPS, ADMIN_USERS, MITRE, SMB_PORT,
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Initial infection source -- patient zero workstation
PATIENT_ZERO_IP = WORKSTATION_IPS[0]
PATIENT_ZERO_USER = REGULAR_USERS[0]

# Infected workstations (8 bots from patient zero spread)
BOT_IPS = WORKSTATION_IPS[1:9]
BOT_USERS = REGULAR_USERS[1:9]

# DDoS target
DDOS_TARGET_IP = "198.51.100.50"      # TEST-NET-2 (RFC 5737) -- simulated external target
DDOS_TARGET_DOMAIN = "target-site.test"

# C2 beacon interval (seconds) -- bots beacon at similar intervals
BEACON_INTERVAL_BASE = 30
BEACON_JITTER = 5

# Bot IDs assigned during registration
BOT_IDS = [f"BOT-{random.randint(10000, 99999):05d}" for _ in range(8)]


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 11: Botnet Detection Simulation             |
|  Attack: Propagation -> Registration -> C2 -> DDoS -> Theft |
|  C2 Server: {C2_SERVER_IP:<48s}|
|  WARNING: Educational use only                               |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Phase 1: Bot Propagation
# ---------------------------------------------------------------------------

def phase_1_propagation(log_gen: LogGenerator) -> list[str]:
    """Simulate worm-like propagation via SMB to 8 workstations."""
    print(f"{Fore.YELLOW}[Phase 1] Bot Propagation via SMB{Style.RESET_ALL}")
    print(f"  Patient Zero: {PATIENT_ZERO_USER}@{PATIENT_ZERO_IP}")
    print(f"  Targets: {len(BOT_IPS)} workstations\n")

    logs = []

    # Patient zero gets initial malware (drive-by or phishing)
    logs.append(log_gen.json_log("malware_download", {
        "user": PATIENT_ZERO_USER,
        "src_ip": PATIENT_ZERO_IP,
        "dst_ip": ATTACKER_IP,
        "dst_port": 443,
        "file_name": "update_patch.exe",
        "file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "mitre_technique": "T1189",
    }, severity="critical"))
    print(f"  [+] Patient zero infected via malicious download")

    # Worm scans internal network on SMB port
    logs.append(log_gen.json_log("network_scan", {
        "src_ip": PATIENT_ZERO_IP,
        "protocol": "TCP",
        "dst_port": SMB_PORT,
        "targets_scanned": len(BOT_IPS),
        "description": "SMB port scan from infected workstation",
        "mitre_technique": MITRE["lateral_movement"]["exploitation_remote"],
    }, severity="warning"))
    print(f"  [+] SMB port scan launched from patient zero")

    # Propagation to each workstation via SMB exploit
    for i, (bot_ip, bot_user) in enumerate(zip(BOT_IPS, BOT_USERS)):
        # SMB connection
        logs.append(log_gen.firewall_log(
            PATIENT_ZERO_IP, bot_ip,
            random.randint(49152, 65535), SMB_PORT, action="allow",
        ))

        # SMB exploitation event
        logs.append(log_gen.json_log("smb_exploitation", {
            "src_ip": PATIENT_ZERO_IP,
            "dst_ip": bot_ip,
            "dst_port": SMB_PORT,
            "exploit": "EternalBlue-variant",
            "user_context": bot_user,
            "result": "success",
            "mitre_technique": MITRE["lateral_movement"]["exploitation_remote"],
        }, severity="critical"))

        # Worm payload delivery
        logs.append(log_gen.json_log("file_transfer", {
            "src_ip": PATIENT_ZERO_IP,
            "dst_ip": bot_ip,
            "protocol": "SMB",
            "file_name": "svchost_update.exe",
            "size_bytes": random.randint(45000, 65000),
            "description": "Worm payload delivered via SMB",
        }, severity="critical"))

        print(f"  [{Fore.RED}INFECTED{Style.RESET_ALL}] {bot_user}@{bot_ip} "
              f"-- SMB exploit successful")

        time.sleep(0.05)

    # IDS alert for worm propagation
    logs.append(log_gen.ids_alert(
        PATIENT_ZERO_IP, BOT_IPS[0],
        "Worm propagation: Multiple SMB exploitation attempts from single host",
        sid=9110001, severity=1,
    ))

    # Wazuh alert for propagation
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100480,
        "rule_level": 10,
        "rule_description": "WCACE S11: Worm-like SMB propagation detected across workstations",
        "src_ip": PATIENT_ZERO_IP,
        "targets": BOT_IPS,
        "exploit_type": "SMB",
        "infections": len(BOT_IPS),
        "mitre": ["T1210"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] {len(BOT_IPS)} workstations infected via SMB "
          f"propagation{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 2: Bot Registration
# ---------------------------------------------------------------------------

def phase_2_registration(log_gen: LogGenerator) -> list[str]:
    """Simulate bots registering with C2 server and receiving bot IDs."""
    print(f"\n{Fore.YELLOW}[Phase 2] Bot Registration with C2{Style.RESET_ALL}")
    print(f"  C2 Server: {C2_SERVER_IP}")
    logs = []

    for i, (bot_ip, bot_user, bot_id) in enumerate(zip(BOT_IPS, BOT_USERS, BOT_IDS)):
        # DNS lookup for C2 domain
        logs.append(log_gen.dns_query_log(
            bot_ip, "updates.evil-cdn.test", query_type="A",
            response=C2_SERVER_IP,
        ))

        # HTTP POST registration to C2
        logs.append(log_gen.json_log("http_request", {
            "src_ip": bot_ip,
            "dst_ip": C2_SERVER_IP,
            "dst_port": 443,
            "method": "POST",
            "url": "/api/v1/register",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "content_type": "application/json",
            "payload_summary": {
                "hostname": f"WS-{bot_ip.split('.')[-1]}",
                "os": "Windows 10 Enterprise",
                "user": bot_user,
                "arch": "x64",
            },
            "mitre_technique": MITRE["resource_development"]["botnet"],
        }, severity="warning"))

        # C2 response with bot_id
        logs.append(log_gen.json_log("http_response", {
            "src_ip": C2_SERVER_IP,
            "dst_ip": bot_ip,
            "status_code": 200,
            "response_summary": {
                "bot_id": bot_id,
                "beacon_interval": BEACON_INTERVAL_BASE,
                "encryption_key": f"AES256-{random.randbytes(8).hex()}",
            },
        }, severity="warning"))

        # System info discovery by bot
        logs.append(log_gen.json_log("command_execution", {
            "user": bot_user,
            "src_ip": bot_ip,
            "command": "systeminfo && ipconfig /all && net user",
            "description": "Bot gathering system information for C2 registration",
            "mitre_technique": "T1082",
        }, severity="warning"))

        print(f"  [+] {bot_ip} registered as {bot_id} -- "
              f"system info sent to C2")

        time.sleep(0.03)

    # Wazuh alert for bot registration
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100481,
        "rule_level": 10,
        "rule_description": "WCACE S11: Bot registration with C2 server detected",
        "c2_server": C2_SERVER_IP,
        "registered_bots": len(BOT_IDS),
        "bot_ids": BOT_IDS,
        "mitre": ["T1583.005", "T1082"],
    }, severity="critical"))

    # IDS alert for C2 registration traffic
    logs.append(log_gen.ids_alert(
        BOT_IPS[0], C2_SERVER_IP,
        "Botnet C2: Multiple hosts registering with same external server",
        sid=9110002, severity=1,
    ))

    print(f"\n  {Fore.CYAN}[*] {len(BOT_IDS)} bots registered with C2 -- "
          f"bot IDs assigned{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 3: C2 Beaconing
# ---------------------------------------------------------------------------

def phase_3_beaconing(log_gen: LogGenerator) -> list[str]:
    """Simulate coordinated C2 beaconing at regular intervals."""
    print(f"\n{Fore.YELLOW}[Phase 3] C2 Beaconing{Style.RESET_ALL}")
    print(f"  Beacon interval: ~{BEACON_INTERVAL_BASE}s (+/- {BEACON_JITTER}s jitter)")
    logs = []

    # Simulate 3 rounds of beaconing from all bots
    beacon_rounds = 3
    for round_num in range(beacon_rounds):
        print(f"\n  [Beacon Round {round_num + 1}/{beacon_rounds}]")

        for bot_ip, bot_id in zip(BOT_IPS, BOT_IDS):
            interval = BEACON_INTERVAL_BASE + random.randint(-BEACON_JITTER, BEACON_JITTER)

            # HTTPS beacon to C2
            logs.append(log_gen.json_log("c2_beacon", {
                "src_ip": bot_ip,
                "dst_ip": C2_SERVER_IP,
                "dst_port": 443,
                "bot_id": bot_id,
                "beacon_interval": interval,
                "method": "GET",
                "url": f"/api/v1/heartbeat?id={bot_id}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "response_size": random.randint(50, 200),
                "mitre_technique": MITRE["command_and_control"]["app_layer"],
            }, severity="warning"))

            # C2 response (keep-alive or pending task)
            task_pending = round_num == beacon_rounds - 1  # last round has tasks
            logs.append(log_gen.json_log("c2_response", {
                "src_ip": C2_SERVER_IP,
                "dst_ip": bot_ip,
                "bot_id": bot_id,
                "status": "task_pending" if task_pending else "standby",
                "response_code": 200,
            }, severity="info"))

            print(f"    {bot_ip} ({bot_id}) -> C2 [interval: {interval}s] "
                  f"{'[TASK PENDING]' if task_pending else '[STANDBY]'}")

        time.sleep(0.05)

    # Wazuh alert for coordinated beaconing
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100482,
        "rule_level": 12,
        "rule_description": "WCACE S11: Coordinated C2 beaconing from multiple internal hosts",
        "c2_server": C2_SERVER_IP,
        "beaconing_hosts": BOT_IPS,
        "beacon_count": beacon_rounds * len(BOT_IPS),
        "avg_interval": BEACON_INTERVAL_BASE,
        "mitre": ["T1071.001"],
    }, severity="critical"))

    # IDS alert for beaconing pattern
    logs.append(log_gen.ids_alert(
        BOT_IPS[0], C2_SERVER_IP,
        "Botnet C2: Coordinated beaconing pattern detected from multiple internal hosts",
        sid=9110003, severity=1,
    ))

    print(f"\n  {Fore.CYAN}[*] {beacon_rounds * len(BOT_IPS)} beacon callbacks detected "
          f"across {len(BOT_IPS)} hosts{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 4: Tasking
# ---------------------------------------------------------------------------

def phase_4_tasking(log_gen: LogGenerator) -> list[str]:
    """Simulate C2 sending commands to bots."""
    print(f"\n{Fore.YELLOW}[Phase 4] Bot Tasking from C2{Style.RESET_ALL}")
    logs = []

    # C2 sends tasking to all bots
    task_commands = [
        {"task": "ddos_syn_flood", "target": DDOS_TARGET_IP, "port": 80,
         "duration": 300, "threads": 50},
        {"task": "ddos_http_flood", "target": DDOS_TARGET_DOMAIN, "port": 443,
         "duration": 300, "threads": 100},
        {"task": "credential_harvest", "scope": "browsers,registry,memory",
         "exfil_endpoint": f"https://{C2_SERVER_IP}/api/v1/upload"},
    ]

    for bot_ip, bot_id in zip(BOT_IPS, BOT_IDS):
        # C2 pushes task list to bot
        logs.append(log_gen.json_log("c2_tasking", {
            "src_ip": C2_SERVER_IP,
            "dst_ip": bot_ip,
            "bot_id": bot_id,
            "method": "POST",
            "url": f"/api/v1/task?id={bot_id}",
            "tasks": task_commands,
            "task_count": len(task_commands),
            "mitre_technique": "T1059",
        }, severity="critical"))

        # Bot acknowledges tasking
        logs.append(log_gen.json_log("c2_task_ack", {
            "src_ip": bot_ip,
            "dst_ip": C2_SERVER_IP,
            "bot_id": bot_id,
            "status": "tasks_received",
            "task_count": len(task_commands),
        }, severity="warning"))

        print(f"  [+] {bot_id}@{bot_ip} received {len(task_commands)} tasks: "
              f"ddos_syn, ddos_http, cred_harvest")

    # Wazuh alert for tasking
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100483,
        "rule_level": 12,
        "rule_description": "WCACE S11: Bot tasking commands received from C2 server",
        "c2_server": C2_SERVER_IP,
        "bots_tasked": len(BOT_IPS),
        "tasks": ["ddos_syn_flood", "ddos_http_flood", "credential_harvest"],
        "mitre": ["T1059"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] {len(BOT_IPS)} bots tasked with DDoS and credential "
          f"harvesting commands{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 5: DDoS Attack
# ---------------------------------------------------------------------------

def phase_5_ddos(log_gen: LogGenerator) -> list[str]:
    """Simulate coordinated DDoS attack from all bots."""
    print(f"\n{Fore.YELLOW}[Phase 5] Coordinated DDoS Attack{Style.RESET_ALL}")
    print(f"  Target: {DDOS_TARGET_DOMAIN} ({DDOS_TARGET_IP})")
    logs = []

    # SYN flood from all bots
    print(f"\n  [SYN Flood Phase]")
    for bot_ip, bot_id in zip(BOT_IPS, BOT_IDS):
        # Generate multiple SYN flood entries per bot
        syn_count = random.randint(500, 1500)
        logs.append(log_gen.json_log("ddos_syn_flood", {
            "src_ip": bot_ip,
            "dst_ip": DDOS_TARGET_IP,
            "dst_port": 80,
            "bot_id": bot_id,
            "packets_sent": syn_count,
            "protocol": "TCP",
            "flags": "SYN",
            "duration_seconds": 60,
            "mitre_technique": "T1498",
        }, severity="critical"))

        logs.append(log_gen.firewall_log(
            bot_ip, DDOS_TARGET_IP,
            random.randint(1024, 65535), 80, action="allow",
        ))

        print(f"    {bot_id}@{bot_ip} -> {DDOS_TARGET_IP}:80 "
              f"[{syn_count} SYN packets]")

    # HTTP flood from all bots
    print(f"\n  [HTTP Flood Phase]")
    for bot_ip, bot_id in zip(BOT_IPS, BOT_IDS):
        http_count = random.randint(200, 800)
        logs.append(log_gen.json_log("ddos_http_flood", {
            "src_ip": bot_ip,
            "dst_ip": DDOS_TARGET_IP,
            "dst_port": 443,
            "bot_id": bot_id,
            "requests_sent": http_count,
            "method": "GET",
            "url": f"https://{DDOS_TARGET_DOMAIN}/",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "duration_seconds": 60,
            "mitre_technique": "T1498",
        }, severity="critical"))

        print(f"    {bot_id}@{bot_ip} -> {DDOS_TARGET_DOMAIN}:443 "
              f"[{http_count} HTTP requests]")

    # IDS alert for DDoS
    logs.append(log_gen.ids_alert(
        BOT_IPS[0], DDOS_TARGET_IP,
        "DDoS Attack: SYN flood from multiple internal hosts to single target",
        sid=9110004, severity=1,
    ))

    # Wazuh alert for individual DDoS participation
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100484,
        "rule_level": 12,
        "rule_description": "WCACE S11: DDoS traffic generation from internal host",
        "src_ips": BOT_IPS,
        "target_ip": DDOS_TARGET_IP,
        "target_domain": DDOS_TARGET_DOMAIN,
        "attack_types": ["syn_flood", "http_flood"],
        "mitre": ["T1498"],
    }, severity="critical"))

    # Wazuh alert for coordinated DDoS
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100485,
        "rule_level": 14,
        "rule_description": "WCACE S11: Coordinated DDoS attack from botnet -- multiple hosts flooding same target",
        "attacking_hosts": BOT_IPS,
        "target_ip": DDOS_TARGET_IP,
        "target_domain": DDOS_TARGET_DOMAIN,
        "total_bots": len(BOT_IPS),
        "mitre": ["T1498", "T1583.005"],
    }, severity="critical"))

    total_syn = sum(random.randint(500, 1500) for _ in BOT_IPS)
    total_http = sum(random.randint(200, 800) for _ in BOT_IPS)
    print(f"\n  {Fore.CYAN}[*] DDoS attack launched: ~{total_syn} SYN + "
          f"~{total_http} HTTP requests from {len(BOT_IPS)} bots{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 6: Data Theft
# ---------------------------------------------------------------------------

def phase_6_data_theft(log_gen: LogGenerator) -> list[str]:
    """Simulate credential harvesting and exfiltration by bots."""
    print(f"\n{Fore.YELLOW}[Phase 6] Credential Harvesting & Data Exfiltration{Style.RESET_ALL}")
    logs = []

    credential_sources = [
        "Chrome saved passwords",
        "Firefox credential store",
        "Windows Credential Manager",
        "Registry cached credentials",
        "LSASS memory dump",
    ]

    for bot_ip, bot_user, bot_id in zip(BOT_IPS, BOT_USERS, BOT_IDS):
        # Credential harvesting
        harvested = random.sample(credential_sources, random.randint(2, 4))
        creds_found = random.randint(5, 30)

        logs.append(log_gen.json_log("credential_harvest", {
            "src_ip": bot_ip,
            "user": bot_user,
            "bot_id": bot_id,
            "sources_scraped": harvested,
            "credentials_found": creds_found,
            "mitre_technique": "T1059",
        }, severity="critical"))

        print(f"  [+] {bot_id}@{bot_ip}: harvested {creds_found} credentials "
              f"from {', '.join(harvested[:2])}...")

        # Data exfiltration to C2
        exfil_size = random.randint(50000, 500000)
        logs.append(log_gen.json_log("data_exfiltration", {
            "src_ip": bot_ip,
            "dst_ip": C2_SERVER_IP,
            "dst_port": 443,
            "bot_id": bot_id,
            "data_type": "credentials",
            "size_bytes": exfil_size,
            "method": "HTTPS POST",
            "url": f"/api/v1/upload?id={bot_id}",
            "encrypted": True,
            "mitre_technique": "T1041",
        }, severity="critical"))

        logs.append(log_gen.firewall_log(
            bot_ip, C2_SERVER_IP,
            random.randint(49152, 65535), 443, action="allow",
        ))

        print(f"    -> Exfiltrated {exfil_size:,} bytes to C2")

        time.sleep(0.03)

    # Wazuh alert for credential harvesting
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100486,
        "rule_level": 12,
        "rule_description": "WCACE S11: Credential harvesting by bot detected",
        "affected_hosts": BOT_IPS,
        "credential_sources": credential_sources,
        "mitre": ["T1059"],
    }, severity="critical"))

    # Wazuh alert for data exfiltration
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100487,
        "rule_level": 13,
        "rule_description": "WCACE S11: Bot exfiltrating stolen data to C2 server",
        "c2_server": C2_SERVER_IP,
        "exfiltrating_hosts": BOT_IPS,
        "data_type": "credentials",
        "mitre": ["T1041"],
    }, severity="critical"))

    # Bot persistence mechanism
    for bot_ip, bot_user, bot_id in zip(BOT_IPS, BOT_USERS, BOT_IDS):
        logs.append(log_gen.json_log("persistence_install", {
            "src_ip": bot_ip,
            "user": bot_user,
            "bot_id": bot_id,
            "mechanism": "scheduled_task",
            "task_name": "WindowsUpdateService",
            "binary": "C:\\Windows\\Temp\\svchost_update.exe",
            "trigger": "on_logon",
            "mitre_technique": "T1053",
        }, severity="critical"))

    # Wazuh alert for persistence
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100488,
        "rule_level": 12,
        "rule_description": "WCACE S11: Bot persistence mechanism installed via scheduled task",
        "affected_hosts": BOT_IPS,
        "persistence_type": "scheduled_task",
        "mitre": ["T1053"],
    }, severity="critical"))

    # IDS alert for exfiltration
    logs.append(log_gen.ids_alert(
        BOT_IPS[0], C2_SERVER_IP,
        "Data Exfiltration: Multiple internal hosts uploading data to known C2 server",
        sid=9110005, severity=1,
    ))

    # Correlation alert: full botnet campaign
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100489,
        "rule_level": 15,
        "rule_description": "WCACE S11: Botnet campaign correlated -- propagation, C2, DDoS, and data theft detected",
        "c2_server": C2_SERVER_IP,
        "patient_zero": PATIENT_ZERO_IP,
        "infected_hosts": BOT_IPS,
        "bot_ids": BOT_IDS,
        "ddos_target": DDOS_TARGET_IP,
        "kill_chain_phases": [
            "propagation",
            "registration",
            "beaconing",
            "tasking",
            "ddos_attack",
            "data_theft",
        ],
        "mitre": ["T1583.005", "T1071.001", "T1498", "T1059", "T1082", "T1210"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Credential harvesting and exfiltration complete "
          f"across {len(BOT_IPS)} bots{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    log_gen = LogGenerator(source_host="botnet-sim", facility="daemon")
    all_logs = []

    # Phase 1: Bot Propagation
    logs_p1 = phase_1_propagation(log_gen)
    all_logs.extend(logs_p1)
    time.sleep(0.5)

    # Phase 2: Bot Registration
    logs_p2 = phase_2_registration(log_gen)
    all_logs.extend(logs_p2)
    time.sleep(0.5)

    # Phase 3: C2 Beaconing
    logs_p3 = phase_3_beaconing(log_gen)
    all_logs.extend(logs_p3)
    time.sleep(0.5)

    # Phase 4: Tasking
    logs_p4 = phase_4_tasking(log_gen)
    all_logs.extend(logs_p4)
    time.sleep(0.5)

    # Phase 5: DDoS Attack
    logs_p5 = phase_5_ddos(log_gen)
    all_logs.extend(logs_p5)
    time.sleep(0.5)

    # Phase 6: Data Theft
    logs_p6 = phase_6_data_theft(log_gen)
    all_logs.extend(logs_p6)

    # ---------------------------------------------------------------------------
    # Save logs
    # ---------------------------------------------------------------------------
    os.makedirs(LOG_DIR, exist_ok=True)

    # Save combined attack log
    log_file = os.path.join(LOG_DIR, "botnet_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Save network-only logs (syslog format entries)
    network_logs = [l for l in all_logs if not l.startswith("{")]
    network_file = os.path.join(LOG_DIR, "network_logs.log")
    SIEMClient.write_logs_to_file(network_logs, network_file)

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
    print(f"  Network log entries:    {len(network_logs)}")
    print(f"  Wazuh alert entries:    {len(wazuh_alerts)}")
    print(f"  Patient zero:           {PATIENT_ZERO_USER}@{PATIENT_ZERO_IP}")
    print(f"  Infected bots:          {len(BOT_IPS)}")
    print(f"  C2 server:              {C2_SERVER_IP}")
    print(f"  DDoS target:            {DDOS_TARGET_DOMAIN} ({DDOS_TARGET_IP})")
    print(f"\n  Log files:")
    print(f"    {log_file}")
    print(f"    {network_file}")
    print(f"    {wazuh_file}")

    # Try to push logs to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "11-botnet-detection"},
            all_logs,
        )
        print(f"\n  {Fore.GREEN}[*] Logs pushed to Loki{Style.RESET_ALL}")
    except Exception:
        print(f"\n  [*] Loki not available -- logs saved locally only")

    print(f"\n  Next: Run detect/verify_detection.py to verify alerts")
    print(f"        Run respond/containment.py for incident response\n")


if __name__ == "__main__":
    main()
