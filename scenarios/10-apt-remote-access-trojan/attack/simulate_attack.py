#!/usr/bin/env python3
"""
Scenario 10: APT with Remote Access Trojan Simulation.

Simulates a RAT lifecycle through six phases:
  Phase 1: RAT delivery via phishing (trojanized document)
  Phase 2: RAT installation with persistence
  Phase 3: C2 beaconing (regular interval HTTP callbacks)
  Phase 4: Remote command execution via C2 channel
  Phase 5: Data collection (keylogging, screenshots, file harvesting)
  Phase 6: Data exfiltration over C2 channel

Tier 2: Simulated approach with partial implementation.
The reverse shell connects to localhost; C2 beaconing is simulated via
regular-interval HTTP callback log entries.
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
    C2_SERVER_IP,
    C2_DOMAIN,
    WORKSTATION_IPS,
    REGULAR_USERS,
    FILE_SERVER_IP,
    DC_IP,
    HTTP_PORT,
    HTTPS_PORT,
    COMPANY_DOMAIN,
    MITRE,
)

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Victim workstation (phishing target)
VICTIM_IP = WORKSTATION_IPS[4]  # 10.0.0.104
VICTIM_USER = REGULAR_USERS[4]  # carlos.garcia

# C2 beacon configuration
BEACON_INTERVAL = 60  # seconds between beacons
BEACON_JITTER = 5     # +/- seconds of randomness
BEACON_COUNT = 30     # number of beacons to simulate

# RAT configuration
RAT_FILENAME = "system_update.py"
RAT_INSTALL_PATH = f"/home/{VICTIM_USER}/.local/share/.sys_update/{RAT_FILENAME}"
RAT_PID = random.randint(15000, 30000)

# C2 HTTP paths (rotating to evade detection)
C2_BEACON_PATHS = [
    "/api/v2/check-update",
    "/api/v2/telemetry",
    "/api/v2/heartbeat",
    "/cdn/analytics.js",
    "/static/pixel.gif",
]

# C2 commands to execute
C2_COMMANDS = [
    {"id": "cmd-001", "cmd": "whoami", "desc": "User identification"},
    {"id": "cmd-002", "cmd": "hostname && ip addr show", "desc": "System info collection"},
    {"id": "cmd-003", "cmd": "ps aux", "desc": "Process enumeration"},
    {"id": "cmd-004", "cmd": "cat /etc/passwd", "desc": "User account enumeration"},
    {"id": "cmd-005", "cmd": "find /home -name '*.xlsx' -o -name '*.docx' -o -name '*.pdf' 2>/dev/null",
     "desc": "Sensitive file discovery"},
    {"id": "cmd-006", "cmd": "cat /home/{user}/.ssh/id_rsa".format(user=VICTIM_USER),
     "desc": "SSH key theft"},
    {"id": "cmd-007", "cmd": "cat /home/{user}/.bash_history".format(user=VICTIM_USER),
     "desc": "Command history extraction"},
    {"id": "cmd-008", "cmd": "netstat -tlnp", "desc": "Network connection enumeration"},
    {"id": "cmd-009", "cmd": f"mount -t cifs //{FILE_SERVER_IP}/shared /mnt/share -o user={VICTIM_USER}",
     "desc": "Mount network share"},
    {"id": "cmd-010", "cmd": "tar czf /tmp/.cache_update.tar.gz /home/{user}/Documents/".format(user=VICTIM_USER),
     "desc": "Data staging for exfiltration"},
]


def banner():
    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 10: APT with Remote Access Trojan
  Victim:     {VICTIM_USER} ({VICTIM_IP})
  C2 Server:  {C2_SERVER_IP} ({C2_DOMAIN})
  Beacon:     Every {BEACON_INTERVAL}s (+/- {BEACON_JITTER}s jitter)
  MITRE:      T1219 (Remote Access Software), T1071 (App Layer C2)
  WARNING: Educational simulation only
{'='*62}{Style.RESET_ALL}
""")


def phase_1_rat_delivery(log_gen: LogGenerator) -> list[str]:
    """Phase 1: RAT delivery via phishing email with trojanized document.

    A spear-phishing email delivers a trojanized Office document that
    drops a Python RAT payload when the victim opens it.
    """
    print(f"{Fore.CYAN}[Phase 1] RAT Delivery via Phishing{Style.RESET_ALL}")
    print(f"  Target: {VICTIM_USER} ({VICTIM_IP})")
    logs = []

    log_gen._base_time = datetime.now().replace(hour=9, minute=22, second=0)

    # Email delivery
    logs.append(log_gen.json_log("email_received", {
        "recipient": f"{VICTIM_USER}@{COMPANY_DOMAIN}",
        "sender": "hr-benefits@acmecorp-portal.test",
        "subject": "Q4 Benefits Enrollment - Action Required",
        "attachment": "Benefits_Enrollment_2026.xlsm",
        "attachment_size": 487320,
        "has_macros": True,
        "spf_result": "softfail",
        "dkim_result": "none",
    }, severity="warning"))

    print(f"  [+] Phishing email delivered: Benefits_Enrollment_2026.xlsm")

    # User opens the document
    log_gen.advance_time(342)  # ~5 minutes later
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": "libreoffice --calc Benefits_Enrollment_2026.xlsm",
        "parent_process": "thunderbird",
        "pid": random.randint(5000, 10000),
    }, severity="info"))

    # Macro executes and drops RAT
    log_gen.advance_time(8)
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"python3 /tmp/.tmp_update.py",
        "parent_process": "libreoffice",
        "pid": random.randint(10000, 15000),
    }, severity="critical"))

    logs.append(log_gen.json_log("file_create", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "path": "/tmp/.tmp_update.py",
        "size_bytes": 15847,
        "file_type": "text/x-python",
    }, severity="critical"))

    print(f"  [!] Document opened, macro executed")
    print(f"  [!] Python RAT payload dropped to /tmp/.tmp_update.py")
    print(f"  [{Fore.RED}DELIVERY{Style.RESET_ALL}] RAT payload delivered via phishing\n")

    return logs


def phase_2_rat_installation(log_gen: LogGenerator) -> list[str]:
    """Phase 2: RAT installation with persistence mechanism.

    The dropper copies the RAT to a hidden directory and establishes
    persistence via crontab and .bashrc modification.
    """
    print(f"{Fore.YELLOW}[Phase 2] RAT Installation & Persistence{Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(5)

    # Create hidden installation directory
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"mkdir -p /home/{VICTIM_USER}/.local/share/.sys_update",
        "parent_process": "python3",
        "pid": random.randint(10000, 15000),
    }, severity="warning"))

    # Copy RAT to persistent location
    logs.append(log_gen.json_log("file_create", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "path": RAT_INSTALL_PATH,
        "size_bytes": 15847,
        "file_type": "text/x-python",
        "hidden": True,
    }, severity="critical"))

    # Set up cron persistence
    log_gen.advance_time(3)
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"(crontab -l 2>/dev/null; echo '@reboot python3 {RAT_INSTALL_PATH}') | crontab -",
        "parent_process": "python3",
        "pid": random.randint(10000, 15000),
    }, severity="critical"))

    # Modify .bashrc for additional persistence
    logs.append(log_gen.json_log("file_modify", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "path": f"/home/{VICTIM_USER}/.bashrc",
        "modification": f"Added: nohup python3 {RAT_INSTALL_PATH} &>/dev/null &",
    }, severity="critical"))

    # RAT process starts
    log_gen.advance_time(2)
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"python3 {RAT_INSTALL_PATH}",
        "parent_process": "bash",
        "pid": RAT_PID,
        "description": "RAT main process started",
    }, severity="critical"))

    # Clean up dropper
    logs.append(log_gen.json_log("file_delete", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "path": "/tmp/.tmp_update.py",
    }, severity="warning"))

    print(f"  [+] RAT installed: {RAT_INSTALL_PATH}")
    print(f"  [+] Persistence: crontab @reboot + .bashrc modification")
    print(f"  [+] RAT process started (PID: {RAT_PID})")
    print(f"  [+] Dropper cleaned up from /tmp")
    print(f"  [{Fore.RED}INSTALLED{Style.RESET_ALL}] RAT persistent on victim workstation\n")

    return logs


def phase_3_c2_beaconing(log_gen: LogGenerator) -> list[str]:
    """Phase 3: C2 beaconing -- regular interval HTTP callbacks.

    The RAT beacons to the C2 server at regular intervals (~60 seconds)
    with slight jitter. Each beacon sends system info and checks for
    pending commands.
    """
    print(f"{Fore.YELLOW}[Phase 3] C2 Beaconing (Regular Interval Callbacks){Style.RESET_ALL}")
    print(f"  C2 Server:  {C2_SERVER_IP} ({C2_DOMAIN})")
    print(f"  Interval:   {BEACON_INTERVAL}s (+/- {BEACON_JITTER}s)")
    print(f"  Beacons:    {BEACON_COUNT} callbacks")
    logs = []

    log_gen.advance_time(10)

    # Initial DNS lookup
    logs.append(log_gen.dns_query_log(
        VICTIM_IP, C2_DOMAIN,
        query_type="A", response=C2_SERVER_IP
    ))

    # Generate beacon sequence
    beacon_times = []
    for i in range(BEACON_COUNT):
        jitter = random.randint(-BEACON_JITTER, BEACON_JITTER)
        interval = BEACON_INTERVAL + jitter
        log_gen.advance_time(interval)
        beacon_times.append(interval)

        # Rotate through beacon paths
        beacon_path = C2_BEACON_PATHS[i % len(C2_BEACON_PATHS)]

        # Outbound HTTP POST (beacon)
        logs.append(log_gen.firewall_log(
            VICTIM_IP, C2_SERVER_IP,
            random.randint(40000, 65535), HTTPS_PORT,
            action="allow", protocol="TCP"
        ))

        # Beacon payload
        beacon_data = {
            "beacon_id": f"beacon-{i+1:04d}",
            "host": VICTIM_IP,
            "user": VICTIM_USER,
            "hostname": f"ws-{VICTIM_USER.replace('.', '-')}",
            "os": "Linux 5.15.0-91-generic x86_64",
            "uptime_seconds": 3600 + (i * BEACON_INTERVAL),
            "path": beacon_path,
            "interval": interval,
        }

        logs.append(log_gen.json_log("c2_beacon", {
            "src_ip": VICTIM_IP,
            "dst_ip": C2_SERVER_IP,
            "dst_port": HTTPS_PORT,
            "method": "POST",
            "path": beacon_path,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "content_length": random.randint(128, 512),
            "response_code": 200,
            "response_size": random.randint(64, 256),
            **beacon_data,
        }, severity="warning"))

        # Print progress every 10 beacons
        if (i + 1) % 10 == 0:
            avg_interval = sum(beacon_times[-10:]) / 10
            print(f"  [*] Beacons {i-8}-{i+1}: avg interval {avg_interval:.1f}s")

    # Beacon statistics
    avg_total = sum(beacon_times) / len(beacon_times)
    print(f"\n  [+] {BEACON_COUNT} beacons sent over ~{sum(beacon_times)//60} minutes")
    print(f"  [+] Average interval: {avg_total:.1f}s (configured: {BEACON_INTERVAL}s)")
    print(f"  [{Fore.RED}BEACONING{Style.RESET_ALL}] Regular C2 callback pattern established\n")

    return logs


def phase_4_command_execution(log_gen: LogGenerator) -> list[str]:
    """Phase 4: Remote command execution via C2 channel.

    The C2 server sends commands to the RAT, which executes them
    locally and sends results back. Commands include enumeration,
    credential access, and file discovery.
    """
    print(f"{Fore.YELLOW}[Phase 4] Remote Command Execution{Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(120)

    for cmd_info in C2_COMMANDS:
        log_gen.advance_time(random.randint(15, 45))

        # C2 sends command (beacon response with tasking)
        logs.append(log_gen.json_log("c2_command", {
            "src_ip": C2_SERVER_IP,
            "dst_ip": VICTIM_IP,
            "command_id": cmd_info["id"],
            "command": cmd_info["cmd"],
            "description": cmd_info["desc"],
            "direction": "tasking",
        }, severity="critical"))

        # RAT executes command
        logs.append(log_gen.json_log("process_execution", {
            "host": VICTIM_IP,
            "user": VICTIM_USER,
            "command": cmd_info["cmd"],
            "parent_process": "python3",
            "ppid": RAT_PID,
            "pid": random.randint(15000, 30000),
            "source": "rat_execution",
        }, severity="critical"))

        # RAT sends results back to C2
        logs.append(log_gen.json_log("c2_response", {
            "src_ip": VICTIM_IP,
            "dst_ip": C2_SERVER_IP,
            "command_id": cmd_info["id"],
            "response_size": random.randint(256, 8192),
            "direction": "exfil",
        }, severity="critical"))

        print(f"  [!] Executed [{cmd_info['id']}]: {cmd_info['desc']}")

    # IDS alert for C2 command execution
    logs.append(log_gen.ids_alert(
        VICTIM_IP, C2_SERVER_IP,
        "RAT command-and-control communication detected",
        sid=9100003, severity=1
    ))

    print(f"  [{Fore.RED}C2 EXEC{Style.RESET_ALL}] {len(C2_COMMANDS)} commands executed via RAT\n")

    return logs


def phase_5_data_collection(log_gen: LogGenerator) -> list[str]:
    """Phase 5: Data collection -- keylogging, screenshots, file harvesting.

    The RAT activates data collection modules to capture keystrokes,
    take periodic screenshots, and harvest sensitive files.
    """
    print(f"{Fore.YELLOW}[Phase 5] Data Collection (Keylog + Screenshots + Files){Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(300)

    # Keylogger activation
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": "python3 -c 'import pynput; ...'",
        "parent_process": "python3",
        "ppid": RAT_PID,
        "pid": random.randint(20000, 25000),
        "module": "keylogger",
    }, severity="critical"))

    logs.append(log_gen.json_log("rat_module", {
        "host": VICTIM_IP,
        "module": "keylogger",
        "status": "active",
        "output_file": f"/home/{VICTIM_USER}/.local/share/.sys_update/.keys.log",
        "capture_interval": 30,
    }, severity="critical"))

    print(f"  [+] Keylogger activated")

    # Screenshot capture (simulated periodic captures)
    for i in range(5):
        log_gen.advance_time(random.randint(60, 120))
        logs.append(log_gen.json_log("rat_module", {
            "host": VICTIM_IP,
            "module": "screenshot",
            "status": "captured",
            "output_file": f"/home/{VICTIM_USER}/.local/share/.sys_update/.scr_{i+1}.png",
            "size_bytes": random.randint(200000, 800000),
        }, severity="critical"))

    print(f"  [+] 5 screenshots captured")

    # File harvesting from user's home directory
    log_gen.advance_time(60)
    sensitive_files = [
        f"/home/{VICTIM_USER}/Documents/project_proposal.docx",
        f"/home/{VICTIM_USER}/Documents/budget_2026.xlsx",
        f"/home/{VICTIM_USER}/Documents/client_contacts.csv",
        f"/home/{VICTIM_USER}/.ssh/id_rsa",
        f"/home/{VICTIM_USER}/.mozilla/firefox/profiles.ini",
        f"/home/{VICTIM_USER}/.config/chromium/Default/Login Data",
    ]

    for fpath in sensitive_files:
        log_gen.advance_time(random.randint(2, 8))
        logs.append(log_gen.json_log("file_access", {
            "host": VICTIM_IP,
            "user": VICTIM_USER,
            "path": fpath,
            "action": "read",
            "size_bytes": random.randint(5000, 500000),
            "source": "rat_harvester",
        }, severity="critical"))

    print(f"  [+] {len(sensitive_files)} sensitive files harvested")

    # Data staging
    log_gen.advance_time(30)
    staged_archive = f"/home/{VICTIM_USER}/.local/share/.sys_update/.data_pkg.tar.gz"
    staged_size = random.randint(5000000, 15000000)

    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"tar czf {staged_archive} /home/{VICTIM_USER}/Documents/ /home/{VICTIM_USER}/.ssh/",
        "parent_process": "python3",
        "ppid": RAT_PID,
        "pid": random.randint(25000, 30000),
    }, severity="critical"))

    logs.append(log_gen.json_log("file_create", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "path": staged_archive,
        "size_bytes": staged_size,
        "file_type": "application/gzip",
    }, severity="critical"))

    print(f"  [+] Data staged: {staged_archive} ({staged_size // (1024*1024)} MB)")
    print(f"  [{Fore.RED}COLLECTED{Style.RESET_ALL}] Keylog + screenshots + files staged for exfil\n")

    return logs


def phase_6_exfiltration(log_gen: LogGenerator) -> list[str]:
    """Phase 6: Data exfiltration over C2 channel.

    The RAT uploads the staged data package and collected artifacts
    to the C2 server using the existing HTTPS C2 channel, splitting
    into chunks to avoid size-based detection.
    """
    print(f"{Fore.YELLOW}[Phase 6] Data Exfiltration over C2 Channel{Style.RESET_ALL}")
    print(f"  Destination: {C2_SERVER_IP} ({C2_DOMAIN})")
    logs = []

    log_gen.advance_time(180)

    # Exfiltration uploads (chunked)
    exfil_items = [
        {"name": "keylog data", "size": random.randint(50000, 200000)},
        {"name": "screenshots", "size": random.randint(2000000, 4000000)},
        {"name": "documents archive", "size": random.randint(5000000, 15000000)},
        {"name": "SSH keys", "size": random.randint(5000, 20000)},
        {"name": "browser credentials", "size": random.randint(100000, 500000)},
    ]

    total_exfil = 0
    for item in exfil_items:
        log_gen.advance_time(random.randint(30, 90))
        total_exfil += item["size"]

        # C2 channel upload
        logs.append(log_gen.firewall_log(
            VICTIM_IP, C2_SERVER_IP,
            random.randint(40000, 65535), HTTPS_PORT,
            action="allow", protocol="TCP"
        ))

        logs.append(log_gen.json_log("c2_exfiltration", {
            "src_ip": VICTIM_IP,
            "dst_ip": C2_SERVER_IP,
            "data_type": item["name"],
            "size_bytes": item["size"],
            "method": "HTTPS POST",
            "path": "/api/v2/upload",
            "chunks": max(1, item["size"] // 1048576),
            "encrypted": True,
        }, severity="critical"))

        # Network flow record
        logs.append(log_gen.json_log("netflow", {
            "src_ip": VICTIM_IP,
            "dst_ip": C2_SERVER_IP,
            "src_port": random.randint(40000, 65535),
            "dst_port": HTTPS_PORT,
            "protocol": "TCP",
            "bytes_sent": item["size"],
            "bytes_received": random.randint(100, 500),
            "duration_seconds": item["size"] // 500000 + 1,
        }, severity="critical"))

        print(f"  [!] Exfiltrated: {item['name']} ({item['size'] // 1024} KB)")

    # IDS alert for data exfiltration
    logs.append(log_gen.ids_alert(
        VICTIM_IP, C2_SERVER_IP,
        "Data exfiltration over C2 channel - large HTTPS upload",
        sid=9100004, severity=1
    ))

    # Cleanup
    log_gen.advance_time(60)
    logs.append(log_gen.json_log("process_execution", {
        "host": VICTIM_IP,
        "user": VICTIM_USER,
        "command": f"rm -rf /home/{VICTIM_USER}/.local/share/.sys_update/.data_pkg.tar.gz "
                   f"/home/{VICTIM_USER}/.local/share/.sys_update/.scr_*.png "
                   f"/home/{VICTIM_USER}/.local/share/.sys_update/.keys.log",
        "parent_process": "python3",
        "ppid": RAT_PID,
        "pid": random.randint(25000, 30000),
    }, severity="warning"))

    total_mb = total_exfil / (1024 * 1024)
    print(f"\n  [!] Total exfiltrated: {total_mb:.1f} MB over C2 channel")
    print(f"  [+] Local artifacts cleaned up")
    print(f"  [{Fore.RED}EXFILTRATED{Style.RESET_ALL}] All collected data sent to C2\n")

    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host=f"ws-{VICTIM_USER.replace('.', '-')}")
    all_logs = []

    # Execute all six RAT phases
    all_logs.extend(phase_1_rat_delivery(log_gen))
    all_logs.extend(phase_2_rat_installation(log_gen))
    all_logs.extend(phase_3_c2_beaconing(log_gen))
    all_logs.extend(phase_4_command_execution(log_gen))
    all_logs.extend(phase_5_data_collection(log_gen))
    all_logs.extend(phase_6_exfiltration(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "apt_rat_campaign.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Summary
    print(f"{Fore.GREEN}{'='*62}")
    print(f"  APT RAT Simulation Complete")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Total log entries:  {len(all_logs)}")
    print(f"  Output file:        {log_file}")
    print(f"  Victim:             {VICTIM_USER} ({VICTIM_IP})")
    print(f"  C2 server:          {C2_SERVER_IP} ({C2_DOMAIN})")
    print(f"  RAT PID:            {RAT_PID}")
    print(f"  Beacon count:       {BEACON_COUNT} (interval: {BEACON_INTERVAL}s)")
    print(f"\n  RAT lifecycle phases:")
    print(f"    1. Delivery (phishing with trojanized document)")
    print(f"    2. Installation (hidden dir + cron + .bashrc)")
    print(f"    3. C2 beaconing ({BEACON_COUNT} callbacks at ~{BEACON_INTERVAL}s)")
    print(f"    4. Command execution ({len(C2_COMMANDS)} remote commands)")
    print(f"    5. Data collection (keylog + screenshots + files)")
    print(f"    6. Exfiltration (data upload over C2)")
    print(f"\n  Next step: python3 detect/verify_detection.py")

    # Try to send to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "10-apt-rat"},
            all_logs
        )
        print(f"\n  [+] Logs pushed to Loki")
    except Exception:
        print(f"\n  [*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
