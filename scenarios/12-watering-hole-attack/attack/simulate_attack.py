#!/usr/bin/env python3
"""
Scenario 12: Watering Hole Attack Simulation.

Full attack chain:
  Phase 1 - Website Compromise: Attacker injects malicious JS/iframe into
            a popular industry news site visited by target employees
  Phase 2 - Victim Browsing: Multiple employees visit the compromised website
            during normal work hours
  Phase 3 - Browser Exploitation: Malicious code exploits browser vulnerability
            (CVE-2024-4761), downloads and stages payload
  Phase 4 - Payload Execution: Dropped malware establishes C2 connection and
            sets up persistence via registry run keys
  Phase 5 - Post-Exploitation: C2 beaconing, system reconnaissance, and
            credential harvesting on compromised workstations

SAFETY: No real exploitation occurs. All activity is log generation only.
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
    WORKSTATION_IPS, WATERING_HOLE_DOMAIN, MITRE,
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

COMPROMISED_WEBSITE = WATERING_HOLE_DOMAIN  # "news-portal.test"
COMPROMISED_WEBSITE_IP = "198.51.100.25"  # Documentation range (RFC 5737)
EXPLOIT_CVE = "CVE-2024-4761"  # Chrome V8 type confusion (real CVE ID)
MALICIOUS_JS_PATH = "/assets/js/analytics-v3.min.js"
EXPLOIT_KIT_PATH = "/api/v2/content/feed"
PAYLOAD_URL = f"https://{COMPROMISED_WEBSITE}{EXPLOIT_KIT_PATH}"
PAYLOAD_NAME = "msedge_update.exe"
PERSISTENCE_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# Legitimate pages on the compromised site that employees visit
LEGITIMATE_PAGES = [
    "/",
    "/industry/cybersecurity-trends-2024",
    "/industry/cloud-security-report",
    "/analysis/threat-landscape-q4",
    "/news/breach-notification-update",
    "/research/zero-trust-framework",
]

# User-Agent strings for realism
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# Employees who visit the watering hole site (subset of REGULAR_USERS)
VICTIM_USERS = random.sample(REGULAR_USERS, min(5, len(REGULAR_USERS)))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 12: Watering Hole Attack Simulation          |
|  Attack: Website Compromise -> Drive-by -> C2 -> Recon       |
|  Target: {COMPROMISED_WEBSITE:<52s}|
|  WARNING: Educational use only                               |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Phase 1: Website Compromise
# ---------------------------------------------------------------------------

def phase_1_website_compromise(log_gen: LogGenerator) -> list[str]:
    """Attacker compromises a legitimate industry website by injecting
    malicious JavaScript that loads an exploit kit."""
    print(f"{Fore.YELLOW}[Phase 1] Website Compromise{Style.RESET_ALL}")
    print(f"  Target website: {COMPROMISED_WEBSITE}")
    print(f"  Attacker IP:    {ATTACKER_IP}")
    logs = []

    # Step 1a: Attacker probes the website for vulnerabilities
    print(f"\n  [1a] Attacker probes website for vulnerabilities...")
    probe_paths = [
        "/wp-admin/", "/admin/login", "/.env", "/robots.txt",
        "/xmlrpc.php", "/wp-content/debug.log",
    ]
    for path in probe_paths:
        status = 404 if "debug" in path or ".env" in path else 200
        logs.append(log_gen.web_access_log(
            ATTACKER_IP, "GET", f"https://{COMPROMISED_WEBSITE}{path}",
            status, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)"
        ))
        print(f"    PROBE  {path} -> {status}")

    log_gen.advance_time(120)

    # Step 1b: Attacker exploits CMS vulnerability to inject malicious JS
    print(f"\n  [1b] Attacker injects malicious JavaScript via CMS exploit...")
    logs.append(log_gen.web_access_log(
        ATTACKER_IP, "POST",
        f"https://{COMPROMISED_WEBSITE}/wp-admin/theme-editor.php",
        200, user_agent="python-requests/2.31.0"
    ))
    logs.append(log_gen.json_log("web_modification", {
        "src_ip": ATTACKER_IP,
        "target_site": COMPROMISED_WEBSITE,
        "modified_file": MALICIOUS_JS_PATH,
        "action": "injected_malicious_script",
        "injection_type": "exploit_kit_loader",
        "exploit_kit": "RIG EK variant",
        "mitre_technique": MITRE["initial_access"]["drive_by"],
    }, severity="critical"))

    # Step 1c: Injected JS redirects visitors to exploit kit
    print(f"  Injected: {MALICIOUS_JS_PATH}")
    print(f"  Payload:  Hidden iframe loading exploit kit from {EXPLOIT_KIT_PATH}")
    logs.append(log_gen.json_log("injection_payload", {
        "compromised_site": COMPROMISED_WEBSITE,
        "injected_script": MALICIOUS_JS_PATH,
        "payload_type": "hidden_iframe",
        "exploit_target": EXPLOIT_CVE,
        "description": f"Injected JS loads hidden iframe exploiting {EXPLOIT_CVE} "
                       f"in visitor browsers to deliver {PAYLOAD_NAME}",
    }, severity="critical"))

    # IDS alert: suspicious modification of website
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, COMPROMISED_WEBSITE_IP,
        f"S12: Suspicious web application modification from external IP",
        sid=9120001,
        severity=1,
    ))

    print(f"\n  {Fore.CYAN}[*] Website {COMPROMISED_WEBSITE} compromised with exploit kit loader{Style.RESET_ALL}")
    return logs


# ---------------------------------------------------------------------------
# Phase 2: Victim Browsing
# ---------------------------------------------------------------------------

def phase_2_victim_browsing(log_gen: LogGenerator) -> tuple[list[str], list[dict]]:
    """Multiple employees visit the compromised website during normal work.
    Returns logs and a list of victim dicts for subsequent phases."""
    print(f"\n{Fore.YELLOW}[Phase 2] Victim Browsing{Style.RESET_ALL}")
    print(f"  Employees visiting {COMPROMISED_WEBSITE} during lunch break...\n")
    logs = []
    victims = []

    for i, user in enumerate(VICTIM_USERS):
        ip = WORKSTATION_IPS[i % len(WORKSTATION_IPS)]
        ua = random.choice(USER_AGENTS)
        page = random.choice(LEGITIMATE_PAGES)

        # Normal page visit
        logs.append(log_gen.web_access_log(
            ip, "GET",
            f"https://{COMPROMISED_WEBSITE}{page}",
            200, user_agent=ua,
        ))
        print(f"  [{user:<16s}] GET {COMPROMISED_WEBSITE}{page}")

        # Browser loads the injected malicious JS
        logs.append(log_gen.web_access_log(
            ip, "GET",
            f"https://{COMPROMISED_WEBSITE}{MALICIOUS_JS_PATH}",
            200, user_agent=ua,
        ))

        # DNS query for the compromised site
        logs.append(log_gen.dns_query_log(
            ip, COMPROMISED_WEBSITE, "A", response=COMPROMISED_WEBSITE_IP,
        ))

        # Log the visit event
        logs.append(log_gen.json_log("watering_hole_visit", {
            "user": user,
            "src_ip": ip,
            "website": COMPROMISED_WEBSITE,
            "page": page,
            "user_agent": ua,
            "loaded_scripts": [MALICIOUS_JS_PATH],
            "mitre_technique": MITRE["initial_access"]["drive_by"],
        }, severity="warning"))

        victims.append({
            "user": user,
            "ip": ip,
            "user_agent": ua,
            "page": page,
        })

        log_gen.advance_time(random.randint(30, 180))

    print(f"\n  {Fore.CYAN}[*] {len(victims)} employees visited the "
          f"compromised site{Style.RESET_ALL}")
    return logs, victims


# ---------------------------------------------------------------------------
# Phase 3: Browser Exploitation
# ---------------------------------------------------------------------------

def phase_3_browser_exploitation(log_gen: LogGenerator,
                                  victims: list[dict]) -> tuple[list[str], list[dict]]:
    """Malicious JavaScript exploits browser vulnerability and downloads
    a payload to a subset of visitors (not all browsers are vulnerable)."""
    print(f"\n{Fore.YELLOW}[Phase 3] Browser Exploitation ({EXPLOIT_CVE}){Style.RESET_ALL}")
    print(f"  Exploit kit targets Chrome V8 type confusion vulnerability...\n")
    logs = []
    exploited_victims = []

    for victim in victims:
        is_chrome = "Chrome" in victim["user_agent"]
        is_vulnerable = is_chrome and random.random() > 0.3  # ~70% of Chrome users

        if is_vulnerable:
            marker = f"{Fore.RED}[EXPLOITED]{Style.RESET_ALL}"
            exploited_victims.append(victim)

            # Hidden iframe loads exploit kit
            logs.append(log_gen.web_access_log(
                victim["ip"], "GET",
                f"https://{COMPROMISED_WEBSITE}{EXPLOIT_KIT_PATH}",
                200, user_agent=victim["user_agent"],
            ))

            # Exploit triggers shellcode execution
            logs.append(log_gen.json_log("browser_exploit", {
                "user": victim["user"],
                "src_ip": victim["ip"],
                "vulnerability": EXPLOIT_CVE,
                "browser": "Chrome" if is_chrome else "Firefox",
                "exploit_type": "V8 type confusion",
                "result": "success",
                "payload_url": PAYLOAD_URL,
                "mitre_technique": MITRE["execution"]["exploitation_client"],
            }, severity="critical"))

            # Payload download (drive-by download)
            logs.append(log_gen.json_log("file_download", {
                "user": victim["user"],
                "src_ip": victim["ip"],
                "url": f"https://{COMPROMISED_WEBSITE}/static/updates/{PAYLOAD_NAME}",
                "file_name": PAYLOAD_NAME,
                "file_size": random.randint(245000, 380000),
                "file_hash": "b3a4f7e2c1d8" + "0" * 52,
                "download_method": "drive-by",
                "mitre_technique": MITRE["initial_access"]["drive_by"],
            }, severity="critical"))

            # IDS alert: exploit kit activity
            logs.append(log_gen.ids_alert(
                COMPROMISED_WEBSITE_IP, victim["ip"],
                f"S12: Browser exploit kit delivery ({EXPLOIT_CVE})",
                sid=9120002,
                severity=1,
            ))

            print(f"  {marker} {victim['user']:<16s} ({victim['ip']}) "
                  f"- Chrome exploited, payload downloaded")
        else:
            marker = "[SAFE]"
            reason = "not Chrome" if not is_chrome else "patched version"
            logs.append(log_gen.json_log("browser_exploit", {
                "user": victim["user"],
                "src_ip": victim["ip"],
                "vulnerability": EXPLOIT_CVE,
                "browser": "Chrome" if is_chrome else "Firefox/Safari",
                "result": "failed",
                "reason": reason,
            }, severity="info"))
            print(f"  {marker}      {victim['user']:<16s} ({victim['ip']}) "
                  f"- {reason}")

        log_gen.advance_time(random.randint(5, 30))

    print(f"\n  {Fore.CYAN}[*] {len(exploited_victims)}/{len(victims)} "
          f"visitors exploited{Style.RESET_ALL}")
    return logs, exploited_victims


# ---------------------------------------------------------------------------
# Phase 4: Payload Execution & Persistence
# ---------------------------------------------------------------------------

def phase_4_payload_execution(log_gen: LogGenerator,
                               exploited_victims: list[dict]) -> list[str]:
    """Dropped payload executes, establishes C2 connection, and sets up
    persistence via registry run keys."""
    print(f"\n{Fore.YELLOW}[Phase 4] Payload Execution & Persistence{Style.RESET_ALL}")
    logs = []

    if not exploited_victims:
        print(f"  {Fore.GREEN}[*] No victims exploited -- phase skipped{Style.RESET_ALL}")
        return logs

    for victim in exploited_victims:
        print(f"\n  Victim: {victim['user']}@{COMPANY_DOMAIN} ({victim['ip']})")

        # Step 4a: Payload executes
        pid = random.randint(4000, 9999)
        logs.append(log_gen.json_log("process_execution", {
            "user": victim["user"],
            "src_ip": victim["ip"],
            "process": PAYLOAD_NAME,
            "parent_process": "chrome.exe",
            "command_line": f"C:\\Users\\{victim['user']}\\AppData\\Local\\Temp\\{PAYLOAD_NAME}",
            "pid": pid,
            "mitre_technique": MITRE["execution"]["exploitation_client"],
        }, severity="critical"))
        print(f"    [EXEC]    {PAYLOAD_NAME} (PID {pid}) spawned by chrome.exe")

        # Step 4b: Persistence via registry run key
        logs.append(log_gen.json_log("registry_modification", {
            "user": victim["user"],
            "src_ip": victim["ip"],
            "key": PERSISTENCE_KEY,
            "value_name": "EdgeUpdate",
            "value_data": f"C:\\Users\\{victim['user']}\\AppData\\Roaming\\{PAYLOAD_NAME}",
            "action": "added",
            "process": PAYLOAD_NAME,
            "mitre_technique": MITRE["persistence"]["registry_run"],
        }, severity="critical"))
        print(f"    [PERSIST] Registry run key added: {PERSISTENCE_KEY}\\EdgeUpdate")

        # Step 4c: Copy self to AppData for persistence
        logs.append(log_gen.json_log("file_creation", {
            "user": victim["user"],
            "src_ip": victim["ip"],
            "file_path": f"C:\\Users\\{victim['user']}\\AppData\\Roaming\\{PAYLOAD_NAME}",
            "source": f"C:\\Users\\{victim['user']}\\AppData\\Local\\Temp\\{PAYLOAD_NAME}",
            "file_hash": "b3a4f7e2c1d8" + "0" * 52,
            "process": PAYLOAD_NAME,
        }, severity="critical"))

        # Step 4d: Initial C2 check-in
        logs.append(log_gen.json_log("network_connection", {
            "src_ip": victim["ip"],
            "dst_ip": C2_SERVER_IP,
            "dst_port": 443,
            "protocol": "TLS",
            "process": PAYLOAD_NAME,
            "connection_type": "initial_checkin",
            "bytes_sent": random.randint(200, 600),
            "bytes_received": random.randint(500, 2000),
            "tls_sni": "updates.evil-cdn.test",
            "mitre_technique": MITRE["command_and_control"]["app_layer"],
        }, severity="critical"))
        print(f"    [C2]      Initial check-in -> {C2_SERVER_IP}:443 (TLS)")

        # IDS alert: C2 communication
        logs.append(log_gen.ids_alert(
            victim["ip"], C2_SERVER_IP,
            f"S12: Watering hole payload C2 beacon to {C2_SERVER_IP}",
            sid=9120003,
            severity=1,
        ))

        # Firewall log: outbound C2
        logs.append(log_gen.firewall_log(
            victim["ip"], C2_SERVER_IP,
            random.randint(49152, 65535), 443,
            action="allow", protocol="TCP",
        ))

        log_gen.advance_time(random.randint(10, 60))

    print(f"\n  {Fore.CYAN}[*] {len(exploited_victims)} hosts compromised "
          f"with C2 implant{Style.RESET_ALL}")
    return logs


# ---------------------------------------------------------------------------
# Phase 5: Post-Exploitation
# ---------------------------------------------------------------------------

def phase_5_post_exploitation(log_gen: LogGenerator,
                               exploited_victims: list[dict]) -> list[str]:
    """C2 beaconing, system information discovery, and credential harvesting
    on compromised workstations."""
    print(f"\n{Fore.YELLOW}[Phase 5] Post-Exploitation{Style.RESET_ALL}")
    logs = []

    if not exploited_victims:
        print(f"  {Fore.GREEN}[*] No compromised hosts -- phase skipped{Style.RESET_ALL}")
        return logs

    for victim in exploited_victims:
        print(f"\n  Host: {victim['ip']} ({victim['user']})")

        # Step 5a: C2 beacon (periodic check-in)
        beacon_count = random.randint(3, 6)
        for b in range(beacon_count):
            logs.append(log_gen.json_log("network_connection", {
                "src_ip": victim["ip"],
                "dst_ip": C2_SERVER_IP,
                "dst_port": 443,
                "protocol": "TLS",
                "process": PAYLOAD_NAME,
                "connection_type": "beacon",
                "beacon_interval_seconds": random.randint(55, 65),
                "bytes_sent": random.randint(100, 400),
                "bytes_received": random.randint(100, 800),
                "mitre_technique": MITRE["command_and_control"]["app_layer"],
            }, severity="warning"))
            log_gen.advance_time(random.randint(55, 65))
        print(f"    [BEACON]  {beacon_count} C2 beacons sent")

        # Step 5b: System information discovery
        recon_commands = [
            ("systeminfo", "System information enumeration"),
            ("whoami /all", "Current user and group enumeration"),
            ("net user /domain", "Domain user enumeration"),
            ("net group \"Domain Admins\" /domain", "Domain admin enumeration"),
            ("ipconfig /all", "Network configuration enumeration"),
            ("tasklist /v", "Running processes enumeration"),
        ]
        for cmd, desc in recon_commands:
            logs.append(log_gen.json_log("process_execution", {
                "user": victim["user"],
                "src_ip": victim["ip"],
                "process": "cmd.exe",
                "parent_process": PAYLOAD_NAME,
                "command_line": f"cmd.exe /c {cmd}",
                "pid": random.randint(4000, 9999),
                "description": desc,
                "mitre_technique": MITRE["initial_access"]["drive_by"],  # T1082 not in constants; log T1189 as parent
            }, severity="warning"))
            log_gen.advance_time(random.randint(2, 8))
        print(f"    [RECON]   {len(recon_commands)} discovery commands executed")

        # IDS alert: reconnaissance activity
        logs.append(log_gen.ids_alert(
            victim["ip"], victim["ip"],
            f"S12: Post-exploitation reconnaissance from compromised host",
            sid=9120004,
            severity=2,
        ))

        # Step 5c: Credential harvesting attempt
        logs.append(log_gen.json_log("process_execution", {
            "user": victim["user"],
            "src_ip": victim["ip"],
            "process": "rundll32.exe",
            "parent_process": PAYLOAD_NAME,
            "command_line": "rundll32.exe comsvcs.dll, MiniDump 624 "
                           f"C:\\Users\\{victim['user']}\\AppData\\Local\\Temp\\d.dmp full",
            "pid": random.randint(4000, 9999),
            "description": "LSASS memory dump for credential harvesting",
            "mitre_technique": "T1003.001",
        }, severity="critical"))
        print(f"    [CREDS]   LSASS memory dump attempted")

        # Step 5d: Exfiltrate reconnaissance data over C2
        logs.append(log_gen.json_log("network_connection", {
            "src_ip": victim["ip"],
            "dst_ip": C2_SERVER_IP,
            "dst_port": 443,
            "protocol": "TLS",
            "process": PAYLOAD_NAME,
            "connection_type": "data_exfiltration",
            "bytes_sent": random.randint(5000, 25000),
            "bytes_received": random.randint(100, 500),
            "mitre_technique": MITRE["exfiltration"]["c2_channel"],
        }, severity="critical"))

        # IDS alert: large data transfer to C2
        logs.append(log_gen.ids_alert(
            victim["ip"], C2_SERVER_IP,
            f"S12: Suspicious data exfiltration to C2 server",
            sid=9120005,
            severity=1,
        ))

        print(f"    [EXFIL]   Recon data sent to C2 ({C2_SERVER_IP})")

        log_gen.advance_time(random.randint(30, 120))

    print(f"\n  {Fore.CYAN}[*] Post-exploitation complete on "
          f"{len(exploited_victims)} hosts{Style.RESET_ALL}")
    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    log_gen = LogGenerator(source_host="soc-sim")
    all_logs = []

    # Phase 1: Website Compromise
    logs_p1 = phase_1_website_compromise(log_gen)
    all_logs.extend(logs_p1)
    time.sleep(0.5)

    # Phase 2: Victim Browsing
    logs_p2, victims = phase_2_victim_browsing(log_gen)
    all_logs.extend(logs_p2)
    time.sleep(0.5)

    # Phase 3: Browser Exploitation
    logs_p3, exploited_victims = phase_3_browser_exploitation(log_gen, victims)
    all_logs.extend(logs_p3)
    time.sleep(0.5)

    # Phase 4: Payload Execution & Persistence
    logs_p4 = phase_4_payload_execution(log_gen, exploited_victims)
    all_logs.extend(logs_p4)
    time.sleep(0.5)

    # Phase 5: Post-Exploitation
    logs_p5 = phase_5_post_exploitation(log_gen, exploited_victims)
    all_logs.extend(logs_p5)

    # ---------------------------------------------------------------------------
    # Save logs
    # ---------------------------------------------------------------------------
    os.makedirs(LOG_DIR, exist_ok=True)

    # Combined attack log
    log_file = os.path.join(LOG_DIR, "watering_hole_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Phase-specific logs
    phase_files = {
        "phase1_website_compromise.jsonl": logs_p1,
        "phase2_victim_browsing.jsonl": logs_p2,
        "phase3_browser_exploit.jsonl": logs_p3,
        "phase4_payload_execution.jsonl": logs_p4,
        "phase5_post_exploitation.jsonl": logs_p5,
    }
    for fname, phase_logs in phase_files.items():
        if phase_logs:
            SIEMClient.write_logs_to_file(
                phase_logs, os.path.join(LOG_DIR, fname)
            )

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Watering Hole Attack Simulation Complete")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Total log entries:      {len(all_logs)}")
    print(f"  Employees who visited:  {len(victims)}")
    print(f"  Hosts exploited:        {len(exploited_victims)}")
    print(f"  Compromised website:    {COMPROMISED_WEBSITE}")
    print(f"  Exploit CVE:            {EXPLOIT_CVE}")
    print(f"  C2 server:              {C2_SERVER_IP}")
    print(f"\n  Log files:")
    print(f"    {log_file}")
    for fname in phase_files:
        print(f"    {os.path.join(LOG_DIR, fname)}")

    # Try to push logs to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "12-watering-hole-attack"},
            all_logs,
        )
        print(f"\n  {Fore.GREEN}[*] Logs pushed to Loki{Style.RESET_ALL}")
    except Exception:
        print(f"\n  [*] Loki not available -- logs saved locally only")

    print(f"\n  Next: Run detect/verify_detection.py to verify alerts")
    print(f"        Run respond/containment.py for incident response\n")


if __name__ == "__main__":
    main()
