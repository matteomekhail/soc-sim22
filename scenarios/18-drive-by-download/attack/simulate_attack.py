#!/usr/bin/env python3
"""
Scenario 18: Drive-By Download Attack Simulation.

Full attack chain:
  Phase 1 - Compromised advertisement network serves malicious ad
  Phase 2 - User visits legitimate site with compromised ad iframe
  Phase 3 - Exploit kit probes browser version and plugins
  Phase 4 - Malicious download triggered via browser exploit
  Phase 5 - Payload execution simulated on victim workstation

SAFETY: No actual exploit kits or downloads are performed -- all activity
is simulated through realistic log generation.
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
    ATTACKER_IP, ATTACKER_IPS, C2_SERVER_IP, C2_DOMAIN,
    COMPANY_DOMAIN, REGULAR_USERS, WORKSTATION_IPS,
    WEB_SERVER_IP, MITRE,
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Legitimate websites the user visits
LEGIT_SITES = [
    "news-daily.test",
    "techblog-central.test",
    "finance-report.test",
]

# Compromised ad network
AD_NETWORK_DOMAIN = "ads.tracknet-media.test"
AD_NETWORK_IP = ATTACKER_IPS[0]

# Exploit kit infrastructure
EXPLOIT_KIT_DOMAIN = "cdn-static.clickserv.test"
EXPLOIT_KIT_LANDING = "gate.exploitkit.test"
EXPLOIT_KIT_IP = ATTACKER_IPS[1]

# Payload delivery
PAYLOAD_DOMAIN = "dl.softupdate.test"
PAYLOAD_IP = ATTACKER_IPS[2]

# Victim details
VICTIM_USER = random.choice(REGULAR_USERS)
VICTIM_IP = random.choice(WORKSTATION_IPS)

# Browser user agents for fingerprinting
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)

# Exploit kit probing URLs
PROBE_PATHS = [
    "/check?p=java&v=8.0.291",
    "/check?p=flash&v=32.0.0.445",
    "/check?p=pdf&v=2021.001",
    "/check?p=silverlight&v=5.1.50918",
    "/check?p=browser&v=Chrome/91.0",
    "/check?p=os&v=Win10/x64",
    "/gate?id=78a3c&t=vuln&e=CVE-2021-30551",
]

# Malicious HTML with hidden iframe (sample content for logging)
MALICIOUS_AD_HTML = """
<div id="ad-banner" style="width:728px;height:90px;">
  <img src="https://ads.tracknet-media.test/img/banner_sale.jpg" />
  <!-- Hidden exploit kit iframe injected by compromised ad network -->
  <iframe src="https://gate.exploitkit.test/landing?id=78a3c"
          width="0" height="0" style="display:none;"></iframe>
</div>
"""


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 18: Drive-By Download Simulation             |
|  Attack: Malicious Ad -> Exploit Kit -> Drive-By Download    |
|  Victim: {VICTIM_USER + '@' + COMPANY_DOMAIN:<50s}|
|  WARNING: Educational use only                               |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Phase 1: Compromised Ad Network
# ---------------------------------------------------------------------------

def phase_1_compromised_ad(log_gen: LogGenerator) -> list[str]:
    """Simulate compromised ad network injecting malicious ad content."""
    print(f"{Fore.YELLOW}[Phase 1] Compromised Advertisement Network{Style.RESET_ALL}")
    logs = []

    print(f"  Ad network: {AD_NETWORK_DOMAIN} ({AD_NETWORK_IP})")
    print(f"  Exploit kit: {EXPLOIT_KIT_DOMAIN} ({EXPLOIT_KIT_IP})")
    print(f"  Payload server: {PAYLOAD_DOMAIN} ({PAYLOAD_IP})\n")

    # Simulate the ad network serving normal ads first (blend in)
    normal_ad_paths = [
        "/serve?zone=top_banner&site=news-daily",
        "/serve?zone=sidebar&site=techblog",
        "/serve?zone=footer&site=finance",
        "/impression?id=ad_12345&fmt=728x90",
        "/impression?id=ad_67890&fmt=300x250",
    ]

    for path in normal_ad_paths:
        logs.append(log_gen.web_access_log(
            random.choice(WORKSTATION_IPS), "GET", path,
            status=200, user_agent=BROWSER_UA,
        ))

    print(f"  [+] Normal ad traffic: {len(normal_ad_paths)} legitimate ad requests")

    # Compromised ad injection -- malicious iframe inserted
    logs.append(log_gen.json_log("ad_injection", {
        "src_ip": AD_NETWORK_IP,
        "dst_ip": WEB_SERVER_IP,
        "ad_network": AD_NETWORK_DOMAIN,
        "injection_type": "iframe",
        "target_domain": EXPLOIT_KIT_LANDING,
        "ad_zone": "top_banner",
        "html_snippet": "<iframe src='...' style='display:none'>",
        "mitre_technique": MITRE["initial_access"]["drive_by"],
    }, severity="critical"))

    print(f"  {Fore.RED}[INJECT]{Style.RESET_ALL} Malicious iframe injected into ad rotation")
    print(f"  {Fore.RED}[INJECT]{Style.RESET_ALL} Target: {EXPLOIT_KIT_LANDING}")

    # Wazuh alert for compromised ad
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100560,
        "rule_level": 10,
        "rule_description": "WCACE S18: Suspicious ad network content - hidden iframe detected",
        "ad_network": AD_NETWORK_DOMAIN,
        "iframe_target": EXPLOIT_KIT_LANDING,
        "mitre": ["T1189"],
    }, severity="warning"))

    print(f"\n  {Fore.CYAN}[*] Ad network compromised -- malicious content in rotation{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 2: User Visits Legitimate Site
# ---------------------------------------------------------------------------

def phase_2_site_visit(log_gen: LogGenerator) -> list[str]:
    """Simulate user visiting a legitimate site that loads the compromised ad."""
    print(f"\n{Fore.YELLOW}[Phase 2] User Visits Legitimate Site{Style.RESET_ALL}")
    logs = []

    target_site = random.choice(LEGIT_SITES)
    print(f"  Victim: {VICTIM_USER} ({VICTIM_IP})")
    print(f"  Browsing: https://{target_site}/\n")

    # Normal page load sequence
    page_resources = [
        (f"https://{target_site}/", 200, "text/html"),
        (f"https://{target_site}/css/style.css", 200, "text/css"),
        (f"https://{target_site}/js/main.js", 200, "application/javascript"),
        (f"https://{target_site}/img/header.png", 200, "image/png"),
        (f"https://{target_site}/api/articles?page=1", 200, "application/json"),
    ]

    for url, status, content_type in page_resources:
        logs.append(log_gen.web_access_log(
            VICTIM_IP, "GET", url, status=status, user_agent=BROWSER_UA,
        ))
        print(f"  [200] GET {url}")

    # Ad network request -- this loads the compromised ad
    ad_url = f"https://{AD_NETWORK_DOMAIN}/serve?zone=top_banner&site={target_site}"
    logs.append(log_gen.web_access_log(
        VICTIM_IP, "GET", ad_url, status=200, user_agent=BROWSER_UA,
    ))
    print(f"\n  {Fore.RED}[AD]{Style.RESET_ALL} GET {ad_url}")

    # Hidden iframe triggers -- loads exploit kit landing page
    ek_url = f"https://{EXPLOIT_KIT_LANDING}/landing?id=78a3c&ref={target_site}"
    logs.append(log_gen.web_access_log(
        VICTIM_IP, "GET", ek_url, status=200, user_agent=BROWSER_UA,
    ))
    print(f"  {Fore.RED}[IFRAME]{Style.RESET_ALL} GET {ek_url} (hidden iframe loaded)")

    # DNS queries for exploit kit domains
    logs.append(log_gen.dns_query_log(
        VICTIM_IP, EXPLOIT_KIT_LANDING, query_type="A",
        response=f"A {EXPLOIT_KIT_IP}",
    ))
    logs.append(log_gen.dns_query_log(
        VICTIM_IP, EXPLOIT_KIT_DOMAIN, query_type="A",
        response=f"A {EXPLOIT_KIT_IP}",
    ))

    # IDS alert for suspicious iframe redirect
    logs.append(log_gen.ids_alert(
        EXPLOIT_KIT_IP, VICTIM_IP,
        "Exploit Kit Landing Page - Suspicious iframe redirect from ad network",
        sid=9180001, severity=1,
    ))

    # Wazuh alert
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100561,
        "rule_level": 11,
        "rule_description": "WCACE S18: Hidden iframe redirect to suspicious domain from ad content",
        "src_ip": VICTIM_IP,
        "legit_site": target_site,
        "redirect_domain": EXPLOIT_KIT_LANDING,
        "mitre": ["T1189"],
    }, severity="warning"))

    print(f"\n  {Fore.CYAN}[*] Victim loaded page with compromised ad -- "
          f"hidden iframe active{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 3: Exploit Kit Browser Probing
# ---------------------------------------------------------------------------

def phase_3_exploit_kit_probing(log_gen: LogGenerator) -> list[str]:
    """Simulate exploit kit fingerprinting browser and plugins."""
    print(f"\n{Fore.YELLOW}[Phase 3] Exploit Kit Browser Probing{Style.RESET_ALL}")
    logs = []

    print(f"  Exploit kit: {EXPLOIT_KIT_LANDING}")
    print(f"  Probing victim browser configuration...\n")

    # Exploit kit sends JavaScript to fingerprint the browser
    for i, probe_path in enumerate(PROBE_PATHS):
        url = f"https://{EXPLOIT_KIT_DOMAIN}{probe_path}"
        status = 200

        # Extract plugin/browser info from path
        parts = probe_path.split("?")[1] if "?" in probe_path else ""

        logs.append(log_gen.web_access_log(
            VICTIM_IP, "GET", url, status=status, user_agent=BROWSER_UA,
        ))

        if "vuln" in probe_path:
            print(f"  {Fore.RED}[VULN]{Style.RESET_ALL} GET {url}")
        else:
            print(f"  [PROBE] GET {url}")

    # Exploit kit sends probing results back via POST
    result_url = f"https://{EXPLOIT_KIT_DOMAIN}/report"
    logs.append(log_gen.web_access_log(
        VICTIM_IP, "POST", result_url, status=200, user_agent=BROWSER_UA,
    ))
    print(f"\n  [POST] Browser fingerprint submitted to {result_url}")

    # Log the fingerprint data
    logs.append(log_gen.json_log("exploit_kit_probe", {
        "src_ip": VICTIM_IP,
        "dst_ip": EXPLOIT_KIT_IP,
        "exploit_kit_domain": EXPLOIT_KIT_DOMAIN,
        "browser": "Chrome/91.0",
        "os": "Windows 10 x64",
        "plugins_detected": {
            "java": "8.0.291",
            "flash": "32.0.0.445",
            "pdf_reader": "2021.001",
        },
        "vulnerability_found": "CVE-2021-30551",
        "mitre_technique": MITRE["execution"]["exploitation_client"],
    }, severity="critical"))

    # IDS alerts for exploit kit probing
    logs.append(log_gen.ids_alert(
        EXPLOIT_KIT_IP, VICTIM_IP,
        "Exploit Kit Probing: Multiple plugin version checks detected",
        sid=9180002, severity=1,
    ))
    logs.append(log_gen.ids_alert(
        EXPLOIT_KIT_IP, VICTIM_IP,
        "Exploit Kit: CVE-2021-30551 exploit attempt detected",
        sid=9180003, severity=1,
    ))

    # Wazuh alert
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100562,
        "rule_level": 12,
        "rule_description": "WCACE S18: Exploit kit browser fingerprinting detected",
        "src_ip": VICTIM_IP,
        "exploit_kit_domain": EXPLOIT_KIT_DOMAIN,
        "probes": len(PROBE_PATHS),
        "vulnerability_targeted": "CVE-2021-30551",
        "mitre": ["T1203"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Browser fingerprinted -- "
          f"vulnerability CVE-2021-30551 identified{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 4: Malicious Download Triggered
# ---------------------------------------------------------------------------

def phase_4_malicious_download(log_gen: LogGenerator) -> list[str]:
    """Simulate drive-by download triggered by browser exploit."""
    print(f"\n{Fore.YELLOW}[Phase 4] Malicious Download Triggered{Style.RESET_ALL}")
    logs = []

    # Exploit triggers -- browser vulnerability exploited
    exploit_url = (
        f"https://{EXPLOIT_KIT_DOMAIN}/exploit?"
        f"cve=CVE-2021-30551&t=chrome&v=91"
    )
    logs.append(log_gen.web_access_log(
        VICTIM_IP, "GET", exploit_url, status=200, user_agent=BROWSER_UA,
    ))
    print(f"  {Fore.RED}[EXPLOIT]{Style.RESET_ALL} Browser exploit triggered: CVE-2021-30551")

    # Shellcode execution redirects to payload download
    payload_url = f"https://{PAYLOAD_DOMAIN}/update/kb5001330.exe"
    logs.append(log_gen.web_access_log(
        VICTIM_IP, "GET", payload_url, status=200, user_agent=BROWSER_UA,
    ))
    print(f"  {Fore.RED}[DOWNLOAD]{Style.RESET_ALL} Payload downloaded: {payload_url}")

    # DNS query for payload domain
    logs.append(log_gen.dns_query_log(
        VICTIM_IP, PAYLOAD_DOMAIN, query_type="A",
        response=f"A {PAYLOAD_IP}",
    ))

    # Firewall log for the download connection
    logs.append(log_gen.firewall_log(
        VICTIM_IP, PAYLOAD_IP,
        random.randint(49152, 65535), 443,
        action="allow", protocol="TCP",
    ))

    # Log the file creation on disk
    payload_hash = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" + "0" * 32
    logs.append(log_gen.json_log("file_creation", {
        "user": VICTIM_USER,
        "src_ip": VICTIM_IP,
        "file_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\kb5001330.exe",
        "file_size": random.randint(150000, 500000),
        "file_hash_sha256": payload_hash,
        "download_url": payload_url,
        "content_type": "application/x-msdownload",
        "mitre_technique": MITRE["initial_access"]["drive_by"],
    }, severity="critical"))

    print(f"  {Fore.RED}[FILE]{Style.RESET_ALL} Payload saved: "
          f"C:\\Users\\victim\\AppData\\Local\\Temp\\kb5001330.exe")
    print(f"  {Fore.RED}[FILE]{Style.RESET_ALL} SHA-256: {payload_hash[:32]}...")

    # IDS alerts
    logs.append(log_gen.ids_alert(
        PAYLOAD_IP, VICTIM_IP,
        "Drive-By Download: Executable downloaded via exploit kit",
        sid=9180004, severity=1,
    ))
    logs.append(log_gen.ids_alert(
        PAYLOAD_IP, VICTIM_IP,
        "Suspicious download: PE executable disguised as Windows update",
        sid=9180005, severity=1,
    ))

    # Wazuh alerts
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100564,
        "rule_level": 14,
        "rule_description": "WCACE S18: Drive-by download detected - executable from exploit kit",
        "src_ip": VICTIM_IP,
        "download_url": payload_url,
        "file_hash": payload_hash,
        "mitre": ["T1189", "T1203"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Drive-by download complete -- "
          f"payload on victim disk{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 5: Payload Execution
# ---------------------------------------------------------------------------

def phase_5_payload_execution(log_gen: LogGenerator) -> list[str]:
    """Simulate payload execution and C2 communication."""
    print(f"\n{Fore.YELLOW}[Phase 5] Payload Execution{Style.RESET_ALL}")
    logs = []

    # Process execution
    logs.append(log_gen.json_log("process_execution", {
        "user": VICTIM_USER,
        "src_ip": VICTIM_IP,
        "process": "kb5001330.exe",
        "parent_process": "chrome.exe",
        "command_line": "kb5001330.exe /silent /norestart",
        "pid": random.randint(4000, 9999),
        "ppid": random.randint(1000, 3999),
        "mitre_technique": MITRE["execution"]["user_execution"],
    }, severity="critical"))
    print(f"  {Fore.RED}[EXEC]{Style.RESET_ALL} kb5001330.exe launched by chrome.exe")

    # Payload drops persistence mechanism
    logs.append(log_gen.json_log("registry_modification", {
        "user": VICTIM_USER,
        "src_ip": VICTIM_IP,
        "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "WindowsUpdateSvc",
        "value_data": "C:\\Users\\victim\\AppData\\Local\\Temp\\kb5001330.exe",
        "process": "kb5001330.exe",
    }, severity="critical"))
    print(f"  {Fore.RED}[PERSIST]{Style.RESET_ALL} Registry Run key added for persistence")

    # C2 communication -- beacon to attacker server
    c2_endpoints = [
        f"https://{C2_DOMAIN}/api/v2/checkin",
        f"https://{C2_DOMAIN}/api/v2/tasks",
        f"https://{C2_DOMAIN}/api/v2/report",
    ]

    for endpoint in c2_endpoints:
        logs.append(log_gen.web_access_log(
            VICTIM_IP, "POST", endpoint, status=200,
            user_agent="Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)",
        ))
        print(f"  {Fore.RED}[C2]{Style.RESET_ALL} POST {endpoint}")

    # DNS query for C2 domain
    logs.append(log_gen.dns_query_log(
        VICTIM_IP, C2_DOMAIN, query_type="A",
        response=f"A {C2_SERVER_IP}",
    ))

    # Firewall log for C2 communication
    logs.append(log_gen.firewall_log(
        VICTIM_IP, C2_SERVER_IP,
        random.randint(49152, 65535), 443,
        action="allow", protocol="TCP",
    ))

    # System information exfiltrated to C2
    logs.append(log_gen.json_log("data_transfer", {
        "src_ip": VICTIM_IP,
        "dst_ip": C2_SERVER_IP,
        "protocol": "HTTPS",
        "bytes_sent": random.randint(1000, 5000),
        "bytes_received": random.randint(200, 1000),
        "content": "system_info_beacon",
        "mitre_technique": MITRE["command_and_control"]["app_layer"],
    }, severity="critical"))

    # IDS alert for C2 beacon
    logs.append(log_gen.ids_alert(
        VICTIM_IP, C2_SERVER_IP,
        "Drive-By Payload C2: Beacon to known malicious domain",
        sid=9180006, severity=1,
    ))

    # Wazuh alerts
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100566,
        "rule_level": 13,
        "rule_description": "WCACE S18: Suspicious process launched by browser - drive-by payload",
        "src_ip": VICTIM_IP,
        "process": "kb5001330.exe",
        "parent_process": "chrome.exe",
        "mitre": ["T1203", "T1204.002"],
    }, severity="critical"))

    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100567,
        "rule_level": 13,
        "rule_description": "WCACE S18: C2 communication from drive-by download payload",
        "src_ip": VICTIM_IP,
        "dst_ip": C2_SERVER_IP,
        "c2_domain": C2_DOMAIN,
        "mitre": ["T1071.001"],
    }, severity="critical"))

    # Correlation alert: full drive-by kill chain
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100568,
        "rule_level": 15,
        "rule_description": "WCACE S18: Drive-by download kill chain detected - ad to exploit to payload",
        "src_ip": VICTIM_IP,
        "victim_user": VICTIM_USER,
        "kill_chain_phases": [
            "compromised_ad_network",
            "exploit_kit_redirect",
            "browser_fingerprinting",
            "drive_by_download",
            "payload_execution",
            "c2_communication",
        ],
        "mitre": ["T1189", "T1203", "T1071.001"],
    }, severity="critical"))

    print(f"\n  {Fore.CYAN}[*] Payload executed -- C2 communication established{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    log_gen = LogGenerator(source_host="proxy-server")
    all_logs = []

    # Phase 1: Compromised ad network
    logs_p1 = phase_1_compromised_ad(log_gen)
    all_logs.extend(logs_p1)
    time.sleep(0.5)

    # Phase 2: User visits legitimate site
    logs_p2 = phase_2_site_visit(log_gen)
    all_logs.extend(logs_p2)
    time.sleep(0.5)

    # Phase 3: Exploit kit probing
    logs_p3 = phase_3_exploit_kit_probing(log_gen)
    all_logs.extend(logs_p3)
    time.sleep(0.5)

    # Phase 4: Malicious download
    logs_p4 = phase_4_malicious_download(log_gen)
    all_logs.extend(logs_p4)
    time.sleep(0.5)

    # Phase 5: Payload execution
    logs_p5 = phase_5_payload_execution(log_gen)
    all_logs.extend(logs_p5)

    # ---------------------------------------------------------------------------
    # Save logs
    # ---------------------------------------------------------------------------
    os.makedirs(LOG_DIR, exist_ok=True)

    # Save combined attack log
    log_file = os.path.join(LOG_DIR, "drive_by_download_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Save web proxy logs separately
    web_logs = [l for l in all_logs if '"event_type": "web_access"' in l]
    proxy_file = os.path.join(LOG_DIR, "proxy_logs.jsonl")
    SIEMClient.write_logs_to_file(web_logs, proxy_file)

    # Save wazuh alerts separately
    wazuh_alerts = [l for l in all_logs if "wazuh_alert" in l]
    wazuh_file = os.path.join(LOG_DIR, "wazuh_alerts.jsonl")
    SIEMClient.write_logs_to_file(wazuh_alerts, wazuh_file)

    # Save malicious ad HTML sample
    html_file = os.path.join(LOG_DIR, "malicious_ad_sample.html")
    with open(html_file, "w") as f:
        f.write("<!-- WCACE Scenario 18: Sample malicious ad HTML -->\n")
        f.write("<!-- FOR EDUCATIONAL PURPOSES ONLY -->\n")
        f.write(MALICIOUS_AD_HTML)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Attack Simulation Complete")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Total log entries:      {len(all_logs)}")
    print(f"  Web proxy entries:      {len(web_logs)}")
    print(f"  Wazuh alert entries:    {len(wazuh_alerts)}")
    print(f"  Victim user:            {VICTIM_USER}")
    print(f"  Victim IP:              {VICTIM_IP}")
    print(f"  Exploit kit domain:     {EXPLOIT_KIT_DOMAIN}")
    print(f"  Payload domain:         {PAYLOAD_DOMAIN}")
    print(f"\n  Log files:")
    print(f"    {log_file}")
    print(f"    {proxy_file}")
    print(f"    {wazuh_file}")
    print(f"    {html_file}")

    # Try to push logs to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "18-drive-by-download"},
            all_logs,
        )
        print(f"\n  {Fore.GREEN}[*] Logs pushed to Loki{Style.RESET_ALL}")
    except Exception:
        print(f"\n  [*] Loki not available -- logs saved locally only")

    print(f"\n  Next: Run detect/verify_detection.py to verify alerts")
    print(f"        Run respond/containment.py for incident response\n")


if __name__ == "__main__":
    main()
