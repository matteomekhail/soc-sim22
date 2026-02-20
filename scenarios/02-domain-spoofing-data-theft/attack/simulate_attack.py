#!/usr/bin/env python3
"""
Scenario 02 - Domain Spoofing & Data Theft
===========================================
Simulates an attacker who:
  1. Registers a lookalike domain (acmec0rp.local)
  2. Deploys a cloned corporate login page
  3. Sends phishing emails linking to the fake site
  4. Harvests credentials when victims log in
  5. Uses stolen credentials to access systems and exfiltrate data

MITRE ATT&CK: T1583.001 (Domains), T1071 (App Layer Protocol),
              T1566.002 (Phishing Link), T1078 (Valid Accounts), T1041 (Exfil over C2)

Usage:
    python simulate_attack.py
"""

import json
import os
import random
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Path setup -- allow imports from the project-level wcace_lib package
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib import EmailSimulator, LogGenerator, SIEMClient  # noqa: E402

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Graceful fallback when colorama is not installed
    class _Noop:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Noop()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPOOFED_DOMAIN  = "acmec0rp.local"       # Lookalike of acmecorp.local (0 vs o)
PHISHING_DOMAIN = "acmecorp-login.test"   # Hosts the cloned login page
COMPANY_DOMAIN  = "acmecorp.local"        # Legitimate company domain
ATTACKER_IP     = "203.0.113.50"          # Attacker C2 / phishing server IP

PHISHING_SERVER_PORT = 443
CREDENTIAL_ENDPOINT  = f"https://{ATTACKER_IP}:8443/collect"

TARGET_USERS = [
    "john.doe", "jane.smith", "bob.wilson", "alice.chen",
    "carlos.garcia", "emma.johnson",
]
SENSITIVE_FILES = [
    "/data/finance/q4_report.xlsx",
    "/data/hr/employee_records.csv",
    "/data/engineering/source_code.tar.gz",
    "/data/legal/contracts_2026.pdf",
    "/data/executive/board_minutes.docx",
]

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(text: str) -> None:
    width = 60
    print(f"\n{Fore.CYAN}{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}{Style.RESET_ALL}\n")


def phase(num: int, title: str) -> None:
    print(f"{Fore.YELLOW}[Phase {num}] {title}{Style.RESET_ALL}")


def info(msg: str) -> None:
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"  {Fore.RED}[!]{Style.RESET_ALL} {msg}")


def save_logs(logs: list, filename: str) -> str:
    """Save log entries to a file inside LOG_DIR."""
    os.makedirs(LOG_DIR, exist_ok=True)
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "w") as fh:
        for entry in logs:
            if isinstance(entry, dict):
                fh.write(json.dumps(entry) + "\n")
            else:
                fh.write(str(entry) + "\n")
    info(f"Saved {len(logs)} log entries -> {filepath}")
    return filepath


# ---------------------------------------------------------------------------
# Phase 1 -- Register Lookalike Domain
# ---------------------------------------------------------------------------
def phase1_register_domain(log_gen: LogGenerator) -> list:
    phase(1, "Register Lookalike Domain")
    logs = []

    info(f"Attacker registers lookalike domain: {SPOOFED_DOMAIN}")
    logs.append(log_gen.json_log("domain_registration", {
        "registrar": "shady-registrar.test",
        "domain": SPOOFED_DOMAIN,
        "registrant_email": f"admin@{SPOOFED_DOMAIN}",
        "nameservers": [f"ns1.{SPOOFED_DOMAIN}", f"ns2.{SPOOFED_DOMAIN}"],
        "ip_resolved": ATTACKER_IP,
        "whois_privacy": True,
    }, severity="warning"))

    info(f"DNS A record created: {SPOOFED_DOMAIN} -> {ATTACKER_IP}")
    logs.append(log_gen.dns_query_log(ATTACKER_IP, SPOOFED_DOMAIN, "A", ATTACKER_IP))

    info(f"Phishing domain configured: {PHISHING_DOMAIN} -> {ATTACKER_IP}")
    logs.append(log_gen.dns_query_log(ATTACKER_IP, PHISHING_DOMAIN, "A", ATTACKER_IP))
    logs.append(log_gen.json_log("domain_registration", {
        "registrar": "shady-registrar.test",
        "domain": PHISHING_DOMAIN,
        "registrant_email": f"admin@{SPOOFED_DOMAIN}",
        "ip_resolved": ATTACKER_IP,
        "ssl_cert_issued": True,
        "ssl_issuer": "Let's Encrypt",
    }, severity="warning"))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Phase 2 -- Deploy Phishing Site
# ---------------------------------------------------------------------------
def phase2_deploy_phishing_site(log_gen: LogGenerator) -> list:
    phase(2, "Deploy Phishing Site (cloned AcmeCorp login)")
    logs = []

    info("Cloning legitimate login page from acmecorp.local")
    logs.append(log_gen.web_access_log(
        ATTACKER_IP, "GET", f"https://{COMPANY_DOMAIN}/login", 200,
        user_agent="HTTrack/3.49"
    ))

    info("Deploying cloned page on phishing-nginx container")
    logs.append(log_gen.json_log("container_deploy", {
        "container": "phishing-nginx",
        "image": "nginx:alpine",
        "domain": PHISHING_DOMAIN,
        "ip": ATTACKER_IP,
        "port": PHISHING_SERVER_PORT,
        "ssl_enabled": True,
        "credential_endpoint": CREDENTIAL_ENDPOINT,
    }))

    info("Injecting credential-harvester.js into cloned page")
    logs.append(log_gen.json_log("file_modification", {
        "file": "/var/www/phishing/index.html",
        "action": "inject_script",
        "script": "credential-harvester.js",
        "attacker_ip": ATTACKER_IP,
    }))

    # Verify phishing site is live
    info(f"Phishing site live at https://{PHISHING_DOMAIN}/login")
    logs.append(log_gen.web_access_log(
        ATTACKER_IP, "GET", f"https://{PHISHING_DOMAIN}/login", 200
    ))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Phase 3 -- Send Phishing Emails
# ---------------------------------------------------------------------------
def phase3_send_phishing_emails(log_gen: LogGenerator,
                                 email_sim: EmailSimulator) -> tuple[list, list]:
    phase(3, "Send Phishing Emails with Link to Fake Site")
    logs = []
    emails = []

    phishing_link = f"https://{PHISHING_DOMAIN}/login?ref=security-update"

    for user in TARGET_USERS:
        to_addr = f"{user}@{COMPANY_DOMAIN}"
        info(f"Sending phishing email to {to_addr}")

        email = email_sim.generate_email(
            from_addr=f"it-security@{SPOOFED_DOMAIN}",
            to_addr=to_addr,
            subject="[Action Required] Mandatory Password Reset - Security Update",
            body=(
                f"Dear {user.replace('.', ' ').title()},\n\n"
                f"As part of our ongoing security improvements, all employees must "
                f"reset their passwords by end of business today.\n\n"
                f"Please click the link below to verify your identity and set a new "
                f"password:\n\n"
                f"  {phishing_link}\n\n"
                f"Failure to comply will result in account suspension.\n\n"
                f"Best regards,\n"
                f"AcmeCorp IT Security Team"
            ),
            headers={
                "Reply-To": f"it-security@{SPOOFED_DOMAIN}",
                "X-Originating-IP": ATTACKER_IP,
            },
        )
        # Override SPF/DKIM/DMARC to show failure (spoofed domain)
        email["spf_result"] = "fail"
        email["dkim_result"] = "fail"
        email["dmarc_result"] = "fail"
        email["suspicious_indicators"] = [
            f"Sender domain {SPOOFED_DOMAIN} is visually similar to {COMPANY_DOMAIN}",
            "SPF check failed",
            "DKIM signature invalid",
            "DMARC policy violation",
            "Contains external link to newly registered domain",
            "Urgency language: 'account suspension'",
        ]
        emails.append(email)

        # DNS query log -- victim resolving phishing domain
        logs.append(log_gen.dns_query_log(
            f"10.0.0.{random.randint(100, 119)}", PHISHING_DOMAIN, "A", ATTACKER_IP
        ))

    time.sleep(0.3)
    return logs, emails


# ---------------------------------------------------------------------------
# Phase 4 -- Victims Enter Credentials on Fake Site
# ---------------------------------------------------------------------------
def phase4_credential_harvesting(log_gen: LogGenerator) -> list:
    phase(4, "Credential Harvesting -- Users Submit Credentials")
    logs = []

    victims_who_clicked = random.sample(TARGET_USERS, k=min(4, len(TARGET_USERS)))

    for user in victims_who_clicked:
        src_ip = f"10.0.0.{random.randint(100, 119)}"
        info(f"Victim {user} clicks phishing link from {src_ip}")

        # Victim loads the phishing page
        logs.append(log_gen.web_access_log(
            src_ip, "GET", f"https://{PHISHING_DOMAIN}/login?ref=security-update", 200,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        ))

        # Page-load beacon to attacker
        logs.append(log_gen.json_log("credential_harvest", {
            "event": "page_load",
            "src_ip": src_ip,
            "phishing_domain": PHISHING_DOMAIN,
            "campaign_id": "sc02-domain-spoof",
        }))

        # Victim submits credentials
        warn(f"Victim {user} submits credentials on fake login page")
        logs.append(log_gen.web_access_log(
            src_ip, "POST", f"https://{PHISHING_DOMAIN}/login", 302,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        ))

        logs.append(log_gen.json_log("credential_harvest", {
            "event": "credentials_captured",
            "src_ip": src_ip,
            "username": f"{user}@{COMPANY_DOMAIN}",
            "phishing_domain": PHISHING_DOMAIN,
            "attacker_endpoint": CREDENTIAL_ENDPOINT,
            "campaign_id": "sc02-domain-spoof",
        }, severity="critical"))

        # Exfiltration of credentials to attacker server
        logs.append(log_gen.firewall_log(
            src_ip, ATTACKER_IP,
            random.randint(49152, 65535), 8443, action="allow", protocol="TCP"
        ))

        # Redirect victim to legitimate site (so they don't suspect)
        logs.append(log_gen.web_access_log(
            src_ip, "GET", f"https://{COMPANY_DOMAIN}/login?session_expired=1", 200
        ))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Phase 5 -- Attacker Uses Stolen Credentials & Exfiltrates Data
# ---------------------------------------------------------------------------
def phase5_data_exfiltration(log_gen: LogGenerator) -> list:
    phase(5, "Attacker Uses Stolen Credentials -- Data Exfiltration")
    logs = []

    # Pick a victim whose credentials were stolen
    compromised_user = random.choice(TARGET_USERS[:4])
    info(f"Attacker logs in as {compromised_user} using stolen credentials")

    # Successful auth from attacker IP (anomalous)
    logs.append(log_gen.auth_success(compromised_user, ATTACKER_IP, method="password"))
    logs.append(log_gen.json_log("authentication", {
        "user": compromised_user,
        "src_ip": ATTACKER_IP,
        "result": "success",
        "method": "password",
        "location": "Unknown / External",
        "anomaly": "Login from external IP not seen before for this user",
    }, severity="critical"))

    # VPN or web portal access
    logs.append(log_gen.web_access_log(
        ATTACKER_IP, "POST", f"https://{COMPANY_DOMAIN}/vpn/login", 200
    ))

    # Access sensitive files
    info("Attacker accessing sensitive internal files")
    for filepath in SENSITIVE_FILES:
        logs.append(log_gen.file_access(compromised_user, filepath, action="read"))
        logs.append(log_gen.json_log("data_access", {
            "user": compromised_user,
            "src_ip": ATTACKER_IP,
            "file": filepath,
            "action": "download",
            "size_bytes": random.randint(50_000, 10_000_000),
        }, severity="warning"))

    # Data exfiltration over HTTPS
    warn("Exfiltrating data to attacker-controlled server")
    exfil_logs = log_gen.data_exfiltration_sequence(
        user=compromised_user,
        src_ip=ATTACKER_IP,
        files=SENSITIVE_FILES,
        dst_ip=ATTACKER_IP,
    )
    logs.extend(exfil_logs)

    # Large outbound data transfer alert
    logs.append(log_gen.json_log("data_transfer_anomaly", {
        "user": compromised_user,
        "src_ip": "10.0.0.20",  # File server
        "dst_ip": ATTACKER_IP,
        "total_bytes": random.randint(50_000_000, 200_000_000),
        "protocol": "HTTPS",
        "duration_seconds": random.randint(120, 600),
        "anomaly": "Unusually large outbound transfer to external IP",
    }, severity="critical"))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    banner("Scenario 02: Domain Spoofing & Data Theft")
    print(f"  {Fore.WHITE}MITRE ATT&CK:{Style.RESET_ALL} T1583.001, T1071, T1566.002, T1078, T1041")
    print(f"  {Fore.WHITE}Spoofed Domain:{Style.RESET_ALL} {SPOOFED_DOMAIN}")
    print(f"  {Fore.WHITE}Phishing Domain:{Style.RESET_ALL} {PHISHING_DOMAIN}")
    print(f"  {Fore.WHITE}Attacker IP:{Style.RESET_ALL} {ATTACKER_IP}")
    print(f"  {Fore.WHITE}Company Domain:{Style.RESET_ALL} {COMPANY_DOMAIN}")
    print()

    log_gen   = LogGenerator(source_host="soc-sim-sc02")
    email_sim = EmailSimulator(domain=COMPANY_DOMAIN)
    all_logs: list = []

    # Phase 1
    logs_p1 = phase1_register_domain(log_gen)
    all_logs.extend(logs_p1)

    # Phase 2
    logs_p2 = phase2_deploy_phishing_site(log_gen)
    all_logs.extend(logs_p2)

    # Phase 3
    logs_p3, emails = phase3_send_phishing_emails(log_gen, email_sim)
    all_logs.extend(logs_p3)

    # Phase 4
    logs_p4 = phase4_credential_harvesting(log_gen)
    all_logs.extend(logs_p4)

    # Phase 5
    logs_p5 = phase5_data_exfiltration(log_gen)
    all_logs.extend(logs_p5)

    # --- Save all logs ---
    banner("Saving Logs")
    save_logs(all_logs, "attack_simulation.json")
    save_logs(emails, "phishing_emails.json")
    save_logs(logs_p1, "phase1_domain_registration.json")
    save_logs(logs_p2, "phase2_phishing_deploy.json")
    save_logs(logs_p3, "phase3_phishing_emails_dns.json")
    save_logs(logs_p4, "phase4_credential_harvesting.json")
    save_logs(logs_p5, "phase5_data_exfiltration.json")

    # Summary
    banner("Simulation Complete")
    print(f"  {Fore.GREEN}Total log entries generated:{Style.RESET_ALL} {len(all_logs)}")
    print(f"  {Fore.GREEN}Phishing emails sent:{Style.RESET_ALL}       {len(emails)}")
    print(f"  {Fore.GREEN}Log directory:{Style.RESET_ALL}              {os.path.abspath(LOG_DIR)}")
    print()


if __name__ == "__main__":
    main()
