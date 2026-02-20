#!/usr/bin/env python3
"""
Scenario 08: Phishing & Ransomware Attack Simulation.

Full attack chain:
  Phase 1 - Phishing email delivery with malicious attachment
  Phase 2 - User opens attachment, payload drops to sandbox
  Phase 3 - Ransomware encrypts files in sandbox using Fernet
  Phase 4 - Generate Wazuh FIM alerts for mass file changes

SAFETY: All file operations are restricted to /tmp/wcace-sandbox/ only.
"""

import json
import os
import random
import shutil
import sys
import time
from datetime import datetime

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.email_sim import EmailSimulator
from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import (
    ATTACKER_IP, C2_SERVER_IP, COMPANY_DOMAIN, REGULAR_USERS,
    WORKSTATION_IPS, PHISHING_DOMAIN, MITRE,
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SANDBOX_ROOT = "/tmp/wcace-sandbox"
SANDBOX_DIR = os.path.join(SANDBOX_ROOT, "victim-files")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Sample files that the "victim" would have on their workstation
SAMPLE_FILES = {
    "quarterly_report.docx": "This is a confidential quarterly report with financial projections.",
    "employee_roster.xlsx": "Name,Department,Salary\nJohn Doe,Engineering,95000\nJane Smith,HR,88000",
    "project_plan.pdf": "Project Alpha - Phase 3 deliverables and milestones for Q2.",
    "meeting_notes.txt": "Board meeting notes - discussed merger strategy and upcoming audit.",
    "credentials.csv": "service,username,password\nVPN,admin,Passw0rd!\nDB,root,dbadmin123",
    "client_contracts/acme_contract.docx": "Master services agreement with Acme Corp - $2.4M annual.",
    "client_contracts/globex_nda.pdf": "Non-disclosure agreement with Globex Corporation.",
    "backups/db_dump_2024.sql": "-- MySQL dump\nCREATE TABLE users (id INT, name VARCHAR(100));",
    "backups/config_backup.tar.gz": "binary-config-data-placeholder-content-for-simulation",
    "photos/team_offsite.jpg": "JPEG-placeholder-binary-content-for-simulation",
}

RANSOM_NOTE = """
===============================================================
           YOUR FILES HAVE BEEN ENCRYPTED!
===============================================================

All your documents, photos, databases, and other important
files have been encrypted with military-grade encryption.

To recover your files you need to pay 2.5 BTC to:
  bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

After payment, email proof of payment to:
  decrypt-support@{phishing_domain}

Your unique ID: {victim_id}
Encryption timestamp: {timestamp}

WARNING: Do not attempt to decrypt files yourself.
         Do not rename encrypted files.
         Do not contact law enforcement.

You have 72 hours before the price doubles.
===============================================================

[SIMULATION NOTICE: This is a WCACE SOC training exercise.
 No real encryption or ransom is involved.]
"""


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def verify_sandbox(path: str) -> bool:
    """Verify that the given path is inside the sandbox directory."""
    real_path = os.path.realpath(path)
    sandbox_real = os.path.realpath(SANDBOX_ROOT)
    return real_path.startswith(sandbox_real)


def safety_check():
    """Perform pre-flight safety checks before running simulation."""
    # Ensure we never operate outside sandbox
    if not SANDBOX_ROOT.startswith("/tmp/"):
        print(f"{Fore.RED}[SAFETY] Sandbox must be under /tmp/. Aborting.{Style.RESET_ALL}")
        sys.exit(1)

    # Verify sandbox path does not escape via symlinks
    # On macOS, /tmp is a symlink to /private/tmp, so we check both
    if os.path.exists(SANDBOX_ROOT):
        real = os.path.realpath(SANDBOX_ROOT)
        if not (real.startswith("/tmp/") or real.startswith("/private/tmp/")):
            print(f"{Fore.RED}[SAFETY] Sandbox symlink escape detected. Aborting.{Style.RESET_ALL}")
            sys.exit(1)

    print(f"{Fore.GREEN}[SAFETY] All pre-flight checks passed. "
          f"Sandbox: {SANDBOX_ROOT}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 08: Phishing & Ransomware Simulation         |
|  Attack: Phishing Email -> Attachment -> Ransomware           |
|  Sandbox: {SANDBOX_ROOT:<50s}|
|  WARNING: Educational use only                                |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Phase 1: Phishing Email Generation
# ---------------------------------------------------------------------------

def phase_1_phishing(log_gen: LogGenerator) -> tuple[list[str], list[dict]]:
    """Generate phishing emails targeting employees."""
    print(f"{Fore.YELLOW}[Phase 1] Phishing Email Delivery{Style.RESET_ALL}")
    print(f"  Generating phishing campaign targeting {COMPANY_DOMAIN} employees...\n")

    logs = []
    email_sim = EmailSimulator(domain=COMPANY_DOMAIN)

    # Generate a mix of legitimate and ransomware phishing emails
    emails = email_sim.generate_email_sequence(scenario="ransomware", count=5)

    phishing_emails = []
    for email in emails:
        is_malicious = email.get("spf_result") == "fail"
        marker = f"{Fore.RED}[MALICIOUS]{Style.RESET_ALL}" if is_malicious else "[LEGIT]"
        print(f"  {marker} From: {email['from']:<40s} Subject: {email['subject'][:50]}")

        if is_malicious:
            phishing_emails.append(email)

        # Generate log entry for each email
        log_entry = log_gen.json_log("email_received", {
            "from": email["from"],
            "to": email["to"],
            "subject": email["subject"],
            "spf_result": email.get("spf_result", "pass"),
            "dkim_result": email.get("dkim_result", "pass"),
            "dmarc_result": email.get("dmarc_result", "pass"),
            "attachments": email.get("attachments", []),
            "suspicious": is_malicious,
        }, severity="critical" if is_malicious else "info")
        logs.append(log_entry)

        if is_malicious:
            # IDS alert for phishing
            logs.append(log_gen.ids_alert(
                ATTACKER_IP,
                random.choice(WORKSTATION_IPS),
                f"Phishing email detected: {email['subject'][:40]}",
                sid=9800001,
                severity=1,
            ))

    print(f"\n  {Fore.CYAN}[*] Delivered {len(emails)} emails "
          f"({len(phishing_emails)} malicious){Style.RESET_ALL}")

    return logs, phishing_emails


# ---------------------------------------------------------------------------
# Phase 2: User Opens Attachment (Sandbox Setup)
# ---------------------------------------------------------------------------

def phase_2_open_attachment(log_gen: LogGenerator) -> list[str]:
    """Simulate user opening the phishing attachment -- create sandbox files."""
    print(f"\n{Fore.YELLOW}[Phase 2] User Opens Malicious Attachment{Style.RESET_ALL}")
    logs = []

    victim_user = random.choice(REGULAR_USERS)
    victim_ip = random.choice(WORKSTATION_IPS)
    print(f"  Victim: {victim_user}@{COMPANY_DOMAIN} ({victim_ip})")

    # Clean and create sandbox
    if os.path.exists(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR)
    os.makedirs(SANDBOX_DIR, exist_ok=True)

    print(f"  Creating sample victim files in {SANDBOX_DIR}...")

    for filename, content in SAMPLE_FILES.items():
        filepath = os.path.join(SANDBOX_DIR, filename)
        filedir = os.path.dirname(filepath)

        # Safety check
        if not verify_sandbox(filedir):
            print(f"  {Fore.RED}[SAFETY] Skipping {filename} -- outside sandbox{Style.RESET_ALL}")
            continue

        os.makedirs(filedir, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"    [+] Created: {filename} ({len(content)} bytes)")

    # Log: user execution of malicious attachment
    logs.append(log_gen.json_log("process_execution", {
        "user": victim_user,
        "src_ip": victim_ip,
        "process": "Invoice_2024.pdf.exe",
        "parent_process": "outlook.exe",
        "command_line": "cmd.exe /c Invoice_2024.pdf.exe",
        "pid": random.randint(4000, 9999),
        "mitre_technique": MITRE["execution"]["user_execution"],
    }, severity="critical"))

    # Log: payload drops to disk
    logs.append(log_gen.json_log("file_creation", {
        "user": victim_user,
        "src_ip": victim_ip,
        "file_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_update.exe",
        "file_hash": "a" * 64,  # Simulated SHA-256
        "process": "Invoice_2024.pdf.exe",
    }, severity="critical"))

    # Log: C2 beacon
    logs.append(log_gen.json_log("network_connection", {
        "src_ip": victim_ip,
        "dst_ip": C2_SERVER_IP,
        "dst_port": 443,
        "protocol": "TLS",
        "process": "svchost_update.exe",
        "bytes_sent": random.randint(100, 500),
        "bytes_received": random.randint(200, 2000),
        "mitre_technique": MITRE["command_and_control"]["encrypted"],
    }, severity="critical"))

    # IDS alert: C2 communication
    logs.append(log_gen.ids_alert(
        victim_ip, C2_SERVER_IP,
        "Ransomware C2 beacon detected",
        sid=9800002,
        severity=1,
    ))

    file_count = sum(1 for _ in SAMPLE_FILES)
    print(f"\n  {Fore.CYAN}[*] Sandbox populated with {file_count} files{Style.RESET_ALL}")

    return logs


# ---------------------------------------------------------------------------
# Phase 3: Ransomware Encryption
# ---------------------------------------------------------------------------

def phase_3_encrypt(log_gen: LogGenerator) -> tuple[list[str], str]:
    """Encrypt files in the sandbox using Fernet symmetric encryption."""
    print(f"\n{Fore.YELLOW}[Phase 3] Ransomware Encryption{Style.RESET_ALL}")
    logs = []

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print(f"  {Fore.RED}[!] cryptography package not installed. "
              f"Run: pip install cryptography{Style.RESET_ALL}")
        return logs, ""

    # Generate encryption key (in real ransomware this would be sent to C2)
    key = Fernet.generate_key()
    fernet = Fernet(key)
    key_str = key.decode()

    print(f"  Encryption key: {key_str[:20]}...  (saved for recovery)")
    print(f"  Encrypting files in {SANDBOX_DIR}...\n")

    encrypted_count = 0
    victim_ip = random.choice(WORKSTATION_IPS)

    for root, dirs, files in os.walk(SANDBOX_DIR):
        # Safety: ensure we are still inside sandbox
        if not verify_sandbox(root):
            print(f"  {Fore.RED}[SAFETY] Skipping directory outside sandbox: {root}{Style.RESET_ALL}")
            continue

        for filename in files:
            # Skip already encrypted files and ransom notes
            if filename.endswith(".encrypted") or filename == "RANSOM_NOTE.txt":
                continue

            filepath = os.path.join(root, filename)

            if not verify_sandbox(filepath):
                print(f"  {Fore.RED}[SAFETY] Skipping file outside sandbox: {filepath}{Style.RESET_ALL}")
                continue

            try:
                # Read original file
                with open(filepath, "rb") as f:
                    original_data = f.read()

                # Encrypt
                encrypted_data = fernet.encrypt(original_data)

                # Write encrypted version
                encrypted_path = filepath + ".encrypted"
                with open(encrypted_path, "wb") as f:
                    f.write(encrypted_data)

                # Remove original
                os.remove(filepath)

                encrypted_count += 1
                rel_path = os.path.relpath(filepath, SANDBOX_DIR)
                print(f"    {Fore.RED}[ENCRYPTED]{Style.RESET_ALL} {rel_path} -> {rel_path}.encrypted")

                # Generate FIM alert for each file change
                logs.append(log_gen.json_log("fim_alert", {
                    "src_ip": victim_ip,
                    "file_path": filepath,
                    "action": "deleted",
                    "file_hash_before": "original_" + str(hash(original_data))[-8:],
                    "alert_type": "syscheck",
                    "mitre_technique": MITRE["impact"]["data_encrypted"],
                }, severity="critical"))

                logs.append(log_gen.json_log("fim_alert", {
                    "src_ip": victim_ip,
                    "file_path": encrypted_path,
                    "action": "created",
                    "file_size": len(encrypted_data),
                    "file_extension": ".encrypted",
                    "alert_type": "syscheck",
                    "mitre_technique": MITRE["impact"]["data_encrypted"],
                }, severity="critical"))

            except Exception as e:
                print(f"    [!] Error encrypting {filename}: {e}")

    # Drop ransom note in each directory
    for root, dirs, files in os.walk(SANDBOX_DIR):
        if not verify_sandbox(root):
            continue

        note_path = os.path.join(root, "RANSOM_NOTE.txt")
        victim_id = f"WCACE-{random.randint(100000, 999999)}"
        note_content = RANSOM_NOTE.format(
            phishing_domain=PHISHING_DOMAIN,
            victim_id=victim_id,
            timestamp=datetime.now().isoformat(),
        )
        with open(note_path, "w") as f:
            f.write(note_content)

        # FIM alert for ransom note creation
        logs.append(log_gen.json_log("fim_alert", {
            "src_ip": victim_ip,
            "file_path": note_path,
            "action": "created",
            "file_name": "RANSOM_NOTE.txt",
            "alert_type": "syscheck",
            "mitre_technique": MITRE["impact"]["data_encrypted"],
        }, severity="critical"))

    print(f"\n  {Fore.RED}[!] {encrypted_count} files encrypted{Style.RESET_ALL}")
    print(f"  {Fore.RED}[!] RANSOM_NOTE.txt dropped in affected directories{Style.RESET_ALL}")

    return logs, key_str


# ---------------------------------------------------------------------------
# Phase 4: Generate Wazuh FIM Alerts
# ---------------------------------------------------------------------------

def phase_4_fim_alerts(log_gen: LogGenerator, encrypted_count: int) -> list[str]:
    """Generate Wazuh FIM (File Integrity Monitoring) alerts for mass file changes."""
    print(f"\n{Fore.YELLOW}[Phase 4] Wazuh FIM Alert Generation{Style.RESET_ALL}")
    logs = []

    victim_ip = random.choice(WORKSTATION_IPS)

    # FIM summary alert: mass file modification
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100300,
        "rule_level": 14,
        "rule_description": "WCACE S08: Mass file modification detected - possible ransomware",
        "src_ip": victim_ip,
        "files_affected": encrypted_count,
        "time_window_seconds": 30,
        "alert_type": "syscheck",
        "mitre": ["T1486"],
    }, severity="critical"))

    # FIM alert: ransomware file extensions
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100301,
        "rule_level": 14,
        "rule_description": "WCACE S08: Ransomware file extension detected (.encrypted)",
        "src_ip": victim_ip,
        "extension": ".encrypted",
        "count": encrypted_count,
        "alert_type": "syscheck",
        "mitre": ["T1486"],
    }, severity="critical"))

    # FIM alert: ransom note creation
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100302,
        "rule_level": 15,
        "rule_description": "WCACE S08: Ransom note file created (RANSOM_NOTE.txt)",
        "src_ip": victim_ip,
        "file_name": "RANSOM_NOTE.txt",
        "alert_type": "syscheck",
        "mitre": ["T1486"],
    }, severity="critical"))

    # Alert: suspicious process execution
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100303,
        "rule_level": 12,
        "rule_description": "WCACE S08: Suspicious process dropped by email attachment",
        "src_ip": victim_ip,
        "process": "svchost_update.exe",
        "parent_process": "outlook.exe",
        "mitre": ["T1204.002"],
    }, severity="critical"))

    # Alert: C2 communication detected
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100304,
        "rule_level": 13,
        "rule_description": "WCACE S08: Ransomware C2 communication detected",
        "src_ip": victim_ip,
        "dst_ip": C2_SERVER_IP,
        "dst_port": 443,
        "mitre": ["T1071"],
    }, severity="critical"))

    # Alert: phishing email with malicious attachment
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100305,
        "rule_level": 10,
        "rule_description": "WCACE S08: Phishing email with suspicious attachment detected",
        "spf_result": "fail",
        "dkim_result": "fail",
        "attachment_type": "executable",
        "mitre": ["T1566.001"],
    }, severity="warning"))

    # Correlation alert: full ransomware kill chain
    logs.append(log_gen.json_log("wazuh_alert", {
        "rule_id": 100306,
        "rule_level": 15,
        "rule_description": "WCACE S08: Ransomware kill chain detected - phishing to encryption",
        "src_ip": victim_ip,
        "kill_chain_phases": [
            "phishing_email",
            "attachment_executed",
            "c2_communication",
            "file_encryption",
            "ransom_note",
        ],
        "mitre": ["T1566.001", "T1204.002", "T1071", "T1486"],
    }, severity="critical"))

    print(f"  Generated {len(logs)} Wazuh FIM and correlation alerts")
    for log in logs:
        entry = json.loads(log)
        rule_id = entry.get("rule_id", "N/A")
        desc = entry.get("rule_description", "N/A")
        print(f"    [{Fore.RED}ALERT{Style.RESET_ALL}] Rule {rule_id}: {desc}")

    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()
    safety_check()

    log_gen = LogGenerator(source_host="victim-workstation")
    all_logs = []

    # Phase 1: Phishing emails
    phishing_logs, phishing_emails = phase_1_phishing(log_gen)
    all_logs.extend(phishing_logs)
    time.sleep(0.5)

    # Phase 2: User opens attachment
    attachment_logs = phase_2_open_attachment(log_gen)
    all_logs.extend(attachment_logs)
    time.sleep(0.5)

    # Phase 3: Ransomware encryption
    encryption_logs, encryption_key = phase_3_encrypt(log_gen)
    all_logs.extend(encryption_logs)

    # Count encrypted files for Phase 4
    encrypted_count = 0
    if os.path.exists(SANDBOX_DIR):
        for root, dirs, files in os.walk(SANDBOX_DIR):
            encrypted_count += sum(1 for f in files if f.endswith(".encrypted"))
    time.sleep(0.5)

    # Phase 4: FIM alerts
    fim_logs = phase_4_fim_alerts(log_gen, encrypted_count)
    all_logs.extend(fim_logs)

    # ---------------------------------------------------------------------------
    # Save logs
    # ---------------------------------------------------------------------------
    os.makedirs(LOG_DIR, exist_ok=True)

    # Save combined attack log
    log_file = os.path.join(LOG_DIR, "ransomware_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Save phishing emails separately
    email_log = os.path.join(LOG_DIR, "phishing_emails.json")
    email_sim = EmailSimulator(domain=COMPANY_DOMAIN)
    email_sim.save_email_log(
        [e for e in phishing_emails] if phishing_emails else [],
        email_log,
    )

    # Save encryption key for recovery exercises
    if encryption_key:
        key_file = os.path.join(LOG_DIR, "encryption_key.txt")
        with open(key_file, "w") as f:
            f.write(f"# WCACE Scenario 08 - Encryption Key for Recovery\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Sandbox: {SANDBOX_DIR}\n")
            f.write(f"key={encryption_key}\n")

    # Save FIM alerts separately for detection verification
    fim_file = os.path.join(LOG_DIR, "fim_alerts.jsonl")
    fim_only = [l for l in all_logs if "fim_alert" in l or "wazuh_alert" in l]
    SIEMClient.write_logs_to_file(fim_only, fim_file)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Attack Simulation Complete")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Total log entries:    {len(all_logs)}")
    print(f"  Files encrypted:      {encrypted_count}")
    print(f"  Phishing emails sent: {len(phishing_emails)}")
    print(f"  Sandbox directory:    {SANDBOX_DIR}")
    print(f"\n  Log files:")
    print(f"    {log_file}")
    print(f"    {email_log}")
    print(f"    {fim_file}")
    if encryption_key:
        print(f"    {os.path.join(LOG_DIR, 'encryption_key.txt')}")

    # Try to push logs to Loki
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "08-phishing-ransomware"},
            all_logs,
        )
        print(f"\n  {Fore.GREEN}[*] Logs pushed to Loki{Style.RESET_ALL}")
    except Exception:
        print(f"\n  [*] Loki not available -- logs saved locally only")

    print(f"\n  Next: Run detect/verify_detection.py to verify alerts")
    print(f"        Run respond/containment.py for incident response\n")


if __name__ == "__main__":
    main()
