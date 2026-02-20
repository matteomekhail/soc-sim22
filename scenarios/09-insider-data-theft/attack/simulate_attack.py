#!/usr/bin/env python3
"""
Scenario 9: Insider Data Theft via Encrypted Exfiltration.

Simulates a malicious insider who abuses legitimate database access
to extract, encrypt, and exfiltrate sensitive data.
"""

import base64
import json
import os
import random
import sys
import time

from colorama import Fore, Style, init
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import (
    INSIDER_USER, DB_SERVER_IP, FILE_SERVER_IP,
    WORKSTATION_IPS, ATTACKER_IP, REGULAR_USERS
)

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")


def banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 9: Insider Data Theft Simulation        ║
║  Insider: {INSIDER_USER:<45s} ║
║  ⚠  Educational use only                                ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def phase_1_normal_db_access(log_gen: LogGenerator) -> list[str]:
    """Phase 1: Establish normal database access baseline."""
    print(f"{Fore.YELLOW}[Phase 1] Normal Database Access (Baseline){Style.RESET_ALL}")
    logs = []
    src_ip = WORKSTATION_IPS[3]  # bob.wilson's workstation

    # Normal queries during business hours
    normal_queries = [
        "SELECT * FROM customers WHERE region='NSW' LIMIT 50",
        "SELECT COUNT(*) FROM orders WHERE date > '2024-01-01'",
        "SELECT product_name, price FROM products WHERE active=1",
        "SELECT name, email FROM employees WHERE dept='sales'",
    ]

    for query in normal_queries:
        logs.append(log_gen.json_log("db_query", {
            "user": INSIDER_USER,
            "src_ip": src_ip,
            "database": "production_crm",
            "query": query,
            "rows_returned": random.randint(10, 50),
            "duration_ms": random.randint(5, 100),
        }))
        print(f"  [+] Normal query: {query[:50]}...")

    # Normal file access
    normal_files = [
        "/shared/sales/Q4_report.xlsx",
        "/shared/marketing/campaign_data.csv",
    ]
    for f in normal_files:
        logs.append(log_gen.file_access(INSIDER_USER, f, "read"))

    return logs


def phase_2_escalating_queries(log_gen: LogGenerator) -> list[str]:
    """Phase 2: Gradually increase query scope and sensitivity."""
    print(f"\n{Fore.YELLOW}[Phase 2] Escalating Database Queries{Style.RESET_ALL}")
    logs = []
    src_ip = WORKSTATION_IPS[3]

    # Increasingly sensitive queries
    suspicious_queries = [
        ("SELECT * FROM customers", 15000, "Full customer table dump"),
        ("SELECT * FROM employees WHERE salary > 100000", 200, "Salary data access"),
        ("SELECT ssn, dob, full_name FROM customers", 15000, "PII extraction"),
        ("SELECT card_number, expiry, cvv FROM payment_methods", 8000, "Payment card data"),
        ("SELECT * FROM contracts WHERE value > 1000000", 50, "High-value contracts"),
        ("SELECT username, password_hash, email FROM admin_users", 25, "Admin credentials"),
    ]

    for query, rows, desc in suspicious_queries:
        logs.append(log_gen.json_log("db_query", {
            "user": INSIDER_USER,
            "src_ip": src_ip,
            "database": "production_crm",
            "query": query,
            "rows_returned": rows,
            "duration_ms": random.randint(100, 5000),
            "data_size_bytes": rows * random.randint(200, 500),
        }, severity="warning"))
        print(f"  {Fore.RED}[!] Suspicious: {desc} ({rows} rows){Style.RESET_ALL}")
        time.sleep(0.2)

    return logs


def phase_3_data_staging(log_gen: LogGenerator) -> list[str]:
    """Phase 3: Stage extracted data locally."""
    print(f"\n{Fore.YELLOW}[Phase 3] Data Staging{Style.RESET_ALL}")
    logs = []
    src_ip = WORKSTATION_IPS[3]

    staged_files = [
        ("/tmp/.cache/customers_full.csv", 45000000),
        ("/tmp/.cache/payment_data.csv", 12000000),
        ("/tmp/.cache/employee_records.csv", 8000000),
        ("/tmp/.cache/admin_creds.csv", 50000),
        ("/tmp/.cache/contracts_sensitive.csv", 25000000),
    ]

    for filepath, size in staged_files:
        logs.append(log_gen.json_log("file_create", {
            "user": INSIDER_USER,
            "src_ip": src_ip,
            "path": filepath,
            "size_bytes": size,
            "hidden_directory": True,
        }, severity="warning"))
        logs.append(log_gen.file_access(INSIDER_USER, filepath, "write"))
        print(f"  [*] Staged: {filepath} ({size/1000000:.1f} MB)")

    return logs


def phase_4_encryption(log_gen: LogGenerator) -> list[str]:
    """Phase 4: Encrypt staged data for exfiltration."""
    print(f"\n{Fore.YELLOW}[Phase 4] Data Encryption{Style.RESET_ALL}")
    logs = []
    src_ip = WORKSTATION_IPS[3]

    # Generate encryption key
    key = Fernet.generate_key()
    print(f"  [*] Encryption key generated: {key[:20].decode()}...")

    encrypted_files = [
        ("/tmp/.cache/export_001.enc", 47000000),
        ("/tmp/.cache/export_002.enc", 13000000),
        ("/tmp/.cache/export_003.enc", 9000000),
        ("/tmp/.cache/export_004.enc", 26000000),
    ]

    for filepath, size in encrypted_files:
        logs.append(log_gen.json_log("file_create", {
            "user": INSIDER_USER,
            "src_ip": src_ip,
            "path": filepath,
            "size_bytes": size,
            "encrypted": True,
            "entropy": round(random.uniform(7.8, 8.0), 2),
        }, severity="warning"))
        print(f"  [*] Encrypted: {filepath} ({size/1000000:.1f} MB, high entropy)")

    # Delete originals
    logs.append(log_gen.json_log("file_delete_batch", {
        "user": INSIDER_USER,
        "src_ip": src_ip,
        "files_deleted": 5,
        "pattern": "/tmp/.cache/*.csv",
    }, severity="warning"))
    print(f"  [*] Original CSV files deleted (anti-forensics)")

    return logs


def phase_5_exfiltration(log_gen: LogGenerator) -> list[str]:
    """Phase 5: Exfiltrate encrypted data in chunks."""
    print(f"\n{Fore.YELLOW}[Phase 5] Covert Exfiltration{Style.RESET_ALL}")
    logs = []
    src_ip = WORKSTATION_IPS[3]
    ext_ip = ATTACKER_IP  # Personal cloud/server

    total_chunks = 0
    total_bytes = 0

    # Exfiltrate via HTTPS in small chunks disguised as API calls
    for chunk_num in range(30):
        chunk_size = random.randint(500000, 2000000)
        total_chunks += 1
        total_bytes += chunk_size

        logs.append(log_gen.firewall_log(
            src_ip, ext_ip,
            random.randint(49152, 65535), 443,
            action="allow", protocol="TCP"
        ))
        logs.append(log_gen.json_log("https_transfer", {
            "user": INSIDER_USER,
            "src_ip": src_ip,
            "dst_ip": ext_ip,
            "dst_domain": "cloud-storage.external.test",
            "method": "PUT",
            "path": f"/api/v1/sync/chunk_{chunk_num:03d}",
            "size_bytes": chunk_size,
            "content_type": "application/octet-stream",
        }, severity="warning"))

    print(f"  {Fore.RED}[!] Exfiltrated {total_chunks} chunks ({total_bytes/1000000:.1f} MB total)")
    print(f"      Destination: cloud-storage.external.test ({ext_ip}){Style.RESET_ALL}")

    # Also exfiltrate some via DNS as backup channel
    dns_logs = log_gen.dns_tunnel_sequence(src_ip, "backup.exfil.test", queries=20)
    logs.extend(dns_logs)
    print(f"  [!] DNS tunnel backup: 20 queries to backup.exfil.test")

    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host="workstation-bob")
    all_logs = []

    all_logs.extend(phase_1_normal_db_access(log_gen))
    all_logs.extend(phase_2_escalating_queries(log_gen))
    all_logs.extend(phase_3_data_staging(log_gen))
    all_logs.extend(phase_4_encryption(log_gen))
    all_logs.extend(phase_5_exfiltration(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "insider_theft.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    print(f"\n{Fore.GREEN}[*] Attack simulation complete")
    print(f"[*] {len(all_logs)} log entries written to {log_file}{Style.RESET_ALL}")

    try:
        siem = SIEMClient()
        siem.loki_push_lines({"job": "attack_sim", "scenario": "09-insider-theft"}, all_logs)
        print(f"[*] Logs pushed to Loki")
    except Exception:
        print(f"[*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
