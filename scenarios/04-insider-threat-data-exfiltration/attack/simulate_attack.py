#!/usr/bin/env python3
"""
Scenario 04: Insider Threat Data Exfiltration Simulation.

Simulates a malicious insider who progresses through five phases:
  Phase 1: Normal working-hours file access (establishes baseline)
  Phase 2: After-hours access to sensitive directories
  Phase 3: Bulk file download/copy exceeding normal patterns
  Phase 4: Data staging via file compression
  Phase 5: Exfiltration via large HTTPS transfers to external IP

Focuses on BEHAVIORAL detection (anomaly from baseline), not signatures.
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
    INSIDER_USER,
    FILE_SERVER_IP,
    ATTACKER_IP,
    WORKSTATION_IPS,
    REGULAR_USERS,
    HTTPS_PORT,
    SMB_PORT,
    VPN_SERVER_IP,
    COMPANY_DOMAIN,
)

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Insider workstation
INSIDER_WORKSTATION = WORKSTATION_IPS[2]  # bob.wilson's workstation: 10.0.0.102

# Sensitive file paths on the file server
NORMAL_PROJECT_FILES = [
    "/shared/projects/webapp/src/main.py",
    "/shared/projects/webapp/src/utils.py",
    "/shared/projects/webapp/docs/api_spec.md",
    "/shared/projects/webapp/tests/test_auth.py",
    "/shared/projects/webapp/README.md",
    "/shared/projects/infra/deploy.yml",
    "/shared/projects/infra/monitoring.yml",
    "/shared/docs/team_notes.docx",
]

SENSITIVE_HR_FILES = [
    "/shared/hr/employee_records/salaries_2025.xlsx",
    "/shared/hr/employee_records/performance_reviews.xlsx",
    "/shared/hr/employee_records/personal_info.csv",
    "/shared/hr/employee_records/benefits_enrollment.xlsx",
    "/shared/hr/employee_records/termination_list.docx",
    "/shared/hr/recruiting/candidate_offers.xlsx",
    "/shared/hr/recruiting/compensation_bands.pdf",
]

SENSITIVE_FINANCE_FILES = [
    "/shared/finance/quarterly_earnings_Q4.xlsx",
    "/shared/finance/revenue_projections_2026.xlsx",
    "/shared/finance/bank_account_details.csv",
    "/shared/finance/vendor_contracts/contract_master.xlsx",
    "/shared/finance/vendor_contracts/payment_schedule.xlsx",
    "/shared/finance/tax_filings/corporate_tax_2025.pdf",
    "/shared/finance/budget/department_budgets.xlsx",
    "/shared/finance/budget/capex_forecast.xlsx",
]

SENSITIVE_EXECUTIVE_FILES = [
    "/shared/executive/board_presentations/q4_board_deck.pptx",
    "/shared/executive/board_presentations/ma_strategy.pptx",
    "/shared/executive/strategy/acquisition_targets.xlsx",
    "/shared/executive/strategy/layoff_plan_2026.docx",
    "/shared/executive/legal/pending_litigation.docx",
    "/shared/executive/legal/patent_portfolio.xlsx",
]

# External destination for exfiltration
EXFIL_DESTINATION = ATTACKER_IP  # 203.0.113.50


def banner():
    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 04: Insider Threat Data Exfiltration
  Insider:    {INSIDER_USER} ({INSIDER_WORKSTATION})
  Target:     {FILE_SERVER_IP} (file server)
  Exfil Dest: {EXFIL_DESTINATION}
  WARNING: Educational simulation only
{'='*62}{Style.RESET_ALL}
""")


def phase_1_normal_access(log_gen: LogGenerator) -> list[str]:
    """Phase 1: Normal working-hours file access to establish baseline.

    This represents typical daily activity -- a few project files accessed
    during business hours (09:00-17:00). This is the 'normal' that later
    phases deviate from.
    """
    print(f"{Fore.GREEN}[Phase 1] Normal Working Hours Access (Baseline){Style.RESET_ALL}")
    print(f"  User: {INSIDER_USER}")
    print(f"  Time: Business hours (09:00-17:00)")
    print(f"  Pattern: 5-8 project files per day, standard directories")
    logs = []

    # Set time to morning working hours
    log_gen._base_time = datetime.now().replace(hour=9, minute=15, second=0)

    # VPN authentication (normal login)
    logs.append(log_gen.auth_success(INSIDER_USER, INSIDER_WORKSTATION))
    print(f"  [+] VPN login at {log_gen._base_time.strftime('%H:%M')}")

    # Normal file access -- small number of project files
    daily_files = random.sample(NORMAL_PROJECT_FILES, min(6, len(NORMAL_PROJECT_FILES)))
    for filepath in daily_files:
        log_gen.advance_time(random.randint(300, 1800))  # 5-30 min between accesses
        logs.append(log_gen.file_access(INSIDER_USER, filepath, action="read"))
        logs.append(log_gen.firewall_log(
            INSIDER_WORKSTATION, FILE_SERVER_IP,
            random.randint(1024, 65535), SMB_PORT,
            action="allow", protocol="TCP"
        ))
        # Normal transfer sizes: 10KB-500KB per file
        logs.append(log_gen.json_log("data_transfer", {
            "user": INSIDER_USER,
            "src_ip": FILE_SERVER_IP,
            "dst_ip": INSIDER_WORKSTATION,
            "file": filepath,
            "size_bytes": random.randint(10000, 500000),
            "protocol": "SMB",
            "direction": "download",
        }))

    print(f"  [+] Accessed {len(daily_files)} project files (normal pattern)")

    # One small edit/save (write back)
    edit_file = random.choice(daily_files)
    logs.append(log_gen.file_access(INSIDER_USER, edit_file, action="write"))
    print(f"  [+] Edited: {edit_file}")

    # Normal logout at end of day
    log_gen._base_time = log_gen._base_time.replace(hour=17, minute=30)
    logs.append(log_gen.syslog(
        f"session closed for user {INSIDER_USER}",
        severity="info", facility="auth"
    ))
    print(f"  [+] Session closed at {log_gen._base_time.strftime('%H:%M')}")
    print(f"  [{Fore.CYAN}BASELINE{Style.RESET_ALL}] {len(logs)} log entries generated\n")

    return logs


def phase_2_afterhours_access(log_gen: LogGenerator) -> list[str]:
    """Phase 2: After-hours access to sensitive directories.

    First behavioral anomaly: the insider connects outside business hours
    and accesses directories they do not normally touch (HR, Finance, Executive).
    """
    print(f"{Fore.YELLOW}[Phase 2] After-Hours Access to Sensitive Directories{Style.RESET_ALL}")
    print(f"  Time: 22:30-01:00 (outside business hours)")
    print(f"  Target: HR, Finance, Executive shares")
    logs = []

    # Set time to late night
    log_gen._base_time = datetime.now().replace(hour=22, minute=30, second=0)

    # VPN login at unusual hour
    logs.append(log_gen.auth_success(INSIDER_USER, INSIDER_WORKSTATION))
    logs.append(log_gen.json_log("vpn_connection", {
        "user": INSIDER_USER,
        "src_ip": INSIDER_WORKSTATION,
        "vpn_server": VPN_SERVER_IP,
        "action": "connect",
        "time_of_day": "after_hours",
        "day_of_week": "Wednesday",
    }, severity="info"))
    print(f"  [!] VPN login at {log_gen._base_time.strftime('%H:%M')} (ANOMALOUS)")

    # Browse sensitive directories -- reconnaissance
    sensitive_dirs = [
        "/shared/hr/",
        "/shared/hr/employee_records/",
        "/shared/finance/",
        "/shared/finance/vendor_contracts/",
        "/shared/executive/",
        "/shared/executive/strategy/",
    ]
    for dirpath in sensitive_dirs:
        log_gen.advance_time(random.randint(30, 120))
        logs.append(log_gen.file_access(INSIDER_USER, dirpath, action="list"))
        logs.append(log_gen.firewall_log(
            INSIDER_WORKSTATION, FILE_SERVER_IP,
            random.randint(1024, 65535), SMB_PORT,
            action="allow", protocol="TCP"
        ))

    print(f"  [!] Browsed {len(sensitive_dirs)} sensitive directories")

    # Read a few files from each sensitive area
    sample_files = (
        random.sample(SENSITIVE_HR_FILES, 2) +
        random.sample(SENSITIVE_FINANCE_FILES, 2) +
        random.sample(SENSITIVE_EXECUTIVE_FILES, 2)
    )
    for filepath in sample_files:
        log_gen.advance_time(random.randint(60, 300))
        logs.append(log_gen.file_access(INSIDER_USER, filepath, action="read"))
        logs.append(log_gen.json_log("data_transfer", {
            "user": INSIDER_USER,
            "src_ip": FILE_SERVER_IP,
            "dst_ip": INSIDER_WORKSTATION,
            "file": filepath,
            "size_bytes": random.randint(50000, 2000000),
            "protocol": "SMB",
            "direction": "download",
        }))

    print(f"  [!] Read {len(sample_files)} sensitive files across HR/Finance/Executive")
    print(f"  [{Fore.RED}ANOMALY{Style.RESET_ALL}] After-hours + sensitive directory access\n")

    return logs


def phase_3_bulk_download(log_gen: LogGenerator) -> list[str]:
    """Phase 3: Bulk file download/copy exceeding normal patterns.

    Second major anomaly: the insider downloads a large volume of files
    in a short time window -- far exceeding their normal 5-8 files/day.
    """
    print(f"{Fore.YELLOW}[Phase 3] Bulk File Download (Volume Anomaly){Style.RESET_ALL}")
    print(f"  Pattern: 50+ files in < 30 minutes (normal: 5-8 per day)")
    logs = []

    # Still after hours, continues from Phase 2
    log_gen.advance_time(300)

    # Bulk download from all sensitive directories
    all_sensitive_files = SENSITIVE_HR_FILES + SENSITIVE_FINANCE_FILES + SENSITIVE_EXECUTIVE_FILES
    total_bytes = 0

    for i, filepath in enumerate(all_sensitive_files):
        log_gen.advance_time(random.randint(2, 15))  # Very rapid access
        logs.append(log_gen.file_access(INSIDER_USER, filepath, action="read"))
        logs.append(log_gen.file_access(INSIDER_USER, filepath, action="copy"))

        file_size = random.randint(500000, 10000000)  # 500KB-10MB per file
        total_bytes += file_size

        logs.append(log_gen.json_log("data_transfer", {
            "user": INSIDER_USER,
            "src_ip": FILE_SERVER_IP,
            "dst_ip": INSIDER_WORKSTATION,
            "file": filepath,
            "size_bytes": file_size,
            "protocol": "SMB",
            "direction": "download",
            "copy_destination": f"/home/{INSIDER_USER}/staging/{os.path.basename(filepath)}",
        }, severity="warning"))

        if (i + 1) % 10 == 0:
            print(f"  [!] Downloaded {i + 1}/{len(all_sensitive_files)} files...")

    # Also grab some files via alternative patterns (search results, recently modified)
    extra_files = [
        "/shared/finance/audit/internal_audit_2025.xlsx",
        "/shared/hr/org_chart/reporting_structure.xlsx",
        "/shared/executive/comms/investor_relations_draft.docx",
        "/shared/finance/payroll/payroll_master_jan2026.csv",
        "/shared/hr/employee_records/ssn_backup.csv.enc",
    ]
    for filepath in extra_files:
        log_gen.advance_time(random.randint(2, 10))
        logs.append(log_gen.file_access(INSIDER_USER, filepath, action="copy"))
        file_size = random.randint(1000000, 15000000)
        total_bytes += file_size
        logs.append(log_gen.json_log("data_transfer", {
            "user": INSIDER_USER,
            "src_ip": FILE_SERVER_IP,
            "dst_ip": INSIDER_WORKSTATION,
            "file": filepath,
            "size_bytes": file_size,
            "protocol": "SMB",
            "direction": "download",
        }, severity="warning"))

    total_files = len(all_sensitive_files) + len(extra_files)
    total_mb = total_bytes / (1024 * 1024)
    print(f"  [!] Downloaded {total_files} files ({total_mb:.1f} MB) in rapid succession")
    print(f"  [{Fore.RED}ANOMALY{Style.RESET_ALL}] Volume exceeds baseline by >6x\n")

    return logs


def phase_4_data_staging(log_gen: LogGenerator) -> list[str]:
    """Phase 4: Data staging via compression.

    The insider compresses collected files into archives, preparing them
    for exfiltration. This creates detectable staging artifacts.
    """
    print(f"{Fore.YELLOW}[Phase 4] Data Staging (Compression/Archiving){Style.RESET_ALL}")
    logs = []

    log_gen.advance_time(120)

    # Create staging directory
    logs.append(log_gen.syslog(
        f"AUDIT: user={INSIDER_USER} action=mkdir path=/home/{INSIDER_USER}/staging result=success",
        severity="info", facility="local0"
    ))

    # Compress HR data
    staging_archives = [
        {
            "command": f"tar czf /tmp/.cache_hr.tar.gz /home/{INSIDER_USER}/staging/hr/",
            "archive": "/tmp/.cache_hr.tar.gz",
            "label": "HR records",
            "size": random.randint(15000000, 30000000),
        },
        {
            "command": f"tar czf /tmp/.cache_fin.tar.gz /home/{INSIDER_USER}/staging/finance/",
            "archive": "/tmp/.cache_fin.tar.gz",
            "label": "Finance records",
            "size": random.randint(20000000, 40000000),
        },
        {
            "command": f"tar czf /tmp/.cache_exec.tar.gz /home/{INSIDER_USER}/staging/exec/",
            "archive": "/tmp/.cache_exec.tar.gz",
            "label": "Executive records",
            "size": random.randint(10000000, 25000000),
        },
    ]

    for archive in staging_archives:
        log_gen.advance_time(random.randint(10, 30))

        # Process execution log
        logs.append(log_gen.json_log("process_execution", {
            "user": INSIDER_USER,
            "host": INSIDER_WORKSTATION,
            "command": archive["command"],
            "process": "tar",
            "parent_process": "bash",
            "pid": random.randint(10000, 65535),
        }, severity="warning"))

        # File creation log for the archive
        logs.append(log_gen.file_access(
            INSIDER_USER, archive["archive"], action="create"
        ))
        logs.append(log_gen.json_log("file_create", {
            "user": INSIDER_USER,
            "path": archive["archive"],
            "size_bytes": archive["size"],
            "file_type": "application/gzip",
        }))

        print(f"  [!] Staged: {archive['label']} -> {archive['archive']} "
              f"({archive['size'] / 1024 / 1024:.1f} MB)")

    # Combine all archives into single exfil package
    log_gen.advance_time(15)
    final_archive = f"/tmp/.sys_update_{datetime.now().strftime('%Y%m%d')}.tar.gz"
    final_size = sum(a["size"] for a in staging_archives)

    logs.append(log_gen.json_log("process_execution", {
        "user": INSIDER_USER,
        "host": INSIDER_WORKSTATION,
        "command": f"tar czf {final_archive} /tmp/.cache_*.tar.gz",
        "process": "tar",
        "parent_process": "bash",
        "pid": random.randint(10000, 65535),
    }, severity="warning"))

    logs.append(log_gen.file_access(INSIDER_USER, final_archive, action="create"))
    logs.append(log_gen.json_log("file_create", {
        "user": INSIDER_USER,
        "path": final_archive,
        "size_bytes": final_size,
        "file_type": "application/gzip",
    }, severity="warning"))

    print(f"  [!] Final package: {final_archive} ({final_size / 1024 / 1024:.1f} MB)")
    print(f"  [{Fore.RED}ANOMALY{Style.RESET_ALL}] Hidden archive files in /tmp with obfuscated names\n")

    return logs


def phase_5_exfiltration(log_gen: LogGenerator) -> list[str]:
    """Phase 5: Data exfiltration via large HTTPS transfers.

    The insider uploads staged archives to an external destination.
    Multiple large HTTPS transfers to an external IP that has never
    been contacted before.
    """
    print(f"{Fore.YELLOW}[Phase 5] Data Exfiltration (HTTPS to External IP){Style.RESET_ALL}")
    print(f"  Destination: {EXFIL_DESTINATION}")
    logs = []

    log_gen.advance_time(180)

    # DNS lookup for the exfil destination (cloud storage cover story)
    logs.append(log_gen.dns_query_log(
        INSIDER_WORKSTATION,
        "storage.cloud-backup-service.test",
        query_type="A",
        response=EXFIL_DESTINATION,
    ))

    # Multiple large HTTPS uploads
    exfil_transfers = [
        {"file": "/tmp/.cache_hr.tar.gz", "label": "HR data",
         "size": random.randint(15000000, 30000000)},
        {"file": "/tmp/.cache_fin.tar.gz", "label": "Finance data",
         "size": random.randint(20000000, 40000000)},
        {"file": "/tmp/.cache_exec.tar.gz", "label": "Executive data",
         "size": random.randint(10000000, 25000000)},
    ]

    total_exfil = 0
    for transfer in exfil_transfers:
        log_gen.advance_time(random.randint(30, 120))
        total_exfil += transfer["size"]

        # Firewall allows outbound HTTPS
        logs.append(log_gen.firewall_log(
            INSIDER_WORKSTATION, EXFIL_DESTINATION,
            random.randint(1024, 65535), HTTPS_PORT,
            action="allow", protocol="TCP"
        ))

        # Data transfer event -- large upload
        logs.append(log_gen.json_log("data_transfer", {
            "user": INSIDER_USER,
            "src_ip": INSIDER_WORKSTATION,
            "dst_ip": EXFIL_DESTINATION,
            "file": transfer["file"],
            "size_bytes": transfer["size"],
            "protocol": "HTTPS",
            "direction": "upload",
            "dst_port": HTTPS_PORT,
            "connection_duration_seconds": transfer["size"] // 500000,
        }, severity="critical"))

        # IDS alert for large outbound transfer
        logs.append(log_gen.ids_alert(
            INSIDER_WORKSTATION, EXFIL_DESTINATION,
            f"Large outbound HTTPS data transfer: {transfer['size'] / 1024 / 1024:.1f} MB",
            sid=9040001, severity=1
        ))

        # Network flow record
        logs.append(log_gen.json_log("netflow", {
            "src_ip": INSIDER_WORKSTATION,
            "dst_ip": EXFIL_DESTINATION,
            "src_port": random.randint(1024, 65535),
            "dst_port": HTTPS_PORT,
            "protocol": "TCP",
            "bytes_sent": transfer["size"],
            "bytes_received": random.randint(200, 2000),
            "packets_sent": transfer["size"] // 1460 + 1,
            "packets_received": random.randint(10, 50),
            "duration_seconds": transfer["size"] // 500000,
            "ratio_sent_received": round(transfer["size"] / max(1, random.randint(200, 2000)), 2),
        }, severity="critical"))

        print(f"  [!] Uploaded: {transfer['label']} "
              f"({transfer['size'] / 1024 / 1024:.1f} MB) -> {EXFIL_DESTINATION}")

    # Additional smaller exfil attempts to diversify detection
    log_gen.advance_time(60)
    logs.append(log_gen.firewall_log(
        INSIDER_WORKSTATION, EXFIL_DESTINATION,
        random.randint(1024, 65535), HTTPS_PORT,
        action="allow", protocol="TCP"
    ))
    logs.append(log_gen.json_log("data_transfer", {
        "user": INSIDER_USER,
        "src_ip": INSIDER_WORKSTATION,
        "dst_ip": EXFIL_DESTINATION,
        "size_bytes": random.randint(5000000, 10000000),
        "protocol": "HTTPS",
        "direction": "upload",
        "dst_port": HTTPS_PORT,
        "content_type": "application/octet-stream",
    }, severity="critical"))

    # Cover tracks: delete staging files
    log_gen.advance_time(60)
    for transfer in exfil_transfers:
        logs.append(log_gen.json_log("file_delete", {
            "user": INSIDER_USER,
            "path": transfer["file"],
            "host": INSIDER_WORKSTATION,
        }))
    logs.append(log_gen.syslog(
        f"AUDIT: user={INSIDER_USER} action=delete path=/tmp/.sys_update_*.tar.gz result=success",
        severity="info", facility="local0"
    ))

    # Disconnect VPN
    log_gen.advance_time(30)
    logs.append(log_gen.json_log("vpn_connection", {
        "user": INSIDER_USER,
        "src_ip": INSIDER_WORKSTATION,
        "vpn_server": VPN_SERVER_IP,
        "action": "disconnect",
    }))

    total_mb = total_exfil / (1024 * 1024)
    print(f"\n  [!] Total exfiltrated: {total_mb:.1f} MB via HTTPS")
    print(f"  [!] Staging files deleted (anti-forensics)")
    print(f"  [{Fore.RED}CRITICAL{Style.RESET_ALL}] Data exfiltration complete\n")

    return logs


def generate_other_user_baseline(log_gen: LogGenerator) -> list[str]:
    """Generate normal activity from other users to provide contrast.

    This makes the insider's behavior stand out as anomalous when compared
    against what other users are doing at the same time.
    """
    print(f"{Fore.CYAN}[Baseline] Generating normal user activity for contrast{Style.RESET_ALL}")
    logs = []

    # Reset to business hours for other users
    log_gen._base_time = datetime.now().replace(hour=10, minute=0, second=0)

    other_users = [u for u in REGULAR_USERS if u != INSIDER_USER][:4]
    for user in other_users:
        workstation = random.choice(WORKSTATION_IPS)
        logs.append(log_gen.auth_success(user, workstation))

        # Each user accesses 3-5 files, all in normal project directories
        num_files = random.randint(3, 5)
        for _ in range(num_files):
            log_gen.advance_time(random.randint(600, 3600))
            filepath = random.choice(NORMAL_PROJECT_FILES)
            logs.append(log_gen.file_access(user, filepath, action="read"))
            logs.append(log_gen.json_log("data_transfer", {
                "user": user,
                "src_ip": FILE_SERVER_IP,
                "dst_ip": workstation,
                "file": filepath,
                "size_bytes": random.randint(5000, 200000),
                "protocol": "SMB",
                "direction": "download",
            }))

    print(f"  [+] Generated baseline for {len(other_users)} normal users")
    print(f"  [+] Pattern: 3-5 files, project dirs only, business hours\n")

    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host="file-server")
    all_logs = []

    # Generate contrast baseline from other users
    all_logs.extend(generate_other_user_baseline(log_gen))

    # Phase 1: Normal insider behavior (establishes what is "normal")
    all_logs.extend(phase_1_normal_access(log_gen))

    # Phase 2: After-hours access (first anomaly)
    all_logs.extend(phase_2_afterhours_access(log_gen))

    # Phase 3: Bulk downloads (volume anomaly)
    all_logs.extend(phase_3_bulk_download(log_gen))

    # Phase 4: Data staging
    all_logs.extend(phase_4_data_staging(log_gen))

    # Phase 5: Exfiltration
    all_logs.extend(phase_5_exfiltration(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "insider_threat.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Summary
    print(f"{Fore.GREEN}{'='*62}")
    print(f"  Simulation Complete")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Total log entries:  {len(all_logs)}")
    print(f"  Output file:        {log_file}")
    print(f"  Insider user:       {INSIDER_USER}")
    print(f"  Exfil destination:  {EXFIL_DESTINATION}")
    print(f"\n  Behavioral indicators present:")
    print(f"    - After-hours access to sensitive directories")
    print(f"    - Bulk file downloads (volume anomaly)")
    print(f"    - Data staging (compression to hidden archives)")
    print(f"    - Large outbound HTTPS transfers to external IP")
    print(f"    - Anti-forensic cleanup (staging file deletion)")
    print(f"\n  Next step: python3 detect/verify_detection.py")

    # Try to send to Loki if available
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "04-insider-threat"},
            all_logs
        )
        print(f"\n  [+] Logs pushed to Loki")
    except Exception:
        print(f"\n  [*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
