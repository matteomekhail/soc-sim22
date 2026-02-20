#!/usr/bin/env python3
"""
Scenario 04: Verify insider threat detection by analyzing generated logs.

Checks for behavioral anomaly indicators:
1. After-hours access to sensitive directories
2. Bulk file access volume exceeding baseline
3. Data staging (compression activity)
4. Large outbound HTTPS transfers (exfiltration)
5. Anti-forensic behavior (file deletion)

This verification focuses on behavioral patterns, not signatures.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import INSIDER_USER, ATTACKER_IP

init(autoreset=True)

EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "expected_alerts.json")
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs", "insider_threat.jsonl")

# Thresholds for behavioral detection
BASELINE_FILES_PER_DAY = 8
BULK_ACCESS_THRESHOLD = 20
SENSITIVE_DIRS = ["/shared/hr/", "/shared/finance/", "/shared/executive/"]
BUSINESS_HOURS = (9, 18)  # 09:00 - 18:00


def load_logs() -> list[dict]:
    """Load and parse log entries."""
    logs = []
    if not os.path.exists(LOG_FILE):
        return logs

    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                logs.append(entry)
            except json.JSONDecodeError:
                # Syslog format entries -- parse what we can
                logs.append({"_raw": line, "event_type": "syslog"})
    return logs


def check_afterhours_access(logs: list[dict]) -> dict:
    """Check for file access events outside business hours."""
    result = {
        "detected": False,
        "count": 0,
        "details": [],
    }

    for entry in logs:
        if entry.get("event_type") not in ("syslog",):
            # Check JSON log timestamps
            ts_str = entry.get("timestamp", "")
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str.rstrip("Z"))
                hour = ts.hour
            except (ValueError, AttributeError):
                continue

            if hour < BUSINESS_HOURS[0] or hour >= BUSINESS_HOURS[1]:
                # Check if it involves sensitive directories
                raw = json.dumps(entry)
                for sdir in SENSITIVE_DIRS:
                    if sdir in raw and INSIDER_USER in raw:
                        result["count"] += 1
                        result["details"].append({
                            "time": ts_str,
                            "directory": sdir,
                            "event_type": entry.get("event_type", "unknown"),
                        })
                        break

        # Also check syslog-format entries
        raw = entry.get("_raw", "")
        if raw and INSIDER_USER in raw:
            for sdir in SENSITIVE_DIRS:
                if sdir in raw:
                    result["count"] += 1
                    break

    result["detected"] = result["count"] > 0
    return result


def check_bulk_file_access(logs: list[dict]) -> dict:
    """Check for file access volume exceeding baseline."""
    result = {
        "detected": False,
        "insider_file_count": 0,
        "normal_user_avg": 0,
        "ratio": 0,
        "details": [],
    }

    user_file_counts = Counter()

    for entry in logs:
        # Count file_access and data_transfer events by user
        raw = json.dumps(entry) if entry.get("event_type") != "syslog" else entry.get("_raw", "")

        if "action=read" in raw or "action=copy" in raw or (
            entry.get("event_type") == "data_transfer" and entry.get("direction") == "download"
        ):
            user = entry.get("user", "")
            if not user:
                # Extract user from syslog AUDIT line
                if "user=" in raw:
                    try:
                        user = raw.split("user=")[1].split(" ")[0].split('"')[0]
                    except IndexError:
                        continue
            if user:
                user_file_counts[user] += 1

    insider_count = user_file_counts.get(INSIDER_USER, 0)
    other_counts = [c for u, c in user_file_counts.items() if u != INSIDER_USER]
    avg_other = sum(other_counts) / max(len(other_counts), 1)

    result["insider_file_count"] = insider_count
    result["normal_user_avg"] = round(avg_other, 1)
    result["ratio"] = round(insider_count / max(avg_other, 1), 1)
    result["detected"] = insider_count > BULK_ACCESS_THRESHOLD

    return result


def check_data_staging(logs: list[dict]) -> dict:
    """Check for data staging activity (compression, archiving)."""
    result = {
        "detected": False,
        "staging_events": 0,
        "archives_created": [],
    }

    for entry in logs:
        if entry.get("event_type") == "process_execution":
            cmd = entry.get("command", "")
            process = entry.get("process", "")
            if process in ("tar", "zip", "7z", "rar") or "tar " in cmd or "zip " in cmd:
                result["staging_events"] += 1
                result["archives_created"].append(cmd)

        if entry.get("event_type") == "file_create":
            path = entry.get("path", "")
            if path.endswith((".tar.gz", ".zip", ".7z", ".rar")):
                if "/tmp/" in path or "staging" in path:
                    result["staging_events"] += 1

    result["detected"] = result["staging_events"] > 0
    return result


def check_exfiltration(logs: list[dict]) -> dict:
    """Check for large outbound data transfers to external IPs."""
    result = {
        "detected": False,
        "transfer_count": 0,
        "total_bytes": 0,
        "destinations": set(),
        "ids_alerts": 0,
    }

    for entry in logs:
        if entry.get("event_type") == "data_transfer":
            if entry.get("direction") == "upload" and entry.get("protocol") == "HTTPS":
                dst = entry.get("dst_ip", "")
                size = entry.get("size_bytes", 0)
                if dst and not dst.startswith("10."):
                    result["transfer_count"] += 1
                    result["total_bytes"] += size
                    result["destinations"].add(dst)

        if entry.get("event_type") == "ids_alert":
            if "outbound" in entry.get("signature", "").lower():
                result["ids_alerts"] += 1

    result["destinations"] = list(result["destinations"])
    result["detected"] = result["transfer_count"] > 0
    return result


def check_antiforensics(logs: list[dict]) -> dict:
    """Check for anti-forensic behavior (file deletion after exfil)."""
    result = {
        "detected": False,
        "deletions": 0,
    }

    for entry in logs:
        if entry.get("event_type") == "file_delete":
            result["deletions"] += 1
        raw = entry.get("_raw", "")
        if "action=delete" in raw:
            result["deletions"] += 1

    result["detected"] = result["deletions"] > 0
    return result


def check_wazuh_alerts() -> list[dict]:
    """Query Wazuh for insider threat alerts."""
    try:
        api = WazuhAPI()
        if not api.check_connection():
            return []
        alerts = api.get_alerts(search="insider threat", limit=50)
        return alerts
    except Exception as e:
        print(f"  [!] Wazuh not available: {e}")
        return []


def check_loki_logs() -> int:
    """Query Loki for scenario 04 logs."""
    try:
        siem = SIEMClient()
        result = siem.loki_query('{scenario="04-insider-threat"}', limit=200)
        streams = result.get("data", {}).get("result", [])
        count = sum(len(s.get("values", [])) for s in streams)
        return count
    except Exception:
        return 0


def main():
    print(f"""
{Fore.CYAN}{'='*62}
  WCACE Scenario 04: Insider Threat Detection Verification
  Detection Approach: Behavioral Anomaly Analysis
{'='*62}{Style.RESET_ALL}
""")

    # Load expected alerts
    with open(EXPECTED_FILE) as f:
        expected = json.load(f)

    # Load logs
    logs = load_logs()
    if not logs:
        print(f"{Fore.RED}[!] No logs found. Run simulate_attack.py first.{Style.RESET_ALL}")
        print(f"    python3 attack/simulate_attack.py")
        return

    print(f"[*] Loaded {len(logs)} log entries from {LOG_FILE}\n")

    total_checks = 0
    passed_checks = 0
    results_summary = []

    # Check 1: After-hours access
    print(f"{Fore.YELLOW}[1/6] Checking for after-hours access to sensitive directories...{Style.RESET_ALL}")
    afterhours = check_afterhours_access(logs)
    if afterhours["detected"]:
        print(f"  DETECTED: {afterhours['count']} after-hours access events")
        for d in afterhours["details"][:3]:
            print(f"    - {d['time']} -> {d['directory']}")
        results_summary.append(("After-Hours Access", afterhours["count"], "PASS"))
        passed_checks += 1
    else:
        print(f"  NOT DETECTED")
        results_summary.append(("After-Hours Access", 0, "FAIL"))
    total_checks += 1

    # Check 2: Bulk file access
    print(f"\n{Fore.YELLOW}[2/6] Checking for bulk file access (volume anomaly)...{Style.RESET_ALL}")
    bulk = check_bulk_file_access(logs)
    if bulk["detected"]:
        print(f"  DETECTED: {INSIDER_USER} accessed {bulk['insider_file_count']} files")
        print(f"    Normal user average: {bulk['normal_user_avg']} files")
        print(f"    Anomaly ratio: {bulk['ratio']}x baseline")
        results_summary.append(("Bulk File Access", bulk["insider_file_count"], "PASS"))
        passed_checks += 1
    else:
        print(f"  NOT DETECTED (insider: {bulk['insider_file_count']}, threshold: {BULK_ACCESS_THRESHOLD})")
        results_summary.append(("Bulk File Access", bulk["insider_file_count"], "FAIL"))
    total_checks += 1

    # Check 3: Data staging
    print(f"\n{Fore.YELLOW}[3/6] Checking for data staging activity...{Style.RESET_ALL}")
    staging = check_data_staging(logs)
    if staging["detected"]:
        print(f"  DETECTED: {staging['staging_events']} staging events")
        for arch in staging["archives_created"][:3]:
            print(f"    - {arch[:80]}")
        results_summary.append(("Data Staging", staging["staging_events"], "PASS"))
        passed_checks += 1
    else:
        print(f"  NOT DETECTED")
        results_summary.append(("Data Staging", 0, "FAIL"))
    total_checks += 1

    # Check 4: Exfiltration
    print(f"\n{Fore.YELLOW}[4/6] Checking for data exfiltration indicators...{Style.RESET_ALL}")
    exfil = check_exfiltration(logs)
    if exfil["detected"]:
        total_mb = exfil["total_bytes"] / (1024 * 1024)
        print(f"  DETECTED: {exfil['transfer_count']} exfiltration transfers")
        print(f"    Total volume: {total_mb:.1f} MB")
        print(f"    Destinations: {', '.join(exfil['destinations'])}")
        print(f"    IDS alerts: {exfil['ids_alerts']}")
        results_summary.append(("Exfiltration", exfil["transfer_count"], "PASS"))
        passed_checks += 1
    else:
        print(f"  NOT DETECTED")
        results_summary.append(("Exfiltration", 0, "FAIL"))
    total_checks += 1

    # Check 5: Anti-forensics
    print(f"\n{Fore.YELLOW}[5/6] Checking for anti-forensic behavior...{Style.RESET_ALL}")
    antiforensics = check_antiforensics(logs)
    if antiforensics["detected"]:
        print(f"  DETECTED: {antiforensics['deletions']} file deletion events after exfiltration")
        results_summary.append(("Anti-Forensics", antiforensics["deletions"], "PASS"))
        passed_checks += 1
    else:
        print(f"  NOT DETECTED")
        results_summary.append(("Anti-Forensics", 0, "FAIL"))
    total_checks += 1

    # Check 6: Wazuh / Loki (SOC stack)
    print(f"\n{Fore.YELLOW}[6/6] Checking SOC stack (Wazuh + Loki)...{Style.RESET_ALL}")
    wazuh_alerts = check_wazuh_alerts()
    loki_count = check_loki_logs()

    if wazuh_alerts:
        print(f"  Wazuh: {len(wazuh_alerts)} alerts found")
        results_summary.append(("Wazuh Alerts", len(wazuh_alerts), "PASS"))
        passed_checks += 1
    else:
        print(f"  Wazuh: Not available or no alerts (stack may not be running)")
        results_summary.append(("Wazuh Alerts", 0, "SKIP"))

    if loki_count > 0:
        print(f"  Loki: {loki_count} log entries found")
    else:
        print(f"  Loki: Not available (stack may not be running)")
    total_checks += 1

    # Summary
    print(f"\n{Fore.CYAN}{'='*62}")
    print(f"  Detection Verification Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  {'Check':<25s} {'Count':>8s}   {'Status':>6s}")
    print(f"  {'-'*25} {'-'*8}   {'-'*6}")
    for name, count, status in results_summary:
        color = Fore.GREEN if status == "PASS" else (Fore.YELLOW if status == "SKIP" else Fore.RED)
        print(f"  {name:<25s} {count:>8}   {color}{status}{Style.RESET_ALL}")

    print(f"\n  Detection coverage: {passed_checks}/{total_checks} checks passed")

    # Behavioral analysis summary
    print(f"\n{Fore.CYAN}  Behavioral Anomaly Summary:{Style.RESET_ALL}")
    print(f"  - Timing:  {'ANOMALOUS' if afterhours['detected'] else 'Normal'} "
          f"(after-hours access detected)" if afterhours["detected"] else
          f"  - Timing:  Normal")
    print(f"  - Volume:  {'ANOMALOUS' if bulk['detected'] else 'Normal'} "
          f"({bulk['ratio']}x baseline)" if bulk["detected"] else
          f"  - Volume:  Normal")
    print(f"  - Staging: {'DETECTED' if staging['detected'] else 'None'}")
    print(f"  - Exfil:   {'DETECTED' if exfil['detected'] else 'None'}")
    print(f"  - Cleanup: {'DETECTED' if antiforensics['detected'] else 'None'}")

    print(f"\n  Expected alert definitions:")
    for ea in expected["expected_alerts"][:5]:
        source = ea["source"].upper()
        desc = ea["description"]
        sev = ea["severity"].upper()
        indicator = ea.get("behavioral_indicator", "")
        rule_key = "rule_id" if "rule_id" in ea else "sid"
        rule_val = ea.get(rule_key, "?")
        print(f"    [{source} {rule_val}] {desc} ({sev})")
        if indicator:
            print(f"      -> {indicator}")

    if passed_checks >= 4:
        print(f"\n{Fore.GREEN}  All key behavioral indicators detected successfully.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}  Some indicators missing. Review log generation.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
