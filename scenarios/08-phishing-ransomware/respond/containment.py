#!/usr/bin/env python3
"""
Scenario 08: Ransomware Incident Containment Response.

Automated containment actions:
1. Isolate affected host (firewall rules)
2. Kill encryption process
3. Preserve encryption key for recovery
4. Attempt file decryption with recovered key
5. Generate incident evidence package
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IP, C2_SERVER_IP, WORKSTATION_IPS

init(autoreset=True)

SANDBOX_DIR = "/tmp/wcace-sandbox/victim-files"
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")
KEY_FILE = os.path.join(LOG_DIR, "encryption_key.txt")


def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 08: Ransomware Containment Response          |
|  Actions: Isolate, Kill Process, Recover Key, Decrypt        |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Step 1: Network Isolation
# ---------------------------------------------------------------------------

def isolate_host(victim_ip: str) -> list[str]:
    """Generate firewall rules to isolate the compromised host."""
    rules = [
        f"iptables -A INPUT -s {victim_ip} -j DROP",
        f"iptables -A OUTPUT -d {victim_ip} -j DROP",
        f"iptables -A FORWARD -s {victim_ip} -j DROP",
        f"iptables -A FORWARD -d {victim_ip} -j DROP",
    ]
    # Block C2 communication from entire network
    c2_rules = [
        f"iptables -A OUTPUT -d {C2_SERVER_IP} -j DROP",
        f"iptables -A FORWARD -d {C2_SERVER_IP} -j DROP",
    ]
    return rules + c2_rules


# ---------------------------------------------------------------------------
# Step 2: Kill Encryption Process
# ---------------------------------------------------------------------------

def kill_encryption_process() -> list[str]:
    """Generate commands to terminate the ransomware process."""
    commands = [
        "# Identify the ransomware process",
        "ps aux | grep -i 'svchost_update\\|encrypt\\|ransom' | grep -v grep",
        "",
        "# Kill by process name",
        "pkill -9 -f svchost_update.exe",
        "pkill -9 -f encrypt",
        "",
        "# Verify process is terminated",
        "ps aux | grep -i 'svchost_update\\|encrypt\\|ransom' | grep -v grep",
        "",
        "# Prevent re-execution (remove from startup)",
        "# Windows: reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v svchost_update /f",
        "# Linux:   rm -f ~/.config/autostart/svchost_update.desktop",
    ]
    return commands


# ---------------------------------------------------------------------------
# Step 3: Preserve / Recover Encryption Key
# ---------------------------------------------------------------------------

def recover_encryption_key() -> str:
    """Attempt to recover the encryption key from logs."""
    if not os.path.exists(KEY_FILE):
        return ""

    with open(KEY_FILE) as f:
        for line in f:
            line = line.strip()
            if line.startswith("key="):
                return line[4:]
    return ""


# ---------------------------------------------------------------------------
# Step 4: Decrypt Files
# ---------------------------------------------------------------------------

def decrypt_files(key_str: str) -> int:
    """Attempt to decrypt files in the sandbox using the recovered key."""
    if not key_str:
        return 0

    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError:
        print(f"  {Fore.RED}[!] cryptography package not installed{Style.RESET_ALL}")
        return 0

    try:
        fernet = Fernet(key_str.encode())
    except Exception as e:
        print(f"  {Fore.RED}[!] Invalid key: {e}{Style.RESET_ALL}")
        return 0

    decrypted_count = 0

    if not os.path.exists(SANDBOX_DIR):
        return 0

    for root, dirs, files in os.walk(SANDBOX_DIR):
        for filename in files:
            if not filename.endswith(".encrypted"):
                continue

            filepath = os.path.join(root, filename)
            original_path = filepath[: -len(".encrypted")]

            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = fernet.decrypt(encrypted_data)

                with open(original_path, "wb") as f:
                    f.write(decrypted_data)

                os.remove(filepath)
                decrypted_count += 1
                rel = os.path.relpath(original_path, SANDBOX_DIR)
                print(f"    {Fore.GREEN}[DECRYPTED]{Style.RESET_ALL} {rel}")

            except InvalidToken:
                rel = os.path.relpath(filepath, SANDBOX_DIR)
                print(f"    {Fore.RED}[FAILED]{Style.RESET_ALL} {rel} -- wrong key or corrupted")
            except Exception as e:
                print(f"    {Fore.RED}[ERROR]{Style.RESET_ALL} {filename}: {e}")

    # Remove ransom notes after decryption
    for root, dirs, files in os.walk(SANDBOX_DIR):
        for filename in files:
            if filename == "RANSOM_NOTE.txt":
                os.remove(os.path.join(root, filename))

    return decrypted_count


# ---------------------------------------------------------------------------
# Step 5: Evidence Preservation
# ---------------------------------------------------------------------------

def preserve_evidence(victim_ip: str, key_recovered: bool, decrypted: int) -> str:
    """Create an incident evidence package."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}-RANSOM",
        "type": "Ransomware Attack (Phishing Vector)",
        "severity": "CRITICAL",
        "timestamp": datetime.now().isoformat(),
        "attacker_ip": ATTACKER_IP,
        "c2_server": C2_SERVER_IP,
        "victim_ip": victim_ip,
        "mitre_techniques": ["T1566.001", "T1204.002", "T1486", "T1071"],
        "containment_actions": [
            "Network isolation rules generated for victim host",
            "C2 server IP blocked at network perimeter",
            "Ransomware process kill commands generated",
            f"Encryption key recovered: {key_recovered}",
            f"Files decrypted: {decrypted}",
        ],
        "evidence_files": [],
        "ioc_indicators": {
            "ip_addresses": [ATTACKER_IP, C2_SERVER_IP],
            "file_extensions": [".encrypted"],
            "file_names": ["RANSOM_NOTE.txt", "svchost_update.exe", "Invoice_2024.pdf.exe"],
            "domains": ["updates.evil-cdn.test", "acmecorp-login.test"],
        },
    }

    # Gather log files as evidence
    if os.path.exists(LOG_DIR):
        for f in os.listdir(LOG_DIR):
            evidence["evidence_files"].append(os.path.join(LOG_DIR, f))

    os.makedirs(LOG_DIR, exist_ok=True)
    evidence_file = os.path.join(LOG_DIR, "incident_evidence.json")
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)

    return evidence_file


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    victim_ip = WORKSTATION_IPS[0]

    # -----------------------------------------------------------------------
    # Step 1: Isolate host
    # -----------------------------------------------------------------------
    print(f"{Fore.YELLOW}[Step 1] Network Isolation{Style.RESET_ALL}")
    print(f"  Victim IP: {victim_ip}")
    print(f"  C2 Server: {C2_SERVER_IP}\n")

    fw_rules = isolate_host(victim_ip)
    print(f"  Generated firewall rules (apply manually or via orchestration):")
    for rule in fw_rules:
        print(f"    {rule}")

    # Wazuh active response (if available)
    print(f"\n  Attempting Wazuh active response...")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [OK] Wazuh connected -- active response would isolate {victim_ip}")
        else:
            print(f"  [SKIP] Wazuh not available -- manual isolation required")
    except Exception:
        print(f"  [SKIP] Wazuh not available -- manual isolation required")

    # -----------------------------------------------------------------------
    # Step 2: Kill encryption process
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 2] Kill Encryption Process{Style.RESET_ALL}")
    kill_commands = kill_encryption_process()
    print(f"  Commands to terminate ransomware (apply on victim host):")
    for cmd in kill_commands:
        print(f"    {cmd}")

    # -----------------------------------------------------------------------
    # Step 3: Recover encryption key
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 3] Recover Encryption Key{Style.RESET_ALL}")
    key = recover_encryption_key()
    if key:
        print(f"  [OK] Encryption key recovered: {key[:20]}...")
        print(f"  Key source: {KEY_FILE}")
    else:
        print(f"  {Fore.RED}[!] Encryption key not found.")
        print(f"      Run attack/simulate_attack.py first to generate the key.{Style.RESET_ALL}")

    # -----------------------------------------------------------------------
    # Step 4: Decrypt files
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 4] File Recovery / Decryption{Style.RESET_ALL}")
    if key:
        print(f"  Attempting decryption of files in {SANDBOX_DIR}...\n")
        decrypted = decrypt_files(key)
        if decrypted > 0:
            print(f"\n  {Fore.GREEN}[OK] {decrypted} files successfully decrypted{Style.RESET_ALL}")
        else:
            print(f"  [!] No encrypted files found to decrypt")
    else:
        decrypted = 0
        print(f"  [SKIP] Cannot decrypt without encryption key")

    # -----------------------------------------------------------------------
    # Step 5: Preserve evidence
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 5] Evidence Preservation{Style.RESET_ALL}")
    evidence_file = preserve_evidence(victim_ip, bool(key), decrypted)
    print(f"  Incident evidence saved to: {evidence_file}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Containment Response Summary")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Victim IP:           {victim_ip}")
    print(f"  C2 Blocked:          {C2_SERVER_IP}")
    print(f"  Firewall Rules:      {len(fw_rules)} rules generated")
    print(f"  Key Recovered:       {'Yes' if key else 'No'}")
    print(f"  Files Decrypted:     {decrypted}")
    print(f"  Evidence Package:    {evidence_file}")
    print(f"\n  Next steps:")
    print(f"    1. Apply firewall rules on network perimeter")
    print(f"    2. Verify all encrypted files are recovered")
    print(f"    3. Scan victim host for persistence mechanisms")
    print(f"    4. Review respond/playbook.md for full IR procedure")
    print(f"    5. Report IOCs to threat intelligence feeds\n")


if __name__ == "__main__":
    main()
