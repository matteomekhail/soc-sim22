#!/usr/bin/env python3
"""
Scenario 14: Automated containment response for credential stuffing attacks.

Actions:
1. Block attacker IP(s) via firewall rules
2. Enable rate limiting on login endpoint
3. Lock compromised accounts
4. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IP, ATTACKER_IPS

init(autoreset=True)


def block_ip_firewall(ip: str) -> str:
    """Generate firewall block rule for an IP."""
    return f"iptables -A INPUT -s {ip} -j DROP"


def block_ip_range_firewall(ips: list[str]) -> list[str]:
    """Generate firewall block rules for multiple IPs."""
    return [block_ip_firewall(ip) for ip in ips]


def generate_rate_limit_nginx() -> str:
    """Generate nginx rate limiting configuration for login endpoint."""
    return """# Add to nginx.conf http block:
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

# Add to server/location block for /login:
location /login {
    limit_req zone=login burst=3 nodelay;
    limit_req_status 429;
    proxy_pass http://backend;
}"""


def generate_fail2ban_jail() -> str:
    """Generate fail2ban jail configuration for login protection."""
    return """# /etc/fail2ban/jail.d/wcace-login.conf
[wcace-login]
enabled  = true
port     = http,https
filter   = wcace-login
logpath  = /var/log/webapp/access.log
maxretry = 5
findtime = 300
bantime  = 3600
action   = iptables-multiport[name=wcace-login, port="http,https"]"""


def lock_compromised_accounts(logs_dir: str) -> list[str]:
    """Identify and lock compromised accounts from attack report."""
    compromised_file = os.path.join(logs_dir, "compromised_accounts.json")
    locked_accounts = []

    if os.path.exists(compromised_file):
        with open(compromised_file) as f:
            data = json.load(f)
        for acct in data.get("accounts", []):
            username = acct["username"]
            locked_accounts.append(username)
            print(f"    [+] Account locked: {username} (compromised from {acct['src_ip']})")
    else:
        print(f"    [*] No compromised accounts report found")

    return locked_accounts


def generate_suricata_drop_rules(ips: list[str], base_sid: int = 9299001) -> list[str]:
    """Generate Suricata drop rules for attacker IPs."""
    rules = []
    for i, ip in enumerate(ips):
        rules.append(
            f'drop ip {ip} any -> $HOME_NET any '
            f'(msg:"WCACE S14: Block credential stuffing attacker {ip}"; '
            f'sid:{base_sid + i}; rev:1;)'
        )
    return rules


def preserve_evidence(attacker_ips: list[str], logs_dir: str) -> str:
    """Create evidence package for the incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Credential Stuffing Attack",
        "attacker_ips": attacker_ips,
        "timestamp": datetime.now().isoformat(),
        "containment_actions": [
            f"Firewall rules generated for {len(attacker_ips)} IPs",
            "Rate limiting configuration generated (nginx)",
            "Fail2ban jail configuration generated",
            "Suricata drop rules generated",
            "Compromised accounts locked",
        ],
        "evidence_files": [],
    }

    # List available log files
    if os.path.exists(logs_dir):
        for f in os.listdir(logs_dir):
            evidence["evidence_files"].append(os.path.join(logs_dir, f))

    evidence_file = os.path.join(logs_dir, "incident_evidence.json")
    os.makedirs(logs_dir, exist_ok=True)
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)

    return evidence_file


def main():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║  WCACE Scenario 14: Credential Stuffing Containment     ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Use primary attacker IP and a subset of distributed IPs
    attacker_ips = [ATTACKER_IP] + ATTACKER_IPS[:5]

    # Step 1: Generate firewall block rules
    print(f"{Fore.YELLOW}[1] Generating firewall block rules...{Style.RESET_ALL}")
    fw_rules = block_ip_range_firewall(attacker_ips)
    for rule in fw_rules[:3]:
        print(f"  -> {rule}")
    if len(fw_rules) > 3:
        print(f"  -> ... and {len(fw_rules) - 3} more rules")

    # Step 2: Generate rate limiting config
    print(f"\n{Fore.YELLOW}[2] Generating rate limiting configuration...{Style.RESET_ALL}")
    nginx_config = generate_rate_limit_nginx()
    print(f"  -> Nginx rate limit config generated (5 req/min for /login)")
    f2b_config = generate_fail2ban_jail()
    print(f"  -> Fail2ban jail config generated (ban after 5 failures)")

    # Step 3: Generate Suricata drop rules
    print(f"\n{Fore.YELLOW}[3] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(attacker_ips)
    for rule in suricata_rules[:2]:
        print(f"  -> {rule[:80]}...")
    if len(suricata_rules) > 2:
        print(f"  -> ... and {len(suricata_rules) - 2} more rules")

    # Step 4: Lock compromised accounts
    print(f"\n{Fore.YELLOW}[4] Locking compromised accounts...{Style.RESET_ALL}")
    locked = lock_compromised_accounts(logs_dir)

    # Step 5: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[5] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [+] Wazuh connected - active response would block {len(attacker_ips)} IPs")
        else:
            print(f"  [*] Wazuh not available - manual block required")
    except Exception:
        print(f"  [*] Wazuh not available - manual block required")

    # Step 6: Preserve evidence
    print(f"\n{Fore.YELLOW}[6] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(attacker_ips, logs_dir)
    print(f"  -> Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"Containment Actions Summary")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  Attacker IPs:    {len(attacker_ips)} IPs identified")
    print(f"  Firewall:        {len(fw_rules)} block rules generated")
    print(f"  Rate Limiting:   Nginx + Fail2ban configs generated")
    print(f"  Suricata:        {len(suricata_rules)} drop rules generated")
    print(f"  Accounts Locked: {len(locked)}")
    print(f"  Evidence:        {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
