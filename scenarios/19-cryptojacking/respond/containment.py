#!/usr/bin/env python3
"""
Scenario 19: Automated containment response for cryptojacking attacks.

Actions:
1. Block mining pool IP and domain at firewall/DNS
2. Identify and remove injected mining JavaScript
3. Scan affected hosts for persistence mechanisms
4. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import MINING_POOL_IP, MINING_POOL_DOMAIN, WORKSTATION_IPS

init(autoreset=True)


def block_mining_pool_firewall(ip: str) -> list[str]:
    """Generate firewall rules to block mining pool connections."""
    rules = [
        f"iptables -A OUTPUT -d {ip} -j DROP",
        f"iptables -A OUTPUT -d {ip} -p tcp --dport 3333 -j DROP",
        f"iptables -A OUTPUT -d {ip} -p tcp --dport 3334 -j DROP",
        f"iptables -A OUTPUT -d {ip} -p tcp --dport 443 -j DROP",
        f"iptables -A FORWARD -d {ip} -j DROP",
    ]
    return rules


def block_mining_pool_dns(domain: str) -> list[str]:
    """Generate DNS sinkhole rules to block mining pool domain."""
    rules = [
        f"# Add to /etc/hosts or DNS sinkhole:",
        f"127.0.0.1  {domain}",
        f"127.0.0.1  *.{domain}",
        f"# Or via dnsmasq:",
        f"address=/{domain}/127.0.0.1",
    ]
    return rules


def generate_suricata_drop_rules(ip: str, domain: str) -> list[str]:
    """Generate Suricata drop rules for mining traffic."""
    rules = [
        f'drop tcp $HOME_NET any -> {ip} any '
        f'(msg:"WCACE: Block mining pool {ip}"; sid:9199001; rev:1;)',
        f'drop http $HOME_NET any -> $EXTERNAL_NET any '
        f'(msg:"WCACE: Block coinhive JS"; content:"coinhive"; nocase; sid:9199002; rev:1;)',
        f'drop tcp $HOME_NET any -> $EXTERNAL_NET 3333:3334 '
        f'(msg:"WCACE: Block stratum protocol"; content:"method"; content:"login"; '
        f'distance:0; sid:9199003; rev:1;)',
    ]
    return rules


def remove_injected_js_commands() -> list[str]:
    """Generate commands to scan for and remove injected mining JS."""
    commands = [
        "# Scan web server document root for injected mining scripts:",
        "grep -rl 'coinhive\\|CoinHive\\|coin-hive\\|cryptonight\\|minero' /var/www/html/",
        "",
        "# Remove coinhive script tags from HTML files:",
        "find /var/www/html -name '*.html' -exec sed -i '/<script.*coinhive/,/<\\/script>/d' {} \\;",
        "",
        "# Remove coinhive JS library files:",
        "find /var/www/html -name 'coinhive*' -delete",
        "find /var/www/html -name '*miner*.js' -delete",
        "",
        "# Check for dynamically loaded miners via server-side code:",
        "grep -rl 'coinhive\\|cryptonight\\|stratum' /var/www/html/*.php /var/www/html/*.py 2>/dev/null",
        "",
        "# Verify web server config for injected headers/footers:",
        "grep -r 'coinhive\\|crypto' /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null",
    ]
    return commands


def scan_persistence_commands() -> list[str]:
    """Generate commands to check for mining persistence mechanisms."""
    commands = [
        "# Check for crontab entries related to mining:",
        "for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -i 'mine\\|xmr\\|crypto'; done",
        "",
        "# Check for mining processes:",
        "ps aux | grep -iE 'xmrig|xmr-stak|minerd|cpuminer|coinhive|cryptonight'",
        "",
        "# Check for suspicious high-CPU processes:",
        "ps aux --sort=-%cpu | head -20",
        "",
        "# Check for startup scripts with mining references:",
        "grep -rl 'mine\\|xmr\\|stratum\\|coinhive' /etc/init.d/ /etc/systemd/system/ 2>/dev/null",
        "",
        "# Check for unauthorized network connections to mining pools:",
        "netstat -an | grep -E ':3333|:3334|:8333'",
        "ss -tnp | grep -E ':3333|:3334|:8333'",
        "",
        "# Check browser extensions for mining plugins:",
        "find /home -path '*/.config/google-chrome/*/Extensions/*' -name 'manifest.json' "
        "-exec grep -l 'mine\\|crypto\\|coinhive' {} \\; 2>/dev/null",
    ]
    return commands


def preserve_evidence(logs_dir: str) -> str:
    """Create evidence package for the cryptojacking incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Cryptojacking - Browser-Based Mining",
        "mining_pool_ip": MINING_POOL_IP,
        "mining_pool_domain": MINING_POOL_DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "affected_hosts": WORKSTATION_IPS[:5],
        "attack_vector": "Injected coinhive-style JS in compromised website",
        "containment_actions": [
            f"Firewall rules: Block {MINING_POOL_IP} (all ports + stratum 3333/3334)",
            f"DNS sinkhole: {MINING_POOL_DOMAIN} -> 127.0.0.1",
            "Suricata drop rules: coinhive JS, stratum protocol",
            "Web server scanned for injected mining scripts",
            "Persistence scan initiated on affected workstations",
        ],
        "evidence_files": [],
        "ioc_list": [
            {"type": "ip", "value": MINING_POOL_IP, "description": "Mining pool IP"},
            {"type": "domain", "value": MINING_POOL_DOMAIN, "description": "Mining pool domain"},
            {"type": "filename", "value": "coinhive.min.js", "description": "Miner JS library"},
            {"type": "port", "value": "3333", "description": "Stratum protocol port"},
            {"type": "port", "value": "3334", "description": "Stratum SSL port"},
        ],
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
{Fore.RED}=====================================================================
  WCACE Scenario 19: Cryptojacking Containment Response
====================================================================={Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Block mining pool at firewall
    print(f"{Fore.YELLOW}[1] Blocking mining pool at firewall...{Style.RESET_ALL}")
    fw_rules = block_mining_pool_firewall(MINING_POOL_IP)
    for rule in fw_rules:
        print(f"  -> {rule}")

    # Step 2: DNS sinkhole for mining pool domain
    print(f"\n{Fore.YELLOW}[2] Setting up DNS sinkhole for mining pool...{Style.RESET_ALL}")
    dns_rules = block_mining_pool_dns(MINING_POOL_DOMAIN)
    for rule in dns_rules:
        print(f"  -> {rule}")

    # Step 3: Suricata drop rules
    print(f"\n{Fore.YELLOW}[3] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(MINING_POOL_IP, MINING_POOL_DOMAIN)
    for rule in suricata_rules:
        print(f"  -> {rule}")

    # Step 4: Remove injected JavaScript
    print(f"\n{Fore.YELLOW}[4] Scanning for and removing injected mining JS...{Style.RESET_ALL}")
    js_commands = remove_injected_js_commands()
    for cmd in js_commands:
        print(f"  {cmd}")

    # Step 5: Scan for persistence
    print(f"\n{Fore.YELLOW}[5] Scanning for mining persistence mechanisms...{Style.RESET_ALL}")
    persist_commands = scan_persistence_commands()
    for cmd in persist_commands:
        print(f"  {cmd}")

    # Step 6: Wazuh active response
    print(f"\n{Fore.YELLOW}[6] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  + Wazuh connected - active response would block {MINING_POOL_IP}")
        else:
            print(f"  ! Wazuh not available - manual block required")
    except Exception:
        print(f"  ! Wazuh not available - manual block required")

    # Step 7: Preserve evidence
    print(f"\n{Fore.YELLOW}[7] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(logs_dir)
    print(f"  -> Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"Containment Actions Summary")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  Mining Pool IP:    {MINING_POOL_IP}")
    print(f"  Mining Pool Domain:{MINING_POOL_DOMAIN}")
    print(f"  Firewall:          {len(fw_rules)} rules generated (apply manually)")
    print(f"  DNS Sinkhole:      Rule generated for {MINING_POOL_DOMAIN}")
    print(f"  Suricata:          {len(suricata_rules)} drop rules generated")
    print(f"  JS Removal:        Scan commands generated")
    print(f"  Persistence:       Scan commands generated")
    print(f"  Evidence:          {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
