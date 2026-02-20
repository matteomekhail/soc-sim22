#!/usr/bin/env python3
"""
Scenario 17: Automated containment response for DNS tunnelling attacks.

Actions:
1. DNS sinkhole - redirect exfil domain to localhost
2. Block exfiltration domain at firewall level
3. Generate Suricata drop rules
4. Alert SOC team
5. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IP, DNS_SERVER_IP, DNS_TUNNEL_DOMAIN

init(autoreset=True)


def generate_sinkhole_entry(domain: str) -> str:
    """Generate DNS sinkhole entry to redirect domain to localhost."""
    # Strip subdomain prefix to sinkhole the entire domain tree
    base_domain = ".".join(domain.split(".")[-2:])  # e.g., exfil.test
    return f"127.0.0.1  {base_domain}\n127.0.0.1  *.{base_domain}"


def generate_hosts_block(domain: str) -> list[str]:
    """Generate /etc/hosts entries to block the exfil domain."""
    base_domain = ".".join(domain.split(".")[-2:])
    return [
        f"# WCACE S17 - DNS Tunnel Containment ({datetime.now().isoformat()})",
        f"0.0.0.0  {base_domain}",
        f"0.0.0.0  {domain}",
        f"0.0.0.0  *.{base_domain}",
    ]


def generate_firewall_rules(attacker_ip: str, dns_server_ip: str) -> list[str]:
    """Generate firewall rules to block DNS tunnel traffic."""
    return [
        f"# Block attacker IP from all DNS traffic",
        f"iptables -A OUTPUT -d {attacker_ip} -p udp --dport 53 -j DROP",
        f"iptables -A OUTPUT -d {attacker_ip} -p tcp --dport 53 -j DROP",
        f"# Block all outbound DNS to non-approved servers",
        f"iptables -A OUTPUT -p udp --dport 53 ! -d {dns_server_ip} -j DROP",
        f"iptables -A OUTPUT -p tcp --dport 53 ! -d {dns_server_ip} -j DROP",
        f"# Rate limit DNS queries from compromised host",
        f"iptables -A OUTPUT -p udp --dport 53 -m limit --limit 10/min --limit-burst 20 -j ACCEPT",
        f"iptables -A OUTPUT -p udp --dport 53 -j DROP",
    ]


def generate_suricata_drop_rules(domain: str, attacker_ip: str) -> list[str]:
    """Generate Suricata drop rules for DNS tunnel containment."""
    base_domain = ".".join(domain.split(".")[-2:])
    return [
        f'drop dns any any -> any 53 (msg:"WCACE S17: Block DNS tunnel to {base_domain}"; '
        f'dns.query; content:"{base_domain}"; nocase; sid:9179001; rev:1;)',
        f'drop dns {attacker_ip} any -> any 53 (msg:"WCACE S17: Block all DNS from tunnel source"; '
        f'sid:9179002; rev:1;)',
    ]


def generate_coredns_block(domain: str) -> str:
    """Generate CoreDNS configuration to sinkhole the domain."""
    base_domain = ".".join(domain.split(".")[-2:])
    return f"""{base_domain} {{
    hosts {{
        0.0.0.0 {base_domain}
        fallthrough
    }}
    log
}}
"""


def preserve_evidence(attacker_ip: str, domain: str, logs_dir: str) -> str:
    """Create evidence package for the incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "DNS Tunnelling - Data Exfiltration",
        "attacker_ip": attacker_ip,
        "exfil_domain": domain,
        "timestamp": datetime.now().isoformat(),
        "mitre_techniques": ["T1071.004", "T1048"],
        "containment_actions": [
            "DNS sinkhole applied for exfil domain",
            "Firewall rules generated to block DNS tunnel",
            "Suricata drop rules generated",
            "CoreDNS block configuration generated",
        ],
        "evidence_files": [],
    }

    # Collect available log files
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
{Fore.RED}{'='*62}
  WCACE Scenario 17: DNS Tunnelling Containment Response
{'='*62}{Style.RESET_ALL}
""")

    attacker_ip = ATTACKER_IP
    domain = DNS_TUNNEL_DOMAIN
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: DNS Sinkhole
    print(f"{Fore.YELLOW}[1/6] Generating DNS sinkhole configuration...{Style.RESET_ALL}")
    sinkhole = generate_sinkhole_entry(domain)
    print(f"  Sinkhole entry:")
    for line in sinkhole.split("\n"):
        print(f"    {line}")

    # Step 2: Hosts file block
    print(f"\n{Fore.YELLOW}[2/6] Generating /etc/hosts block entries...{Style.RESET_ALL}")
    hosts_entries = generate_hosts_block(domain)
    for entry in hosts_entries:
        print(f"    {entry}")

    # Step 3: Firewall rules
    print(f"\n{Fore.YELLOW}[3/6] Generating firewall rules...{Style.RESET_ALL}")
    fw_rules = generate_firewall_rules(attacker_ip, DNS_SERVER_IP)
    for rule in fw_rules:
        print(f"    {rule}")

    # Step 4: Suricata drop rules
    print(f"\n{Fore.YELLOW}[4/6] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(domain, attacker_ip)
    for rule in suricata_rules:
        print(f"    {rule}")

    # Step 5: CoreDNS block
    print(f"\n{Fore.YELLOW}[5/6] Generating CoreDNS sinkhole block...{Style.RESET_ALL}")
    coredns_block = generate_coredns_block(domain)
    for line in coredns_block.strip().split("\n"):
        print(f"    {line}")

    # Step 6: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[6/6] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  + Wazuh connected - active response would block DNS to {domain}")
        else:
            print(f"  ! Wazuh not available - manual containment required")
    except Exception:
        print(f"  ! Wazuh not available - manual containment required")

    # Preserve evidence
    print(f"\n{Fore.YELLOW}[*] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(attacker_ip, domain, logs_dir)
    print(f"  Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Attacker IP       : {attacker_ip}")
    print(f"  Exfil Domain      : {domain}")
    print(f"  DNS Sinkhole      : Generated (apply to /etc/hosts or DNS server)")
    print(f"  Firewall Rules    : {len(fw_rules)} rules generated")
    print(f"  Suricata Rules    : {len(suricata_rules)} drop rules generated")
    print(f"  CoreDNS Block     : Sinkhole config generated")
    print(f"  Evidence          : {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
