#!/usr/bin/env python3
"""
Scenario 18: Automated containment response for drive-by download attacks.

Actions:
1. Block exploit kit and payload domains at DNS/firewall
2. Quarantine downloaded payload
3. Kill malicious process on victim workstation
4. Block C2 communication
5. Generate Suricata drop rules
6. Preserve evidence
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import ATTACKER_IPS, C2_SERVER_IP, C2_DOMAIN

init(autoreset=True)

# Domains identified in the attack
MALICIOUS_DOMAINS = [
    "ads.tracknet-media.test",
    "cdn-static.clickserv.test",
    "gate.exploitkit.test",
    "dl.softupdate.test",
    C2_DOMAIN,
]

# IPs identified in the attack
MALICIOUS_IPS = ATTACKER_IPS[:3] + [C2_SERVER_IP]


def block_domains_dns(domains: list[str]) -> list[str]:
    """Generate DNS sinkhole entries for malicious domains."""
    entries = ["# WCACE S18 - Drive-By Download Containment - DNS Sinkhole"]
    for domain in domains:
        entries.append(f"0.0.0.0  {domain}")
        entries.append(f"0.0.0.0  *.{domain}")
    return entries


def generate_firewall_rules(ips: list[str]) -> list[str]:
    """Generate firewall rules to block malicious IPs."""
    rules = ["# Block exploit kit and payload delivery IPs"]
    for ip in ips:
        rules.append(f"iptables -A INPUT -s {ip} -j DROP")
        rules.append(f"iptables -A OUTPUT -d {ip} -j DROP")
    rules.extend([
        "",
        "# Block known exploit kit ports",
        "iptables -A INPUT -p tcp --dport 8080 -j DROP",
    ])
    return rules


def quarantine_payload() -> list[str]:
    """Generate commands to quarantine the downloaded payload."""
    return [
        "# Quarantine the downloaded payload",
        "mkdir -p /quarantine/$(date +%Y%m%d)",
        "mv 'C:\\Users\\victim\\AppData\\Local\\Temp\\kb5001330.exe' /quarantine/$(date +%Y%m%d)/",
        "",
        "# Or on Windows:",
        'move "%TEMP%\\kb5001330.exe" C:\\Quarantine\\',
        "",
        "# Calculate file hash for IOC sharing",
        "sha256sum /quarantine/$(date +%Y%m%d)/kb5001330.exe",
        "",
        "# Remove persistence (Windows registry)",
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdateSvc /f',
    ]


def kill_malicious_process() -> list[str]:
    """Generate commands to kill the malicious process."""
    return [
        "# Kill the malicious payload process",
        "taskkill /IM kb5001330.exe /F",
        "pkill -f kb5001330.exe  # Linux equivalent",
        "",
        "# Kill any child processes",
        "wmic process where \"ParentProcessId=(wmic process where name='kb5001330.exe' get ProcessId)\" delete",
        "",
        "# Check for any remaining suspicious processes",
        "tasklist /FI \"IMAGENAME eq kb5001330.exe\"",
    ]


def generate_proxy_block_rules(domains: list[str]) -> list[str]:
    """Generate web proxy block rules for malicious domains."""
    rules = ["# Squid proxy ACL rules to block exploit kit domains"]
    for domain in domains:
        rules.append(f"acl blocked_ek dstdomain .{domain}")
    rules.append("http_access deny blocked_ek")
    rules.extend([
        "",
        "# Nginx proxy block (add to server block)",
    ])
    for domain in domains:
        rules.append(f'if ($http_referer ~* "{domain}") {{ return 403; }}')
    return rules


def generate_suricata_drop_rules(ips: list[str], domains: list[str]) -> list[str]:
    """Generate Suricata drop rules for containment."""
    rules = []
    base_sid = 9189001

    for i, ip in enumerate(ips):
        rules.append(
            f'drop ip {ip} any -> $HOME_NET any '
            f'(msg:"WCACE S18: Block drive-by download source {ip}"; '
            f'sid:{base_sid + i}; rev:1;)'
        )

    for i, domain in enumerate(domains):
        rules.append(
            f'drop dns any any -> any 53 '
            f'(msg:"WCACE S18: Block DNS to exploit kit domain {domain}"; '
            f'dns.query; content:"{domain}"; nocase; '
            f'sid:{base_sid + len(ips) + i}; rev:1;)'
        )

    return rules


def generate_browser_hardening() -> list[str]:
    """Generate browser security hardening recommendations."""
    return [
        "# Browser security settings (Group Policy / Chrome Enterprise):",
        "# Disable Flash plugin",
        '# "DefaultPluginsSetting": 2',
        "# Block JavaScript on untrusted sites",
        '# "DefaultJavaScriptSetting": 2',
        "# Enable site isolation",
        '# "SitePerProcess": true',
        "# Block automatic downloads",
        '# "AutomaticDownloadsAllowedForUrls": []',
        "# Enable Safe Browsing",
        '# "SafeBrowsingProtectionLevel": 2',
        "",
        "# Deploy ad blocker via enterprise policy:",
        '# "ExtensionInstallForcelist": ["uBlock Origin extension ID"]',
    ]


def preserve_evidence(ips: list[str], domains: list[str], logs_dir: str) -> str:
    """Create evidence package for the incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Drive-By Download Attack",
        "malicious_ips": ips,
        "malicious_domains": domains,
        "timestamp": datetime.now().isoformat(),
        "mitre_techniques": ["T1189", "T1203", "T1071.001"],
        "attack_chain": [
            "Compromised ad network injected malicious iframe",
            "Exploit kit probed browser for vulnerabilities",
            "Drive-by download triggered via CVE-2021-30551",
            "Payload executed and established C2 communication",
        ],
        "containment_actions": [
            f"DNS sinkhole applied for {len(domains)} domains",
            f"Firewall rules generated for {len(ips)} IPs",
            "Payload quarantined and persistence removed",
            "Malicious process terminated",
            "Suricata drop rules generated",
            "Web proxy block rules generated",
        ],
        "evidence_files": [],
    }

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
{Fore.RED}+============================================================+
|  WCACE Scenario 18: Drive-By Download Containment          |
+============================================================+{Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: DNS sinkhole
    print(f"{Fore.YELLOW}[1/7] Generating DNS sinkhole for malicious domains...{Style.RESET_ALL}")
    dns_entries = block_domains_dns(MALICIOUS_DOMAINS)
    for entry in dns_entries[:6]:
        print(f"  {entry}")
    if len(dns_entries) > 6:
        print(f"  ... and {len(dns_entries) - 6} more entries")

    # Step 2: Firewall rules
    print(f"\n{Fore.YELLOW}[2/7] Generating firewall block rules...{Style.RESET_ALL}")
    fw_rules = generate_firewall_rules(MALICIOUS_IPS)
    for rule in fw_rules[:5]:
        print(f"  {rule}")
    if len(fw_rules) > 5:
        print(f"  ... and {len(fw_rules) - 5} more rules")

    # Step 3: Kill malicious process
    print(f"\n{Fore.YELLOW}[3/7] Generating process termination commands...{Style.RESET_ALL}")
    kill_cmds = kill_malicious_process()
    for cmd in kill_cmds:
        print(f"  {cmd}")

    # Step 4: Quarantine payload
    print(f"\n{Fore.YELLOW}[4/7] Generating payload quarantine commands...{Style.RESET_ALL}")
    quarantine_cmds = quarantine_payload()
    for cmd in quarantine_cmds:
        print(f"  {cmd}")

    # Step 5: Web proxy blocking
    print(f"\n{Fore.YELLOW}[5/7] Generating web proxy block rules...{Style.RESET_ALL}")
    proxy_rules = generate_proxy_block_rules(MALICIOUS_DOMAINS)
    for rule in proxy_rules[:6]:
        print(f"  {rule}")

    # Step 6: Suricata drop rules
    print(f"\n{Fore.YELLOW}[6/7] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(MALICIOUS_IPS, MALICIOUS_DOMAINS)
    for rule in suricata_rules[:3]:
        print(f"  {rule[:80]}...")
    if len(suricata_rules) > 3:
        print(f"  ... and {len(suricata_rules) - 3} more rules")

    # Step 7: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[7/7] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [+] Wazuh connected - active response would block {len(MALICIOUS_IPS)} IPs")
        else:
            print(f"  [*] Wazuh not available - manual containment required")
    except Exception:
        print(f"  [*] Wazuh not available - manual containment required")

    # Preserve evidence
    print(f"\n{Fore.YELLOW}[*] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(MALICIOUS_IPS, MALICIOUS_DOMAINS, logs_dir)
    print(f"  Evidence saved to: {evidence_path}")

    # Browser hardening
    print(f"\n{Fore.YELLOW}[*] Browser hardening recommendations:{Style.RESET_ALL}")
    hardening = generate_browser_hardening()
    for line in hardening[:5]:
        print(f"  {line}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  Malicious Domains:  {len(MALICIOUS_DOMAINS)} domains sinkheld")
    print(f"  Malicious IPs:      {len(MALICIOUS_IPS)} IPs blocked")
    print(f"  Firewall Rules:     {len(fw_rules)} rules generated")
    print(f"  Suricata Rules:     {len(suricata_rules)} drop rules generated")
    print(f"  Proxy Rules:        {len(proxy_rules)} ACL entries generated")
    print(f"  Evidence:           {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
