#!/usr/bin/env python3
"""
Scenario 11: Automated containment response for botnet infections.

Actions:
1. Isolate infected network segment
2. Block C2 server communications
3. Terminate bot processes on infected hosts
4. Remove bot persistence mechanisms
5. Block DDoS target traffic
6. Generate Suricata drop rules
7. Preserve evidence
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

PATIENT_ZERO_IP = WORKSTATION_IPS[0]
BOT_IPS = WORKSTATION_IPS[1:9]
DDOS_TARGET_IP = "198.51.100.50"
C2_DOMAIN = "updates.evil-cdn.test"
BOT_PROCESS_NAMES = ["svchost_update.exe", "WindowsUpdateService"]


def isolate_infected_segment(bot_ips: list[str]) -> list[str]:
    """Generate commands to isolate infected network segment."""
    commands = [
        "# Isolate infected workstations at switch level",
        "# Move infected hosts to quarantine VLAN",
    ]
    for ip in bot_ips:
        commands.append(f"iptables -A FORWARD -s {ip} -j DROP")
        commands.append(f"iptables -A FORWARD -d {ip} -j DROP")
    commands.extend([
        "",
        "# Block all outbound from infected segment",
        "iptables -A FORWARD -s 10.0.0.100/28 -d 0.0.0.0/0 -j DROP",
        "# Allow only management access for remediation",
        "iptables -A FORWARD -s 10.0.0.0/24 -d 10.0.0.100/28 -p tcp --dport 22 -j ACCEPT",
    ])
    return commands


def block_c2_communications(c2_ip: str, c2_domain: str) -> list[str]:
    """Generate commands to block all C2 communications."""
    return [
        f"# Block C2 server IP at firewall",
        f"iptables -A OUTPUT -d {c2_ip} -j DROP",
        f"iptables -A INPUT -s {c2_ip} -j DROP",
        f"iptables -A FORWARD -d {c2_ip} -j DROP",
        f"",
        f"# Block C2 domain at DNS level",
        f"echo '0.0.0.0 {c2_domain}' >> /etc/hosts",
        f"# Add to DNS sinkhole",
        f"echo 'address=/{c2_domain}/0.0.0.0' >> /etc/dnsmasq.d/botnet-sinkhole.conf",
        f"systemctl restart dnsmasq",
        f"",
        f"# Block initial attacker IP",
        f"iptables -A INPUT -s {ATTACKER_IP} -j DROP",
        f"iptables -A OUTPUT -d {ATTACKER_IP} -j DROP",
    ]


def terminate_bot_processes(bot_ips: list[str], process_names: list[str]) -> list[str]:
    """Generate commands to terminate bot processes on infected hosts."""
    commands = [
        "# For each infected host, terminate bot processes:",
    ]
    for ip in bot_ips:
        commands.append(f"")
        commands.append(f"# --- Host: {ip} ---")
        for proc in process_names:
            commands.append(f"ssh admin@{ip} 'taskkill /F /IM {proc}'")
        commands.append(f"ssh admin@{ip} 'netstat -an | findstr {C2_SERVER_IP}'")
    return commands


def remove_persistence(bot_ips: list[str]) -> list[str]:
    """Generate commands to remove bot persistence mechanisms."""
    commands = [
        "# Remove scheduled task persistence from all infected hosts:",
    ]
    for ip in bot_ips:
        commands.extend([
            f"",
            f"# --- Host: {ip} ---",
            f"ssh admin@{ip} 'schtasks /Delete /TN WindowsUpdateService /F'",
            f"ssh admin@{ip} 'del /F C:\\Windows\\Temp\\svchost_update.exe'",
            f"ssh admin@{ip} 'reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdateService /f'",
        ])
    return commands


def block_ddos_traffic(target_ip: str) -> list[str]:
    """Generate commands to block outbound DDoS traffic."""
    return [
        f"# Block outbound DDoS traffic to target",
        f"iptables -A OUTPUT -d {target_ip} -j DROP",
        f"iptables -A FORWARD -d {target_ip} -j DROP",
        f"# Rate limit outbound SYN packets from internal network",
        f"iptables -A OUTPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
        f"iptables -A OUTPUT -p tcp --syn -j DROP",
        f"# Log blocked DDoS attempts",
        f"iptables -A OUTPUT -d {target_ip} -j LOG --log-prefix 'WCACE-DDOS-BLOCK: '",
    ]


def generate_suricata_drop_rules(c2_ip: str, target_ip: str) -> list[str]:
    """Generate Suricata drop rules for containment."""
    return [
        f'drop ip any any -> {c2_ip} any '
        f'(msg:"WCACE S11: Block botnet C2 server"; '
        f'sid:9119001; rev:1;)',
        f'drop ip {c2_ip} any -> any any '
        f'(msg:"WCACE S11: Block inbound from C2 server"; '
        f'sid:9119002; rev:1;)',
        f'drop tcp $HOME_NET any -> {target_ip} any '
        f'(msg:"WCACE S11: Block DDoS traffic to target"; '
        f'sid:9119003; rev:1;)',
        f'drop tcp $HOME_NET any -> $EXTERNAL_NET 443 '
        f'(msg:"WCACE S11: Block botnet data exfiltration"; '
        f'content:"/api/v1/upload"; sid:9119004; rev:1;)',
    ]


def generate_dns_sinkhole(domains: list[str]) -> list[str]:
    """Generate DNS sinkhole entries for botnet domains."""
    commands = [
        "# DNS sinkhole configuration for botnet domains",
        "# Add to /etc/dnsmasq.d/botnet-sinkhole.conf:",
    ]
    for domain in domains:
        commands.append(f"address=/{domain}/0.0.0.0")
    return commands


def preserve_evidence(c2_ip: str, logs_dir: str) -> str:
    """Create evidence package for the botnet incident."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "type": "Botnet Infection",
        "c2_server": c2_ip,
        "c2_domain": C2_DOMAIN,
        "patient_zero": PATIENT_ZERO_IP,
        "infected_hosts": BOT_IPS,
        "ddos_target": DDOS_TARGET_IP,
        "timestamp": datetime.now().isoformat(),
        "mitre_techniques": [
            "T1583.005", "T1071.001", "T1498",
            "T1059", "T1082", "T1210",
        ],
        "propagation_method": "SMB worm (EternalBlue-variant)",
        "containment_actions": [
            "Infected segment isolated via firewall rules",
            "C2 server IP and domain blocked",
            "Bot processes terminated on infected hosts",
            "Persistence mechanisms removed",
            "DDoS traffic blocked at firewall",
            "Suricata drop rules generated",
            "DNS sinkhole configured for C2 domain",
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
|  WCACE Scenario 11: Botnet Infection Containment           |
+============================================================+{Style.RESET_ALL}
""")

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

    # Step 1: Isolate infected segment
    print(f"{Fore.YELLOW}[1/8] Isolating infected network segment...{Style.RESET_ALL}")
    isolate_cmds = isolate_infected_segment(BOT_IPS)
    for cmd in isolate_cmds:
        print(f"  {cmd}")

    # Step 2: Block C2 communications
    print(f"\n{Fore.YELLOW}[2/8] Blocking C2 server communications...{Style.RESET_ALL}")
    c2_cmds = block_c2_communications(C2_SERVER_IP, C2_DOMAIN)
    for cmd in c2_cmds:
        print(f"  {cmd}")

    # Step 3: Terminate bot processes
    print(f"\n{Fore.YELLOW}[3/8] Terminating bot processes on infected hosts...{Style.RESET_ALL}")
    kill_cmds = terminate_bot_processes(BOT_IPS, BOT_PROCESS_NAMES)
    for cmd in kill_cmds:
        print(f"  {cmd}")

    # Step 4: Remove persistence mechanisms
    print(f"\n{Fore.YELLOW}[4/8] Removing bot persistence mechanisms...{Style.RESET_ALL}")
    persist_cmds = remove_persistence(BOT_IPS)
    for cmd in persist_cmds:
        print(f"  {cmd}")

    # Step 5: Block DDoS traffic
    print(f"\n{Fore.YELLOW}[5/8] Blocking outbound DDoS traffic...{Style.RESET_ALL}")
    ddos_cmds = block_ddos_traffic(DDOS_TARGET_IP)
    for cmd in ddos_cmds:
        print(f"  {cmd}")

    # Step 6: Suricata drop rules
    print(f"\n{Fore.YELLOW}[6/8] Generating Suricata drop rules...{Style.RESET_ALL}")
    suricata_rules = generate_suricata_drop_rules(C2_SERVER_IP, DDOS_TARGET_IP)
    for rule in suricata_rules:
        print(f"  {rule[:80]}...")

    # Step 7: DNS sinkhole
    print(f"\n{Fore.YELLOW}[7/8] Configuring DNS sinkhole...{Style.RESET_ALL}")
    sinkhole = generate_dns_sinkhole([C2_DOMAIN, "evil-cdn.test", "*.evil-cdn.test"])
    for line in sinkhole:
        print(f"  {line}")

    # Step 8: Try Wazuh active response
    print(f"\n{Fore.YELLOW}[8/8] Attempting Wazuh active response...{Style.RESET_ALL}")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [+] Wazuh connected - active response would block {C2_SERVER_IP}")
            print(f"  [+] Wazuh connected - would isolate {len(BOT_IPS)} infected agents")
        else:
            print(f"  [*] Wazuh not available - manual containment required")
    except Exception:
        print(f"  [*] Wazuh not available - manual containment required")

    # Preserve evidence
    print(f"\n{Fore.YELLOW}[*] Preserving evidence...{Style.RESET_ALL}")
    evidence_path = preserve_evidence(C2_SERVER_IP, logs_dir)
    print(f"  Evidence saved to: {evidence_path}")

    # Summary
    print(f"\n{Fore.GREEN}{'='*62}")
    print(f"  Containment Actions Summary")
    print(f"{'='*62}{Style.RESET_ALL}")
    print(f"  C2 Server:          {C2_SERVER_IP} ({C2_DOMAIN})")
    print(f"  Patient Zero:       {PATIENT_ZERO_IP}")
    print(f"  Infected Hosts:     {len(BOT_IPS)} workstations isolated")
    print(f"  DDoS Target:        {DDOS_TARGET_IP} (outbound blocked)")
    print(f"  Firewall Rules:     Segment isolation + C2 block + DDoS block")
    print(f"  Suricata Rules:     {len(suricata_rules)} drop rules generated")
    print(f"  DNS Sinkhole:       C2 domain sinkholed")
    print(f"  Bot Cleanup:        Process termination + persistence removal")
    print(f"  Evidence:           {evidence_path}")
    print(f"\n  Next steps: Review respond/playbook.md for full IR procedure")


if __name__ == "__main__":
    main()
