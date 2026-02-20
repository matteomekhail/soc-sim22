#!/usr/bin/env python3
"""
Scenario 12: Watering Hole Attack Incident Containment Response.

Automated containment actions:
1. Block the compromised website at DNS/proxy
2. Isolate infected workstations from the network
3. Block C2 server IP at firewall perimeter
4. Remove persistence mechanisms on compromised hosts
5. Scan all endpoints that visited the compromised site
6. Preserve evidence and generate incident package
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import (
    ATTACKER_IP, C2_SERVER_IP, WORKSTATION_IPS, WATERING_HOLE_DOMAIN,
)

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")
ATTACK_LOG = os.path.join(LOG_DIR, "watering_hole_attack.jsonl")

COMPROMISED_WEBSITE = WATERING_HOLE_DOMAIN
PAYLOAD_NAME = "msedge_update.exe"
PERSISTENCE_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"


def banner():
    print(f"""
{Fore.RED}+==============================================================+
|  WCACE Scenario 12: Watering Hole Containment Response       |
|  Actions: Block Site, Isolate Hosts, Block C2, Clean, Scan   |
+==============================================================+{Style.RESET_ALL}
""")


# ---------------------------------------------------------------------------
# Step 1: Block Compromised Website
# ---------------------------------------------------------------------------

def block_compromised_website() -> list[str]:
    """Generate commands to block the compromised watering hole website."""
    commands = [
        f"# Block compromised website at DNS sinkhole",
        f"echo '0.0.0.0 {COMPROMISED_WEBSITE}' >> /etc/hosts",
        f"",
        f"# Block at proxy/firewall level",
        f"iptables -A OUTPUT -d 198.51.100.25 -j DROP",
        f"iptables -A FORWARD -d 198.51.100.25 -j DROP",
        f"",
        f"# Add to web proxy blocklist",
        f"# squid: acl blocked_watering_hole dstdomain {COMPROMISED_WEBSITE}",
        f"# squid: http_access deny blocked_watering_hole",
        f"",
        f"# Notify website owner of compromise",
        f"# Contact: abuse@{COMPROMISED_WEBSITE}",
    ]
    return commands


# ---------------------------------------------------------------------------
# Step 2: Isolate Infected Workstations
# ---------------------------------------------------------------------------

def identify_compromised_hosts() -> list[str]:
    """Identify workstations that were exploited by parsing attack logs."""
    compromised = set()

    if not os.path.exists(ATTACK_LOG):
        return list(compromised)

    with open(ATTACK_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                # Hosts with C2 connections are confirmed compromised
                if entry.get("event_type") == "network_connection" and \
                   entry.get("dst_ip") == C2_SERVER_IP:
                    compromised.add(entry.get("src_ip", ""))
                # Hosts with registry persistence are confirmed compromised
                if entry.get("event_type") == "registry_modification":
                    compromised.add(entry.get("src_ip", ""))
            except json.JSONDecodeError:
                pass

    compromised.discard("")
    return sorted(compromised)


def isolate_hosts(compromised_ips: list[str]) -> list[str]:
    """Generate firewall rules to isolate compromised workstations."""
    rules = []
    for ip in compromised_ips:
        rules.extend([
            f"iptables -A INPUT -s {ip} -j DROP",
            f"iptables -A OUTPUT -d {ip} -j DROP",
            f"iptables -A FORWARD -s {ip} -j DROP",
            f"iptables -A FORWARD -d {ip} -j DROP",
        ])
    return rules


# ---------------------------------------------------------------------------
# Step 3: Block C2 Server
# ---------------------------------------------------------------------------

def block_c2_server() -> list[str]:
    """Generate rules to block C2 server communication network-wide."""
    rules = [
        f"# Block C2 server IP at perimeter firewall",
        f"iptables -A OUTPUT -d {C2_SERVER_IP} -j DROP",
        f"iptables -A FORWARD -d {C2_SERVER_IP} -j DROP",
        f"iptables -A INPUT -s {C2_SERVER_IP} -j DROP",
        f"",
        f"# Block C2 domain at DNS",
        f"echo '0.0.0.0 updates.evil-cdn.test' >> /etc/hosts",
        f"",
        f"# Block attacker IP",
        f"iptables -A INPUT -s {ATTACKER_IP} -j DROP",
        f"iptables -A FORWARD -s {ATTACKER_IP} -j DROP",
    ]
    return rules


# ---------------------------------------------------------------------------
# Step 4: Remove Persistence Mechanisms
# ---------------------------------------------------------------------------

def remove_persistence() -> list[str]:
    """Generate commands to remove persistence on compromised hosts."""
    commands = [
        f"# Remove registry run key persistence",
        f"reg delete \"{PERSISTENCE_KEY}\" /v EdgeUpdate /f",
        f"",
        f"# Remove dropped payload",
        f"del /f /q \"%APPDATA%\\{PAYLOAD_NAME}\"",
        f"del /f /q \"%TEMP%\\{PAYLOAD_NAME}\"",
        f"",
        f"# Kill running payload process",
        f"taskkill /f /im {PAYLOAD_NAME}",
        f"",
        f"# Verify removal",
        f"reg query \"{PERSISTENCE_KEY}\" /v EdgeUpdate",
        f"dir \"%APPDATA%\\{PAYLOAD_NAME}\"",
        f"tasklist /fi \"imagename eq {PAYLOAD_NAME}\"",
    ]
    return commands


# ---------------------------------------------------------------------------
# Step 5: Endpoint Scan
# ---------------------------------------------------------------------------

def generate_scan_commands(all_visitor_ips: list[str]) -> list[str]:
    """Generate commands to scan all hosts that visited the compromised site."""
    commands = [
        f"# Scan all workstations that visited the compromised site",
        f"# These hosts may have been exposed but not necessarily exploited",
        f"",
    ]
    for ip in all_visitor_ips:
        commands.append(f"# Scan {ip} for IOCs:")
        commands.append(f"#   - Check for {PAYLOAD_NAME} in %TEMP% and %APPDATA%")
        commands.append(f"#   - Check registry: {PERSISTENCE_KEY}")
        commands.append(f"#   - Check outbound connections to {C2_SERVER_IP}")
        commands.append(f"#   - Run full AV/EDR scan")
        commands.append(f"")
    return commands


def identify_all_visitors() -> list[str]:
    """Identify all workstations that visited the compromised site."""
    visitors = set()

    if not os.path.exists(ATTACK_LOG):
        return list(visitors)

    with open(ATTACK_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "watering_hole_visit":
                    visitors.add(entry.get("src_ip", ""))
            except json.JSONDecodeError:
                pass

    visitors.discard("")
    return sorted(visitors)


# ---------------------------------------------------------------------------
# Step 6: Evidence Preservation
# ---------------------------------------------------------------------------

def preserve_evidence(compromised_ips: list[str],
                      visitor_ips: list[str]) -> str:
    """Create an incident evidence package."""
    evidence = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}-WATERINGHOLE",
        "type": "Watering Hole Attack",
        "severity": "CRITICAL",
        "timestamp": datetime.now().isoformat(),
        "attacker_ip": ATTACKER_IP,
        "c2_server": C2_SERVER_IP,
        "compromised_website": COMPROMISED_WEBSITE,
        "compromised_hosts": compromised_ips,
        "all_visitors": visitor_ips,
        "mitre_techniques": [
            "T1189",       # Drive-by Compromise
            "T1203",       # Exploitation for Client Execution
            "T1547.001",   # Registry Run Keys
            "T1071.001",   # Application Layer Protocol: Web
            "T1082",       # System Information Discovery
            "T1003.001",   # OS Credential Dumping: LSASS Memory
        ],
        "containment_actions": [
            f"Compromised website ({COMPROMISED_WEBSITE}) blocked at DNS/proxy",
            f"C2 server ({C2_SERVER_IP}) blocked at perimeter firewall",
            f"Attacker IP ({ATTACKER_IP}) blocked at perimeter",
            f"{len(compromised_ips)} compromised host(s) isolated from network",
            f"{len(visitor_ips)} visitor host(s) queued for IOC scan",
            "Persistence mechanisms (registry run keys) removal commands generated",
            "Payload removal commands generated",
        ],
        "evidence_files": [],
        "ioc_indicators": {
            "ip_addresses": [ATTACKER_IP, C2_SERVER_IP, "198.51.100.25"],
            "domains": [COMPROMISED_WEBSITE, "updates.evil-cdn.test"],
            "file_names": [PAYLOAD_NAME],
            "file_hashes": ["b3a4f7e2c1d8" + "0" * 52],
            "registry_keys": [f"{PERSISTENCE_KEY}\\EdgeUpdate"],
            "cve": ["CVE-2024-4761"],
            "urls": [
                f"https://{COMPROMISED_WEBSITE}/assets/js/analytics-v3.min.js",
                f"https://{COMPROMISED_WEBSITE}/api/v2/content/feed",
            ],
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

    # -----------------------------------------------------------------------
    # Step 1: Block compromised website
    # -----------------------------------------------------------------------
    print(f"{Fore.YELLOW}[Step 1] Block Compromised Website{Style.RESET_ALL}")
    print(f"  Website: {COMPROMISED_WEBSITE}\n")

    block_cmds = block_compromised_website()
    print(f"  Commands to block the compromised website:")
    for cmd in block_cmds:
        print(f"    {cmd}")

    # -----------------------------------------------------------------------
    # Step 2: Isolate infected workstations
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 2] Isolate Infected Workstations{Style.RESET_ALL}")
    compromised_ips = identify_compromised_hosts()
    if compromised_ips:
        print(f"  Compromised hosts identified: {len(compromised_ips)}")
        for ip in compromised_ips:
            print(f"    {Fore.RED}[COMPROMISED]{Style.RESET_ALL} {ip}")
        fw_rules = isolate_hosts(compromised_ips)
        print(f"\n  Firewall isolation rules ({len(fw_rules)} rules):")
        for rule in fw_rules:
            print(f"    {rule}")
    else:
        print(f"  [INFO] No compromised hosts identified from logs")
        print(f"         Run attack/simulate_attack.py first")

    # Wazuh active response (if available)
    print(f"\n  Attempting Wazuh active response...")
    try:
        api = WazuhAPI()
        if api.check_connection():
            print(f"  [OK] Wazuh connected -- active response available")
        else:
            print(f"  [SKIP] Wazuh not available -- manual isolation required")
    except Exception:
        print(f"  [SKIP] Wazuh not available -- manual isolation required")

    # -----------------------------------------------------------------------
    # Step 3: Block C2 server
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 3] Block C2 Server{Style.RESET_ALL}")
    print(f"  C2 Server: {C2_SERVER_IP}")
    print(f"  Attacker:  {ATTACKER_IP}\n")

    c2_rules = block_c2_server()
    print(f"  Network-wide C2 blocking rules:")
    for rule in c2_rules:
        print(f"    {rule}")

    # -----------------------------------------------------------------------
    # Step 4: Remove persistence
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 4] Remove Persistence Mechanisms{Style.RESET_ALL}")
    persist_cmds = remove_persistence()
    print(f"  Commands to remove persistence on each compromised host:")
    for cmd in persist_cmds:
        print(f"    {cmd}")

    # -----------------------------------------------------------------------
    # Step 5: Scan all visitor endpoints
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 5] Scan Visitor Endpoints{Style.RESET_ALL}")
    visitor_ips = identify_all_visitors()
    if visitor_ips:
        print(f"  Hosts that visited the compromised site: {len(visitor_ips)}")
        for ip in visitor_ips:
            status = f"{Fore.RED}[COMPROMISED]{Style.RESET_ALL}" \
                if ip in compromised_ips else "[EXPOSED]"
            print(f"    {status} {ip}")

        scan_cmds = generate_scan_commands(visitor_ips)
        print(f"\n  IOC scan commands:")
        for cmd in scan_cmds[:10]:  # Show first 10 lines
            print(f"    {cmd}")
        if len(scan_cmds) > 10:
            print(f"    ... ({len(scan_cmds) - 10} more lines)")
    else:
        print(f"  [INFO] No visitor hosts identified from logs")

    # -----------------------------------------------------------------------
    # Step 6: Evidence preservation
    # -----------------------------------------------------------------------
    print(f"\n{Fore.YELLOW}[Step 6] Evidence Preservation{Style.RESET_ALL}")
    evidence_file = preserve_evidence(compromised_ips, visitor_ips)
    print(f"  Incident evidence saved to: {evidence_file}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{Fore.GREEN}{'=' * 62}")
    print(f"  Containment Response Summary")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(f"  Compromised website:   {COMPROMISED_WEBSITE} (BLOCKED)")
    print(f"  C2 server:             {C2_SERVER_IP} (BLOCKED)")
    print(f"  Attacker IP:           {ATTACKER_IP} (BLOCKED)")
    print(f"  Compromised hosts:     {len(compromised_ips)} (ISOLATED)")
    print(f"  Visitor hosts:         {len(visitor_ips)} (SCANNING)")
    print(f"  Evidence package:      {evidence_file}")
    print(f"\n  Next steps:")
    print(f"    1. Apply firewall and DNS blocking rules on network perimeter")
    print(f"    2. Execute persistence removal on each compromised host")
    print(f"    3. Run full AV/EDR scan on all visitor workstations")
    print(f"    4. Notify the compromised website owner")
    print(f"    5. Review respond/playbook.md for full IR procedure")
    print(f"    6. Report IOCs to threat intelligence feeds\n")


if __name__ == "__main__":
    main()
