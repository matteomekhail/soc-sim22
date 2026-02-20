#!/usr/bin/env python3
"""
Scenario 19: Cryptojacking Attack Simulation.

Simulates a browser-based cryptojacking attack where a compromised website
serves mining JavaScript that connects to a mining pool. Generates realistic
attack traffic and logs for SOC detection.
"""

import json
import os
import random
import sys
import time

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import (
    MINING_POOL_IP, MINING_POOL_DOMAIN, WORKSTATION_IPS,
    WEB_SERVER_IP, ATTACKER_IP, COMPANY_DOMAIN,
)
from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# Simulated mining pool stratum ports
STRATUM_PORT = 3333
STRATUM_SSL_PORT = 3334
POOL_HTTP_PORT = 80
POOL_HTTPS_PORT = 443

# Simulated coinhive-style site key
SITE_KEY = "a1b2c3d4e5f6g7h8i9j0SimulatedKey"


def banner():
    print(f"""
{Fore.RED}=====================================================================
  WCACE Scenario 19: Cryptojacking Attack Simulation
  Mining Pool: {MINING_POOL_DOMAIN} ({MINING_POOL_IP})
  WARNING: Educational use only - no actual mining occurs
====================================================================={Style.RESET_ALL}
""")


def phase_1_website_visit(log_gen: LogGenerator) -> list[str]:
    """Phase 1: User visits compromised website and mining JS is loaded."""
    print(f"{Fore.YELLOW}[Phase 1] User Visits Compromised Website{Style.RESET_ALL}")
    logs = []

    # Select victim workstations
    victims = random.sample(WORKSTATION_IPS, min(5, len(WORKSTATION_IPS)))

    for victim_ip in victims:
        print(f"  [+] Victim {victim_ip} browses to compromised website")

        # Normal page load
        logs.append(log_gen.web_access_log(
            victim_ip, "GET", "/",
            200, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ))

        # CSS and normal assets
        for asset in ["/css/style.css", "/js/app.js", "/images/logo.png"]:
            logs.append(log_gen.web_access_log(
                victim_ip, "GET", asset, 200,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            ))

        # Injected miner JS loaded (this is the malicious resource)
        logs.append(log_gen.web_access_log(
            victim_ip, "GET", "/lib/coinhive.min.js",
            200, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ))
        print(f"      Loaded coinhive.min.js (injected miner script)")

        # DNS resolution for mining pool
        logs.append(log_gen.dns_query_log(
            victim_ip, MINING_POOL_DOMAIN,
            query_type="A", response=MINING_POOL_IP
        ))
        print(f"      DNS query: {MINING_POOL_DOMAIN} -> {MINING_POOL_IP}")

    print(f"  [{Fore.GREEN}*{Style.RESET_ALL}] {len(victims)} victims loaded compromised page")
    return logs


def phase_2_mining_execution(log_gen: LogGenerator) -> list[str]:
    """Phase 2: Mining JavaScript initializes and begins execution."""
    print(f"\n{Fore.YELLOW}[Phase 2] Mining JavaScript Loaded and Executed{Style.RESET_ALL}")
    logs = []

    victims = random.sample(WORKSTATION_IPS, min(5, len(WORKSTATION_IPS)))

    for victim_ip in victims:
        print(f"  [+] {victim_ip}: CoinHive miner initializing")

        # WebSocket upgrade attempt to mining pool proxy
        logs.append(log_gen.json_log("web_access", {
            "src_ip": victim_ip,
            "dst_ip": MINING_POOL_IP,
            "method": "GET",
            "path": f"/proxy?key={SITE_KEY}",
            "status_code": 101,
            "upgrade": "websocket",
            "host": MINING_POOL_DOMAIN,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }))

        # Firewall log: outbound connection to mining pool
        logs.append(log_gen.firewall_log(
            victim_ip, MINING_POOL_IP,
            random.randint(49152, 65535), POOL_HTTPS_PORT,
            action="allow", protocol="TCP"
        ))
        print(f"      WebSocket connection to {MINING_POOL_DOMAIN}:{POOL_HTTPS_PORT}")

        # Stratum protocol initialization (TCP connection to mining pool)
        logs.append(log_gen.firewall_log(
            victim_ip, MINING_POOL_IP,
            random.randint(49152, 65535), STRATUM_PORT,
            action="allow", protocol="TCP"
        ))

        # Stratum login message
        stratum_login = {
            "id": 1,
            "method": "login",
            "params": {
                "login": SITE_KEY,
                "pass": "x",
                "agent": "coinhive/1.0"
            }
        }
        logs.append(log_gen.json_log("stratum_protocol", {
            "src_ip": victim_ip,
            "dst_ip": MINING_POOL_IP,
            "dst_port": STRATUM_PORT,
            "direction": "outbound",
            "payload": json.dumps(stratum_login),
        }, severity="warning"))
        print(f"      Stratum login sent (site key: {SITE_KEY[:16]}...)")

        # IDS alert for mining pool connection
        logs.append(log_gen.ids_alert(
            victim_ip, MINING_POOL_IP,
            "Cryptocurrency Mining Pool Connection Detected",
            sid=9190001, severity=1
        ))

        # Simulate CPU spike log from endpoint agent
        logs.append(log_gen.json_log("endpoint_telemetry", {
            "src_ip": victim_ip,
            "hostname": f"WS-{victim_ip.split('.')[-1]}",
            "process": "chrome.exe",
            "cpu_percent": random.uniform(75.0, 98.0),
            "memory_mb": random.randint(800, 2048),
            "threads": random.randint(4, 8),
            "description": "Sustained high CPU from browser process",
        }, severity="warning"))
        print(f"      CPU spike detected: {random.uniform(75, 98):.1f}% (chrome.exe)")

    return logs


def phase_3_pool_connections(log_gen: LogGenerator) -> list[str]:
    """Phase 3: Ongoing connections to mining pool (HTTP/stratum)."""
    print(f"\n{Fore.YELLOW}[Phase 3] Mining Pool Connections (HTTP/Stratum){Style.RESET_ALL}")
    logs = []

    victims = random.sample(WORKSTATION_IPS, min(5, len(WORKSTATION_IPS)))

    for victim_ip in victims:
        # Simulated stratum job requests and submissions
        for job_num in range(1, 6):
            job_id = f"job_{random.randint(100000, 999999)}"
            nonce = f"{random.randint(0, 0xFFFFFFFF):08x}"
            result_hash = "".join(random.choice("0123456789abcdef") for _ in range(64))

            # Pool sends job to miner
            logs.append(log_gen.json_log("stratum_protocol", {
                "src_ip": MINING_POOL_IP,
                "dst_ip": victim_ip,
                "dst_port": STRATUM_PORT,
                "direction": "inbound",
                "payload": json.dumps({
                    "jsonrpc": "2.0",
                    "method": "job",
                    "params": {
                        "job_id": job_id,
                        "blob": "".join(random.choice("0123456789abcdef") for _ in range(128)),
                        "target": "b4b40000",
                    }
                }),
            }))

            # Miner submits result
            logs.append(log_gen.json_log("stratum_protocol", {
                "src_ip": victim_ip,
                "dst_ip": MINING_POOL_IP,
                "dst_port": STRATUM_PORT,
                "direction": "outbound",
                "payload": json.dumps({
                    "id": job_num + 1,
                    "method": "submit",
                    "params": {
                        "id": SITE_KEY,
                        "job_id": job_id,
                        "nonce": nonce,
                        "result": result_hash,
                    }
                }),
            }))

        print(f"  [+] {victim_ip}: 5 mining jobs processed via stratum")

        # HTTP POST to mining pool API (alternative submission method)
        logs.append(log_gen.web_access_log(
            victim_ip, "POST", "/api/v1/submit",
            200, user_agent="Mozilla/5.0 (coinhive-worker)"
        ))

        # IDS alert for stratum protocol
        logs.append(log_gen.ids_alert(
            victim_ip, MINING_POOL_IP,
            "Stratum Mining Protocol Detected",
            sid=9190003, severity=1
        ))

    print(f"  [{Fore.RED}!{Style.RESET_ALL}] Active mining sessions across {len(victims)} workstations")
    return logs


def phase_4_beacon_pattern(log_gen: LogGenerator) -> list[str]:
    """Phase 4: Sustained beacon pattern (mining pool check-ins)."""
    print(f"\n{Fore.YELLOW}[Phase 4] Sustained Beacon Pattern (Mining Pool Check-ins){Style.RESET_ALL}")
    logs = []

    victims = random.sample(WORKSTATION_IPS, min(5, len(WORKSTATION_IPS)))
    beacon_count = 10  # Number of check-ins per victim

    for victim_ip in victims:
        hashes_total = 0
        for i in range(beacon_count):
            hashes_batch = random.randint(5000, 25000)
            hashes_total += hashes_batch

            # Periodic keep-alive / hashrate report to pool
            logs.append(log_gen.json_log("mining_beacon", {
                "src_ip": victim_ip,
                "dst_ip": MINING_POOL_IP,
                "dst_port": STRATUM_PORT,
                "beacon_interval_sec": random.randint(25, 35),
                "hashes_submitted": hashes_total,
                "hashrate": random.randint(20, 80),
                "pool_domain": MINING_POOL_DOMAIN,
                "site_key": SITE_KEY,
            }, severity="warning"))

            # Firewall log for each check-in
            logs.append(log_gen.firewall_log(
                victim_ip, MINING_POOL_IP,
                random.randint(49152, 65535), STRATUM_PORT,
                action="allow", protocol="TCP"
            ))

        print(f"  [+] {victim_ip}: {beacon_count} pool check-ins, {hashes_total} total hashes")

        # IDS alert for sustained beacon pattern
        logs.append(log_gen.ids_alert(
            victim_ip, MINING_POOL_IP,
            "Sustained Cryptocurrency Mining Beacon Pattern",
            sid=9190004, severity=2
        ))

    # Final summary alert: multiple hosts mining
    logs.append(log_gen.ids_alert(
        victims[0], MINING_POOL_IP,
        "Multiple Hosts Detected Mining - Possible Cryptojacking Campaign",
        sid=9190005, severity=1
    ))

    print(f"\n  [{Fore.RED}!{Style.RESET_ALL}] Sustained mining detected across {len(victims)} hosts")
    print(f"  [{Fore.RED}!{Style.RESET_ALL}] Total beacons: {beacon_count * len(victims)}")
    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host="soc-sensor")
    all_logs = []

    # Execute attack phases
    all_logs.extend(phase_1_website_visit(log_gen))
    all_logs.extend(phase_2_mining_execution(log_gen))
    all_logs.extend(phase_3_pool_connections(log_gen))
    all_logs.extend(phase_4_beacon_pattern(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "cryptojacking_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    print(f"\n{Fore.GREEN}[*] Attack simulation complete")
    print(f"[*] {len(all_logs)} log entries written to {log_file}{Style.RESET_ALL}")

    # Try to send to Loki if available
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "19-cryptojacking"},
            all_logs
        )
        print(f"[*] Logs pushed to Loki")
    except Exception:
        print(f"[*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
