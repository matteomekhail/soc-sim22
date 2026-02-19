"""Network traffic simulation utilities using scapy and sockets."""

import random
import socket
import struct
import time
from typing import Optional

from .constants import (
    ATTACKER_IP, INTERNAL_SUBNET, WORKSTATION_IPS,
    WEB_SERVER_IP, DB_SERVER_IP, C2_SERVER_IP,
    HTTP_PORT, HTTPS_PORT, DNS_PORT, SSH_PORT
)


class NetworkSimulator:
    """Simulate network traffic patterns for SOC scenarios."""

    def __init__(self, use_scapy: bool = False):
        self.use_scapy = use_scapy
        self._scapy_available = False
        if use_scapy:
            try:
                from scapy.all import IP, TCP, UDP, DNS, DNSQR, send, sr1
                self._scapy_available = True
            except ImportError:
                print("[!] scapy not available, falling back to socket simulation")

    # === HTTP simulation ===

    @staticmethod
    def http_request(host: str, port: int = 80, method: str = "GET",
                     path: str = "/", headers: Optional[dict] = None,
                     body: Optional[str] = None, timeout: int = 5) -> Optional[str]:
        """Make a raw HTTP request."""
        import requests
        url = f"http://{host}:{port}{path}"
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=timeout)
            elif method == "POST":
                resp = requests.post(url, headers=headers, data=body, timeout=timeout)
            else:
                resp = requests.request(method, url, headers=headers, data=body, timeout=timeout)
            return resp.text
        except requests.exceptions.RequestException as e:
            return f"ERROR: {e}"

    @staticmethod
    def http_flood(host: str, port: int = 80, path: str = "/",
                   count: int = 100, delay: float = 0.01) -> list[int]:
        """Send rapid HTTP requests (simulated DDoS/brute force)."""
        import requests
        statuses = []
        for _ in range(count):
            try:
                resp = requests.get(f"http://{host}:{port}{path}", timeout=2)
                statuses.append(resp.status_code)
            except requests.exceptions.RequestException:
                statuses.append(0)
            time.sleep(delay)
        return statuses

    # === Port scanning ===

    @staticmethod
    def port_scan(host: str, ports: Optional[list[int]] = None,
                  timeout: float = 0.5) -> dict[int, bool]:
        """Basic TCP port scan."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        results = {}
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            results[port] = result == 0
            sock.close()
        return results

    # === DNS simulation ===

    @staticmethod
    def dns_query(domain: str, server: str = "127.0.0.1",
                  port: int = 53, qtype: str = "A") -> Optional[str]:
        """Send a DNS query using dnslib."""
        try:
            from dnslib import DNSRecord, QTYPE
            q = DNSRecord.question(domain, getattr(QTYPE, qtype, QTYPE.A))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(q.pack(), (server, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            response = DNSRecord.parse(data)
            return str(response)
        except Exception as e:
            return f"ERROR: {e}"

    @staticmethod
    def dns_tunnel_send(data: bytes, domain: str, server: str = "127.0.0.1",
                        port: int = 53) -> bool:
        """Encode data as DNS subdomain queries (DNS tunnelling simulation)."""
        import base64
        try:
            from dnslib import DNSRecord
            encoded = base64.b32encode(data).decode().rstrip("=").lower()
            # Split into 63-char labels
            labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
            query_name = ".".join(labels) + "." + domain
            q = DNSRecord.question(query_name, "TXT")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(q.pack(), (server, port))
            sock.close()
            return True
        except Exception:
            return False

    # === C2 Beaconing simulation ===

    @staticmethod
    def c2_beacon(host: str, port: int = 443, interval: int = 60,
                  count: int = 10, jitter: float = 0.2) -> list[float]:
        """Simulate C2 beaconing pattern (timing only, no actual connection)."""
        timestamps = []
        for _ in range(count):
            timestamps.append(time.time())
            jittered = interval * (1 + random.uniform(-jitter, jitter))
            time.sleep(jittered)
        return timestamps

    # === PCAP generation ===

    def generate_pcap(self, packets: list, output_path: str):
        """Write packets to a PCAP file (requires scapy)."""
        if not self._scapy_available:
            print("[!] scapy required for PCAP generation")
            return
        from scapy.all import wrpcap
        wrpcap(output_path, packets)

    # === Traffic pattern generators ===

    @staticmethod
    def generate_normal_traffic_log(count: int = 100) -> list[dict]:
        """Generate realistic normal traffic patterns."""
        from .log_generator import LogGenerator
        gen = LogGenerator(source_host="firewall")
        logs = []
        normal_paths = ["/", "/index.html", "/about", "/api/status",
                        "/css/style.css", "/js/app.js", "/images/logo.png"]
        for _ in range(count):
            src = random.choice(WORKSTATION_IPS)
            logs.append(gen.web_access_log(
                src, "GET", random.choice(normal_paths),
                random.choice([200, 200, 200, 304, 301]),
            ))
        return logs

    @staticmethod
    def generate_lateral_movement_log(src_ip: str, targets: list[str]) -> list[dict]:
        """Generate lateral movement traffic pattern."""
        from .log_generator import LogGenerator
        gen = LogGenerator(source_host="soc-sensor")
        logs = []
        for target in targets:
            logs.append(gen.firewall_log(src_ip, target, random.randint(1024, 65535), SSH_PORT))
            logs.append(gen.auth_success("admin", src_ip))
            logs.append(gen.firewall_log(src_ip, target, random.randint(1024, 65535), SMB_PORT))
        return logs


SMB_PORT = 445
