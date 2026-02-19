"""Client for sending logs and querying alerts from Wazuh and Loki."""

import json
import socket
import time
from typing import Optional

import requests
import urllib3

from .constants import WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS, LOKI_URL

# Suppress insecure HTTPS warnings for local Wazuh
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SIEMClient:
    """Send logs to Wazuh/Loki and query alerts."""

    def __init__(self, wazuh_url: str = WAZUH_API_URL, loki_url: str = LOKI_URL):
        self.wazuh_url = wazuh_url
        self.loki_url = loki_url
        self._wazuh_token: Optional[str] = None

    # === Wazuh API ===

    def wazuh_authenticate(self) -> str:
        """Get JWT token from Wazuh API."""
        resp = requests.post(
            f"{self.wazuh_url}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
        )
        resp.raise_for_status()
        self._wazuh_token = resp.json()["data"]["token"]
        return self._wazuh_token

    def _wazuh_headers(self) -> dict:
        if not self._wazuh_token:
            self.wazuh_authenticate()
        return {"Authorization": f"Bearer {self._wazuh_token}"}

    def wazuh_get_alerts(self, limit: int = 20, offset: int = 0,
                         search: Optional[str] = None) -> dict:
        """Query Wazuh alerts."""
        params = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        resp = requests.get(
            f"{self.wazuh_url}/alerts",
            headers=self._wazuh_headers(),
            params=params,
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()

    def wazuh_get_agents(self) -> dict:
        """List Wazuh agents."""
        resp = requests.get(
            f"{self.wazuh_url}/agents",
            headers=self._wazuh_headers(),
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()

    # === Syslog sender ===

    def send_syslog(self, message: str, host: str = "127.0.0.1",
                    port: int = 514, protocol: str = "udp"):
        """Send a syslog message to Wazuh or any syslog collector."""
        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (host, port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.send(message.encode() + b"\n")
            sock.close()

    def send_syslog_batch(self, messages: list[str], host: str = "127.0.0.1",
                          port: int = 514, delay: float = 0.1):
        """Send multiple syslog messages with delay between them."""
        for msg in messages:
            self.send_syslog(msg, host, port)
            time.sleep(delay)

    # === Loki ===

    def loki_push(self, labels: dict, entries: list[tuple[str, str]]):
        """Push log entries to Loki.

        Args:
            labels: Label set (e.g., {"job": "attack_sim", "scenario": "13"})
            entries: List of (timestamp_ns, log_line) tuples
        """
        stream = {
            "stream": labels,
            "values": [[ts, line] for ts, line in entries],
        }
        payload = {"streams": [stream]}
        resp = requests.post(
            f"{self.loki_url}/loki/api/v1/push",
            json=payload,
        )
        resp.raise_for_status()

    def loki_push_lines(self, labels: dict, lines: list[str]):
        """Push log lines to Loki with auto-generated timestamps."""
        entries = []
        base_ns = int(time.time() * 1e9)
        for i, line in enumerate(lines):
            entries.append((str(base_ns + i * 1000000), line))
        self.loki_push(labels, entries)

    def loki_query(self, query: str, limit: int = 100) -> dict:
        """Query logs from Loki using LogQL."""
        resp = requests.get(
            f"{self.loki_url}/loki/api/v1/query_range",
            params={"query": query, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()

    # === File-based log output (for offline/demo) ===

    @staticmethod
    def write_logs_to_file(logs: list[str], filepath: str):
        """Write log entries to a file."""
        with open(filepath, "w") as f:
            for line in logs:
                f.write(line + "\n")

    @staticmethod
    def read_logs_from_file(filepath: str) -> list[str]:
        """Read log entries from a file."""
        with open(filepath, "r") as f:
            return [line.strip() for line in f if line.strip()]
