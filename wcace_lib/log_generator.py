"""Generate realistic log entries in various formats (syslog, JSON, CEF)."""

import json
import random
import time
from datetime import datetime, timedelta
from typing import Optional

from .constants import (
    COMPANY_DOMAIN, INTERNAL_SUBNET, SYSLOG_FACILITY, SYSLOG_SEVERITY,
    REGULAR_USERS, WORKSTATION_IPS
)


class LogGenerator:
    """Generate simulated log entries for SOC scenarios."""

    def __init__(self, source_host: str = "soc-sim", facility: str = "auth"):
        self.source_host = source_host
        self.facility = facility
        self._base_time = datetime.now()

    def _timestamp(self, offset_seconds: int = 0) -> str:
        t = self._base_time + timedelta(seconds=offset_seconds)
        return t.strftime("%b %d %H:%M:%S")

    def _iso_timestamp(self, offset_seconds: int = 0) -> str:
        t = self._base_time + timedelta(seconds=offset_seconds)
        return t.isoformat() + "Z"

    def advance_time(self, seconds: int = 1):
        """Advance the internal clock for sequential log generation."""
        self._base_time += timedelta(seconds=seconds)

    # === Syslog Format ===

    def syslog(self, message: str, severity: str = "info",
               facility: Optional[str] = None, host: Optional[str] = None) -> str:
        fac = facility or self.facility
        pri = SYSLOG_FACILITY.get(fac, 1) * 8 + SYSLOG_SEVERITY.get(severity, 6)
        h = host or self.source_host
        ts = self._timestamp()
        self.advance_time(random.randint(0, 3))
        return f"<{pri}>{ts} {h} {fac}: {message}"

    def auth_success(self, user: str, src_ip: str, method: str = "password") -> str:
        return self.syslog(
            f"Accepted {method} for {user} from {src_ip} port {random.randint(1024, 65535)} ssh2",
            severity="info", facility="auth"
        )

    def auth_failure(self, user: str, src_ip: str, method: str = "password") -> str:
        return self.syslog(
            f"Failed {method} for {user} from {src_ip} port {random.randint(1024, 65535)} ssh2",
            severity="warning", facility="auth"
        )

    def sudo_event(self, user: str, command: str, success: bool = True) -> str:
        status = "" if success else "NOT in sudoers"
        if success:
            msg = f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
        else:
            msg = f"{user} : user {status} ; TTY=pts/0 ; PWD=/home/{user} ; COMMAND={command}"
        return self.syslog(msg, severity="notice" if success else "alert", facility="auth")

    def file_access(self, user: str, path: str, action: str = "read") -> str:
        return self.syslog(
            f"AUDIT: user={user} action={action} path={path} result=success",
            severity="info", facility="local0"
        )

    # === JSON Format (for Wazuh/Loki) ===

    def json_log(self, event_type: str, data: dict, severity: str = "info") -> str:
        entry = {
            "timestamp": self._iso_timestamp(),
            "host": self.source_host,
            "event_type": event_type,
            "severity": severity,
            **data,
        }
        self.advance_time(random.randint(0, 2))
        return json.dumps(entry)

    def web_access_log(self, src_ip: str, method: str, path: str,
                       status: int, user_agent: str = "Mozilla/5.0") -> str:
        return self.json_log("web_access", {
            "src_ip": src_ip,
            "method": method,
            "path": path,
            "status_code": status,
            "user_agent": user_agent,
            "response_size": random.randint(200, 50000),
        })

    def dns_query_log(self, src_ip: str, domain: str,
                      query_type: str = "A", response: str = "") -> str:
        return self.json_log("dns_query", {
            "src_ip": src_ip,
            "query": domain,
            "query_type": query_type,
            "response": response,
            "query_length": len(domain),
        })

    def firewall_log(self, src_ip: str, dst_ip: str, src_port: int,
                     dst_port: int, action: str = "allow",
                     protocol: str = "TCP") -> str:
        return self.json_log("firewall", {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
        }, severity="warning" if action == "deny" else "info")

    def ids_alert(self, src_ip: str, dst_ip: str, signature: str,
                  sid: int, severity: int = 2) -> str:
        return self.json_log("ids_alert", {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "signature": signature,
            "sid": sid,
            "severity": severity,
            "protocol": "TCP",
        }, severity="critical" if severity == 1 else "warning")

    # === CEF Format ===

    def cef(self, vendor: str, product: str, version: str,
            sig_id: str, name: str, severity: int, extensions: dict) -> str:
        ext_str = " ".join(f"{k}={v}" for k, v in extensions.items())
        ts = self._iso_timestamp()
        self.advance_time(1)
        return f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{severity}|{ext_str} rt={ts}"

    # === Scenario-specific generators ===

    def brute_force_sequence(self, target_user: str, src_ip: str,
                             attempts: int = 50, success_at_end: bool = True) -> list[str]:
        logs = []
        for i in range(attempts):
            if i == attempts - 1 and success_at_end:
                logs.append(self.auth_success(target_user, src_ip))
            else:
                user = target_user if random.random() > 0.3 else random.choice(REGULAR_USERS)
                logs.append(self.auth_failure(user, src_ip))
        return logs

    def sql_injection_sequence(self, src_ip: str, target_url: str,
                               payloads: Optional[list] = None) -> list[str]:
        if payloads is None:
            payloads = [
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "'; DROP TABLE users;--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "admin'--",
            ]
        logs = []
        for payload in payloads:
            path = f"{target_url}?id={payload}"
            logs.append(self.web_access_log(src_ip, "GET", path, 200))
            logs.append(self.ids_alert(
                src_ip, WEB_SERVER_IP,
                f"SQL Injection Attempt: {payload[:30]}",
                sid=random.randint(2000001, 2000100), severity=1
            ))
        return logs

    def data_exfiltration_sequence(self, user: str, src_ip: str,
                                   files: list[str], dst_ip: str) -> list[str]:
        logs = []
        for f in files:
            logs.append(self.file_access(user, f))
            logs.append(self.firewall_log(
                src_ip, dst_ip,
                random.randint(1024, 65535), 443, action="allow"
            ))
            logs.append(self.json_log("data_transfer", {
                "user": user,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "file": f,
                "size_bytes": random.randint(100000, 50000000),
                "protocol": "HTTPS",
            }, severity="warning"))
        return logs

    def dns_tunnel_sequence(self, src_ip: str, domain: str,
                            queries: int = 100) -> list[str]:
        import base64
        logs = []
        for _ in range(queries):
            data = base64.b32encode(random.randbytes(random.randint(10, 30))).decode().rstrip("=")
            subdomain = f"{data}.{domain}"
            logs.append(self.dns_query_log(src_ip, subdomain, "TXT"))
        return logs


# Import here to avoid circular
from .constants import WEB_SERVER_IP  # noqa: E402
