"""Tests for wcace_lib.log_generator - syslog, JSON, CEF, and sequences."""

import json
import re
from datetime import datetime

import pytest

from wcace_lib.log_generator import LogGenerator
from wcace_lib.constants import WEB_SERVER_IP


class TestSyslogFormat:
    """Syslog output format validation."""

    def test_syslog_has_pri(self, log_gen):
        msg = log_gen.syslog("test message")
        assert re.match(r"^<\d+>", msg)

    def test_syslog_pri_calculation(self, log_gen):
        # auth facility = 4, info severity = 6 -> PRI = 4*8+6 = 38
        msg = log_gen.syslog("test", severity="info", facility="auth")
        assert msg.startswith("<38>")

    def test_syslog_contains_host(self, log_gen):
        msg = log_gen.syslog("hello")
        assert "test-host" in msg

    def test_syslog_contains_message(self, log_gen):
        msg = log_gen.syslog("custom payload")
        assert "custom payload" in msg

    def test_syslog_contains_timestamp(self, log_gen):
        msg = log_gen.syslog("test")
        # Timestamp format: "Feb 20 14:30:00"
        assert re.search(r"[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}", msg)


class TestAuthLogs:
    def test_auth_success_format(self, log_gen):
        msg = log_gen.auth_success("admin", "10.0.0.1")
        assert "Accepted" in msg
        assert "admin" in msg
        assert "10.0.0.1" in msg

    def test_auth_failure_format(self, log_gen):
        msg = log_gen.auth_failure("baduser", "10.0.0.99")
        assert "Failed" in msg
        assert "baduser" in msg
        assert "10.0.0.99" in msg

    def test_auth_method_included(self, log_gen):
        msg = log_gen.auth_success("user", "10.0.0.1", method="publickey")
        assert "publickey" in msg


class TestSudoEvent:
    def test_sudo_success(self, log_gen):
        msg = log_gen.sudo_event("admin", "/usr/bin/cat /etc/shadow", success=True)
        assert "admin" in msg
        assert "/usr/bin/cat" in msg

    def test_sudo_failure(self, log_gen):
        msg = log_gen.sudo_event("user", "/usr/bin/su", success=False)
        assert "NOT in sudoers" in msg


class TestFileAccess:
    def test_file_access_format(self, log_gen):
        msg = log_gen.file_access("bob", "/etc/passwd", action="read")
        assert "AUDIT" in msg
        assert "bob" in msg
        assert "/etc/passwd" in msg
        assert "read" in msg


class TestJsonLog:
    """JSON output format."""

    def test_json_parseable(self, log_gen):
        msg = log_gen.json_log("test_event", {"key": "value"})
        data = json.loads(msg)
        assert data["event_type"] == "test_event"

    def test_json_has_timestamp(self, log_gen):
        msg = log_gen.json_log("test", {})
        data = json.loads(msg)
        assert "timestamp" in data

    def test_json_has_host(self, log_gen):
        msg = log_gen.json_log("test", {})
        data = json.loads(msg)
        assert data["host"] == "test-host"

    def test_json_has_severity(self, log_gen):
        msg = log_gen.json_log("test", {}, severity="critical")
        data = json.loads(msg)
        assert data["severity"] == "critical"

    def test_json_custom_data_merged(self, log_gen):
        msg = log_gen.json_log("test", {"custom_field": 42})
        data = json.loads(msg)
        assert data["custom_field"] == 42


class TestWebAccessLog:
    def test_web_log_fields(self, log_gen):
        msg = log_gen.web_access_log("10.0.0.1", "GET", "/index.html", 200)
        data = json.loads(msg)
        assert data["src_ip"] == "10.0.0.1"
        assert data["method"] == "GET"
        assert data["path"] == "/index.html"
        assert data["status_code"] == 200
        assert "user_agent" in data
        assert "response_size" in data


class TestDnsQueryLog:
    def test_dns_log_fields(self, log_gen):
        msg = log_gen.dns_query_log("10.0.0.1", "evil.com", "A", "1.2.3.4")
        data = json.loads(msg)
        assert data["query"] == "evil.com"
        assert data["query_type"] == "A"
        assert data["query_length"] == len("evil.com")


class TestFirewallLog:
    def test_firewall_allow(self, log_gen):
        msg = log_gen.firewall_log("10.0.0.1", "10.0.0.2", 12345, 80, action="allow")
        data = json.loads(msg)
        assert data["action"] == "allow"
        assert data["severity"] == "info"

    def test_firewall_deny(self, log_gen):
        msg = log_gen.firewall_log("10.0.0.1", "10.0.0.2", 12345, 80, action="deny")
        data = json.loads(msg)
        assert data["action"] == "deny"
        assert data["severity"] == "warning"


class TestIdsAlert:
    def test_ids_alert_fields(self, log_gen):
        msg = log_gen.ids_alert("10.0.0.1", "10.0.0.2", "Evil Traffic", sid=9999, severity=1)
        data = json.loads(msg)
        assert data["signature"] == "Evil Traffic"
        assert data["sid"] == 9999
        # severity is the numeric value from the IDS alert (int),
        # which overwrites the string severity in json_log via **data merge
        assert data["severity"] in (1, "critical")


class TestCEF:
    def test_cef_format(self, log_gen):
        msg = log_gen.cef("TestVendor", "TestProduct", "1.0", "100", "Alert", 5, {"src": "10.0.0.1"})
        assert msg.startswith("CEF:0|")
        assert "TestVendor" in msg
        assert "TestProduct" in msg
        assert "src=10.0.0.1" in msg


class TestAdvanceTime:
    def test_advance_time(self, log_gen):
        t1 = log_gen._base_time
        log_gen.advance_time(60)
        t2 = log_gen._base_time
        assert (t2 - t1).total_seconds() == 60


class TestBruteForceSequence:
    def test_returns_list(self, log_gen):
        logs = log_gen.brute_force_sequence("admin", "10.0.0.1", attempts=5)
        assert isinstance(logs, list)
        assert len(logs) == 5

    def test_last_is_success(self, log_gen):
        logs = log_gen.brute_force_sequence("admin", "10.0.0.1", attempts=5, success_at_end=True)
        assert "Accepted" in logs[-1]

    def test_all_failures(self, log_gen):
        logs = log_gen.brute_force_sequence("admin", "10.0.0.1", attempts=3, success_at_end=False)
        for entry in logs:
            assert "Failed" in entry


class TestSqlInjectionSequence:
    def test_returns_pairs(self, log_gen):
        logs = log_gen.sql_injection_sequence("10.0.0.1", "/search")
        # Default 5 payloads, each generates 2 logs (web + ids)
        assert len(logs) == 10

    def test_contains_payloads(self, log_gen):
        logs = log_gen.sql_injection_sequence("10.0.0.1", "/search")
        combined = " ".join(logs)
        assert "UNION SELECT" in combined or "OR 1=1" in combined


class TestDataExfilSequence:
    def test_returns_logs_per_file(self, log_gen):
        files = ["/secret/a.txt", "/secret/b.txt"]
        logs = log_gen.data_exfiltration_sequence("bob", "10.0.0.1", files, "10.0.0.99")
        # 3 logs per file
        assert len(logs) == 6


class TestDnsTunnelSequence:
    def test_returns_queries(self, log_gen):
        logs = log_gen.dns_tunnel_sequence("10.0.0.1", "exfil.test", queries=10)
        assert len(logs) == 10

    def test_queries_contain_domain(self, log_gen):
        logs = log_gen.dns_tunnel_sequence("10.0.0.1", "exfil.test", queries=3)
        for entry in logs:
            data = json.loads(entry)
            assert "exfil.test" in data["query"]
