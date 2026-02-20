"""Tests for wcace_lib.constants - validate types, values, and consistency."""

import ipaddress
import re

import pytest

from wcace_lib import constants as C


# ---------------------------------------------------------------------------
# IP address validation
# ---------------------------------------------------------------------------

class TestIPAddresses:
    """All IP constants must be valid IPv4 addresses."""

    SINGLE_IPS = [
        C.DC_IP, C.FILE_SERVER_IP, C.DB_SERVER_IP, C.MAIL_SERVER_IP,
        C.DNS_SERVER_IP, C.WEB_SERVER_IP, C.API_SERVER_IP, C.VPN_SERVER_IP,
        C.ATTACKER_IP, C.C2_SERVER_IP, C.MINING_POOL_IP,
    ]

    @pytest.mark.parametrize("ip", SINGLE_IPS)
    def test_single_ip_valid(self, ip):
        ipaddress.ip_address(ip)

    def test_workstation_ips_valid(self):
        assert len(C.WORKSTATION_IPS) > 0
        for ip in C.WORKSTATION_IPS:
            ipaddress.ip_address(ip)

    def test_attacker_ips_valid(self):
        assert len(C.ATTACKER_IPS) > 0
        for ip in C.ATTACKER_IPS:
            ipaddress.ip_address(ip)


# ---------------------------------------------------------------------------
# Subnet validation
# ---------------------------------------------------------------------------

class TestSubnets:
    @pytest.mark.parametrize("subnet", [C.INTERNAL_SUBNET, C.DMZ_SUBNET, C.EXTERNAL_SUBNET])
    def test_subnet_valid(self, subnet):
        ipaddress.ip_network(subnet)


# ---------------------------------------------------------------------------
# Port validation
# ---------------------------------------------------------------------------

class TestPorts:
    PORTS = [
        C.HTTP_PORT, C.HTTPS_PORT, C.SSH_PORT, C.DNS_PORT,
        C.SMTP_PORT, C.SMB_PORT, C.RDP_PORT, C.MYSQL_PORT,
        C.MSSQL_PORT, C.API_PORT,
    ]

    @pytest.mark.parametrize("port", PORTS)
    def test_port_is_int(self, port):
        assert isinstance(port, int)

    @pytest.mark.parametrize("port", PORTS)
    def test_port_range(self, port):
        assert 1 <= port <= 65535


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

class TestDomains:
    DOMAINS = [
        C.COMPANY_DOMAIN, C.SPOOFED_DOMAIN, C.C2_DOMAIN,
        C.MINING_POOL_DOMAIN, C.PHISHING_DOMAIN,
        C.DNS_TUNNEL_DOMAIN, C.WATERING_HOLE_DOMAIN,
    ]

    @pytest.mark.parametrize("domain", DOMAINS)
    def test_domain_non_empty(self, domain):
        assert isinstance(domain, str) and len(domain) > 0

    @pytest.mark.parametrize("domain", DOMAINS)
    def test_domain_has_dot(self, domain):
        assert "." in domain


# ---------------------------------------------------------------------------
# User lists
# ---------------------------------------------------------------------------

class TestUsers:
    def test_admin_users_non_empty(self):
        assert len(C.ADMIN_USERS) > 0

    def test_regular_users_non_empty(self):
        assert len(C.REGULAR_USERS) > 0

    def test_service_accounts_non_empty(self):
        assert len(C.SERVICE_ACCOUNTS) > 0

    def test_insider_user_in_regular(self):
        assert C.INSIDER_USER in C.REGULAR_USERS


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

class TestMITRE:
    def test_mitre_is_dict(self):
        assert isinstance(C.MITRE, dict) and len(C.MITRE) > 0

    def test_mitre_tactics_have_techniques(self):
        for tactic, techniques in C.MITRE.items():
            assert isinstance(techniques, dict), f"Tactic {tactic} should be a dict"
            assert len(techniques) > 0, f"Tactic {tactic} should have techniques"

    def test_mitre_technique_ids_pattern(self):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tactic, techniques in C.MITRE.items():
            for name, tid in techniques.items():
                assert pattern.match(tid), f"Invalid MITRE ID: {tid} ({tactic}/{name})"


# ---------------------------------------------------------------------------
# Syslog maps
# ---------------------------------------------------------------------------

class TestSyslog:
    def test_facility_values_are_ints(self):
        for name, val in C.SYSLOG_FACILITY.items():
            assert isinstance(val, int)

    def test_severity_values_are_ints(self):
        for name, val in C.SYSLOG_SEVERITY.items():
            assert isinstance(val, int)

    def test_facility_range(self):
        for name, val in C.SYSLOG_FACILITY.items():
            assert 0 <= val <= 23

    def test_severity_range(self):
        for name, val in C.SYSLOG_SEVERITY.items():
            assert 0 <= val <= 7
