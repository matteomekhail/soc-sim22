"""Shared constants for all WCACE scenarios."""

# === Network Configuration ===
INTERNAL_SUBNET = "10.0.0.0/24"
DMZ_SUBNET = "10.0.1.0/24"
EXTERNAL_SUBNET = "203.0.113.0/24"  # TEST-NET-3 (RFC 5737)

# Internal hosts
DC_IP = "10.0.0.10"
FILE_SERVER_IP = "10.0.0.20"
DB_SERVER_IP = "10.0.0.30"
MAIL_SERVER_IP = "10.0.0.40"
DNS_SERVER_IP = "10.0.0.50"
WORKSTATION_IPS = [f"10.0.0.{i}" for i in range(100, 120)]

# DMZ hosts
WEB_SERVER_IP = "10.0.1.10"
API_SERVER_IP = "10.0.1.20"
VPN_SERVER_IP = "10.0.1.30"

# Attacker IPs (external)
ATTACKER_IP = "203.0.113.50"
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(50, 70)]
C2_SERVER_IP = "203.0.113.100"
MINING_POOL_IP = "203.0.113.200"

# === Domains ===
COMPANY_DOMAIN = "acmecorp.local"
SPOOFED_DOMAIN = "acmec0rp.local"
C2_DOMAIN = "updates.evil-cdn.test"
MINING_POOL_DOMAIN = "pool.cryptomine.test"
PHISHING_DOMAIN = "acmecorp-login.test"
DNS_TUNNEL_DOMAIN = "t.exfil.test"
WATERING_HOLE_DOMAIN = "news-portal.test"

# === Users ===
ADMIN_USERS = ["admin", "sysadmin", "root"]
REGULAR_USERS = [
    "john.doe", "jane.smith", "bob.wilson", "alice.chen",
    "carlos.garcia", "emma.johnson", "david.lee", "sarah.brown",
    "mike.taylor", "lisa.wang"
]
SERVICE_ACCOUNTS = ["svc_backup", "svc_monitor", "svc_web", "svc_db"]
INSIDER_USER = "bob.wilson"
CEO_USER = "ceo@acmecorp.local"
CFO_USER = "cfo@acmecorp.local"

# === Ports ===
HTTP_PORT = 80
HTTPS_PORT = 443
SSH_PORT = 22
DNS_PORT = 53
SMTP_PORT = 25
SMB_PORT = 445
RDP_PORT = 3389
MYSQL_PORT = 3306
MSSQL_PORT = 1433
API_PORT = 8080

# === SOC Stack ===
WAZUH_API_URL = "https://localhost:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr3tP4ssw0rd"
WAZUH_DASHBOARD_URL = "https://localhost:5601"
GRAFANA_URL = "http://localhost:3000"
LOKI_URL = "http://localhost:3100"
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

# === MITRE ATT&CK Techniques ===
MITRE = {
    "initial_access": {
        "phishing": "T1566",
        "phishing_attachment": "T1566.001",
        "phishing_link": "T1566.002",
        "drive_by": "T1189",
        "exploit_public": "T1190",
        "supply_chain": "T1195",
        "usb": "T1091",
    },
    "execution": {
        "command_line": "T1059",
        "user_execution": "T1204",
        "exploitation_client": "T1203",
    },
    "persistence": {
        "web_shell": "T1505",
        "scheduled_task": "T1053",
        "registry_run": "T1547.001",
    },
    "privilege_escalation": {
        "exploitation": "T1068",
        "sudo_abuse": "T1548",
    },
    "lateral_movement": {
        "remote_services": "T1021",
        "exploitation_remote": "T1210",
        "rat": "T1219",
    },
    "exfiltration": {
        "c2_channel": "T1041",
        "dns": "T1048",
        "web_service": "T1567",
        "alt_protocol": "T1048.003",
    },
    "command_and_control": {
        "app_layer": "T1071",
        "dns_tunnel": "T1071.004",
        "encrypted": "T1573",
    },
    "impact": {
        "data_encrypted": "T1486",
        "resource_hijack": "T1496",
        "data_manipulation": "T1565",
    },
    "credential_access": {
        "brute_force": "T1110",
        "credential_stuffing": "T1110.004",
        "valid_accounts": "T1078",
    },
    "collection": {
        "data_staged": "T1074",
        "data_cloud": "T1530",
    },
    "resource_development": {
        "domains": "T1583.001",
        "botnet": "T1583.005",
        "search_info": "T1597",
    },
}

# === Log Formats ===
SYSLOG_FACILITY = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3,
    "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

SYSLOG_SEVERITY = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}
