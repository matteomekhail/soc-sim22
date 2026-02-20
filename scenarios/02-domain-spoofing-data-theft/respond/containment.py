#!/usr/bin/env python3
"""
Scenario 02 - Domain Spoofing & Data Theft: Containment Actions
================================================================
Automated containment response:
  1. DNS sinkhole the phishing and spoofed domains
  2. Block the phishing domain and attacker IP at the firewall
  3. Reset compromised user credentials
  4. Revoke active sessions for compromised users
  5. Quarantine phishing emails from mailboxes

Usage:
    python containment.py                  # Simulate all containment actions
    python containment.py --mode simulate  # Dry-run (default)
    python containment.py --mode execute   # Execute against live infrastructure
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Noop:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Noop()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPOOFED_DOMAIN   = "acmec0rp.local"
PHISHING_DOMAIN  = "acmecorp-login.test"
ATTACKER_IP      = "203.0.113.50"
SINKHOLE_IP      = "0.0.0.0"
COMPANY_DOMAIN   = "acmecorp.local"
DNS_SERVER       = "10.0.0.50"

COMPROMISED_USERS = [
    "john.doe", "jane.smith", "bob.wilson", "alice.chen",
]

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(text: str) -> None:
    width = 60
    print(f"\n{Fore.CYAN}{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}{Style.RESET_ALL}\n")


def action(msg: str, simulate: bool = True) -> None:
    mode_tag = f"{Fore.YELLOW}[SIMULATE]{Style.RESET_ALL}" if simulate else f"{Fore.RED}[EXECUTE]{Style.RESET_ALL}"
    print(f"  {mode_tag} {msg}")


def success(msg: str) -> None:
    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")


def log_action(actions_log: list, action_name: str, details: dict) -> None:
    entry = {
        "timestamp": datetime.now().isoformat() + "Z",
        "action": action_name,
        **details,
    }
    actions_log.append(entry)


# ---------------------------------------------------------------------------
# Containment Actions
# ---------------------------------------------------------------------------

def dns_sinkhole(simulate: bool, actions_log: list) -> None:
    """Redirect malicious domains to sinkhole IP via DNS server update."""
    print(f"\n  {Fore.MAGENTA}[1/5] DNS Sinkhole{Style.RESET_ALL}")

    domains = [SPOOFED_DOMAIN, PHISHING_DOMAIN]
    for domain in domains:
        action(f"Adding DNS sinkhole: {domain} -> {SINKHOLE_IP}", simulate)
        log_action(actions_log, "dns_sinkhole", {
            "domain": domain,
            "sinkhole_ip": SINKHOLE_IP,
            "dns_server": DNS_SERVER,
        })
        if not simulate:
            # In a real environment, this would update the DNS server config
            # e.g., via nsupdate, BIND API, or Active Directory DNS
            pass
        success(f"Domain {domain} sinkholed to {SINKHOLE_IP}")

    time.sleep(0.2)


def block_attacker(simulate: bool, actions_log: list) -> None:
    """Block attacker IP and phishing domain at firewall and proxy."""
    print(f"\n  {Fore.MAGENTA}[2/5] Firewall & Proxy Blocking{Style.RESET_ALL}")

    # Block attacker IP at firewall
    action(f"Blocking attacker IP {ATTACKER_IP} at perimeter firewall", simulate)
    log_action(actions_log, "firewall_block_ip", {
        "ip": ATTACKER_IP,
        "direction": "both",
        "rule": "DROP",
    })
    success(f"Firewall rule added: DROP all traffic to/from {ATTACKER_IP}")

    # Block phishing domain at web proxy
    for domain in [PHISHING_DOMAIN, SPOOFED_DOMAIN]:
        action(f"Adding {domain} to web proxy blocklist", simulate)
        log_action(actions_log, "proxy_block_domain", {
            "domain": domain,
            "action": "block",
        })
        success(f"Domain {domain} added to proxy blocklist")

    # Block attacker port
    action(f"Blocking outbound port 8443 to {ATTACKER_IP}", simulate)
    log_action(actions_log, "firewall_block_port", {
        "ip": ATTACKER_IP,
        "port": 8443,
        "direction": "outbound",
        "rule": "DROP",
    })
    success(f"Outbound port 8443 to {ATTACKER_IP} blocked")

    time.sleep(0.2)


def reset_credentials(simulate: bool, actions_log: list) -> None:
    """Force password reset for all compromised users."""
    print(f"\n  {Fore.MAGENTA}[3/5] Credential Reset{Style.RESET_ALL}")

    for user in COMPROMISED_USERS:
        action(f"Forcing password reset for {user}@{COMPANY_DOMAIN}", simulate)
        log_action(actions_log, "credential_reset", {
            "user": f"{user}@{COMPANY_DOMAIN}",
            "method": "forced_reset",
            "mfa_re_enrollment": True,
        })
        if not simulate:
            # In a real environment:
            # - Reset password in Active Directory / IdP
            # - Force MFA re-enrollment
            # - Send notification to user via out-of-band channel
            pass
        success(f"Password reset initiated for {user}")

    time.sleep(0.2)


def revoke_sessions(simulate: bool, actions_log: list) -> None:
    """Revoke all active sessions and tokens for compromised users."""
    print(f"\n  {Fore.MAGENTA}[4/5] Session Revocation{Style.RESET_ALL}")

    for user in COMPROMISED_USERS:
        action(f"Revoking all active sessions for {user}", simulate)
        log_action(actions_log, "session_revocation", {
            "user": f"{user}@{COMPANY_DOMAIN}",
            "sessions_revoked": "all",
            "oauth_tokens_revoked": True,
            "vpn_sessions_terminated": True,
        })
        success(f"All sessions revoked for {user}")

    # Also revoke any sessions from attacker IP
    action(f"Terminating all sessions originating from {ATTACKER_IP}", simulate)
    log_action(actions_log, "session_revocation_by_ip", {
        "src_ip": ATTACKER_IP,
        "sessions_terminated": "all",
    })
    success(f"All sessions from {ATTACKER_IP} terminated")

    time.sleep(0.2)


def quarantine_emails(simulate: bool, actions_log: list) -> None:
    """Remove phishing emails from all mailboxes."""
    print(f"\n  {Fore.MAGENTA}[5/5] Email Quarantine{Style.RESET_ALL}")

    search_criteria = [
        f"from:*@{SPOOFED_DOMAIN}",
        f"contains:acmecorp-login.test",
        "subject:'Mandatory Password Reset'",
    ]

    for criteria in search_criteria:
        action(f"Searching and quarantining emails matching: {criteria}", simulate)
        log_action(actions_log, "email_quarantine", {
            "search_criteria": criteria,
            "action": "quarantine",
            "scope": "all_mailboxes",
        })
        success(f"Matching emails quarantined: {criteria}")

    # Block sender domain in email gateway
    action(f"Blocking sender domain {SPOOFED_DOMAIN} at email gateway", simulate)
    log_action(actions_log, "email_gateway_block", {
        "domain": SPOOFED_DOMAIN,
        "action": "reject",
    })
    success(f"Sender domain {SPOOFED_DOMAIN} blocked at email gateway")

    time.sleep(0.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 02: Domain Spoofing & Data Theft - Containment"
    )
    parser.add_argument(
        "--mode", choices=["simulate", "execute"], default="simulate",
        help="Run in simulate (dry-run) or execute mode (default: simulate)"
    )
    args = parser.parse_args()
    simulate = args.mode == "simulate"

    banner("Scenario 02: Containment Response")
    mode_label = "SIMULATION" if simulate else "LIVE EXECUTION"
    print(f"  Mode: {Fore.YELLOW if simulate else Fore.RED}{mode_label}{Style.RESET_ALL}")
    print(f"  Targets: {SPOOFED_DOMAIN}, {PHISHING_DOMAIN}, {ATTACKER_IP}")
    print(f"  Compromised users: {', '.join(COMPROMISED_USERS)}")
    print()

    actions_log: list[dict] = []

    dns_sinkhole(simulate, actions_log)
    block_attacker(simulate, actions_log)
    reset_credentials(simulate, actions_log)
    revoke_sessions(simulate, actions_log)
    quarantine_emails(simulate, actions_log)

    # Save containment log
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "containment_actions.json")
    with open(log_path, "w") as fh:
        for entry in actions_log:
            fh.write(json.dumps(entry) + "\n")

    banner("Containment Complete")
    print(f"  {Fore.GREEN}Actions taken:{Style.RESET_ALL}  {len(actions_log)}")
    print(f"  {Fore.GREEN}Log saved to:{Style.RESET_ALL}   {os.path.abspath(log_path)}")
    print()


if __name__ == "__main__":
    main()
