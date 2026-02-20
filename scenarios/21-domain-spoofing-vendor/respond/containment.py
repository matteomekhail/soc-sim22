#!/usr/bin/env python3
"""
Scenario 21 - Domain Spoofing Vendor: Containment Actions
===========================================================
Automated containment response:
  1. DNS sinkhole the spoofed vendor domain
  2. Block attacker IP and spoofed domain at firewall/proxy
  3. Alert finance team and freeze pending payments
  4. Quarantine fraudulent emails from mailboxes
  5. Notify legitimate vendor and initiate bank recall

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
VENDOR_DOMAIN         = "globalparts-supply.test"
SPOOFED_VENDOR_DOMAIN = "g1obalparts-supply.test"
ATTACKER_IP           = "203.0.113.50"
SINKHOLE_IP           = "0.0.0.0"
COMPANY_DOMAIN        = "acmecorp.local"
DNS_SERVER            = "10.0.0.50"

FINANCE_USERS = [
    "cfo@acmecorp.local",
    "jane.smith@acmecorp.local",
    "carlos.garcia@acmecorp.local",
    "emma.johnson@acmecorp.local",
]

ATTACKER_BANK = {
    "bank": "Offshore Trust Bank",
    "account_name": "GP Supply International",
    "routing_number": "091000019",
    "account_number": "****8912",
}

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
    """Redirect spoofed vendor domain to sinkhole IP."""
    print(f"\n  {Fore.MAGENTA}[1/5] DNS Sinkhole{Style.RESET_ALL}")

    action(f"Adding DNS sinkhole: {SPOOFED_VENDOR_DOMAIN} -> {SINKHOLE_IP}", simulate)
    log_action(actions_log, "dns_sinkhole", {
        "domain": SPOOFED_VENDOR_DOMAIN,
        "sinkhole_ip": SINKHOLE_IP,
        "dns_server": DNS_SERVER,
    })
    if not simulate:
        # Update DNS server configuration (e.g., via nsupdate or BIND API)
        pass
    success(f"Domain {SPOOFED_VENDOR_DOMAIN} sinkholed to {SINKHOLE_IP}")

    time.sleep(0.2)


def block_attacker(simulate: bool, actions_log: list) -> None:
    """Block attacker IP and spoofed domain at firewall and proxy."""
    print(f"\n  {Fore.MAGENTA}[2/5] Firewall & Proxy Blocking{Style.RESET_ALL}")

    # Firewall block
    action(f"Blocking attacker IP {ATTACKER_IP} at perimeter firewall", simulate)
    log_action(actions_log, "firewall_block_ip", {
        "ip": ATTACKER_IP,
        "direction": "both",
        "rule": "DROP",
    })
    success(f"Firewall rule added: DROP all traffic to/from {ATTACKER_IP}")

    # Proxy block
    action(f"Adding {SPOOFED_VENDOR_DOMAIN} to web proxy blocklist", simulate)
    log_action(actions_log, "proxy_block_domain", {
        "domain": SPOOFED_VENDOR_DOMAIN,
        "action": "block",
    })
    success(f"Domain {SPOOFED_VENDOR_DOMAIN} added to proxy blocklist")

    # Block at email gateway
    action(f"Blocking sender domain {SPOOFED_VENDOR_DOMAIN} at email gateway", simulate)
    log_action(actions_log, "email_gateway_block", {
        "domain": SPOOFED_VENDOR_DOMAIN,
        "action": "reject",
    })
    success(f"Email gateway now rejecting emails from {SPOOFED_VENDOR_DOMAIN}")

    time.sleep(0.2)


def freeze_payments(simulate: bool, actions_log: list) -> None:
    """Alert finance team and freeze all pending payments to the spoofed vendor."""
    print(f"\n  {Fore.MAGENTA}[3/5] Alert Finance & Freeze Payments{Style.RESET_ALL}")

    # Alert finance team
    for user in FINANCE_USERS:
        action(f"Sending fraud alert to {user}", simulate)
        log_action(actions_log, "fraud_alert_sent", {
            "recipient": user,
            "alert_type": "vendor_impersonation_fraud",
            "spoofed_domain": SPOOFED_VENDOR_DOMAIN,
            "legitimate_domain": VENDOR_DOMAIN,
            "channel": "phone_and_email",
        })
        success(f"Fraud alert sent to {user}")

    # Freeze pending payments
    action("Freezing all pending payments referencing spoofed vendor", simulate)
    log_action(actions_log, "payment_freeze", {
        "scope": "all_pending",
        "vendor_filter": SPOOFED_VENDOR_DOMAIN,
        "status": "frozen",
        "reason": "Suspected vendor domain impersonation fraud",
    })
    success("All pending payments to spoofed vendor frozen")

    # Freeze any payments to the attacker bank details
    action(f"Flagging bank account {ATTACKER_BANK['account_number']} as fraudulent", simulate)
    log_action(actions_log, "bank_account_flag", {
        "bank": ATTACKER_BANK["bank"],
        "account": ATTACKER_BANK["account_number"],
        "routing": ATTACKER_BANK["routing_number"],
        "status": "flagged_fraudulent",
    })
    success(f"Attacker bank account flagged as fraudulent")

    time.sleep(0.2)


def quarantine_emails(simulate: bool, actions_log: list) -> None:
    """Remove fraudulent vendor emails from all mailboxes."""
    print(f"\n  {Fore.MAGENTA}[4/5] Email Quarantine{Style.RESET_ALL}")

    search_criteria = [
        f"from:*@{SPOOFED_VENDOR_DOMAIN}",
        "subject:'Updated Payment Instructions'",
        "subject:'Outstanding Invoices'",
        f"contains:{SPOOFED_VENDOR_DOMAIN}",
    ]

    for criteria in search_criteria:
        action(f"Quarantining emails matching: {criteria}", simulate)
        log_action(actions_log, "email_quarantine", {
            "search_criteria": criteria,
            "action": "quarantine",
            "scope": "all_mailboxes",
        })
        success(f"Matching emails quarantined: {criteria}")

    time.sleep(0.2)


def notify_and_recall(simulate: bool, actions_log: list) -> None:
    """Notify legitimate vendor and initiate bank recall if payment was sent."""
    print(f"\n  {Fore.MAGENTA}[5/5] Vendor Notification & Bank Recall{Style.RESET_ALL}")

    # Notify legitimate vendor
    action(f"Contacting legitimate vendor ({VENDOR_DOMAIN}) about impersonation", simulate)
    log_action(actions_log, "vendor_notification", {
        "vendor_domain": VENDOR_DOMAIN,
        "contact_method": "phone_and_verified_email",
        "reason": "Domain impersonation detected",
        "spoofed_domain": SPOOFED_VENDOR_DOMAIN,
        "recommendation": "File domain abuse complaint with registrar",
    })
    success(f"Legitimate vendor ({VENDOR_DOMAIN}) notified via verified channel")

    # Initiate bank recall
    action("Initiating wire transfer recall with company bank", simulate)
    log_action(actions_log, "wire_recall", {
        "status": "initiated",
        "destination_bank": ATTACKER_BANK["bank"],
        "destination_account": ATTACKER_BANK["account_number"],
        "reason": "Fraudulent wire transfer - vendor impersonation",
        "law_enforcement_notified": True,
    })
    success("Wire transfer recall initiated with banking partner")

    # File domain abuse report
    action(f"Filing abuse report for domain {SPOOFED_VENDOR_DOMAIN}", simulate)
    log_action(actions_log, "domain_abuse_report", {
        "domain": SPOOFED_VENDOR_DOMAIN,
        "registrar": "shady-registrar.test",
        "reason": "Domain registered for vendor impersonation and payment fraud",
        "evidence_preserved": True,
    })
    success(f"Abuse report filed for {SPOOFED_VENDOR_DOMAIN}")

    # Law enforcement notification
    action("Preparing law enforcement notification (IC3/FBI)", simulate)
    log_action(actions_log, "law_enforcement_notification", {
        "agency": "FBI IC3",
        "report_type": "Business Email Compromise",
        "spoofed_domain": SPOOFED_VENDOR_DOMAIN,
        "attacker_ip": ATTACKER_IP,
        "financial_loss_potential": True,
    })
    success("Law enforcement notification prepared")

    time.sleep(0.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scenario 21: Domain Spoofing Vendor - Containment"
    )
    parser.add_argument(
        "--mode", choices=["simulate", "execute"], default="simulate",
        help="Run in simulate (dry-run) or execute mode (default: simulate)"
    )
    args = parser.parse_args()
    simulate = args.mode == "simulate"

    banner("Scenario 21: Containment Response")
    mode_label = "SIMULATION" if simulate else "LIVE EXECUTION"
    print(f"  Mode: {Fore.YELLOW if simulate else Fore.RED}{mode_label}{Style.RESET_ALL}")
    print(f"  Spoofed domain: {SPOOFED_VENDOR_DOMAIN}")
    print(f"  Legitimate vendor: {VENDOR_DOMAIN}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print()

    actions_log: list[dict] = []

    dns_sinkhole(simulate, actions_log)
    block_attacker(simulate, actions_log)
    freeze_payments(simulate, actions_log)
    quarantine_emails(simulate, actions_log)
    notify_and_recall(simulate, actions_log)

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
