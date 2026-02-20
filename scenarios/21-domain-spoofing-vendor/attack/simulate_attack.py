#!/usr/bin/env python3
"""
Scenario 21 - Domain Spoofing Vendor
======================================
Simulates an attacker who:
  1. Registers a vendor-lookalike domain (g1obalparts-supply.test)
  2. Sends fake invoice emails impersonating the vendor
  3. Redirects payment to attacker-controlled bank account

MITRE ATT&CK: T1583.001 (Domains), T1036 (Masquerading), T1566.002 (Phishing Link),
              T1565 (Data Manipulation)

Usage:
    python simulate_attack.py
"""

import json
import os
import random
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Path setup -- allow imports from the project-level wcace_lib package
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib import EmailSimulator, LogGenerator, SIEMClient  # noqa: E402

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
VENDOR_DOMAIN         = "globalparts-supply.test"    # Legitimate vendor domain
SPOOFED_VENDOR_DOMAIN = "g1obalparts-supply.test"    # Lookalike (1 vs l)
COMPANY_DOMAIN        = "acmecorp.local"
ATTACKER_IP           = "203.0.113.50"

# Vendor contacts (legitimate)
VENDOR_CONTACT    = "accounts@globalparts-supply.test"
VENDOR_MANAGER    = "j.martinez@globalparts-supply.test"

# Spoofed vendor contacts
FAKE_VENDOR_CONTACT = f"accounts@{SPOOFED_VENDOR_DOMAIN}"
FAKE_VENDOR_MANAGER = f"j.martinez@{SPOOFED_VENDOR_DOMAIN}"

# AcmeCorp finance team targets
FINANCE_USERS = [
    "cfo@acmecorp.local",
    "jane.smith@acmecorp.local",      # Accounts Payable
    "carlos.garcia@acmecorp.local",   # Finance Manager
    "emma.johnson@acmecorp.local",    # Finance Analyst
]

# Payment details
LEGITIMATE_BANK = {
    "bank": "First National Bank",
    "account_name": "Global Parts Supply LLC",
    "routing_number": "021000089",
    "account_number": "****4567",
}
ATTACKER_BANK = {
    "bank": "Offshore Trust Bank",
    "account_name": "GP Supply International",
    "routing_number": "091000019",
    "account_number": "****8912",
}

INVOICE_AMOUNTS = [47_500.00, 82_300.00, 125_750.00, 31_200.00]

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "sample_logs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def banner(text: str) -> None:
    width = 60
    print(f"\n{Fore.CYAN}{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}{Style.RESET_ALL}\n")


def phase(num: int, title: str) -> None:
    print(f"{Fore.YELLOW}[Phase {num}] {title}{Style.RESET_ALL}")


def info(msg: str) -> None:
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"  {Fore.RED}[!]{Style.RESET_ALL} {msg}")


def save_logs(logs: list, filename: str) -> str:
    """Save log entries to a file inside LOG_DIR."""
    os.makedirs(LOG_DIR, exist_ok=True)
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "w") as fh:
        for entry in logs:
            if isinstance(entry, dict):
                fh.write(json.dumps(entry) + "\n")
            else:
                fh.write(str(entry) + "\n")
    info(f"Saved {len(logs)} log entries -> {filepath}")
    return filepath


# ---------------------------------------------------------------------------
# Phase 1 -- Register Vendor-Lookalike Domain
# ---------------------------------------------------------------------------
def phase1_register_domain(log_gen: LogGenerator) -> list:
    phase(1, "Register Vendor-Lookalike Domain")
    logs = []

    info(f"Attacker identifies vendor: {VENDOR_DOMAIN}")
    info(f"Attacker registers lookalike: {SPOOFED_VENDOR_DOMAIN} (1 vs l)")

    logs.append(log_gen.json_log("domain_registration", {
        "registrar": "shady-registrar.test",
        "domain": SPOOFED_VENDOR_DOMAIN,
        "registrant_email": f"admin@{SPOOFED_VENDOR_DOMAIN}",
        "nameservers": [f"ns1.{SPOOFED_VENDOR_DOMAIN}", f"ns2.{SPOOFED_VENDOR_DOMAIN}"],
        "ip_resolved": ATTACKER_IP,
        "whois_privacy": True,
        "registration_date": datetime.now().isoformat(),
    }, severity="warning"))

    # DNS A record
    logs.append(log_gen.dns_query_log(ATTACKER_IP, SPOOFED_VENDOR_DOMAIN, "A", ATTACKER_IP))

    # MX record for receiving bounce-backs and replies
    info(f"Configuring MX records for {SPOOFED_VENDOR_DOMAIN}")
    logs.append(log_gen.json_log("dns_record", {
        "domain": SPOOFED_VENDOR_DOMAIN,
        "record_type": "MX",
        "value": f"mail.{SPOOFED_VENDOR_DOMAIN}",
        "ip": ATTACKER_IP,
    }))

    # Attacker researches vendor communication patterns (OSINT)
    info("Attacker performs OSINT on vendor-company relationship")
    logs.append(log_gen.json_log("reconnaissance", {
        "technique": "T1597",
        "target": COMPANY_DOMAIN,
        "vendor_identified": VENDOR_DOMAIN,
        "data_sources": ["LinkedIn", "public filings", "press releases"],
        "contacts_identified": [
            "CFO: cfo@acmecorp.local",
            "AP Manager: jane.smith@acmecorp.local",
        ],
    }))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Phase 2 -- Send Fake Invoice Emails
# ---------------------------------------------------------------------------
def phase2_fake_invoices(log_gen: LogGenerator,
                          email_sim: EmailSimulator) -> tuple[list, list]:
    phase(2, "Send Fake Invoice Emails Impersonating Vendor")
    logs = []
    emails = []

    # Send multiple fake invoices to finance team
    for i, target in enumerate(FINANCE_USERS):
        invoice_num = f"INV-2026-{random.randint(10000, 99999)}"
        amount = random.choice(INVOICE_AMOUNTS)

        info(f"Sending fake invoice {invoice_num} (${amount:,.2f}) to {target}")

        email = email_sim.generate_email(
            from_addr=FAKE_VENDOR_CONTACT,
            to_addr=target,
            subject=f"Invoice {invoice_num} - Updated Payment Instructions",
            body=(
                f"Dear AcmeCorp Accounts Payable,\n\n"
                f"Please find attached invoice {invoice_num} for ${amount:,.2f} "
                f"for recent parts order PO-2026-{random.randint(1000, 9999)}.\n\n"
                f"IMPORTANT: Please note our banking details have been updated "
                f"due to a recent change in our banking provider. The new details "
                f"are as follows:\n\n"
                f"  Bank: {ATTACKER_BANK['bank']}\n"
                f"  Account Name: {ATTACKER_BANK['account_name']}\n"
                f"  Routing: {ATTACKER_BANK['routing_number']}\n"
                f"  Account: {ATTACKER_BANK['account_number']}\n\n"
                f"Please process this payment within 5 business days to avoid "
                f"any supply chain delays.\n\n"
                f"If you have any questions, please contact me directly.\n\n"
                f"Best regards,\n"
                f"Jose Martinez\n"
                f"Senior Account Manager\n"
                f"Global Parts Supply\n"
                f"Phone: +1 (555) 0147\n"
            ),
            attachments=[f"{invoice_num}.pdf"],
            headers={
                "Reply-To": FAKE_VENDOR_MANAGER,
                "X-Originating-IP": ATTACKER_IP,
                "Return-Path": f"bounce@{SPOOFED_VENDOR_DOMAIN}",
            },
        )
        # Mark as spoofed
        email["spf_result"] = "fail"
        email["dkim_result"] = "fail"
        email["dmarc_result"] = "fail"
        email["suspicious_indicators"] = [
            f"Sender domain {SPOOFED_VENDOR_DOMAIN} resembles known vendor {VENDOR_DOMAIN}",
            "SPF check failed for sender domain",
            "DKIM signature invalid",
            "DMARC policy violation",
            "Bank details differ from vendor records on file",
            "Domain registered recently (< 7 days old)",
            "Invoice references updated payment instructions",
            "PDF attachment with invoice",
        ]
        email["invoice_details"] = {
            "invoice_number": invoice_num,
            "amount": amount,
            "new_bank_details": ATTACKER_BANK,
            "original_bank_details": LEGITIMATE_BANK,
        }
        emails.append(email)

        # DNS resolution log for spoofed domain
        logs.append(log_gen.dns_query_log(
            f"10.0.0.{random.randint(100, 119)}", SPOOFED_VENDOR_DOMAIN, "A", ATTACKER_IP
        ))

    # Also send a follow-up "urgent" email to the CFO
    info("Sending urgent follow-up to CFO")
    followup = email_sim.generate_email(
        from_addr=FAKE_VENDOR_MANAGER,
        to_addr="cfo@acmecorp.local",
        subject="RE: Urgent - Outstanding Invoices & Updated Bank Details",
        body=(
            f"Hi,\n\n"
            f"I wanted to follow up on the invoices sent earlier this week. "
            f"We have not received confirmation of payment and our records "
            f"show multiple outstanding invoices.\n\n"
            f"Please ensure all payments are redirected to our new banking "
            f"details as communicated. The old account will be closed within "
            f"48 hours.\n\n"
            f"This is time-sensitive as it may affect your supply agreements.\n\n"
            f"Regards,\n"
            f"Jose Martinez\n"
            f"Global Parts Supply\n"
        ),
        headers={
            "Reply-To": FAKE_VENDOR_MANAGER,
            "X-Originating-IP": ATTACKER_IP,
        },
    )
    followup["spf_result"] = "fail"
    followup["dkim_result"] = "fail"
    followup["dmarc_result"] = "fail"
    followup["suspicious_indicators"] = [
        f"Sender domain {SPOOFED_VENDOR_DOMAIN} resembles known vendor",
        "Urgency language detected",
        "Account closure threat",
        "Follow-up pressure for payment",
    ]
    emails.append(followup)

    time.sleep(0.3)
    return logs, emails


# ---------------------------------------------------------------------------
# Phase 3 -- Payment Redirect
# ---------------------------------------------------------------------------
def phase3_payment_redirect(log_gen: LogGenerator) -> list:
    phase(3, "Payment Redirect to Attacker Bank Account")
    logs = []

    # Simulate finance team processing the fraudulent invoice
    compromised_amount = random.choice(INVOICE_AMOUNTS)
    processor = "jane.smith"

    warn(f"Finance user {processor} processes fraudulent invoice")
    logs.append(log_gen.json_log("payment_processing", {
        "user": f"{processor}@{COMPANY_DOMAIN}",
        "action": "initiate_wire_transfer",
        "vendor": SPOOFED_VENDOR_DOMAIN,
        "amount": compromised_amount,
        "currency": "USD",
        "destination_bank": ATTACKER_BANK["bank"],
        "destination_account": ATTACKER_BANK["account_number"],
        "routing_number": ATTACKER_BANK["routing_number"],
        "invoice_reference": f"INV-2026-{random.randint(10000, 99999)}",
        "approval_status": "pending",
    }, severity="warning"))

    # Approval chain
    info("Payment enters approval workflow")
    logs.append(log_gen.json_log("payment_approval", {
        "user": "carlos.garcia@acmecorp.local",
        "action": "approve_payment",
        "amount": compromised_amount,
        "vendor": SPOOFED_VENDOR_DOMAIN,
        "approval_level": 1,
        "approved": True,
        "note": "Vendor bank update seems legitimate per email",
    }, severity="warning"))

    # CFO final approval
    logs.append(log_gen.json_log("payment_approval", {
        "user": "cfo@acmecorp.local",
        "action": "approve_payment",
        "amount": compromised_amount,
        "vendor": SPOOFED_VENDOR_DOMAIN,
        "approval_level": 2,
        "approved": True,
    }, severity="warning"))

    # Wire transfer executed
    warn(f"Wire transfer of ${compromised_amount:,.2f} sent to attacker account")
    logs.append(log_gen.json_log("wire_transfer", {
        "transaction_id": f"WT-{random.randint(100000, 999999)}",
        "user": f"{processor}@{COMPANY_DOMAIN}",
        "amount": compromised_amount,
        "currency": "USD",
        "source_bank": "Company Bank",
        "source_account": "****1234",
        "destination_bank": ATTACKER_BANK["bank"],
        "destination_account": ATTACKER_BANK["account_number"],
        "destination_routing": ATTACKER_BANK["routing_number"],
        "beneficiary": ATTACKER_BANK["account_name"],
        "status": "completed",
        "anomaly_flags": [
            "New beneficiary bank account",
            "Bank details differ from vendor master record",
            "Offshore bank destination",
            "First-time routing number",
        ],
    }, severity="critical"))

    # Post-transfer: attacker moves funds
    info("Attacker begins laundering transferred funds")
    logs.append(log_gen.json_log("funds_movement", {
        "event": "attacker_fund_transfer",
        "source_bank": ATTACKER_BANK["bank"],
        "amount": compromised_amount,
        "destination": "Multiple cryptocurrency exchanges",
        "status": "funds_dispersed",
    }, severity="critical"))

    # Anomaly detection kicks in (after the fact)
    logs.append(log_gen.json_log("payment_anomaly", {
        "alert": "Vendor bank details mismatch",
        "vendor_on_file": VENDOR_DOMAIN,
        "vendor_in_invoice": SPOOFED_VENDOR_DOMAIN,
        "bank_on_file": LEGITIMATE_BANK,
        "bank_in_invoice": ATTACKER_BANK,
        "amount": compromised_amount,
        "risk_score": 95,
    }, severity="critical"))

    time.sleep(0.3)
    return logs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    banner("Scenario 21: Domain Spoofing Vendor")
    print(f"  {Fore.WHITE}MITRE ATT&CK:{Style.RESET_ALL} T1583.001, T1036, T1566.002, T1565")
    print(f"  {Fore.WHITE}Legitimate Vendor:{Style.RESET_ALL} {VENDOR_DOMAIN}")
    print(f"  {Fore.WHITE}Spoofed Domain:{Style.RESET_ALL}   {SPOOFED_VENDOR_DOMAIN}")
    print(f"  {Fore.WHITE}Attacker IP:{Style.RESET_ALL}      {ATTACKER_IP}")
    print(f"  {Fore.WHITE}Company Domain:{Style.RESET_ALL}   {COMPANY_DOMAIN}")
    print()

    log_gen   = LogGenerator(source_host="soc-sim-sc21")
    email_sim = EmailSimulator(domain=COMPANY_DOMAIN)
    all_logs: list = []

    # Phase 1
    logs_p1 = phase1_register_domain(log_gen)
    all_logs.extend(logs_p1)

    # Phase 2
    logs_p2, emails = phase2_fake_invoices(log_gen, email_sim)
    all_logs.extend(logs_p2)

    # Phase 3
    logs_p3 = phase3_payment_redirect(log_gen)
    all_logs.extend(logs_p3)

    # --- Save all logs ---
    banner("Saving Logs")
    save_logs(all_logs, "attack_simulation.json")
    save_logs(emails, "phishing_emails.json")
    save_logs(logs_p1, "phase1_domain_registration.json")
    save_logs(logs_p2, "phase2_fake_invoices_dns.json")
    save_logs(logs_p3, "phase3_payment_redirect.json")

    # Summary
    banner("Simulation Complete")
    print(f"  {Fore.GREEN}Total log entries generated:{Style.RESET_ALL} {len(all_logs)}")
    print(f"  {Fore.GREEN}Phishing emails sent:{Style.RESET_ALL}       {len(emails)}")
    print(f"  {Fore.GREEN}Log directory:{Style.RESET_ALL}              {os.path.abspath(LOG_DIR)}")
    print()


if __name__ == "__main__":
    main()
