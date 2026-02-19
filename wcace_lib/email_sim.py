"""Email simulation for phishing and social engineering scenarios."""

import json
import random
import time
from datetime import datetime
from typing import Optional

from .constants import (
    COMPANY_DOMAIN, SPOOFED_DOMAIN, PHISHING_DOMAIN,
    CEO_USER, CFO_USER, REGULAR_USERS
)


class EmailSimulator:
    """Generate simulated email events for SOC scenarios."""

    # Common phishing templates
    PHISHING_SUBJECTS = [
        "URGENT: Wire Transfer Required",
        "Action Required: Verify Your Account",
        "Invoice #INV-{num} - Payment Due",
        "IT Security: Password Reset Required",
        "Shared Document: Q4 Financial Report",
        "Meeting Notes - Board of Directors",
        "Your Account Has Been Compromised",
        "Package Delivery Notification",
        "HR: Updated Employee Benefits",
        "Vendor Payment Confirmation Needed",
    ]

    LEGITIMATE_SUBJECTS = [
        "Team Meeting - Weekly Standup",
        "RE: Project Update",
        "FW: Client Feedback",
        "Lunch plans?",
        "PTO Request Approved",
        "Monthly Report Attached",
        "Welcome aboard!",
        "Conference Room Booking",
    ]

    def __init__(self, domain: str = COMPANY_DOMAIN):
        self.domain = domain

    def generate_email(self, from_addr: str, to_addr: str, subject: str,
                       body: str, attachments: Optional[list[str]] = None,
                       headers: Optional[dict] = None) -> dict:
        """Generate a mock email event."""
        email = {
            "timestamp": datetime.now().isoformat() + "Z",
            "message_id": f"<{random.randint(100000, 999999)}.{int(time.time())}@{self.domain}>",
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "body_preview": body[:200],
            "body_length": len(body),
            "attachments": attachments or [],
            "headers": {
                "X-Mailer": "Microsoft Outlook 16.0",
                "Content-Type": "multipart/mixed",
                "DKIM-Signature": "v=1; a=rsa-sha256; d=" + from_addr.split("@")[-1],
                **(headers or {}),
            },
            "spf_result": "pass",
            "dkim_result": "pass",
            "dmarc_result": "pass",
        }
        return email

    def phishing_email(self, to_addr: str,
                       spoofed_from: Optional[str] = None,
                       attachment: Optional[str] = None) -> dict:
        """Generate a phishing email with suspicious indicators."""
        from_addr = spoofed_from or f"ceo@{SPOOFED_DOMAIN}"
        subject = random.choice(self.PHISHING_SUBJECTS).format(
            num=random.randint(10000, 99999)
        )
        body = (
            f"Dear colleague,\n\n"
            f"Please review the attached document and take immediate action.\n"
            f"This is time-sensitive and requires your attention today.\n\n"
            f"Click here to verify: https://{PHISHING_DOMAIN}/verify?token="
            f"{random.randbytes(16).hex()}\n\n"
            f"Best regards,\nManagement"
        )

        email = self.generate_email(from_addr, to_addr, subject, body,
                                    attachments=[attachment] if attachment else [])

        # Phishing indicators
        email["spf_result"] = "fail"
        email["dkim_result"] = "fail"
        email["dmarc_result"] = "fail"
        email["headers"]["X-Originating-IP"] = f"203.0.113.{random.randint(1, 254)}"
        email["headers"]["Return-Path"] = f"bounce-{random.randint(1000, 9999)}@{SPOOFED_DOMAIN}"
        email["suspicious_indicators"] = [
            "SPF check failed",
            "Domain similar to company domain (homoglyph)",
            "Urgency language detected",
            "External link in body",
            "From domain mismatch with Reply-To",
        ]
        if attachment:
            email["suspicious_indicators"].append(f"Suspicious attachment: {attachment}")

        return email

    def ceo_fraud_email(self, to_addr: str, amount: float = 50000.0) -> dict:
        """Generate a CEO fraud / BEC email."""
        email = self.phishing_email(to_addr, spoofed_from=f"ceo@{SPOOFED_DOMAIN}")
        email["subject"] = "URGENT: Wire Transfer Required - Confidential"
        email["body_preview"] = (
            f"I need you to process an urgent wire transfer of ${amount:,.2f} "
            f"to the following account. This is for a confidential acquisition. "
            f"Please handle this immediately and do not discuss with anyone."
        )
        email["suspicious_indicators"].append("Wire transfer request")
        email["suspicious_indicators"].append("Secrecy language detected")
        return email

    def ransomware_email(self, to_addr: str) -> dict:
        """Generate a phishing email with ransomware attachment."""
        attachments = random.choice([
            "Invoice_2024.pdf.exe",
            "Document_Scan.zip",
            "Urgent_Notice.docm",
            "Payment_Details.xlsm",
        ])
        email = self.phishing_email(to_addr, attachment=attachments)
        email["subject"] = "Invoice #INV-" + str(random.randint(10000, 99999))
        email["suspicious_indicators"].append("Double extension in attachment")
        email["suspicious_indicators"].append("Macro-enabled document")
        return email

    def generate_email_sequence(self, scenario: str = "phishing",
                                count: int = 5) -> list[dict]:
        """Generate a sequence of emails mixing legitimate and malicious."""
        emails = []
        targets = [f"{u}@{self.domain}" for u in REGULAR_USERS[:count]]

        # Add some legitimate emails as noise
        for _ in range(count * 2):
            sender = f"{random.choice(REGULAR_USERS)}@{self.domain}"
            recipient = f"{random.choice(REGULAR_USERS)}@{self.domain}"
            emails.append(self.generate_email(
                sender, recipient,
                random.choice(self.LEGITIMATE_SUBJECTS),
                "Normal email content for daily business communication."
            ))

        # Add malicious emails
        for target in targets:
            if scenario == "phishing":
                emails.append(self.phishing_email(target))
            elif scenario == "ceo_fraud":
                emails.append(self.ceo_fraud_email(target))
            elif scenario == "ransomware":
                emails.append(self.ransomware_email(target))

        random.shuffle(emails)
        return emails

    def save_email_log(self, emails: list[dict], filepath: str):
        """Save email events to a JSON log file."""
        with open(filepath, "w") as f:
            for email in emails:
                f.write(json.dumps(email) + "\n")

    @staticmethod
    def load_email_log(filepath: str) -> list[dict]:
        """Load email events from a JSON log file."""
        emails = []
        with open(filepath, "r") as f:
            for line in f:
                if line.strip():
                    emails.append(json.loads(line))
        return emails
