"""Tests for wcace_lib.email_sim - email generation and phishing indicators."""

import json
import os

import pytest

from wcace_lib.email_sim import EmailSimulator
from wcace_lib.constants import SPOOFED_DOMAIN, COMPANY_DOMAIN


class TestGenerateEmail:
    def test_basic_fields(self, email_sim):
        email = email_sim.generate_email(
            "sender@acme.com", "recipient@acme.com",
            "Test Subject", "Test body content",
        )
        assert email["from"] == "sender@acme.com"
        assert email["to"] == "recipient@acme.com"
        assert email["subject"] == "Test Subject"
        assert "timestamp" in email
        assert "message_id" in email

    def test_spf_default_pass(self, email_sim):
        email = email_sim.generate_email("a@a.com", "b@b.com", "s", "b")
        assert email["spf_result"] == "pass"
        assert email["dkim_result"] == "pass"
        assert email["dmarc_result"] == "pass"

    def test_attachments_default_empty(self, email_sim):
        email = email_sim.generate_email("a@a.com", "b@b.com", "s", "b")
        assert email["attachments"] == []

    def test_attachments_populated(self, email_sim):
        email = email_sim.generate_email(
            "a@a.com", "b@b.com", "s", "b", attachments=["virus.exe"],
        )
        assert "virus.exe" in email["attachments"]

    def test_body_preview_truncated(self, email_sim):
        body = "X" * 500
        email = email_sim.generate_email("a@a.com", "b@b.com", "s", body)
        assert len(email["body_preview"]) <= 200


class TestPhishingEmail:
    def test_spf_fails(self, email_sim):
        email = email_sim.phishing_email("victim@acme.com")
        assert email["spf_result"] == "fail"
        assert email["dkim_result"] == "fail"
        assert email["dmarc_result"] == "fail"

    def test_suspicious_indicators_present(self, email_sim):
        email = email_sim.phishing_email("victim@acme.com")
        assert len(email["suspicious_indicators"]) > 0
        assert any("SPF" in i for i in email["suspicious_indicators"])

    def test_from_uses_spoofed_domain(self, email_sim):
        email = email_sim.phishing_email("victim@acme.com")
        assert SPOOFED_DOMAIN in email["from"]

    def test_custom_spoofed_from(self, email_sim):
        email = email_sim.phishing_email("victim@acme.com", spoofed_from="evil@evil.com")
        assert email["from"] == "evil@evil.com"


class TestCeoFraudEmail:
    def test_contains_wire_transfer(self, email_sim):
        email = email_sim.ceo_fraud_email("cfo@acme.com", amount=100000)
        assert "wire transfer" in email["body_preview"].lower() or \
               "Wire Transfer" in email["subject"]

    def test_has_secrecy_indicator(self, email_sim):
        email = email_sim.ceo_fraud_email("cfo@acme.com")
        assert any("ecrecy" in i for i in email["suspicious_indicators"])


class TestRansomwareEmail:
    def test_has_attachment(self, email_sim):
        email = email_sim.ransomware_email("victim@acme.com")
        assert len(email["attachments"]) > 0

    def test_attachment_suspicious(self, email_sim):
        email = email_sim.ransomware_email("victim@acme.com")
        indicators = email["suspicious_indicators"]
        assert any("attachment" in i.lower() for i in indicators)


class TestEmailSequence:
    def test_generates_mix(self, email_sim):
        emails = email_sim.generate_email_sequence(scenario="phishing", count=3)
        assert len(emails) > 3  # includes legitimate noise

    def test_contains_malicious(self, email_sim):
        emails = email_sim.generate_email_sequence(scenario="phishing", count=3)
        malicious = [e for e in emails if e.get("spf_result") == "fail"]
        assert len(malicious) > 0


class TestEmailLogIO:
    def test_save_and_load(self, email_sim, tmp_path):
        emails = [
            email_sim.generate_email("a@a.com", "b@b.com", "s1", "body1"),
            email_sim.generate_email("c@c.com", "d@d.com", "s2", "body2"),
        ]
        filepath = str(tmp_path / "emails.jsonl")
        email_sim.save_email_log(emails, filepath)

        loaded = EmailSimulator.load_email_log(filepath)
        assert len(loaded) == 2
        assert loaded[0]["subject"] == "s1"
