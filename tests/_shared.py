"""Shared constants for the WCACE test suite.

Imported by test modules that need scenario lists and paths.
Not a conftest (which pytest auto-loads but can't be imported normally).
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "scenarios")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

ALL_SCENARIOS = [
    "01-apt-deepfake-ceo",
    "02-domain-spoofing-data-theft",
    "03-financial-transaction-fraud",
    "04-insider-threat-data-exfiltration",
    "05-apt-vulnerability-exploitation",
    "06-dark-web-monitoring",
    "07-zero-day-lateral-movement",
    "08-phishing-ransomware",
    "09-insider-data-theft",
    "10-apt-remote-access-trojan",
    "11-botnet-detection",
    "12-watering-hole-attack",
    "13-sql-injection-database",
    "14-credential-stuffing",
    "15-usb-malware-propagation",
    "16-privilege-escalation",
    "17-dns-tunnelling",
    "18-drive-by-download",
    "19-cryptojacking",
    "20-ransomware-exploit-kit",
    "21-domain-spoofing-vendor",
    "22-api-vulnerability-exploitation",
]

TIER3_DEMO_ONLY = [
    "01-apt-deepfake-ceo",
    "03-financial-transaction-fraud",
    "06-dark-web-monitoring",
    "15-usb-malware-propagation",
]

IMPLEMENTED_SCENARIOS = [s for s in ALL_SCENARIOS if s not in TIER3_DEMO_ONLY]
