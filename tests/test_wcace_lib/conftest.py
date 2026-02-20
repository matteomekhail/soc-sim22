"""Fixtures specific to wcace_lib tests."""

import pytest

from wcace_lib.log_generator import LogGenerator
from wcace_lib.siem_client import SIEMClient
from wcace_lib.email_sim import EmailSimulator
from wcace_lib.network_sim import NetworkSimulator
from wcace_lib.wazuh_api import WazuhAPI


@pytest.fixture
def log_gen():
    """Fresh LogGenerator instance."""
    return LogGenerator(source_host="test-host", facility="auth")


@pytest.fixture
def siem():
    """SIEMClient instance (offline mode -- no live SIEM)."""
    return SIEMClient()


@pytest.fixture
def email_sim():
    """EmailSimulator with default domain."""
    return EmailSimulator()


@pytest.fixture
def net_sim():
    """NetworkSimulator without scapy."""
    return NetworkSimulator(use_scapy=False)


@pytest.fixture
def wazuh():
    """WazuhAPI instance (no live connection)."""
    return WazuhAPI()
