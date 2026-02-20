"""Tests for wcace_lib.wazuh_api - init only (no live API)."""

import pytest

from wcace_lib.wazuh_api import WazuhAPI
from wcace_lib.constants import WAZUH_API_URL


class TestWazuhAPIInit:
    def test_default_url(self, wazuh):
        assert wazuh.url == WAZUH_API_URL

    def test_custom_url_strips_slash(self):
        api = WazuhAPI(url="https://example.com/")
        assert api.url == "https://example.com"

    def test_initial_token_none(self, wazuh):
        assert wazuh._token is None

    def test_check_connection_returns_false_offline(self, wazuh):
        # No live Wazuh available, should return False
        assert wazuh.check_connection() is False
