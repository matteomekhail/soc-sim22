"""Tests for wcace_lib.siem_client - file I/O round-trip (no live SIEM)."""

import os
import tempfile

import pytest

from wcace_lib.siem_client import SIEMClient


class TestWriteReadRoundTrip:
    """File-based log I/O should round-trip correctly."""

    def test_write_and_read(self, tmp_path):
        filepath = str(tmp_path / "test.log")
        logs = ["line1", "line2", "line3"]
        SIEMClient.write_logs_to_file(logs, filepath)
        result = SIEMClient.read_logs_from_file(filepath)
        assert result == logs

    def test_write_creates_file(self, tmp_path):
        filepath = str(tmp_path / "new.log")
        SIEMClient.write_logs_to_file(["hello"], filepath)
        assert os.path.isfile(filepath)

    def test_read_skips_blank_lines(self, tmp_path):
        filepath = str(tmp_path / "blanks.log")
        with open(filepath, "w") as f:
            f.write("line1\n\n\nline2\n")
        result = SIEMClient.read_logs_from_file(filepath)
        assert result == ["line1", "line2"]

    def test_empty_list_creates_empty_file(self, tmp_path):
        filepath = str(tmp_path / "empty.log")
        SIEMClient.write_logs_to_file([], filepath)
        result = SIEMClient.read_logs_from_file(filepath)
        assert result == []


class TestSIEMClientInit:
    def test_default_urls(self, siem):
        assert "localhost" in siem.wazuh_url
        assert "localhost" in siem.loki_url

    def test_custom_urls(self):
        client = SIEMClient(wazuh_url="https://custom:55000", loki_url="http://custom:3100")
        assert client.wazuh_url == "https://custom:55000"
        assert client.loki_url == "http://custom:3100"

    def test_initial_token_none(self, siem):
        assert siem._wazuh_token is None


class TestSyslogBatch:
    """send_syslog_batch should iterate over all messages."""

    def test_batch_calls_send(self, siem, mocker):
        mock_send = mocker.patch.object(siem, "send_syslog")
        mocker.patch("time.sleep")
        siem.send_syslog_batch(["msg1", "msg2", "msg3"])
        assert mock_send.call_count == 3
