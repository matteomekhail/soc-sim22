"""Tests for wcace_lib.network_sim - log generation (no actual network I/O)."""

import json

import pytest

from wcace_lib.network_sim import NetworkSimulator


class TestInit:
    def test_default_no_scapy(self, net_sim):
        assert net_sim.use_scapy is False
        assert net_sim._scapy_available is False


class TestNormalTrafficLog:
    def test_returns_list(self):
        logs = NetworkSimulator.generate_normal_traffic_log(count=10)
        assert isinstance(logs, list)
        assert len(logs) == 10

    def test_logs_are_json(self):
        logs = NetworkSimulator.generate_normal_traffic_log(count=5)
        for entry in logs:
            data = json.loads(entry)
            assert data["event_type"] == "web_access"

    def test_default_count(self):
        logs = NetworkSimulator.generate_normal_traffic_log()
        assert len(logs) == 100


class TestLateralMovementLog:
    def test_returns_logs(self):
        targets = ["10.0.0.100", "10.0.0.101"]
        logs = NetworkSimulator.generate_lateral_movement_log("10.0.0.50", targets)
        assert isinstance(logs, list)
        # 3 logs per target (firewall, auth, firewall)
        assert len(logs) == 6

    def test_logs_reference_targets(self):
        targets = ["10.0.0.200"]
        logs = NetworkSimulator.generate_lateral_movement_log("10.0.0.50", targets)
        combined = " ".join(logs)
        assert "10.0.0.200" in combined
