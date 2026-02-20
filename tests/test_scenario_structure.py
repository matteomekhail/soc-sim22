"""Tests for scenario file structure - parametrized across all 22 scenarios.

Each scenario must have:
  - README.md
  - config/suricata-rules.rules (non-empty, valid sid: lines)
  - config/wazuh-rules.xml (non-empty, valid XML with rule ids)
  - detect/expected_alerts.json (valid JSON with required fields)
  - respond/playbook.md OR respond/containment.py
"""

import json
import os
import re
import xml.etree.ElementTree as ET

import pytest

from _shared import ALL_SCENARIOS, SCENARIOS_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scenario_path(name: str, *parts: str) -> str:
    return os.path.join(SCENARIOS_DIR, name, *parts)


def load_expected_alerts(name: str) -> list[dict]:
    """Load the alerts list from expected_alerts.json, handling key variants."""
    path = scenario_path(name, "detect", "expected_alerts.json")
    with open(path) as f:
        data = json.load(f)
    # Some scenarios use "alerts" key, others use "expected_alerts"
    return data.get("expected_alerts", data.get("alerts", []))


# ---------------------------------------------------------------------------
# Parametrized tests across all 22 scenarios
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
class TestScenarioStructure:
    """Each scenario directory must follow the standard layout."""

    @pytest.mark.structure
    def test_readme_exists(self, scenario):
        readme = scenario_path(scenario, "README.md")
        assert os.path.isfile(readme), f"Missing README.md for {scenario}"

    @pytest.mark.structure
    def test_readme_non_empty(self, scenario):
        readme = scenario_path(scenario, "README.md")
        assert os.path.getsize(readme) > 50, f"README too small for {scenario}"

    @pytest.mark.structure
    def test_suricata_rules_exist(self, scenario):
        rules = scenario_path(scenario, "config", "suricata-rules.rules")
        assert os.path.isfile(rules), f"Missing suricata-rules.rules for {scenario}"

    @pytest.mark.structure
    def test_suricata_rules_have_sids(self, scenario):
        rules = scenario_path(scenario, "config", "suricata-rules.rules")
        with open(rules) as f:
            content = f.read()
        sids = re.findall(r"sid:(\d+)", content)
        assert len(sids) > 0, f"No sid: found in suricata-rules for {scenario}"

    @pytest.mark.structure
    def test_wazuh_rules_exist(self, scenario):
        rules = scenario_path(scenario, "config", "wazuh-rules.xml")
        assert os.path.isfile(rules), f"Missing wazuh-rules.xml for {scenario}"

    @pytest.mark.structure
    def test_wazuh_rules_valid_xml(self, scenario):
        rules = scenario_path(scenario, "config", "wazuh-rules.xml")
        with open(rules) as f:
            content = f.read()
        # Wazuh rules may not have a single root, wrap in <root>
        wrapped = f"<root>{content}</root>"
        ET.fromstring(wrapped)

    @pytest.mark.structure
    def test_wazuh_rules_have_rule_ids(self, scenario):
        rules = scenario_path(scenario, "config", "wazuh-rules.xml")
        with open(rules) as f:
            content = f.read()
        ids = re.findall(r'rule id="(\d+)"', content)
        assert len(ids) > 0, f"No rule ids in wazuh-rules.xml for {scenario}"

    @pytest.mark.structure
    def test_expected_alerts_exist(self, scenario):
        alerts = scenario_path(scenario, "detect", "expected_alerts.json")
        assert os.path.isfile(alerts), f"Missing expected_alerts.json for {scenario}"

    @pytest.mark.structure
    def test_expected_alerts_valid_json(self, scenario):
        alerts_path = scenario_path(scenario, "detect", "expected_alerts.json")
        with open(alerts_path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    @pytest.mark.structure
    def test_expected_alerts_have_required_fields(self, scenario):
        alerts = load_expected_alerts(scenario)
        for alert in alerts:
            assert "source" in alert, f"Alert missing 'source' in {scenario}"
            assert "description" in alert, f"Alert missing 'description' in {scenario}"
            assert "severity" in alert, f"Alert missing 'severity' in {scenario}"

    @pytest.mark.structure
    def test_response_materials_exist(self, scenario):
        playbook = scenario_path(scenario, "respond", "playbook.md")
        containment = scenario_path(scenario, "respond", "containment.py")
        assert os.path.isfile(playbook) or os.path.isfile(containment), \
            f"Missing playbook.md or containment.py for {scenario}"
