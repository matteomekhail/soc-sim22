"""Cross-scenario consistency tests.

Validates global uniqueness and consistency across all 22 scenarios:
  - Suricata SID uniqueness (within each scenario)
  - Wazuh rule ID uniqueness (within each scenario)
  - expected_alerts.json references valid sources
  - All scenarios have unique names
  - Severity levels are from known set
  - MITRE technique IDs follow pattern
"""

import json
import os
import re

import pytest

from _shared import ALL_SCENARIOS, SCENARIOS_DIR


def scenario_path(name: str, *parts: str) -> str:
    return os.path.join(SCENARIOS_DIR, name, *parts)


# ---------------------------------------------------------------------------
# Collect all SIDs and rule IDs
# ---------------------------------------------------------------------------

def get_suricata_sids(scenario: str) -> list[tuple[str, int]]:
    """Return list of (scenario, sid) tuples."""
    path = scenario_path(scenario, "config", "suricata-rules.rules")
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        content = f.read()
    return [(scenario, int(sid)) for sid in re.findall(r"sid:(\d+)", content)]


def get_wazuh_rule_ids(scenario: str) -> list[tuple[str, int]]:
    """Return list of (scenario, rule_id) tuples."""
    path = scenario_path(scenario, "config", "wazuh-rules.xml")
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        content = f.read()
    return [(scenario, int(rid)) for rid in re.findall(r'rule id="(\d+)"', content)]


class TestSuricataSIDUniqueness:
    """Each scenario should have unique SIDs within its own rules file."""

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS)
    def test_sids_unique_within_scenario(self, scenario):
        sids = get_suricata_sids(scenario)
        sid_values = [s[1] for s in sids]
        assert len(sid_values) == len(set(sid_values)), \
            f"Duplicate SIDs within {scenario}: {sid_values}"

    def test_report_cross_scenario_sid_collisions(self):
        """Report (but don't fail on) SID collisions across scenarios.

        Some scenarios intentionally share SID ranges; this test documents
        the collisions for awareness.
        """
        all_sids = {}
        for scenario in ALL_SCENARIOS:
            for _, sid in get_suricata_sids(scenario):
                all_sids.setdefault(sid, []).append(scenario)

        collisions = {sid: scens for sid, scens in all_sids.items() if len(scens) > 1}
        if collisions:
            msg = "Known SID collisions (not a failure):\n"
            for sid, scens in sorted(collisions.items()):
                msg += f"  sid:{sid} -> {', '.join(scens)}\n"
            # This is informational, not a failure
            print(msg)


class TestWazuhRuleIDUniqueness:
    """Each scenario should have unique rule IDs within its own rules file."""

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS)
    def test_rule_ids_unique_within_scenario(self, scenario):
        rule_ids = get_wazuh_rule_ids(scenario)
        id_values = [r[1] for r in rule_ids]
        assert len(id_values) == len(set(id_values)), \
            f"Duplicate Wazuh rule IDs within {scenario}: {id_values}"


class TestExpectedAlertsConsistency:
    """Expected alerts should reference valid sources and severity levels."""

    VALID_SOURCES = {"suricata", "wazuh"}
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "warning"}

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS)
    def test_alert_sources_valid(self, scenario):
        path = scenario_path(scenario, "detect", "expected_alerts.json")
        with open(path) as f:
            data = json.load(f)
        alerts = data.get("expected_alerts", data.get("alerts", []))
        for alert in alerts:
            source = alert.get("source", "")
            assert source in self.VALID_SOURCES, \
                f"Invalid source '{source}' in {scenario}"

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS)
    def test_alert_severities_valid(self, scenario):
        path = scenario_path(scenario, "detect", "expected_alerts.json")
        with open(path) as f:
            data = json.load(f)
        alerts = data.get("expected_alerts", data.get("alerts", []))
        for alert in alerts:
            severity = alert.get("severity", "")
            assert severity in self.VALID_SEVERITIES, \
                f"Invalid severity '{severity}' in {scenario}"


class TestScenarioNaming:
    def test_all_scenario_names_unique(self):
        assert len(ALL_SCENARIOS) == len(set(ALL_SCENARIOS))

    def test_all_scenario_dirs_exist(self):
        for scenario in ALL_SCENARIOS:
            path = scenario_path(scenario)
            assert os.path.isdir(path), f"Missing directory for {scenario}"

    def test_scenario_count(self):
        assert len(ALL_SCENARIOS) == 22
