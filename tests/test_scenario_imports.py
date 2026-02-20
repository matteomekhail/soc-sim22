"""Tests for scenario imports - parametrized across 18 implemented scenarios.

Each implemented scenario must:
  - Import without errors
  - Have a callable main() function
  - Import from wcace_lib (LogGenerator, SIEMClient at minimum)
  - Have a banner() function
  - Have an attack/ directory
  - Have a simulate_attack.py file
  - Use colorama
"""

import importlib
import importlib.util
import os
import sys

import pytest

from _shared import IMPLEMENTED_SCENARIOS, SCENARIOS_DIR


def script_path(scenario: str) -> str:
    return os.path.join(SCENARIOS_DIR, scenario, "attack", "simulate_attack.py")


def load_module(scenario: str):
    """Import a scenario's simulate_attack.py as a module."""
    path = script_path(scenario)
    name = f"scenario_{scenario.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("scenario", IMPLEMENTED_SCENARIOS)
class TestScenarioImports:
    """Each implemented scenario must be importable and well-structured."""

    def test_script_exists(self, scenario):
        assert os.path.isfile(script_path(scenario))

    def test_imports_without_error(self, scenario):
        load_module(scenario)

    def test_has_main(self, scenario):
        mod = load_module(scenario)
        assert hasattr(mod, "main"), f"No main() in {scenario}"
        assert callable(mod.main)

    def test_has_banner(self, scenario):
        mod = load_module(scenario)
        assert hasattr(mod, "banner"), f"No banner() in {scenario}"
        assert callable(mod.banner)

    def test_uses_log_generator(self, scenario):
        """The scenario should reference LogGenerator somewhere."""
        with open(script_path(scenario)) as f:
            source = f.read()
        assert "LogGenerator" in source

    def test_uses_siem_client(self, scenario):
        with open(script_path(scenario)) as f:
            source = f.read()
        assert "SIEMClient" in source

    def test_has_log_dir(self, scenario):
        with open(script_path(scenario)) as f:
            source = f.read()
        assert "LOG_DIR" in source or "log_dir" in source or "log_file" in source
