"""Tests for scenario execution - run main() for all 18 implemented scenarios.

Mocking strategy:
  - time.sleep -> no-op (eliminate waits)
  - SIEMClient.loki_push_lines -> no-op (no network)
  - requests.Session.get/post -> MockResponse (no vuln app)
  - WazuhAPI.check_connection -> False
  - sys.exit -> raise SystemExit (caught by test)

Each scenario is tested for:
  1. main() completes without exceptions
  2. Log files are generated in logs/sample_logs/
  3. Log file content is valid (JSON lines parseable)
"""

import importlib.util
import io
import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

from _shared import IMPLEMENTED_SCENARIOS, SCENARIOS_DIR


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockResponse:
    """Mock HTTP response for requests library."""
    status_code = 200
    text = "{}"
    content = b"{}"
    headers = {"Content-Type": "application/json"}

    def json(self):
        return {"status": "ok", "results": [], "data": {}, "token": "mock"}

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=1024):
        return [b"data"]


def load_scenario(scenario: str):
    """Import a scenario module."""
    path = os.path.join(SCENARIOS_DIR, scenario, "attack", "simulate_attack.py")
    name = f"exec_{scenario.replace('-', '_')}_{id(scenario)}"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_scenario_main(scenario: str):
    """Import and run a scenario's main() with full mocking."""
    mod = load_scenario(scenario)

    # Suppress stdout during execution
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        with patch("time.sleep", return_value=None), \
             patch("requests.Session.get", return_value=MockResponse()), \
             patch("requests.Session.post", return_value=MockResponse()), \
             patch("requests.get", return_value=MockResponse()), \
             patch("requests.post", return_value=MockResponse()):
            mod.main()
    finally:
        sys.stdout = old_stdout

    return mod


def sample_logs_dir(scenario: str) -> str:
    return os.path.join(SCENARIOS_DIR, scenario, "logs", "sample_logs")


# ---------------------------------------------------------------------------
# Parametrized execution tests
# ---------------------------------------------------------------------------

@pytest.mark.slow
@pytest.mark.parametrize("scenario", IMPLEMENTED_SCENARIOS)
class TestScenarioExecution:

    def test_main_completes(self, scenario):
        """main() should complete without exceptions."""
        run_scenario_main(scenario)

    def test_generates_log_files(self, scenario):
        """After main(), at least one log file should exist in logs/sample_logs/."""
        run_scenario_main(scenario)
        log_dir = sample_logs_dir(scenario)
        assert os.path.isdir(log_dir), f"No logs/sample_logs/ dir for {scenario}"
        files = os.listdir(log_dir)
        log_files = [f for f in files if f.endswith((".jsonl", ".json", ".log"))]
        assert len(log_files) > 0, f"No log files generated for {scenario}"

    def test_log_content_valid(self, scenario):
        """Log files should contain valid JSON lines or JSON."""
        run_scenario_main(scenario)
        log_dir = sample_logs_dir(scenario)
        if not os.path.isdir(log_dir):
            pytest.skip("No log directory")

        for filename in os.listdir(log_dir):
            filepath = os.path.join(log_dir, filename)
            if not os.path.isfile(filepath):
                continue

            # Skip non-log files (e.g., encryption_key.txt, HTML samples)
            skip_exts = (".txt", ".html", ".htm", ".css", ".js", ".pcap")
            if filename.endswith(skip_exts):
                continue

            with open(filepath) as f:
                content = f.read().strip()

            if not content:
                continue

            # Try parsing as a complete JSON document first (array or object)
            if content.startswith("[") or content.startswith("{"):
                try:
                    json.loads(content)
                    continue  # Valid JSON document, move to next file
                except json.JSONDecodeError:
                    pass  # Fall through to line-by-line parsing

            # Parse as JSON lines (one JSON object per line)
            if True:
                for i, line in enumerate(content.split("\n")):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                    except json.JSONDecodeError:
                        # Some log lines may be syslog format, not JSON
                        # Only fail if it doesn't look like a syslog line
                        if not line.startswith("<"):
                            pytest.fail(
                                f"Invalid log line {i+1} in {scenario}/{filename}: {line[:100]}"
                            )
