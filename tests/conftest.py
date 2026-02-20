"""Global fixtures for the WCACE test suite."""

import os
import shutil
import sys

import pytest

# ---------------------------------------------------------------------------
# Project path setup
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "scenarios")

# Ensure project root is importable
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure tests/ dir is importable (for _shared module)
TESTS_DIR = os.path.dirname(__file__)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def add_project_to_path():
    """Ensure the project root is on sys.path for the entire test session."""
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    if TESTS_DIR not in sys.path:
        sys.path.insert(0, TESTS_DIR)
    yield


SANDBOX_ROOT = "/tmp/wcace-sandbox"


@pytest.fixture(autouse=True)
def cleanup_sandbox():
    """Remove the sandbox directory after each test to avoid side-effects."""
    yield
    if os.path.exists(SANDBOX_ROOT):
        shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)


@pytest.fixture
def scenario_dir():
    """Return a helper that resolves a scenario directory path."""
    def _resolve(scenario_name: str) -> str:
        return os.path.join(SCENARIOS_DIR, scenario_name)
    return _resolve
