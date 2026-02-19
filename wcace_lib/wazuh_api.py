"""Wazuh API client for querying alerts and managing agents."""

import json
from typing import Optional

import requests
import urllib3

from .constants import WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPI:
    """High-level Wazuh API client for SOC scenarios."""

    def __init__(self, url: str = WAZUH_API_URL,
                 user: str = WAZUH_API_USER, password: str = WAZUH_API_PASS):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self._token: Optional[str] = None

    def authenticate(self) -> str:
        """Authenticate and get JWT token."""
        resp = requests.post(
            f"{self.url}/security/user/authenticate",
            auth=(self.user, self.password),
            verify=False,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    def _headers(self) -> dict:
        if not self._token:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        resp = requests.get(
            f"{self.url}{endpoint}",
            headers=self._headers(),
            params=params,
            verify=False,
        )
        if resp.status_code == 401:
            self.authenticate()
            resp = requests.get(
                f"{self.url}{endpoint}",
                headers=self._headers(),
                params=params,
                verify=False,
            )
        resp.raise_for_status()
        return resp.json()

    # === Agents ===

    def list_agents(self, status: Optional[str] = None) -> list[dict]:
        params = {}
        if status:
            params["status"] = status
        result = self._get("/agents", params)
        return result.get("data", {}).get("affected_items", [])

    def get_agent(self, agent_id: str) -> dict:
        result = self._get(f"/agents/{agent_id}")
        return result.get("data", {}).get("affected_items", [{}])[0]

    # === Alerts ===

    def get_alerts(self, limit: int = 20, offset: int = 0,
                   search: Optional[str] = None,
                   sort: str = "-timestamp") -> list[dict]:
        params = {"limit": limit, "offset": offset, "sort": sort}
        if search:
            params["search"] = search
        result = self._get("/alerts", params)
        return result.get("data", {}).get("affected_items", [])

    def get_alerts_by_rule(self, rule_id: int, limit: int = 20) -> list[dict]:
        return self.get_alerts(limit=limit, search=str(rule_id))

    def get_alerts_summary(self) -> dict:
        """Get a summary of recent alerts grouped by rule."""
        alerts = self.get_alerts(limit=100)
        summary = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in summary:
                summary[rule_id] = {
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                    "count": 0,
                }
            summary[rule_id]["count"] += 1
        return summary

    # === Rules ===

    def get_rules(self, limit: int = 500) -> list[dict]:
        result = self._get("/rules", {"limit": limit})
        return result.get("data", {}).get("affected_items", [])

    def get_rule(self, rule_id: int) -> dict:
        result = self._get(f"/rules/{rule_id}")
        items = result.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    # === Syscheck (FIM) ===

    def get_syscheck_events(self, agent_id: str = "001",
                            limit: int = 20) -> list[dict]:
        result = self._get(f"/syscheck/{agent_id}", {"limit": limit})
        return result.get("data", {}).get("affected_items", [])

    # === Vulnerability detection ===

    def get_vulnerabilities(self, agent_id: str = "001",
                            limit: int = 20) -> list[dict]:
        result = self._get(f"/vulnerability/{agent_id}", {"limit": limit})
        return result.get("data", {}).get("affected_items", [])

    # === Utility ===

    def check_connection(self) -> bool:
        """Check if Wazuh API is reachable."""
        try:
            self.authenticate()
            return True
        except Exception:
            return False

    def wait_for_alert(self, search: str, timeout: int = 60,
                       poll_interval: int = 5) -> Optional[dict]:
        """Poll Wazuh for an alert matching a search string."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            alerts = self.get_alerts(search=search, limit=5)
            if alerts:
                return alerts[0]
            time.sleep(poll_interval)
        return None
