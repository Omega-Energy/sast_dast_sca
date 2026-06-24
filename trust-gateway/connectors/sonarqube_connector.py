"""
SonarQube connector — import analysis results.
"""
from typing import Optional

import requests


class SonarQubeConnector:
    """Client for SonarQube API interactions."""

    def __init__(self, base_url: str, token: str, config: Optional[dict] = None):
        self.base_url = base_url.rstrip("/")
        self.auth = (token, "") if token else None
        self.config = config or {}

    def get_projects(self, page_size: int = 50) -> list:
        """List projects in SonarQube."""
        url = f"{self.base_url}/api/projects/search"
        resp = requests.get(url, auth=self.auth, params={"ps": page_size}, timeout=15)
        resp.raise_for_status()
        return resp.json().get("components", [])

    def get_issues(self, project_key: str, severities: str = "CRITICAL,MAJOR", page_size: int = 100) -> list:
        """Get issues for a project filtered by severity."""
        url = f"{self.base_url}/api/issues/search"
        params = {
            "componentKeys": project_key,
            "severities": severities,
            "ps": page_size,
            "resolved": "false",
        }
        resp = requests.get(url, auth=self.auth, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get("issues", [])

    def get_measures(self, project_key: str, metrics: str = "bugs,vulnerabilities,code_smells,coverage") -> dict:
        """Get project measures/metrics."""
        url = f"{self.base_url}/api/measures/component"
        params = {"component": project_key, "metricKeys": metrics}
        resp = requests.get(url, auth=self.auth, params=params, timeout=15)
        resp.raise_for_status()
        component = resp.json().get("component", {})
        measures = {}
        for m in component.get("measures", []):
            measures[m["metric"]] = m.get("value", "0")
        return measures

    def get_quality_gate_status(self, project_key: str) -> dict:
        """Get quality gate status for a project."""
        url = f"{self.base_url}/api/qualitygates/project_status"
        params = {"projectKey": project_key}
        resp = requests.get(url, auth=self.auth, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get("projectStatus", {})

    def import_results(self, project_key: str) -> dict:
        """Import SonarQube results into our platform format."""
        issues = self.get_issues(project_key, severities="CRITICAL,MAJOR,MINOR")
        measures = self.get_measures(project_key)
        qg = self.get_quality_gate_status(project_key)

        findings = []
        for issue in issues:
            findings.append({
                "key": issue.get("key", ""),
                "file": issue.get("component", "").split(":")[-1],
                "line": issue.get("line", 0),
                "severity": issue.get("severity", "UNKNOWN"),
                "type": issue.get("type", ""),
                "message": issue.get("message", ""),
                "rule": issue.get("rule", ""),
                "effort": issue.get("effort", ""),
            })

        return {
            "findings": findings,
            "measures": measures,
            "quality_gate": qg.get("status", "UNKNOWN"),
        }
