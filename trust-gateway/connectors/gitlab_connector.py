"""
GitLab connector — webhook handler and API integration.
"""
import json
from typing import Optional

import requests


class GitLabConnector:
    """Client for GitLab API interactions."""

    def __init__(self, base_url: str, token: str, config: Optional[dict] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.config = config or {}
        self.headers = {"PRIVATE-TOKEN": token} if token else {}

    def get_projects(self, per_page: int = 20) -> list:
        """List accessible projects."""
        url = f"{self.base_url}/api/v4/projects"
        resp = requests.get(
            url, headers=self.headers, params={"per_page": per_page}, timeout=15
        )
        resp.raise_for_status()
        return resp.json()

    def get_project(self, project_id: int) -> dict:
        """Get a single project by ID."""
        url = f"{self.base_url}/api/v4/projects/{project_id}"
        resp = requests.get(url, headers=self.headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def get_pipelines(self, project_id: int, per_page: int = 10) -> list:
        """List recent pipelines for a project."""
        url = f"{self.base_url}/api/v4/projects/{project_id}/pipelines"
        resp = requests.get(
            url, headers=self.headers, params={"per_page": per_page}, timeout=15
        )
        resp.raise_for_status()
        return resp.json()

    def trigger_pipeline(self, project_id: int, ref: str = "main", variables: dict = None) -> dict:
        """Trigger a new pipeline for a project."""
        url = f"{self.base_url}/api/v4/projects/{project_id}/pipeline"
        payload = {"ref": ref}
        if variables:
            payload["variables"] = [
                {"key": k, "value": v} for k, v in variables.items()
            ]
        resp = requests.post(url, headers=self.headers, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def register_webhook(self, project_id: int, webhook_url: str, events: list = None) -> dict:
        """Register a webhook on a GitLab project."""
        if events is None:
            events = ["push_events", "merge_requests_events"]
        url = f"{self.base_url}/api/v4/projects/{project_id}/hooks"
        payload = {"url": webhook_url}
        for event in events:
            payload[event] = True
        resp = requests.post(url, headers=self.headers, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def post_commit_status(
        self, project_id: int, sha: str, state: str, description: str, target_url: str = ""
    ) -> dict:
        """Post a commit status (for pipeline integration)."""
        url = f"{self.base_url}/api/v4/projects/{project_id}/statuses/{sha}"
        payload = {
            "state": state,  # pending | running | success | failed | canceled
            "description": description,
            "name": "security-scan",
        }
        if target_url:
            payload["target_url"] = target_url
        resp = requests.post(url, headers=self.headers, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()
