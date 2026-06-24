"""
Base connector interface and test_connection dispatcher.
"""
import json
from typing import Tuple

import requests


async def test_connection(connector) -> Tuple[bool, str]:
    """Test connectivity to the external system. Returns (success, message)."""
    handlers = {
        "gitlab": _test_gitlab,
        "sonarqube": _test_sonarqube,
        "cuckoo": _test_cuckoo,
        "assemblyline": _test_assemblyline,
    }
    handler = handlers.get(connector.connector_type)
    if not handler:
        return False, f"Unknown connector type: {connector.connector_type}"

    try:
        return handler(connector.base_url, connector.api_token, connector.config_json)
    except Exception as e:
        return False, f"Connection failed: {str(e)}"


def _test_gitlab(base_url: str, token: str, config_json: str) -> Tuple[bool, str]:
    """Test GitLab API connectivity."""
    if not base_url:
        return False, "base_url is required"
    headers = {}
    if token:
        headers["PRIVATE-TOKEN"] = token
    url = f"{base_url.rstrip('/')}/api/v4/version"
    resp = requests.get(url, headers=headers, timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        return True, f"GitLab {data.get('version', 'unknown')} connected"
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


def _test_sonarqube(base_url: str, token: str, config_json: str) -> Tuple[bool, str]:
    """Test SonarQube API connectivity."""
    if not base_url:
        return False, "base_url is required"
    url = f"{base_url.rstrip('/')}/api/system/status"
    auth = (token, "") if token else None
    resp = requests.get(url, auth=auth, timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        return True, f"SonarQube status: {data.get('status', 'unknown')}"
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


def _test_cuckoo(base_url: str, token: str, config_json: str) -> Tuple[bool, str]:
    """Test Cuckoo Sandbox API connectivity."""
    if not base_url:
        return False, "base_url is required"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{base_url.rstrip('/')}/cuckoo/status"
    resp = requests.get(url, headers=headers, timeout=10)
    if resp.status_code == 200:
        return True, "Cuckoo connected"
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


def _test_assemblyline(base_url: str, token: str, config_json: str) -> Tuple[bool, str]:
    """Test AssemblyLine API connectivity."""
    if not base_url:
        return False, "base_url is required"
    headers = {}
    if token:
        headers["X-APIKEY"] = token
    config = json.loads(config_json) if config_json else {}
    user = config.get("user", "admin")
    url = f"{base_url.rstrip('/')}/api/v4/user/whoami/"
    resp = requests.get(url, headers=headers, timeout=10)
    if resp.status_code == 200:
        return True, "AssemblyLine connected"
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
