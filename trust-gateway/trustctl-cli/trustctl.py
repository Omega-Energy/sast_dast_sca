#!/usr/bin/env python3
"""
trustctl — CLI for managing the Security Platform.
"""
import json
import sys
from typing import Optional

import typer
import requests

app = typer.Typer(name="trustctl", help="Security Platform CLI")
scans_app = typer.Typer(help="Manage scans")
projects_app = typer.Typer(help="Manage projects")
connectors_app = typer.Typer(help="Manage connectors")

app.add_typer(scans_app, name="scan")
app.add_typer(projects_app, name="project")
app.add_typer(connectors_app, name="connector")

BASE_URL = "http://localhost:8000"


def _api(method: str, path: str, data: dict = None) -> dict:
    """Make an API call to the platform."""
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            resp = requests.get(url, timeout=30)
        elif method == "POST":
            resp = requests.post(url, json=data, timeout=60)
        elif method == "PUT":
            resp = requests.put(url, json=data, timeout=30)
        elif method == "DELETE":
            resp = requests.delete(url, timeout=30)
        else:
            typer.echo(f"Unknown method: {method}", err=True)
            raise typer.Exit(1)

        if resp.status_code >= 400:
            typer.echo(f"Error {resp.status_code}: {resp.text}", err=True)
            raise typer.Exit(1)
        return resp.json()
    except requests.ConnectionError:
        typer.echo(f"Cannot connect to {BASE_URL}. Is the platform running?", err=True)
        raise typer.Exit(1)


# ── Scans ─────────────────────────────────────────────────────────────────────

@scans_app.command("run")
def scan_run(
    repo: str = typer.Argument(..., help="Repository URL to scan"),
    branch: str = typer.Option("main", "--branch", "-b", help="Branch to scan"),
    token: str = typer.Option("", "--token", "-t", help="GitHub/GitLab token"),
):
    """Run a new security scan."""
    typer.echo(f"Starting scan: {repo} (branch: {branch})")
    result = _api("POST", "/api/scans", {"repo_url": repo, "branch": branch, "github_token": token})
    typer.echo(f"Scan #{result['id']} created — status: {result['status']}")
    typer.echo(f"Monitor: {BASE_URL}/scans/{result['id']}")


@scans_app.command("status")
def scan_status(scan_id: int = typer.Argument(..., help="Scan ID")):
    """Check scan status."""
    result = _api("GET", f"/api/scans/{scan_id}")
    typer.echo(f"Scan #{result['id']}: {result['status']}")
    typer.echo(f"  Repo: {result['repo_url']} ({result['branch']})")
    if result["status"] == "done":
        typer.echo(f"  Duration: {result['duration_sec']:.1f}s")
        typer.echo(f"  Findings: {result['total_count']} total")
        typer.echo(f"    Bandit: {result['bandit_count']}")
        typer.echo(f"    Semgrep: {result['semgrep_count']}")
        typer.echo(f"    pip-audit: {result['pip_audit_count']}")
        typer.echo(f"    Gitleaks: {result['gitleaks_count']}")
        typer.echo(f"    YARA: {result['yara_count']}")
        typer.echo(f"    DAST: {result['dast_count']}")


@scans_app.command("list")
def scan_list():
    """List all scans."""
    results = _api("GET", "/api/scans")
    if not results:
        typer.echo("No scans found.")
        return
    typer.echo(f"{'ID':<5} {'Status':<10} {'Repo':<30} {'Findings':<10} {'Created'}")
    typer.echo("-" * 80)
    for s in results[:20]:
        typer.echo(
            f"{s['id']:<5} {s['status']:<10} {s['repo_name']:<30} "
            f"{s['total_count']:<10} {s['created_at'][:19]}"
        )


@scans_app.command("results")
def scan_results(
    scan_id: int = typer.Argument(..., help="Scan ID"),
    output: str = typer.Option("", "--output", "-o", help="Output file (JSON)"),
):
    """Get scan results."""
    result = _api("GET", f"/api/scans/{scan_id}/results")
    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        typer.echo(f"Results saved to {output}")
    else:
        typer.echo(json.dumps(result, indent=2, ensure_ascii=False))


# ── Projects ──────────────────────────────────────────────────────────────────

@projects_app.command("list")
def project_list():
    """List all projects."""
    results = _api("GET", "/api/projects")
    if not results:
        typer.echo("No projects found.")
        return
    typer.echo(f"{'ID':<5} {'Name':<25} {'Repo URL':<40} {'Active'}")
    typer.echo("-" * 80)
    for p in results:
        typer.echo(f"{p['id']:<5} {p['name']:<25} {p['repo_url']:<40} {p['is_active']}")


@projects_app.command("create")
def project_create(
    name: str = typer.Argument(..., help="Project name"),
    repo_url: str = typer.Option("", "--repo", "-r", help="Repository URL"),
    branch: str = typer.Option("main", "--branch", "-b", help="Default branch"),
    description: str = typer.Option("", "--desc", "-d", help="Description"),
):
    """Create a new project."""
    result = _api("POST", "/api/projects", {
        "name": name, "repo_url": repo_url, "default_branch": branch, "description": description
    })
    typer.echo(f"Project #{result['id']} '{result['name']}' created.")


# ── Connectors ────────────────────────────────────────────────────────────────

@connectors_app.command("list")
def connector_list():
    """List all connectors."""
    results = _api("GET", "/api/connectors")
    if not results:
        typer.echo("No connectors configured.")
        return
    typer.echo(f"{'ID':<5} {'Name':<20} {'Type':<15} {'URL':<30} {'Status'}")
    typer.echo("-" * 80)
    for c in results:
        typer.echo(f"{c['id']:<5} {c['name']:<20} {c['connector_type']:<15} {c['base_url']:<30} {c['status']}")


@connectors_app.command("add")
def connector_add(
    name: str = typer.Argument(..., help="Connector name"),
    connector_type: str = typer.Argument(..., help="Type: gitlab|sonarqube|cuckoo|assemblyline"),
    base_url: str = typer.Option("", "--url", "-u", help="Base URL"),
    token: str = typer.Option("", "--token", "-t", help="API token"),
):
    """Add a new connector."""
    if connector_type not in ("gitlab", "sonarqube", "cuckoo", "assemblyline"):
        typer.echo("Invalid type. Use: gitlab, sonarqube, cuckoo, assemblyline", err=True)
        raise typer.Exit(1)
    result = _api("POST", "/api/connectors", {
        "name": name, "connector_type": connector_type, "base_url": base_url, "api_token": token
    })
    typer.echo(f"Connector #{result['id']} '{result['name']}' ({result['connector_type']}) added.")


@connectors_app.command("test")
def connector_test(connector_id: int = typer.Argument(..., help="Connector ID")):
    """Test connector connectivity."""
    result = _api("POST", f"/api/connectors/{connector_id}/test")
    if result.get("ok"):
        typer.echo(f"✓ Connection successful: {result.get('message', '')}")
    else:
        typer.echo(f"✗ Connection failed: {result.get('message', '')}", err=True)


# ── Main ──────────────────────────────────────────────────────────────────────

@app.command("status")
def platform_status():
    """Show platform status."""
    try:
        stats = _api("GET", "/api/stats")
        typer.echo("Security Platform Status")
        typer.echo("=" * 40)
        typer.echo(f"  Total scans: {stats['total_scans']}")
        typer.echo(f"  Completed: {stats['done']}")
        typer.echo(f"  Failed: {stats['failed']}")
        typer.echo(f"  Running: {stats['running']}")
        typer.echo(f"  Total findings: {stats['total_findings']}")
    except SystemExit:
        pass


@app.callback()
def main(
    url: str = typer.Option("http://localhost:8000", "--url", envvar="TRUSTCTL_URL", help="Platform URL"),
):
    """Security Platform CLI — manage scans, projects, and connectors."""
    global BASE_URL
    BASE_URL = url.rstrip("/")


if __name__ == "__main__":
    app()
