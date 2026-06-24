#!/usr/bin/env python3
"""
Source scanner entrypoint.
Runs Bandit, Semgrep, pip-audit, and Gitleaks on a target directory.
Outputs unified JSON report to stdout or a file.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_cmd(cmd: list[str], cwd: str = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def scan_bandit(target: str) -> dict:
    """Run Bandit SAST scanner."""
    r = run_cmd(["bandit", "-r", target, "-f", "json", "-ll", "--exit-zero"])
    try:
        data = json.loads(r.stdout)
        findings = []
        for item in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "file": item.get("filename", ""),
                "line": item.get("line_number", 0),
                "severity": item.get("issue_severity", "UNKNOWN"),
                "confidence": item.get("issue_confidence", "UNKNOWN"),
                "title": item.get("test_name", ""),
                "detail": item.get("issue_text", ""),
                "cwe": item.get("issue_cwe", {}).get("id", ""),
            })
        return {"tool": "bandit", "findings": findings}
    except Exception as e:
        return {"tool": "bandit", "findings": [], "error": str(e)}


def scan_semgrep(target: str, rules_dir: str = "/opt/rules") -> dict:
    """Run Semgrep with custom and community rules."""
    configs = ["p/python", "p/secrets"]
    rules_path = Path(rules_dir)
    if rules_path.exists() and any(rules_path.rglob("*.yml")):
        configs.append(str(rules_path))

    cmd = ["semgrep"] + [arg for c in configs for arg in ("--config", c)]
    cmd += ["--json", "--no-git-ignore", "--quiet",
            "--exclude", "venv", "--exclude", ".venv",
            "--exclude", "node_modules", "--exclude", ".git",
            "--timeout", "60", target]

    r = run_cmd(cmd)
    try:
        data = json.loads(r.stdout)
        findings = []
        for item in data.get("results", []):
            findings.append({
                "tool": "semgrep",
                "file": item.get("path", ""),
                "line": item.get("start", {}).get("line", 0),
                "severity": item.get("extra", {}).get("severity", "INFO"),
                "title": item.get("check_id", ""),
                "detail": item.get("extra", {}).get("message", ""),
            })
        return {"tool": "semgrep", "findings": findings}
    except Exception as e:
        return {"tool": "semgrep", "findings": [], "error": str(e)}


def scan_pip_audit(target: str) -> dict:
    """Run pip-audit SCA scanner."""
    target_path = Path(target)
    req_files = list(target_path.rglob("requirements*.txt"))
    if not req_files:
        return {"tool": "pip-audit", "findings": [], "skipped": "no requirements files found"}

    req_args = []
    for rf in req_files[:5]:
        req_args += ["-r", str(rf)]

    cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"] + req_args
    r = run_cmd(cmd)
    try:
        data = json.loads(r.stdout)
        findings = []
        for pkg in data.get("dependencies", []):
            for vuln in pkg.get("vulns", []):
                findings.append({
                    "tool": "pip-audit",
                    "package": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "severity": "HIGH",
                    "vuln_id": vuln.get("id", ""),
                    "detail": vuln.get("description", ""),
                    "fix": ", ".join(vuln.get("fix_versions", [])) or "No fix",
                })
        return {"tool": "pip-audit", "findings": findings}
    except Exception as e:
        return {"tool": "pip-audit", "findings": [], "error": str(e)}


def scan_gitleaks(target: str) -> dict:
    """Run Gitleaks secrets scanner."""
    out_file = "/tmp/gitleaks_report.json"
    run_cmd([
        "gitleaks", "detect", "--source", target,
        "--report-format", "json", "--report-path", out_file,
        "--no-banner", "--exit-code", "0"
    ])
    try:
        report_path = Path(out_file)
        raw = json.loads(report_path.read_text()) if report_path.exists() else []
        report_path.unlink(missing_ok=True)
        findings = []
        for item in (raw or []):
            match_str = item.get("Match", "")
            findings.append({
                "tool": "gitleaks",
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "severity": "HIGH",
                "rule": item.get("RuleID", ""),
                "detail": item.get("Description", ""),
                "match": (match_str[:80] + "...") if len(match_str) > 80 else match_str,
                "commit": item.get("Commit", "")[:8],
            })
        return {"tool": "gitleaks", "findings": findings}
    except Exception as e:
        return {"tool": "gitleaks", "findings": [], "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Source code security scanner")
    parser.add_argument("target", help="Path to source code directory")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--tools", default="all",
                        help="Comma-separated tools: bandit,semgrep,pip-audit,gitleaks (default: all)")
    parser.add_argument("--rules-dir", default="/opt/rules",
                        help="Custom rules directory for Semgrep")
    args = parser.parse_args()

    target = args.target
    if not Path(target).exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    tools = args.tools.split(",") if args.tools != "all" else ["bandit", "semgrep", "pip-audit", "gitleaks"]

    report = {
        "meta": {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": tools,
        },
        "results": [],
        "summary": {},
    }

    for tool in tools:
        print(f"[*] Running {tool}...", file=sys.stderr)
        if tool == "bandit":
            result = scan_bandit(target)
        elif tool == "semgrep":
            result = scan_semgrep(target, args.rules_dir)
        elif tool == "pip-audit":
            result = scan_pip_audit(target)
        elif tool == "gitleaks":
            result = scan_gitleaks(target)
        else:
            result = {"tool": tool, "findings": [], "error": f"Unknown tool: {tool}"}

        report["results"].append(result)
        report["summary"][tool] = len(result.get("findings", []))
        print(f"[+] {tool}: {len(result.get('findings', []))} findings", file=sys.stderr)

    report["summary"]["total"] = sum(report["summary"].values())

    output_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output_json)
        print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
