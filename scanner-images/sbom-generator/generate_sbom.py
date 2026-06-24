#!/usr/bin/env python3
"""
SBOM generator entrypoint.
Generates Software Bill of Materials using Syft (CycloneDX/SPDX format)
and optionally scans for vulnerabilities with Grype.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_syft(target: str, output_format: str = "cyclonedx-json") -> dict:
    """Generate SBOM using Syft."""
    cmd = [
        "syft", target,
        "-o", output_format,
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return {"error": f"Syft failed: {result.stderr[:500]}"}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw_output": result.stdout[:2000], "error": "Invalid JSON from Syft"}


def run_grype(target: str) -> dict:
    """Scan for vulnerabilities using Grype."""
    cmd = [
        "grype", target,
        "-o", "json",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and not result.stdout:
        return {"error": f"Grype failed: {result.stderr[:500]}"}
    try:
        data = json.loads(result.stdout)
        matches = data.get("matches", [])
        vulnerabilities = []
        for m in matches:
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})
            vulnerabilities.append({
                "id": vuln.get("id", ""),
                "severity": vuln.get("severity", "Unknown"),
                "package": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "fixed_in": vuln.get("fix", {}).get("versions", []),
                "description": vuln.get("description", "")[:200],
                "datasource": vuln.get("dataSource", ""),
            })
        return {
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "by_severity": _count_by_severity(vulnerabilities),
        }
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from Grype"}


def _count_by_severity(vulns: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
    for v in vulns:
        sev = v.get("severity", "Unknown")
        if sev in counts:
            counts[sev] += 1
    return counts


def generate_cyclonedx_python(target: str) -> dict:
    """Generate CycloneDX SBOM from Python project using cyclonedx-bom."""
    target_path = Path(target)
    req_file = None
    for candidate in ["requirements.txt", "requirements.lock", "Pipfile.lock"]:
        f = target_path / candidate
        if f.exists():
            req_file = f
            break

    if not req_file:
        return {"error": "No Python dependency file found"}

    cmd = [
        "cyclonedx-py", "requirements",
        str(req_file),
        "--format", "json",
        "--output", "-",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "Invalid CycloneDX output"}
    return {"error": f"cyclonedx-bom failed: {result.stderr[:300]}"}


def main():
    parser = argparse.ArgumentParser(description="SBOM generator and vulnerability scanner")
    parser.add_argument("target", help="Path or image to generate SBOM for")
    parser.add_argument("-o", "--output", help="Output file for SBOM")
    parser.add_argument("--format", default="cyclonedx-json",
                        choices=["cyclonedx-json", "spdx-json", "json", "table"],
                        help="SBOM output format")
    parser.add_argument("--vuln-scan", action="store_true",
                        help="Also run vulnerability scan with Grype")
    parser.add_argument("--python-only", action="store_true",
                        help="Use cyclonedx-bom for Python projects instead of Syft")
    args = parser.parse_args()

    report = {
        "meta": {
            "target": args.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "format": args.format,
        },
    }

    # Generate SBOM
    print(f"[*] Generating SBOM for: {args.target}", file=sys.stderr)
    if args.python_only:
        sbom = generate_cyclonedx_python(args.target)
    else:
        sbom = run_syft(args.target, args.format)

    if "error" in sbom:
        print(f"[!] SBOM error: {sbom['error']}", file=sys.stderr)
        report["sbom"] = sbom
    else:
        report["sbom"] = sbom
        # Count components
        components = sbom.get("components", [])
        report["meta"]["components_count"] = len(components)
        print(f"[+] SBOM generated: {len(components)} components", file=sys.stderr)

    # Vulnerability scan
    if args.vuln_scan:
        print(f"[*] Running vulnerability scan...", file=sys.stderr)
        vuln_results = run_grype(args.target)
        report["vulnerabilities"] = vuln_results
        if "error" not in vuln_results:
            print(f"[+] Vulnerabilities: {vuln_results['total']} found", file=sys.stderr)
            by_sev = vuln_results.get("by_severity", {})
            for sev, count in by_sev.items():
                if count > 0:
                    print(f"    {sev}: {count}", file=sys.stderr)

    # Output
    output_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output_json)
        print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
