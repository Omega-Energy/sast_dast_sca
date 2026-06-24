#!/usr/bin/env python3
"""
ClamAV scanner entrypoint.
Scans project files for malware, viruses, trojans, and suspicious payloads.
Supports both local clamscan and clamd (daemon) modes.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import pyclamd
    PYCLAMD_AVAILABLE = True
except ImportError:
    PYCLAMD_AVAILABLE = False


# File extensions to skip (large binaries, media)
SKIP_EXTS = {
    ".mp4", ".avi", ".mkv", ".mov", ".mp3", ".wav", ".flac",
    ".iso", ".vmdk", ".vdi", ".qcow2",
}

MAX_FILE_SIZE_MB = 100


def scan_with_clamscan(target: str, max_size_mb: int = MAX_FILE_SIZE_MB) -> dict:
    """Run clamscan CLI (no daemon required)."""
    cmd = [
        "clamscan",
        "--recursive",
        "--infected",
        "--no-summary",
        f"--max-filesize={max_size_mb}M",
        f"--max-scansize={max_size_mb * 2}M",
        "--stdout",
        target,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    findings = []
    for line in result.stdout.strip().split("\n"):
        if not line or "OK" in line or "Empty file" in line:
            continue
        # Format: /path/to/file: ThreatName FOUND
        if "FOUND" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                file_path = parts[0].strip()
                threat = parts[1].replace("FOUND", "").strip()
                findings.append({
                    "file": file_path,
                    "threat": threat,
                    "severity": _classify_severity(threat),
                    "tool": "clamav",
                })

    return {
        "tool": "clamav",
        "mode": "clamscan",
        "findings": findings,
        "exit_code": result.returncode,
    }


def scan_with_clamd(target: str, host: str = "localhost", port: int = 3310) -> dict:
    """Scan using clamd daemon via network socket (faster for repeated scans)."""
    if not PYCLAMD_AVAILABLE:
        return {"tool": "clamav", "mode": "clamd", "findings": [], "error": "pyclamd not available"}

    try:
        cd = pyclamd.ClamdNetworkSocket(host=host, port=port, timeout=120)
        if not cd.ping():
            return {"tool": "clamav", "mode": "clamd", "findings": [], "error": "clamd not reachable"}
    except Exception as e:
        return {"tool": "clamav", "mode": "clamd", "findings": [], "error": f"Connection failed: {e}"}

    findings = []
    target_path = Path(target)

    if target_path.is_file():
        files = [target_path]
    else:
        files = [f for f in target_path.rglob("*") if f.is_file()]

    for file_path in files:
        if file_path.suffix.lower() in SKIP_EXTS:
            continue
        if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            continue
        if file_path.stat().st_size == 0:
            continue

        try:
            result = cd.scan_file(str(file_path))
            if result:
                for path, info in result.items():
                    status, threat = info
                    if status == "FOUND":
                        findings.append({
                            "file": str(path),
                            "threat": threat,
                            "severity": _classify_severity(threat),
                            "tool": "clamav",
                        })
        except Exception:
            continue

    return {
        "tool": "clamav",
        "mode": "clamd",
        "findings": findings,
    }


def _classify_severity(threat_name: str) -> str:
    """Classify threat severity based on name patterns."""
    threat_lower = threat_name.lower()

    # Critical threats
    if any(t in threat_lower for t in ["trojan", "backdoor", "rootkit", "ransomware", "exploit"]):
        return "CRITICAL"

    # High threats
    if any(t in threat_lower for t in ["virus", "worm", "miner", "keylogger", "stealer"]):
        return "HIGH"

    # Medium threats
    if any(t in threat_lower for t in ["adware", "pup", "potentially", "heuristic", "suspicious"]):
        return "MEDIUM"

    # Low
    if any(t in threat_lower for t in ["phishing", "spam", "test"]):
        return "LOW"

    return "HIGH"  # Default to HIGH for unknown threats


def get_clamav_version() -> dict:
    """Get ClamAV version and database info."""
    version_result = subprocess.run(["clamscan", "--version"], capture_output=True, text=True)
    return {"version": version_result.stdout.strip()}


def main():
    parser = argparse.ArgumentParser(description="ClamAV malware scanner for project files")
    parser.add_argument("target", help="Path to scan (file or directory)")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--mode", choices=["local", "daemon"], default="local",
                        help="Scan mode: local (clamscan) or daemon (clamd)")
    parser.add_argument("--clamd-host", default="localhost",
                        help="clamd host (daemon mode)")
    parser.add_argument("--clamd-port", type=int, default=3310,
                        help="clamd port (daemon mode)")
    parser.add_argument("--max-size", type=int, default=MAX_FILE_SIZE_MB,
                        help="Max file size in MB to scan")
    args = parser.parse_args()

    target = args.target
    if not Path(target).exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    # Count files to scan
    target_path = Path(target)
    if target_path.is_file():
        file_count = 1
    else:
        file_count = sum(1 for f in target_path.rglob("*") if f.is_file())

    print(f"[*] ClamAV scan starting: {target} ({file_count} files)", file=sys.stderr)

    # Get version info
    version_info = get_clamav_version()
    print(f"[*] {version_info.get('version', 'unknown')}", file=sys.stderr)

    # Run scan
    if args.mode == "daemon":
        print(f"[*] Using clamd at {args.clamd_host}:{args.clamd_port}", file=sys.stderr)
        result = scan_with_clamd(target, args.clamd_host, args.clamd_port)
    else:
        print("[*] Using local clamscan", file=sys.stderr)
        result = scan_with_clamscan(target, args.max_size)

    # Build report
    report = {
        "meta": {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": file_count,
            "mode": args.mode,
            "clamav_version": version_info.get("version", ""),
        },
        "results": result,
        "summary": {
            "total_threats": len(result.get("findings", [])),
            "by_severity": {},
        },
    }

    # Count by severity
    for finding in result.get("findings", []):
        sev = finding.get("severity", "UNKNOWN")
        report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1

    # Print findings
    for f in result.get("findings", []):
        print(f"[!] {f['severity']}: {f['file']} -> {f['threat']}", file=sys.stderr)

    if not result.get("findings"):
        print("[+] No threats detected", file=sys.stderr)
    else:
        print(f"[!] {len(result['findings'])} threat(s) detected!", file=sys.stderr)

    # Output
    output_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output_json)
        print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(output_json)

    # Exit with non-zero if threats found
    sys.exit(1 if result.get("findings") else 0)


if __name__ == "__main__":
    main()
