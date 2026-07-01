#!/usr/bin/env python3
"""
Binary static scanner entrypoint.
Performs YARA matching, string extraction, entropy analysis, and PE header inspection.
"""
import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False


BINARY_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".pyd",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".o", ".obj", ".lib", ".a", ".elf",
}

SUSPICIOUS_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "HIGH"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key", "HIGH"),
    (r"(?:password|passwd|secret)\s*[=:]\s*\S{6,}", "Hardcoded credential", "MEDIUM"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Hardcoded IP URL", "MEDIUM"),
    (r"https?://[^\s\"'<>]+\.(?:exe|dll|ps1|bat|cmd|sh|vbs|js|msi|hta|scr|pif|reg|jar|zip|rar|7z|iso|docm|xlsm|pptm)(?:\?[^\s\"'<>]*)?", "URL with executable payload", "HIGH"),
    (r"hxxp[s]?://[^\s\"'<>]+", "Obfuscated URL", "MEDIUM"),
    (r"stratum\+tcp://[^\s\"'<>]+", "Crypto mining pool URL", "HIGH"),
    (r"(?:/bin/sh|/bin/bash|cmd\.exe)", "Shell reference", "MEDIUM"),
    (r"(?:CreateRemoteThread|VirtualAlloc|WriteProcessMemory)", "Win32 injection API", "HIGH"),
    (r"(?:socket\.connect|recv\(|send\()", "Network socket", "LOW"),
]


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0-8). >7.0 = likely packed/encrypted."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings."""
    return [s.decode() for s in re.findall(rb"[ -~]{%d,}" % min_len, data)]


def scan_yara(file_path: str, rules_dir: str) -> list[dict]:
    """Run YARA rules against a file."""
    if not YARA_AVAILABLE:
        return []
    rules_path = Path(rules_dir)
    rule_files = list(rules_path.rglob("*.yar"))
    if not rule_files:
        return []

    try:
        rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
        matches = rules.match(file_path)
        findings = []
        for m in matches:
            findings.append({
                "type": "yara_match",
                "rule": m.rule,
                "severity": m.meta.get("severity", "MEDIUM"),
                "category": m.meta.get("category", ""),
                "description": m.meta.get("description", ""),
            })
        return findings
    except Exception:
        return []


def scan_pe_headers(file_path: str) -> dict:
    """Analyze PE file headers for suspicious indicators."""
    if not PE_AVAILABLE:
        return {}
    try:
        pe = pefile.PE(file_path)
        info = {
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "sections": [],
            "imports": [],
            "suspicious_imports": [],
        }

        suspicious_apis = {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
            "LoadLibraryA", "GetProcAddress", "WinExec",
        }

        for section in pe.sections:
            name = section.Name.decode(errors="replace").strip("\x00")
            entropy = shannon_entropy(section.get_data())
            info["sections"].append({
                "name": name,
                "entropy": entropy,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "packed": entropy > 7.0,
            })

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode(errors="replace")
                        info["imports"].append(f"{dll_name}:{func_name}")
                        if func_name in suspicious_apis:
                            info["suspicious_imports"].append(func_name)

        pe.close()
        return info
    except Exception:
        return {}


def analyze_file(file_path: Path, rules_dir: str) -> dict:
    """Full analysis of a single binary file."""
    data = file_path.read_bytes()
    entropy = shannon_entropy(data)
    strings = extract_strings(data)
    strings_text = "\n".join(strings)

    findings = []

    # Entropy check
    if entropy > 7.2:
        findings.append({
            "type": "high_entropy",
            "severity": "MEDIUM",
            "detail": f"Shannon entropy {entropy}/8.0 - possibly packed/encrypted",
        })

    # Suspicious string patterns
    compiled = [(re.compile(pat, re.IGNORECASE), desc, sev) for pat, desc, sev in SUSPICIOUS_PATTERNS]
    for pattern, desc, sev in compiled:
        m = pattern.search(strings_text)
        if m:
            findings.append({
                "type": "suspicious_string",
                "severity": sev,
                "detail": desc,
                "match": m.group(0)[:120],
            })

    # YARA
    yara_findings = scan_yara(str(file_path), rules_dir)
    findings.extend(yara_findings)

    # PE analysis
    pe_info = {}
    if file_path.suffix.lower() in (".exe", ".dll", ".pyd"):
        pe_info = scan_pe_headers(str(file_path))
        if pe_info.get("suspicious_imports"):
            findings.append({
                "type": "suspicious_imports",
                "severity": "HIGH",
                "detail": f"Suspicious Win32 APIs: {', '.join(pe_info['suspicious_imports'])}",
            })

    return {
        "file": str(file_path),
        "size_bytes": file_path.stat().st_size,
        "entropy": entropy,
        "strings_count": len(strings),
        "findings": findings,
        "pe_info": pe_info if pe_info else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Binary static analysis scanner")
    parser.add_argument("target", help="Path to scan (file or directory)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--rules-dir", default="/opt/yara-rules",
                        help="YARA rules directory")
    parser.add_argument("--max-size-mb", type=int, default=50,
                        help="Skip files larger than this (MB)")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    files = []
    if target.is_file():
        files = [target]
    else:
        for f in target.rglob("*"):
            if f.is_file() and f.suffix.lower() in BINARY_EXTS:
                if f.stat().st_size <= args.max_size_mb * 1024 * 1024:
                    files.append(f)

    report = {
        "meta": {
            "target": str(target),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(files),
            "yara_available": YARA_AVAILABLE,
            "pe_available": PE_AVAILABLE,
        },
        "results": [],
        "summary": {"total_findings": 0, "files_with_findings": 0},
    }

    for file_path in files:
        print(f"[*] Analyzing: {file_path}", file=sys.stderr)
        result = analyze_file(file_path, args.rules_dir)
        if result["findings"]:
            report["results"].append(result)
            report["summary"]["files_with_findings"] += 1
            report["summary"]["total_findings"] += len(result["findings"])

    output_json = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    if args.output:
        Path(args.output).write_text(output_json)
        print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(output_json)

    print(f"[+] Done: {report['summary']['total_findings']} findings in "
          f"{report['summary']['files_with_findings']}/{len(files)} files", file=sys.stderr)


if __name__ == "__main__":
    main()
