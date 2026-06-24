#!/usr/bin/env python3
"""
Unpacker/deobfuscator entrypoint.
Handles: UPX-packed binaries, compressed archives, base64-encoded payloads,
simple XOR deobfuscation, and Python bytecode decompilation.
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ARCHIVE_EXTS = {".zip", ".7z", ".tar", ".gz", ".bz2", ".xz", ".rar"}


def detect_upx(file_path: Path) -> bool:
    """Check if file is UPX-packed."""
    try:
        data = file_path.read_bytes()[:4096]
        return b"UPX0" in data or b"UPX1" in data or b"UPX!" in data
    except Exception:
        return False


def unpack_upx(file_path: Path, output_dir: Path) -> dict:
    """Attempt UPX decompression."""
    output_file = output_dir / f"{file_path.stem}_unpacked{file_path.suffix}"
    shutil.copy2(file_path, output_file)

    result = subprocess.run(
        ["upx", "-d", str(output_file)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return {"method": "upx", "output": str(output_file), "success": True}
    else:
        output_file.unlink(missing_ok=True)
        return {"method": "upx", "success": False, "error": result.stderr[:200]}


def extract_archive(file_path: Path, output_dir: Path) -> dict:
    """Extract compressed archives."""
    extract_dir = output_dir / file_path.stem
    extract_dir.mkdir(parents=True, exist_ok=True)

    ext = file_path.suffix.lower()
    if ext == ".zip":
        cmd = ["unzip", "-o", str(file_path), "-d", str(extract_dir)]
    elif ext == ".7z":
        cmd = ["7z", "x", str(file_path), f"-o{extract_dir}", "-y"]
    elif ext in (".tar", ".gz", ".bz2", ".xz"):
        cmd = ["tar", "xf", str(file_path), "-C", str(extract_dir)]
    else:
        return {"method": "archive", "success": False, "error": f"Unsupported: {ext}"}

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        extracted = [str(f) for f in extract_dir.rglob("*") if f.is_file()]
        return {"method": "archive", "output": str(extract_dir), "files": extracted[:50], "success": True}
    return {"method": "archive", "success": False, "error": result.stderr[:200]}


def decode_base64_payloads(file_path: Path, output_dir: Path) -> dict:
    """Find and decode base64-encoded payloads in file."""
    try:
        content = file_path.read_text(errors="replace")
    except Exception:
        content = file_path.read_bytes().decode(errors="replace")

    # Find base64 strings (min 40 chars)
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    matches = b64_pattern.findall(content)

    decoded_files = []
    for i, match in enumerate(matches[:10]):
        try:
            decoded = base64.b64decode(match)
            if len(decoded) < 10:
                continue
            out_file = output_dir / f"{file_path.stem}_b64_{i}.bin"
            out_file.write_bytes(decoded)
            decoded_files.append({
                "file": str(out_file),
                "size": len(decoded),
                "starts_with": decoded[:20].hex(),
            })
        except Exception:
            continue

    if decoded_files:
        return {"method": "base64", "decoded": decoded_files, "success": True}
    return {"method": "base64", "success": False, "error": "No valid base64 payloads found"}


def xor_bruteforce(file_path: Path, output_dir: Path) -> dict:
    """Try single-byte XOR decoding to find hidden PE/ELF headers."""
    data = file_path.read_bytes()[:8192]
    pe_magic = b"MZ"
    elf_magic = b"\x7fELF"

    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data[:16])
        if decoded[:2] == pe_magic or decoded[:4] == elf_magic:
            # Full decode
            full_decoded = bytes(b ^ key for b in file_path.read_bytes())
            out_file = output_dir / f"{file_path.stem}_xor_{key:02x}.bin"
            out_file.write_bytes(full_decoded)
            results.append({"key": f"0x{key:02x}", "file": str(out_file), "type": "PE" if decoded[:2] == pe_magic else "ELF"})

    if results:
        return {"method": "xor", "results": results, "success": True}
    return {"method": "xor", "success": False, "error": "No XOR-encoded binaries found"}


def decompile_pyc(file_path: Path, output_dir: Path) -> dict:
    """Decompile Python bytecode (.pyc/.pyo)."""
    out_file = output_dir / f"{file_path.stem}.py"
    result = subprocess.run(
        ["python", "-m", "uncompyle6", "-o", str(out_file), str(file_path)],
        capture_output=True, text=True
    )
    if result.returncode == 0 and out_file.exists():
        return {"method": "pyc_decompile", "output": str(out_file), "success": True}
    return {"method": "pyc_decompile", "success": False, "error": result.stderr[:200]}


def analyze_file(file_path: Path, output_dir: Path) -> dict:
    """Run all applicable unpack methods on a file."""
    results = []
    ext = file_path.suffix.lower()

    # UPX detection
    if detect_upx(file_path):
        results.append(unpack_upx(file_path, output_dir))

    # Archive extraction
    if ext in ARCHIVE_EXTS:
        results.append(extract_archive(file_path, output_dir))

    # Base64 decoding
    results.append(decode_base64_payloads(file_path, output_dir))

    # XOR bruteforce (only for small suspicious files)
    if file_path.stat().st_size < 1_000_000 and ext in (".bin", ".dat", ".tmp"):
        results.append(xor_bruteforce(file_path, output_dir))

    # Python bytecode
    if ext in (".pyc", ".pyo"):
        results.append(decompile_pyc(file_path, output_dir))

    successful = [r for r in results if r.get("success")]
    return {
        "file": str(file_path),
        "size_bytes": file_path.stat().st_size,
        "operations": results,
        "unpacked": len(successful) > 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Binary unpacker/deobfuscator")
    parser.add_argument("target", help="File or directory to unpack")
    parser.add_argument("-o", "--output-dir", default="/tmp/unpacked",
                        help="Output directory for unpacked files")
    parser.add_argument("--report", help="JSON report output file")
    args = parser.parse_args()

    target = Path(args.target)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    files = [target] if target.is_file() else list(target.rglob("*"))
    files = [f for f in files if f.is_file() and f.stat().st_size > 0]

    report = {
        "meta": {
            "target": str(target),
            "output_dir": str(output_dir),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_processed": len(files),
        },
        "results": [],
    }

    for file_path in files:
        print(f"[*] Processing: {file_path.name}", file=sys.stderr)
        result = analyze_file(file_path, output_dir)
        if result["unpacked"]:
            report["results"].append(result)
            print(f"[+] Unpacked: {file_path.name}", file=sys.stderr)

    report["summary"] = {
        "total_files": len(files),
        "unpacked_files": len(report["results"]),
    }

    report_json = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    if args.report:
        Path(args.report).write_text(report_json)
        print(f"[+] Report: {args.report}", file=sys.stderr)
    else:
        print(report_json)


if __name__ == "__main__":
    main()
