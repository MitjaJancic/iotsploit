"""
firmware_audit.py

Static analysis for hardcoded secrets, API keys, and high-entropy tokens
in extracted firmware filesystems.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy for character frequency in a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _mask_token(val: str) -> str:
    """Masks secret token, keeping the first 4 characters visible."""
    if not val:
        return ""
    if len(val) <= 4:
        return "*" * len(val)
    return val[:4] + ("*" * (len(val) - 4))


def scan_for_secrets(extract_dir: Path) -> list[dict[str, Any]]:
    """
    Scans text files (.conf, .cfg, .json, .yaml, .py, .sh, .js) in extracted firmware.
    Matches known public token patterns (AWS keys AKIA*, JWT eyJ*, OAuth Bearer) via regex.
    Calculates Shannon entropy for strings 20-100 chars; flags >4.5 entropy.
    Masks all discovered values (first 4 chars + asterisks) in output.
    Skips binary directories (/bin/, /lib/).
    """
    extract_dir = Path(extract_dir)
    findings: list[dict[str, Any]] = []

    if not extract_dir.exists() or not extract_dir.is_dir():
        return findings

    target_extensions = {".conf", ".cfg", ".json", ".yaml", ".yml", ".py", ".sh", ".js"}
    skip_dir_names = {"bin", "sbin", "lib", "lib64", "usr/bin", "usr/lib", "node_modules", ".git"}

    patterns = {
        "aws_access_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "jwt_token": re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "bearer_token": re.compile(r"(?i)\bbearer\s+([a-zA-Z0-9_\-\.]{20,})\b"),
    }

    candidate_pattern = re.compile(r"[A-Za-z0-9+/=_\-]{20,100}")

    for root, dirs, files in os.walk(extract_dir):
        # Prune skipped binary and VCS directories
        dirs[:] = [d for d in dirs if d not in skip_dir_names]

        rel_root = Path(root).relative_to(extract_dir).as_posix()
        if any(rel_root == d or rel_root.startswith(f"{d}/") for d in skip_dir_names):
            continue

        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() not in target_extensions:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        line_str = line.strip()
                        if not line_str:
                            continue

                        # 1. Regex pattern matching for known token formats
                        for token_type, regex in patterns.items():
                            for match in regex.finditer(line_str):
                                raw_val = match.group(1)
                                findings.append({
                                    "file": str(file_path.relative_to(extract_dir)),
                                    "line": line_no,
                                    "type": token_type,
                                    "masked_value": _mask_token(raw_val),
                                    "entropy": round(calculate_shannon_entropy(raw_val), 2),
                                })

                        # 2. Shannon entropy analysis on candidate strings (20-100 chars)
                        for candidate in candidate_pattern.findall(line_str):
                            entropy = calculate_shannon_entropy(candidate)
                            if entropy > 4.5:
                                masked = _mask_token(candidate)
                                if not any(
                                    f["file"] == str(file_path.relative_to(extract_dir))
                                    and f["line"] == line_no
                                    and f["masked_value"] == masked
                                    for f in findings
                                ):
                                    findings.append({
                                        "file": str(file_path.relative_to(extract_dir)),
                                        "line": line_no,
                                        "type": "high_entropy_string",
                                        "masked_value": masked,
                                        "entropy": round(entropy, 2),
                                    })
            except (OSError, PermissionError):
                continue

    return findings
