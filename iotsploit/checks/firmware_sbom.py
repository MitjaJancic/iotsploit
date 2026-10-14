"""
firmware_sbom.py

OpenWrt / Embedded Linux Software Bill of Materials (SBOM) and Outdated Component Scanner.
Extracts package inventory from /usr/lib/opkg/status and correlates versions against
known high-impact IoT vulnerabilities (e.g., dnsmasq CVE-2020-7982, pppd CVE-2020-8597,
miniupnpd buffer overflows).
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


# Vulnerability correlation knowledge-base for embedded Linux packages
VULNERABLE_PACKAGE_RULES = [
    {
        "package": "dnsmasq",
        "version_pattern": r"^(2\.(?:[0-7]\d|80))(?:[.-].*)?$",
        "cve": "CVE-2020-7982 / DNSpooq",
        "description": "dnsmasq version < 2.81 is vulnerable to package validation bypass (CVE-2020-7982) and DNSpooq cache poisoning/heap overflows (CVE-2020-25681).",
        "cvss": 9.8,
        "damage": {"availability": 2, "chaining_depth": 2, "privacy": 1},
    },
    {
        "package": "miniupnpd",
        "version_pattern": r"^(1\..*|2\.(?:0\..*|1\.(?:201[0-8].*|20190[1-7].*)))$",
        "cve": "CVE-2019-12108 / CVE-2019-12109",
        "description": "miniupnpd < 2.1.20190824 contains critical stack-based buffer overflows in UPnP parsing, allowing remote code execution without authentication.",
        "cvss": 8.8,
        "damage": {"availability": 2, "chaining_depth": 2, "privacy": 1},
    },
    {
        "package": "ppp",
        "version_pattern": r"^(2\.[0-4]\.[0-7])(?:[.-].*)?$",
        "cve": "CVE-2020-8597",
        "description": "pppd < 2.4.8 contains a critical buffer overflow in EAP packet processing, allowing unauthenticated remote attackers to execute arbitrary code with root privileges.",
        "cvss": 9.8,
        "damage": {"availability": 2, "chaining_depth": 3, "privacy": 2},
    },
    {
        "package": "dropbear",
        "version_pattern": r"^(201[0-9]\.(?:[0-6]\d|7[0-8]))(?:[.-].*)?$",
        "cve": "CVE-2020-36254",
        "description": "dropbear SSH < 2020.80 has insecure symlink and key generation vulnerabilities.",
        "cvss": 6.8,
        "damage": {"availability": 1, "chaining_depth": 1},
    },
]


def parse_opkg_status(status_file: Path) -> list[dict[str, str]]:
    """Parses an OpenWrt /usr/lib/opkg/status database into structured records."""
    packages: list[dict[str, str]] = []
    try:
        content = status_file.read_text(encoding="utf-8", errors="replace")
        raw_blocks = content.split("\n\n")
        for block in raw_blocks:
            if not block.strip():
                continue
            entry: dict[str, str] = {}
            for line in block.splitlines():
                if ": " in line:
                    key, val = line.split(": ", 1)
                    entry[key.strip().lower()] = val.strip()
            if "package" in entry:
                packages.append(entry)
    except Exception:
        pass
    return packages


def audit_firmware_sbom(firmware_dir: str | Path,
                        device_id: str | None = None,
                        evidence_store=None) -> list[Finding]:
    """
    Audits the extracted firmware for package management databases (opkg status),
    extracting installed software inventory and correlating with known IoT CVEs.
    """
    root = Path(firmware_dir)
    device_id = device_id or root.name
    findings: list[Finding] = []

    # Search common OpenWrt opkg status locations
    candidates = [
        root / "usr" / "lib" / "opkg" / "status",
        root / "lib" / "opkg" / "status",
        root / "var" / "lib" / "opkg" / "status",
    ]
    status_file = next((f for f in candidates if f.exists() and f.is_file()), None)

    if not status_file:
        # Fallback recursive search
        status_file = next((p for p in root.rglob("status") if "opkg" in str(p).lower() and p.is_file()), None)

    if not status_file:
        return [Finding(
            finding_id=_fid("sbom_missing", device_id),
            device_id=device_id,
            check_name="firmware_sbom",
            description=f"No OpenWrt opkg status database identified under {firmware_dir}.",
            cvss=None,
            damage={},
        )]

    packages = parse_opkg_status(status_file)
    if not packages:
        return [Finding(
            finding_id=_fid("sbom_empty", device_id),
            device_id=device_id,
            check_name="firmware_sbom",
            description=f"opkg status file found at {status_file}, but contained no valid package records.",
            cvss=None,
            damage={},
        )]

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_json(
            _fid("opkg_sbom", device_id),
            "installed_packages",
            {"count": len(packages), "packages": packages},
        )

    # 1. Package Inventory Summary Finding
    sample_pkgs = ", ".join(p.get("package", "") for p in packages[:6])
    findings.append(Finding(
        finding_id=_fid("sbom_summary", device_id),
        device_id=device_id,
        check_name="firmware_sbom_inventory",
        description=(
            f"Software Bill of Materials (SBOM): Identified {len(packages)} installed OpenWrt packages "
            f"(e.g., {sample_pkgs}...) in {status_file.name}."
        ),
        cvss=None,
        damage={},
        evidence_path=evidence_path,
    ))

    # 2. Correlate with Known Vulnerability Rules
    for rule in VULNERABLE_PACKAGE_RULES:
        rule_pkg = rule["package"].lower()
        matched = next((p for p in packages if p.get("package", "").lower() == rule_pkg), None)
        if matched:
            version = matched.get("version", "")
            if re.search(rule["version_pattern"], version):
                findings.append(Finding(
                    finding_id=_fid(f"vuln_{rule_pkg}", device_id),
                    device_id=device_id,
                    check_name="firmware_vulnerable_component",
                    description=(
                        f"Outdated Component: Package '{rule_pkg}' version '{version}' matches {rule['cve']}. "
                        f"{rule['description']}"
                    ),
                    cvss=rule["cvss"],
                    damage=rule["damage"],
                    evidence_path=evidence_path,
                ))

    return findings
