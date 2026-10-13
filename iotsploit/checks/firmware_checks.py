"""
firmware_checks.py

Static analysis of an ALREADY-EXTRACTED firmware filesystem (e.g. the
output of `binwalk -e firmware.bin`) for hardcoded/default credential
material. This is the Chapter 9 "Statically Analyzing the Filesystem
Contents" technique: everything here reads files on disk, nothing
connects to a network or a live device.

What this deliberately stops short of:
- It does NOT run a hash cracker (john/hashcat) against anything in
  /etc/shadow. It identifies that a hash exists and names its type
  (useful for picking the right cracking mode), but cracking is a
  separate, deliberate step you run yourself against a wordlist you
  choose - same reasoning as not auto-brute-forcing MQTT credentials.
- It does NOT attempt to use any credential it finds against a live
  device. Finding a hardcoded password in firmware and typing it into
  a login prompt are two different actions; this module only does the
  first.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from iotsploit.core.scoring import Finding

# Hash-prefix -> human name, for crypt(3)-style /etc/shadow fields.
_HASH_PREFIXES = {
    "$1$": "MD5 crypt",
    "$5$": "SHA-256 crypt",
    "$6$": "SHA-512 crypt",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
}

# Patterns suggesting a literal hardcoded credential in a script/config,
# not a hash. Deliberately broad; expect some noise to review by hand.
_HARDCODED_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{2,}['\"]"),
    re.compile(r"(?i)\b(root|admin)_?(password|pwd)\s*[=:]\s*['\"]?[^'\"\s]{2,}"),
    re.compile(r"(?i)backdoor"),
    re.compile(r"(?i)\btelnetd\b.*-l\s*/bin/(sh|login)"),  # telnetd dropping straight to a shell
    # Broader secret types - same "grep for a shape, let a human confirm"
    # approach as the credential patterns above, just covering the other
    # kinds of hardcoded secrets firmware tends to ship.
    re.compile(r"AKIA[0-9A-Z]{16}"),                        # AWS access key ID
    re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT shape
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"),
]

# Files/dirs that are expensive or pointless to text-scan.
_SKIP_SUFFIXES = {".jpg", ".png", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".squashfs", ".bin"}
_SKIP_DIR_NAMES = {".git", "node_modules"}


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _parse_passwd(passwd_path: Path) -> list[dict]:
    users = []
    for line in passwd_path.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        users.append({
            "username": fields[0],
            "passwd_field": fields[1],
            "uid": fields[2],
            "shell": fields[6],
        })
    return users


def _parse_shadow(shadow_path: Path) -> list[dict]:
    entries = []
    for line in shadow_path.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        username, hash_field = fields[0], fields[1]
        if hash_field in ("", "!", "!!", "*"):
            status = "no-password" if hash_field == "" else "locked"
            hash_type = None
        else:
            hash_type = next((name for prefix, name in _HASH_PREFIXES.items()
                               if hash_field.startswith(prefix)), "unrecognized/legacy DES crypt")
            status = "hashed"
        entries.append({"username": username, "status": status, "hash_type": hash_type,
                         "hash_field": hash_field})
    return entries


def check_firmware_credentials(firmware_root: str | Path, device_id: str | None = None,
                                evidence_store=None, max_grep_file_size: int = 2_000_000) -> list[Finding]:
    """
    Walks an extracted firmware filesystem looking for:
    1. /etc/passwd entries, especially accounts with a UID of 0 other
       than 'root' (a classic hidden-backdoor-account pattern).
    2. /etc/shadow entries with no password set at all, or with a
       crackable hash (named by type, not cracked here).
    3. Hardcoded credential-shaped strings in scripts/configs.
    """
    firmware_root = Path(firmware_root)
    device_id = device_id or firmware_root.name
    findings = []

    if not firmware_root.exists():
        return [Finding(
            finding_id=_fid("firmware_creds", device_id), device_id=device_id,
            check_name="firmware_credentials",
            description=f"Path {firmware_root} does not exist.",
            cvss=None, damage={},
        )]

    # --- /etc/passwd ---
    passwd_matches = list(firmware_root.rglob("passwd")) + list(firmware_root.rglob("etc/passwd"))
    passwd_files = [p for p in set(passwd_matches) if p.is_file()]
    for passwd_path in passwd_files:
        try:
            users = _parse_passwd(passwd_path)
        except Exception as exc:
            findings.append(Finding(
                finding_id=_fid("firmware_passwd", device_id), device_id=device_id,
                check_name="firmware_passwd", description=f"Could not parse {passwd_path}: {exc}",
                cvss=None, damage={},
            ))
            continue

        uid0_extra = [u for u in users if u["uid"] == "0" and u["username"] != "root"]
        description = (
            f"{passwd_path}: {len(users)} account(s): " + ", ".join(u["username"] for u in users)
        )
        damage = {}
        if uid0_extra:
            description += (
                f". WARNING: non-root account(s) with UID 0 (root-equivalent): "
                f"{', '.join(u['username'] for u in uid0_extra)} - classic hidden-backdoor pattern."
            )
            damage = {"privacy": 2, "availability": 1, "chaining_depth": 1}

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("firmware_passwd", device_id), "passwd_raw", passwd_path.read_text(errors="replace"))

        findings.append(Finding(
            finding_id=_fid("firmware_passwd", device_id), device_id=device_id,
            check_name="firmware_passwd", description=description, cvss=None,
            damage=damage, evidence_path=evidence_path,
        ))

    # --- /etc/shadow ---
    shadow_matches = list(firmware_root.rglob("shadow")) + list(firmware_root.rglob("etc/shadow"))
    shadow_files = [p for p in set(shadow_matches) if p.is_file()]
    for shadow_path in shadow_files:
        try:
            entries = _parse_shadow(shadow_path)
        except Exception as exc:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow", device_id), device_id=device_id,
                check_name="firmware_shadow", description=f"Could not parse {shadow_path}: {exc}",
                cvss=None, damage={},
            ))
            continue

        no_password = [e for e in entries if e["status"] == "no-password"]
        hashed = [e for e in entries if e["status"] == "hashed"]

        if no_password:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow_nopw", device_id), device_id=device_id,
                check_name="firmware_shadow",
                description=(
                    f"{shadow_path}: account(s) with NO password at all (empty hash field): "
                    f"{', '.join(e['username'] for e in no_password)} - logs in with any/no password."
                ),
                cvss=9.8,
                damage={"physical_safety": 1, "privacy": 2, "financial": 1, "availability": 1, "chaining_depth": 2},
            ))

        for e in hashed:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow_hash", device_id), device_id=device_id,
                check_name="firmware_shadow",
                description=(
                    f"{shadow_path}: account '{e['username']}' has a {e['hash_type']} hash - "
                    f"crackable offline with john/hashcat against a wordlist of your choosing; "
                    f"this tool deliberately stops at identifying it, not cracking it."
                ),
                cvss=None,
                damage={"privacy": 1, "chaining_depth": 1},
            ))

    # --- grep for hardcoded credential-shaped strings ---
    text_hits = []
    for path in firmware_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_grep_file_size:
                continue
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for pattern in _HARDCODED_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                text_hits.append((path, line_no, match.group(0)[:120]))

    if text_hits:
        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("firmware_grep", device_id), "matches",
                "\n".join(f"{p}:{line}: {snippet}" for p, line, snippet in text_hits),
            )
        sample = "; ".join(f"{p.relative_to(firmware_root)}:{line}" for p, line, _ in text_hits[:5])
        more = f" (+{len(text_hits) - 5} more)" if len(text_hits) > 5 else ""
        findings.append(Finding(
            finding_id=_fid("firmware_grep", device_id), device_id=device_id,
            check_name="firmware_hardcoded_strings",
            description=(
                f"{len(text_hits)} credential-shaped string(s) found in scripts/configs - review by "
                f"hand, this is a broad pattern match with expected false positives: {sample}{more}"
            ),
            cvss=None,
            damage={"privacy": 1, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    if not findings:
        findings.append(Finding(
            finding_id=_fid("firmware_creds", device_id), device_id=device_id,
            check_name="firmware_credentials",
            description=f"No passwd/shadow files or hardcoded-credential patterns found under {firmware_root}.",
            cvss=None, damage={},
        ))

    return findings
