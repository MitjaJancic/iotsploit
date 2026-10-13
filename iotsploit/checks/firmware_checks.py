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
from iotsploit.checks.firmware_audit import scan_for_secrets, map_firmware_services

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
_SKIP_SUFFIXES = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".squashfs", ".bin", ".rom", ".img", ".iso",
    ".so", ".o", ".a", ".ko", ".ipk", ".deb",
    ".gz", ".tar", ".tgz", ".zip", ".xz", ".bz2",
}
_SKIP_DIR_NAMES = {
    ".git", "node_modules", "bin", "sbin", "lib", "lib64",
    "dev", "proc", "sys",
}


def _is_binary_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if chunk.startswith(b"\x7fELF") or b"\x00" in chunk:
                return True
    except (OSError, PermissionError):
        return True
    return False


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _parse_passwd(passwd_path: Path) -> list[dict]:
    users = []
    try:
        text = passwd_path.read_text(errors="replace")
    except Exception:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        # A valid UNIX passwd line has exactly 7 fields, with numeric UID and GID
        if len(fields) != 7:
            continue
        if not fields[2].isdigit() or not fields[3].isdigit():
            continue
        if not re.match(r"^[a-zA-Z0-9_.-]+$", fields[0]):
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
    try:
        text = shadow_path.read_text(errors="replace")
    except Exception:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        username, hash_field = fields[0].strip(), fields[1].strip()
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            continue

        # In Linux/BusyBox shadow files:
        # "" means empty password (logs in without password)
        # "*", "!", "!!", "x", or anything starting with "!" means account is locked/disabled
        if hash_field in ("", "!", "!!", "*", "x") or hash_field.startswith("!"):
            status = "no-password" if hash_field == "" else "locked"
            hash_type = None
        else:
            hash_type = next((name for prefix, name in _HASH_PREFIXES.items()
                               if hash_field.startswith(prefix)), None)
            if not hash_type:
                # Check for legacy 13-char DES crypt
                if len(hash_field) == 13 and re.match(r"^[a-zA-Z0-9./]{13}$", hash_field):
                    hash_type = "legacy DES crypt"
                else:
                    status = "locked"
                    hash_type = None

            status = "hashed" if hash_type else "locked"

        entries.append({
            "username": username,
            "status": status,
            "hash_type": hash_type,
            "hash_field": hash_field,
        })
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
    passwd_candidates = list(firmware_root.rglob("passwd"))
    passwd_files = [
        p for p in set(passwd_candidates)
        if p.is_file()
        and "etc" in p.parts
        and not any(d in p.parts for d in ("bin", "sbin", "lib", "lib64"))
        and not _is_binary_file(p)
    ]
    for passwd_path in passwd_files:
        rel_p = passwd_path.relative_to(firmware_root)
        try:
            users = _parse_passwd(passwd_path)
        except Exception as exc:
            findings.append(Finding(
                finding_id=_fid("firmware_passwd", device_id), device_id=device_id,
                check_name="firmware_passwd", description=f"Could not parse {rel_p}: {exc}",
                cvss=None, damage={},
            ))
            continue

        if not users:
            continue

        uid0_extra = [u for u in users if u["uid"] == "0" and u["username"] != "root"]
        if uid0_extra:
            for u in uid0_extra:
                findings.append(Finding(
                    finding_id=_fid("firmware_backdoor_uid0", device_id), device_id=device_id,
                    check_name="firmware_passwd",
                    description=f"Backdoor account UID 0: {u['username']}:0 [{rel_p}]",
                    cvss=9.8,
                    damage={"privacy": 2, "availability": 1, "chaining_depth": 1},
                ))

        # Check for passwords stored directly in /etc/passwd
        for u in users:
            if u["passwd_field"] not in ("x", "*", "!", ""):
                findings.append(Finding(
                    finding_id=_fid("firmware_passwd_cred", device_id), device_id=device_id,
                    check_name="firmware_passwd",
                    description=f"{u['username']}:{u['passwd_field']} [{rel_p}]",
                    cvss=7.5,
                    damage={"privacy": 1, "chaining_depth": 1},
                ))

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("firmware_passwd", device_id), "passwd_raw", passwd_path.read_text(errors="replace"))

        user_names = [u["username"] for u in users]
        summary_str = f"{len(users)} accounts in {rel_p}: {', '.join(user_names[:8])}{'...' if len(user_names) > 8 else ''}"
        findings.append(Finding(
            finding_id=_fid("firmware_passwd", device_id), device_id=device_id,
            check_name="firmware_passwd", description=summary_str, cvss=None,
            damage={}, evidence_path=evidence_path,
        ))

    # --- /etc/shadow ---
    shadow_candidates = list(firmware_root.rglob("shadow"))
    shadow_files = [
        p for p in set(shadow_candidates)
        if p.is_file()
        and "etc" in p.parts
        and not any(d in p.parts for d in ("bin", "sbin", "lib", "lib64"))
        and not _is_binary_file(p)
    ]
    for shadow_path in shadow_files:
        rel_s = shadow_path.relative_to(firmware_root)
        try:
            entries = _parse_shadow(shadow_path)
        except Exception as exc:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow", device_id), device_id=device_id,
                check_name="firmware_shadow", description=f"Could not parse {rel_s}: {exc}",
                cvss=None, damage={},
            ))
            continue

        no_password = [e for e in entries if e["status"] == "no-password"]
        hashed = [e for e in entries if e["status"] == "hashed"]

        for e in no_password:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow_nopw", device_id), device_id=device_id,
                check_name="firmware_shadow",
                description=f"{e['username']}:<NO_PASSWORD> [empty password in {rel_s}]",
                cvss=9.8,
                damage={"physical_safety": 1, "privacy": 2, "financial": 1, "availability": 1, "chaining_depth": 2},
            ))

        for e in hashed:
            findings.append(Finding(
                finding_id=_fid("firmware_shadow_hash", device_id), device_id=device_id,
                check_name="firmware_shadow",
                description=f"{e['username']}:{e['hash_field']} ({e['hash_type']}) [{rel_s}]",
                cvss=7.5,
                damage={"privacy": 2, "chaining_depth": 1},
            ))

    # --- grep for hardcoded credential-shaped strings ---
    text_hits = []
    for path in firmware_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if _is_binary_file(path):
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
                snippet = match.group(0).strip().replace("\n", " ")[:60]
                text_hits.append((path, line_no, snippet))

    if text_hits:
        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("firmware_grep", device_id), "matches",
                "\n".join(f"{p}:{line}: {snippet}" for p, line, snippet in text_hits),
            )
        sample = "; ".join(f"{snippet} [{p.relative_to(firmware_root)}:{line}]" for p, line, snippet in text_hits[:3])
        more = f" (+{len(text_hits) - 3} more)" if len(text_hits) > 3 else ""
        findings.append(Finding(
            finding_id=_fid("firmware_grep", device_id), device_id=device_id,
            check_name="firmware_hardcoded_strings",
            description=f"{len(text_hits)} hardcoded credential string(s): {sample}{more}",
            cvss=None,
            damage={"privacy": 1, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    if not findings:
        findings.append(Finding(
            finding_id=_fid("firmware_creds", device_id), device_id=device_id,
            check_name="firmware_credentials",
            description=f"No credentials or shadow files found under {firmware_root}.",
            cvss=None, damage={},
        ))

    return findings
