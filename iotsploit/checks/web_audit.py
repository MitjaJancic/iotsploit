"""
web_audit.py

HTTP/Web Interface Security Header & CSRF Posture Auditor.
Assesses IoT management interfaces (such as OpenWrt LuCI, router web UIs) for:
1. Missing security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS).
2. Cookie security flags (HttpOnly, Secure, SameSite on session cookies like LuCI 'sysauth').
3. Cross-Site Request Forgery (CSRF) & Clickjacking exposures (OWASP IoT Top 10 #9).
"""

from __future__ import annotations

import urllib.request
import urllib.error
import uuid
from typing import Any

from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _fetch_headers(url: str, timeout: float = 3.5) -> tuple[int, dict[str, str], str]:
    """Fetches HTTP response status, headers (lowercased), and body preview."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) iotsploit-audit/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(2048).decode("utf-8", errors="replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        body = exc.read(2048).decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
        return exc.code, headers, body
    except Exception:
        return 0, {}, ""


def audit_web_security(target: str, port: int = 80, path: str = "/",
                       device_id: str | None = None,
                       evidence_store=None) -> list[Finding]:
    """
    Audits an HTTP service for security headers, cookie flags, and clickjacking/CSRF posture.
    """
    device_id = device_id or f"web_{target.replace('.', '_')}"
    findings: list[Finding] = []

    scheme = "https" if port == 443 else "http"
    base_url = f"{scheme}://{target}:{port}"
    full_url = f"{base_url}{path if path.startswith('/') else '/' + path}"

    status, headers, body = _fetch_headers(full_url)
    if status == 0:
        return [Finding(
            finding_id=_fid("web_unreachable", device_id),
            device_id=device_id,
            check_name="web_unreachable",
            description=f"HTTP service at {full_url} did not respond.",
            cvss=None,
            damage={},
        )]

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_json(
            _fid("web_headers", device_id),
            "response_headers",
            {"url": full_url, "status": status, "headers": headers, "body_preview": body[:500]},
        )

    # 1. Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)
    has_xfo = "x-frame-options" in headers
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not has_xfo and not has_frame_ancestors:
        findings.append(Finding(
            finding_id=_fid("clickjacking", device_id),
            device_id=device_id,
            check_name="missing_clickjacking_protection",
            description=(
                f"Web interface at {full_url} lacks anti-framing protections "
                f"(missing X-Frame-Options and CSP frame-ancestors). Vulnerable to UI clickjacking."
            ),
            cvss=4.3,
            damage={"privacy": 1, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    # 2. Content Security Policy (CSP)
    if not csp:
        findings.append(Finding(
            finding_id=_fid("missing_csp", device_id),
            device_id=device_id,
            check_name="missing_csp_header",
            description=f"Web management at {full_url} does not enforce Content-Security-Policy (CSP).",
            cvss=3.7,
            damage={"privacy": 1},
            evidence_path=evidence_path,
        ))

    # 3. MIME-Sniffing Protection (X-Content-Type-Options)
    if "x-content-type-options" not in headers:
        findings.append(Finding(
            finding_id=_fid("missing_xcto", device_id),
            device_id=device_id,
            check_name="missing_nosniff_header",
            description=f"Web service at {full_url} lacks 'X-Content-Type-Options: nosniff'.",
            cvss=3.1,
            damage={},
        ))

    # 4. Cleartext HTTP / Missing HSTS (if running unencrypted HTTP on port 80)
    if scheme == "http":
        findings.append(Finding(
            finding_id=_fid("cleartext_http", device_id),
            device_id=device_id,
            check_name="cleartext_web_transport",
            description=(
                f"Web administrative interface at {full_url} is served over unencrypted plaintext HTTP. "
                f"Session tokens and credentials transmitted in cleartext on local network."
            ),
            cvss=6.5,
            damage={"privacy": 2, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))
    elif scheme == "https" and "strict-transport-security" not in headers:
        findings.append(Finding(
            finding_id=_fid("missing_hsts", device_id),
            device_id=device_id,
            check_name="missing_hsts_header",
            description=f"HTTPS service at {full_url} lacks Strict-Transport-Security (HSTS).",
            cvss=3.7,
            damage={"privacy": 1},
        ))

    # 5. Cookie Security Flag Audit
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies_lower = set_cookie.lower()
        missing_flags = []
        if "httponly" not in cookies_lower:
            missing_flags.append("HttpOnly (accessible to JavaScript / XSS)")
        if "secure" not in cookies_lower and scheme == "https":
            missing_flags.append("Secure (transmitted over cleartext HTTP)")
        if "samesite" not in cookies_lower:
            missing_flags.append("SameSite (CSRF exposure)")

        if missing_flags:
            findings.append(Finding(
                finding_id=_fid("insecure_cookie", device_id),
                device_id=device_id,
                check_name="insecure_cookie_flags",
                description=(
                    f"Session cookie on {full_url} missing security flags: {', '.join(missing_flags)}."
                ),
                cvss=5.3,
                damage={"privacy": 2, "chaining_depth": 1},
                evidence_path=evidence_path,
            ))

    # 6. LuCI Management Interface Check
    if "/cgi-bin/luci" in path or "luci" in body.lower() or "luci" in headers.get("server", "").lower():
        findings.append(Finding(
            finding_id=_fid("luci_detected", device_id),
            device_id=device_id,
            check_name="luci_interface_detected",
            description=f"OpenWrt LuCI web management console identified at {full_url} (HTTP {status}).",
            cvss=None,
            damage={"chaining_depth": 1},
        ))

    return findings
