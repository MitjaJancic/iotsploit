"""
shelly_checks.py

Audits Shelly smart home and smart lock actuator devices (Shelly 1, Plus 1, Pro, LOQED).
Inspects for:
1. Unauthenticated Gen 1 HTTP endpoints (/status, /settings, /relay/0).
2. Unauthenticated Gen 2/Plus RPC endpoints (/rpc/Shelly.GetDeviceInfo, /rpc/Switch.Set).
3. The Gen 4 Open Access Point flaw (persistent unencrypted setup AP).
4. Safe, non-destructive Active Verification (momentary timed pulse actuation).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from typing import Any

from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _http_get_json(url: str, timeout: float = 3.0) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
    """Performs HTTP GET using standard library urllib."""
    req = urllib.request.Request(url, headers={"User-Agent": "iotsploit-auditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except Exception:
                data = None
            return status, data, headers
    except urllib.error.HTTPError as exc:
        return exc.code, None, dict(exc.headers)
    except Exception:
        return 0, None, {}


def check_shelly_open_ap(target: str = "192.168.33.1", device_id: str | None = None,
                          evidence_store=None, timeout: float = 2.5) -> list[Finding]:
    """
    Audits for the Shelly Gen 4 configuration flaw where the setup access point
    (AP) remains active and unencrypted after initial provisioning.
    Default AP gateway is 192.168.33.1.
    """
    device_id = device_id or f"shelly_ap_{target.replace('.', '_')}"
    findings: list[Finding] = []

    # Probe Gen 1 /status and Gen 2 /rpc/Shelly.GetDeviceInfo
    code_g1, data_g1, _ = _http_get_json(f"http://{target}/status", timeout=timeout)
    code_g2, data_g2, _ = _http_get_json(f"http://{target}/rpc/Shelly.GetDeviceInfo", timeout=timeout)

    is_shelly = (code_g1 == 200 and isinstance(data_g1, dict) and "relays" in data_g1) or \
                (code_g2 == 200 and isinstance(data_g2, dict) and "gen" in data_g2)

    if is_shelly:
        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_json(
                _fid("shelly_open_ap", device_id),
                "open_ap_response",
                {"g1": data_g1, "g2": data_g2},
            )
        findings.append(Finding(
            finding_id=_fid("shelly_open_ap", device_id),
            device_id=device_id,
            check_name="shelly_open_ap_vulnerability",
            description=(
                f"Open Setup AP flaw detected on {target}: unencrypted management interface is active "
                f"without authentication, allowing adjacent wireless attackers to bypass network security."
            ),
            cvss=8.8,
            damage={"physical_safety": 3, "chaining_depth": 3, "privacy": 2},
            evidence_path=evidence_path,
        ))

    return findings


def check_shelly_endpoints(target: str, port: int = 80,
                           allow_active_verification: bool = False,
                           device_id: str | None = None,
                           evidence_store=None,
                           timeout: float = 3.0) -> list[Finding]:
    """
    Audits Shelly relay and lock controllers for missing authentication.
    If allow_active_verification is True, issues a safe auto-reverting timed pulse (1s timer)
    to confirm solenoid/relay control non-destructively.
    """
    device_id = device_id or f"shelly_{target.replace('.', '_')}"
    base_url = f"http://{target}:{port}"
    findings: list[Finding] = []

    # 1. Audit Gen 2 / Plus / Pro RPC Interface
    g2_code, g2_info, _ = _http_get_json(f"{base_url}/rpc/Shelly.GetDeviceInfo", timeout=timeout)
    if g2_code == 200 and isinstance(g2_info, dict) and "gen" in g2_info:
        auth_en = g2_info.get("auth_en", False)
        model = g2_info.get("model", "Shelly Gen 2")
        dev_name = g2_info.get("id", device_id)

        if not auth_en:
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_json(
                    _fid("shelly_rpc_noauth", device_id), "device_info", g2_info
                )
            findings.append(Finding(
                finding_id=_fid("shelly_rpc_noauth", device_id),
                device_id=device_id,
                check_name="shelly_auth_bypass",
                description=(
                    f"{model} ({dev_name}) at {target}:{port} exposes Gen 2 RPC API WITHOUT authentication. "
                    f"Physical actuators and lock relays can be controlled via /rpc/Switch.Set."
                ),
                cvss=7.5,
                damage={"physical_safety": 3, "chaining_depth": 2, "availability": 1},
                evidence_path=evidence_path,
            ))

            # Non-destructive active verification: momentary 1-second pulse
            if allow_active_verification:
                pulse_url = f"{base_url}/rpc/Switch.Set?id=0&on=true&toggle_after=1"
                p_code, p_data, _ = _http_get_json(pulse_url, timeout=timeout)
                if p_code == 200 and isinstance(p_data, dict):
                    findings.append(Finding(
                        finding_id=_fid("shelly_active_actuation", device_id),
                        device_id=device_id,
                        check_name="shelly_active_verification",
                        description=(
                            f"Active Verification Confirmed: Momentary 1-second auto-reverting pulse successfully "
                            f"actuated {dev_name} relay via /rpc/Switch.Set."
                        ),
                        cvss=9.1,
                        damage={"physical_safety": 3, "chaining_depth": 3, "availability": 2},
                    ))
        return findings

    # 2. Audit Gen 1 HTTP Interface
    g1_code, g1_status, _ = _http_get_json(f"{base_url}/status", timeout=timeout)
    if g1_code == 200 and isinstance(g1_status, dict) and "relays" in g1_status:
        # Check /settings for password authentication
        s_code, s_settings, _ = _http_get_json(f"{base_url}/settings", timeout=timeout)
        login_enabled = False
        if s_code == 200 and isinstance(s_settings, dict):
            login_enabled = s_settings.get("login", {}).get("enabled", False)

        if not login_enabled:
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_json(
                    _fid("shelly_http_noauth", device_id), "status_response", g1_status
                )
            findings.append(Finding(
                finding_id=_fid("shelly_http_noauth", device_id),
                device_id=device_id,
                check_name="shelly_auth_bypass",
                description=(
                    f"Shelly Gen 1 device at {target}:{port} exposes HTTP management WITHOUT authentication. "
                    f"Relay endpoint /relay/0 is directly accessible."
                ),
                cvss=7.5,
                damage={"physical_safety": 3, "chaining_depth": 2, "availability": 1},
                evidence_path=evidence_path,
            ))

            # Non-destructive active verification: momentary 1-second pulse with auto-off timer
            if allow_active_verification:
                pulse_url = f"{base_url}/relay/0?turn=on&timer=1"
                p_code, p_data, _ = _http_get_json(pulse_url, timeout=timeout)
                if p_code == 200 and isinstance(p_data, dict) and p_data.get("ison") is True:
                    findings.append(Finding(
                        finding_id=_fid("shelly_active_actuation", device_id),
                        device_id=device_id,
                        check_name="shelly_active_verification",
                        description=(
                            f"Active Verification Confirmed: Momentary 1-second auto-reverting pulse successfully "
                            f"actuated relay 0 via /relay/0?turn=on&timer=1."
                        ),
                        cvss=9.1,
                        damage={"physical_safety": 3, "chaining_depth": 3, "availability": 2},
                    ))
        return findings

    # If port answered HTTP 401 Unauthorized
    if g1_code == 401 or g2_code == 401:
        findings.append(Finding(
            finding_id=_fid("shelly_auth_enforced", device_id),
            device_id=device_id,
            check_name="shelly_auth_enforced",
            description=f"Shelly device at {target}:{port} correctly requires authentication (HTTP 401).",
            cvss=None,
            damage={},
        ))
    else:
        findings.append(Finding(
            finding_id=_fid("shelly_check", device_id),
            device_id=device_id,
            check_name="shelly_check",
            description=f"No responsive Shelly Gen 1 or Gen 2 API identified at {target}:{port}.",
            cvss=None,
            damage={},
        ))

    return findings
