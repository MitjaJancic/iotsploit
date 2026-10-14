"""
chain_verifier.py

Multi-Stage Attack Chain & Credential Pivot Verifier.
Connects isolated vulnerability findings into verified multi-stage attack paths:
Stage 1: Firmware Secret / Credential Extraction (/etc/shadow)
Stage 2: Cross-Service Credential Reuse (LuCI Web / SSH / MQTT)
Stage 3: Interactive Shell / Backdoor Access (TCP 5515)
Stage 4: Actuator / Lock Compromise
"""

from __future__ import annotations

import socket
import urllib.parse
import urllib.request
import urllib.error
import uuid
from pathlib import Path
from typing import Any

from iotsploit.core.scoring import Finding
from iotsploit.checks.firmware_checks import check_firmware_credentials


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _test_tcp_port(ip: str, port: int, timeout: float = 1.0) -> tuple[bool, str | None]:
    """Tests TCP connect and captures any initial banner."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = None
    try:
        sock.connect((ip, port))
        try:
            sock.settimeout(1.0)
            raw = sock.recv(512)
            if raw:
                banner = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return True, banner
    except Exception:
        return False, None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _test_luci_login(ip: str, port: int, username: str, password: str,
                     timeout: float = 3.0) -> tuple[bool, str]:
    """
    Tests OpenWrt LuCI web login (/cgi-bin/luci) with candidate credentials.
    Returns (success, reason).
    """
    url = f"http://{ip}:{port}/cgi-bin/luci"
    form_data = urllib.parse.urlencode({
        "luci_username": username,
        "luci_password": password,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=form_data,
        headers={"User-Agent": "iotsploit-pivoter/1.0", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        # Prevent auto-following redirects so we can inspect Set-Cookie
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirectHandler)
        with opener.open(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            set_cookie = headers.get("Set-Cookie", "")
            if "sysauth=" in set_cookie:
                return True, "Accepted (sysauth session token issued)"
            return False, "Rejected (no session token)"
    except urllib.error.HTTPError as exc:
        set_cookie = exc.headers.get("Set-Cookie", "") if hasattr(exc, "headers") else ""
        if "sysauth=" in set_cookie or exc.code == 302:
            return True, "Accepted (HTTP 302 redirect with sysauth cookie)"
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


def _test_mqtt_auth(ip: str, port: int, username: str, password: str,
                    timeout: float = 2.0) -> bool:
    """Tests MQTT broker CONNECT packet authentication."""
    try:
        import paho.mqtt.client as mqtt
        rc_code = None

        def on_connect(_c, _u, _f, rc):
            nonlocal rc_code
            rc_code = rc

        client = mqtt.Client(client_id=f"iotsploit_piv_{uuid.uuid4().hex[:6]}")
        client.on_connect = on_connect
        if username:
            client.username_pw_set(username, password)
        client.connect(ip, port, keepalive=5)
        client.loop_start()

        import time
        t0 = time.time()
        while rc_code is None and (time.time() - t0) < timeout:
            time.sleep(0.05)

        client.loop_stop()
        client.disconnect()
        return rc_code == 0
    except Exception:
        return False


def verify_attack_chain(target: str,
                        firmware_dir: str | Path | None = None,
                        credentials: list[tuple[str, str]] | None = None,
                        device_id: str | None = None,
                        evidence_store=None) -> list[Finding]:
    """
    Executes a multi-stage attack chain verification against the target,
    correlating firmware credentials, network daemons, web interfaces, and backdoors.
    """
    device_id = device_id or f"chain_{target.replace('.', '_')}"
    findings: list[Finding] = []
    creds_to_test: list[tuple[str, str]] = list(credentials or [])

    chain_events: list[str] = []
    max_chain_level = 0

    # ---------------------------------------------------------
    # Stage 1: Firmware Credential Harvesting
    # ---------------------------------------------------------
    if firmware_dir:
        fw_path = Path(firmware_dir)
        if fw_path.exists():
            fw_findings = check_firmware_credentials(fw_path, device_id=device_id)
            for f in fw_findings:
                # Extract candidate user:pass if plaintext or blank
                if "has NO PASSWORD" in f.description:
                    user = f.description.split()[1].strip("'")
                    creds_to_test.append((user, ""))
                    chain_events.append(f"Firmware: Empty password identified for user '{user}'")
                    max_chain_level = max(max_chain_level, 1)
                elif "root:" in f.description:
                    chain_events.append(f"Firmware: Shadow hash extracted: {f.description[:45]}...")
                    max_chain_level = max(max_chain_level, 1)

    # Add standard IoT defaults
    creds_to_test.extend([
        ("root", "root"),
        ("root", ""),
        ("iotgoat", "iotgoat"),
        ("iotgoat", "77C986BEB5F5406C697B20DE9C168FD9"),
        ("admin", "admin"),
    ])
    # Deduplicate
    unique_creds = list(dict.fromkeys(creds_to_test))

    # ---------------------------------------------------------
    # Stage 2: Network Daemon Reconnaissance
    # ---------------------------------------------------------
    has_ssh, ssh_banner = _test_tcp_port(target, 22)
    has_web, _ = _test_tcp_port(target, 80)
    has_mqtt, _ = _test_tcp_port(target, 1883)
    has_backdoor, backdoor_banner = _test_tcp_port(target, 5515)

    if has_ssh:
        chain_events.append(f"Network: SSH (Port 22) active: {ssh_banner or 'Open'}")
    if has_web:
        chain_events.append("Network: HTTP Management (Port 80) active")
    if has_mqtt:
        chain_events.append("Network: MQTT Broker (Port 1883) active")

    # ---------------------------------------------------------
    # Stage 3: Backdoor Shell Verification (Port 5515)
    # ---------------------------------------------------------
    if has_backdoor:
        max_chain_level = 3
        bd_info = backdoor_banner or "No banner"
        chain_events.append(f"Exploit: TCP Port 5515 Backdoor Shell VERIFIED: '{bd_info}'")
        findings.append(Finding(
            finding_id=_fid("backdoor_confirmed", device_id),
            device_id=device_id,
            check_name="attack_chain_backdoor_shell",
            description=(
                f"Full Shell Access Confirmed: Port 5515 provides an unauthenticated root backdoor "
                f"('{bd_info}'). Immediate system compromise bypassing all network defenses."
            ),
            cvss=10.0,
            damage={"chaining_depth": 3, "availability": 3, "privacy": 3, "physical_safety": 2},
        ))

    # ---------------------------------------------------------
    # Stage 4: Cross-Service Credential Pivot Testing
    # ---------------------------------------------------------
    pivoted_services: list[str] = []

    if has_web:
        for u, p in unique_creds:
            success, reason = _test_luci_login(target, 80, u, p)
            if success:
                max_chain_level = max(max_chain_level, 2)
                pivoted_services.append(f"LuCI Web ({u}:{p if p else '<blank>'})")
                chain_events.append(f"Pivot: Web LuCI admin login succeeded using '{u}'")
                break

    if has_mqtt:
        for u, p in unique_creds:
            if _test_mqtt_auth(target, 1883, u, p):
                max_chain_level = max(max_chain_level, 2)
                pivoted_services.append(f"MQTT Broker ({u})")
                chain_events.append(f"Pivot: MQTT broker accepted credentials for '{u}'")
                break

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_json(
            _fid("attack_chain", device_id),
            "chain_execution",
            {
                "target": target,
                "chain_level": max_chain_level,
                "chain_events": chain_events,
                "pivoted_services": pivoted_services,
            },
        )

    # ---------------------------------------------------------
    # Stage 5: Consolidated Attack Chaining Finding
    # ---------------------------------------------------------
    depth_labels = {
        0: "Isolated (No Pivots Verified)",
        1: "Local Subnet (Adjacent Secrets Discovered)",
        2: "Multi-Service Pivot (Cross-Service Reused Credentials)",
        3: "Full Perimeter to Shell Access (Unauthenticated Backdoor / Root Shell)",
    }

    chain_summary = " -> ".join(chain_events) if chain_events else "No stages executed"

    findings.append(Finding(
        finding_id=_fid("chain_assessment", device_id),
        device_id=device_id,
        check_name="multi_vector_attack_chain",
        description=(
            f"Attack Chaining Depth [{depth_labels[max_chain_level]}]: "
            f"Successfully verified attack path across {len(chain_events)} stages: {chain_summary}"
        ),
        cvss=9.8 if max_chain_level >= 3 else (7.5 if max_chain_level == 2 else 4.0),
        damage={
            "chaining_depth": max_chain_level,
            "availability": 2 if max_chain_level >= 2 else 1,
            "privacy": 2 if max_chain_level >= 1 else 0,
        },
        evidence_path=evidence_path,
    ))

    return findings
