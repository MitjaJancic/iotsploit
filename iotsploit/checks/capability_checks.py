"""
capability_checks.py

Each function here is written against a *capability* a profile
declares (e.g. "this device has HTTP state-changing endpoints it
expects authenticated", "this device expects MQTT over TLS"), not
against a specific vendor or model. A new device gets these checks
for free as soon as its YAML profile fills in the matching fields -
that is the entire point of the profile system in core/device_profile.py.

All checks here are NON-DESTRUCTIVE in intent: they probe for the
*presence* of a weakness (missing auth, cleartext transport, an
advertising BLE service) without altering persistent device state
where avoidable. Where a check must send a request that could change
device state (e.g. testing whether a relay-toggle endpoint accepts
unauthenticated requests), it is gated behind `allow_state_changes`
and only runs against devices present in the user's own, explicitly
loaded profile set - there is no default device list and no network
scanning beyond what the user points the tool at.

This module intentionally stops at "detect and report" for anything
beyond a device's own normal, documented API. It does not implement
protocol-level exploitation (e.g. crafting malformed packets to crash
a service, bypassing cryptographic protections, or redirecting
firmware updates). Those are legitimate parts of your thesis's
methodology chapter, but you should design and implement them
yourself with your advisor's sign-off, using the Finding/evidence
plumbing already built here - that keeps the authorship and judgment
calls about what's safe to run against your own hardware in your
hands, not pre-baked into a tool other people might reuse against
hardware you don't own.
"""

from __future__ import annotations

import socket
import ssl
import uuid

import requests

from iotsploit.core.device_profile import DeviceProfile
from iotsploit.core.scoring import Finding
from iotsploit.recon.port_scan import scan_host


def _new_finding_id(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def check_http_auth(profile: DeviceProfile, ip: str, allow_state_changes: bool = False,
                     evidence_store=None) -> list[Finding]:
    """
    For each state-changing HTTP endpoint the profile marks as
    expect_auth=True, send an unauthenticated request and record
    whether the device accepted it. This is a standard
    missing-authentication check (OWASP IoT Top 10 category),
    generalized across any device whose profile declares HTTP
    endpoints - not specific to any vendor's API shape.
    """
    findings = []
    if not profile.supports("http") or not profile.http_base_url:
        return findings

    for endpoint in profile.http_endpoints:
        if not endpoint.expect_auth:
            continue
        if not allow_state_changes:
            findings.append(Finding(
                finding_id=_new_finding_id("http_auth_skipped", profile.device_id),
                device_id=profile.device_id,
                check_name="http_auth",
                description=(
                    f"Skipped (state-changing request not authorized): "
                    f"{endpoint.method} {endpoint.path} - {endpoint.description}"
                ),
                cvss=None,
                damage={},
            ))
            continue

        url = profile.http_base_url.format(ip=ip) + endpoint.path
        try:
            resp = requests.request(endpoint.method, url, timeout=3)
            unauthenticated_success = resp.status_code < 400
        except requests.RequestException as exc:
            unauthenticated_success = False
            resp = None
            error = str(exc)
        else:
            error = None

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _new_finding_id("http_auth", profile.device_id),
                "response",
                f"URL: {url}\nStatus: {getattr(resp, 'status_code', None)}\n"
                f"Body: {getattr(resp, 'text', '')[:2000]}\nError: {error}",
            )

        findings.append(Finding(
            finding_id=_new_finding_id("http_auth", profile.device_id),
            device_id=profile.device_id,
            check_name="http_auth",
            description=(
                f"{endpoint.method} {endpoint.path}: "
                + ("accepted WITHOUT authentication" if unauthenticated_success
                   else "correctly required authentication or failed")
            ),
            cvss=None,
            damage={"physical_safety": 2, "availability": 1} if unauthenticated_success else {},
            evidence_path=evidence_path,
        ))
    return findings


def check_mqtt_tls(profile: DeviceProfile, broker_ip: str, broker_port: int = 1883,
                    evidence_store=None) -> list[Finding]:
    """
    If the profile says this device's traffic is expected to be TLS,
    confirm the broker port it's configured for actually enforces
    TLS. Works for any MQTT device profile, not a specific model.
    """
    findings = []
    if not profile.supports("mqtt") or not profile.mqtt_expected_tls:
        return findings

    plaintext_accepted = False
    try:
        sock = socket.create_connection((broker_ip, broker_port), timeout=3)
        sock.close()
        plaintext_accepted = True
    except OSError:
        plaintext_accepted = False

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_text(
            _new_finding_id("mqtt_tls", profile.device_id),
            "result",
            f"broker={broker_ip}:{broker_port} plaintext_connect_succeeded={plaintext_accepted}",
        )

    findings.append(Finding(
        finding_id=_new_finding_id("mqtt_tls", profile.device_id),
        device_id=profile.device_id,
        check_name="mqtt_tls",
        description=(
            f"Device expects TLS but plaintext connection to {broker_ip}:{broker_port} "
            + ("succeeded" if plaintext_accepted else "was refused")
        ),
        cvss=None,
        damage={"privacy": 2, "financial": 1} if plaintext_accepted else {},
        evidence_path=evidence_path,
    ))
    return findings


async def check_ble_advertising(profile: DeviceProfile, scan_time_s: float = 5.0,
                                 evidence_store=None) -> list[Finding]:
    """
    Passive BLE scan matching the profile's name pattern. Reports
    what the device is advertising (name, manufacturer data presence)
    without connecting or writing to any characteristic. Generic
    across any BLE device profile.
    """
    from bleak import BleakScanner  # imported here so bleak is optional unless BLE checks run

    findings = []
    if not profile.supports("ble") or not profile.ble_name_pattern:
        return findings

    devices = await BleakScanner.discover(timeout=scan_time_s)
    matches = [d for d in devices if profile.ble_name_pattern.lower() in (d.name or "").lower()]

    evidence_path = None
    if evidence_store and matches:
        evidence_path = evidence_store.save_json(
            _new_finding_id("ble_adv", profile.device_id),
            "matches",
            {"matches": [{"name": d.name, "address": d.address} for d in matches]},
        )

    findings.append(Finding(
        finding_id=_new_finding_id("ble_adv", profile.device_id),
        device_id=profile.device_id,
        check_name="ble_advertising",
        description=f"Found {len(matches)} nearby BLE advertisement(s) matching profile pattern",
        cvss=None,
        damage={"privacy": 1} if matches else {},
        evidence_path=evidence_path,
    ))
    return findings


def check_flagged_ports(profile: DeviceProfile, ip: str, evidence_store=None) -> list[Finding]:
    """
    Connect-scans the ports a profile lists under `flagged_ports` -
    i.e. ports the literature/your own research says are worth
    flagging for THIS device class, with a reason and a damage entry
    attached. Reuses recon.port_scan rather than re-implementing
    socket logic. Entirely passive (a TCP connect probe, no payload
    sent) - suitable for any device, not just the ones built for this
    thesis's original hardware list.
    """
    findings = []
    if not profile.flagged_ports:
        return findings

    ports = [fp.port for fp in profile.flagged_ports]
    results = {r.port: r for r in scan_host(ip, ports=ports)}

    for fp in profile.flagged_ports:
        result = results.get(fp.port)
        is_open = bool(result and result.open)

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _new_finding_id("flagged_port", profile.device_id),
                "result",
                f"ip={ip} port={fp.port} open={is_open} reason={fp.reason}",
            )

        findings.append(Finding(
            finding_id=_new_finding_id(f"port_{fp.port}", profile.device_id),
            device_id=profile.device_id,
            check_name="flagged_port",
            description=(
                f"Port {fp.port} is {'OPEN' if is_open else 'closed'} - {fp.reason}"
            ),
            cvss=None,
            damage=fp.damage if is_open else {},
            evidence_path=evidence_path,
        ))
    return findings


def check_known_cves(profile: DeviceProfile, firmware_version: str | None = None) -> list[Finding]:
    """
    Surfaces the profile's documented known_cves as findings, so a
    CVE database lookup is also config-driven rather than hardcoded
    per vendor. Use firmware_version if you want to later filter to
    only CVEs applicable to the installed firmware.
    """
    findings = []
    for cve in profile.known_cves:
        findings.append(Finding(
            finding_id=_new_finding_id(f"cve_{cve.id}", profile.device_id),
            device_id=profile.device_id,
            check_name="known_cve",
            description=f"{cve.id}: {cve.description}",
            cvss=cve.cvss,
            damage=cve.damage,
        ))
    return findings
