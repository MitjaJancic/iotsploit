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
import urllib.request
import urllib.error
import uuid
from typing import Any

try:
    import requests
except ImportError:
    requests = None

from iotsploit.core.device_profile import DeviceProfile
from iotsploit.core.scoring import Finding
from iotsploit.recon.port_scan import scan_host


def _new_finding_id(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def skipped_finding(check_name: str, device_id: str, reason: str) -> Finding:
    """Standard helper to generate a skipped finding when authorization is absent."""
    return Finding(
        finding_id=_new_finding_id(f"{check_name}_skipped", device_id),
        device_id=device_id,
        check_name=check_name,
        description=f"Skipped (authorization required): {reason}",
        cvss=None,
        damage={},
    )


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
            findings.append(skipped_finding(
                "http_auth", profile.device_id,
                f"{endpoint.method} {endpoint.path} - {endpoint.description}"
            ))
            continue

        url = profile.http_base_url.format(ip=ip) + endpoint.path
        status_code = None
        resp_body = ""
        error = None

        if requests is not None:
            try:
                resp = requests.request(endpoint.method, url, timeout=3)
                status_code = resp.status_code
                resp_body = resp.text
                unauthenticated_success = status_code < 400
            except requests.RequestException as exc:
                unauthenticated_success = False
                error = str(exc)
        else:
            try:
                req = urllib.request.Request(url, method=endpoint.method)
                with urllib.request.urlopen(req, timeout=3) as resp_obj:
                    status_code = resp_obj.status
                    resp_body = resp_obj.read().decode("utf-8", errors="replace")
                    unauthenticated_success = status_code < 400
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                resp_body = exc.read().decode("utf-8", errors="replace")
                unauthenticated_success = status_code < 400
                error = str(exc)
            except Exception as exc:
                unauthenticated_success = False
                error = str(exc)

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _new_finding_id("http_auth", profile.device_id),
                "response",
                f"URL: {url}\nStatus: {status_code}\n"
                f"Body: {resp_body[:2000]}\nError: {error}",
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


def check_http_injection(profile: DeviceProfile, ip: str, allow_state_changes: bool = False,
                          delay_seconds: int = 4, evidence_store=None) -> list[Finding]:
    """
    Time-based blind command-injection detection against each
    endpoint's declared injectable_params. For each param, sends a
    handful of shell-metacharacter + `sleep N` payloads and compares
    response latency to an unmodified baseline request. A response
    that takes ~N seconds longer than baseline indicates the payload
    executed server-side, without ever needing to see command output.

    This is the same technique legitimate DAST scanners (Burp,
    Nuclei's command-injection templates, etc.) use, deliberately kept
    to the non-destructive half: the payload's only effect, if it
    executes, is a delay - no data read, no state changed, no shell
    retained. Gated behind authorization like check_http_auth, since
    it still sends real requests to a live device's state-changing
    surface.

    Requires injectable_params to be filled in on the profile first -
    this check does not guess parameter names, see
    core/device_profile.py's HttpEndpoint docstring.
    """
    import time

    findings = []
    if not profile.supports("http") or not profile.http_base_url:
        return findings

    payload_templates = [
        "; sleep {n} #",
        "| sleep {n}",
        "`sleep {n}`",
        "$(sleep {n})",
        "&& sleep {n}",
    ]

    for endpoint in profile.http_endpoints:
        if not endpoint.injectable_params:
            continue

        if not allow_state_changes:
            findings.append(skipped_finding(
                "http_injection", profile.device_id,
                f"{endpoint.method} {endpoint.path}, params={endpoint.injectable_params}"
            ))
            continue

        base_url = profile.http_base_url.format(ip=ip) + endpoint.path

        # Baseline timing, no payload.
        try:
            t0 = time.monotonic()
            requests.request(endpoint.method, base_url, timeout=delay_seconds + 5)
            baseline = time.monotonic() - t0
        except requests.RequestException as exc:
            findings.append(Finding(
                finding_id=_new_finding_id("http_injection", profile.device_id),
                device_id=profile.device_id,
                check_name="http_injection",
                description=f"Baseline request to {base_url} failed: {exc}",
                cvss=None, damage={},
            ))
            continue

        for param in endpoint.injectable_params:
            injected = False
            for template in payload_templates:
                payload_value = template.format(n=delay_seconds)
                sep = "&" if "?" in endpoint.path else "?"
                url = base_url + sep + endpoint.param_template.format(
                    param_name=param, value=requests.utils.quote(payload_value))

                evidence_path = None
                try:
                    t0 = time.monotonic()
                    resp = requests.request(endpoint.method, url, timeout=delay_seconds + 5)
                    elapsed = time.monotonic() - t0
                except requests.RequestException as exc:
                    continue

                if evidence_store:
                    evidence_path = evidence_store.save_text(
                        _new_finding_id("http_injection", profile.device_id), "timing",
                        f"url={url}\nbaseline={baseline:.2f}s elapsed={elapsed:.2f}s "
                        f"threshold={baseline + delay_seconds * 0.8:.2f}s",
                    )

                if elapsed >= baseline + delay_seconds * 0.8:
                    findings.append(Finding(
                        finding_id=_new_finding_id("http_injection", profile.device_id),
                        device_id=profile.device_id,
                        check_name="http_injection",
                        description=(
                            f"Likely command injection: param '{param}' on {endpoint.method} "
                            f"{endpoint.path} - response took {elapsed:.1f}s vs {baseline:.1f}s "
                            f"baseline after payload `{payload_value}` (time-based blind detection, "
                            f"no command output observed)."
                        ),
                        cvss=9.8,
                        damage={"physical_safety": 1, "privacy": 2, "financial": 1,
                                "availability": 2, "chaining_depth": 2},
                        evidence_path=evidence_path,
                    ))
                    injected = True
                    break  # one confirmed payload per param is enough

            if not injected:
                findings.append(Finding(
                    finding_id=_new_finding_id("http_injection", profile.device_id),
                    device_id=profile.device_id,
                    check_name="http_injection",
                    description=(
                        f"No timing anomaly for param '{param}' on {endpoint.method} {endpoint.path} "
                        f"across {len(payload_templates)} payloads - no injection detected "
                        f"(or the backend doesn't use a shell for this param)."
                    ),
                    cvss=None, damage={},
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


def check_mqtt_auth_enforcement(profile: DeviceProfile, ip: str, port: int = 1883,
                                evidence_store=None) -> list[Finding]:
    """
    Tests whether an MQTT broker enforces authentication using CONNECT-only packets.
    Tests:
    1. Anonymous connection attempt.
    2. Credentials explicitly declared in profile.mqtt_credentials_to_test.
    Disconnects immediately upon handshake completion (no publish/subscribe, no dictionary attack).
    """
    findings = []
    if not profile.supports("mqtt"):
        return findings

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        return findings

    import time

    def _probe_connect(username: str | None = None, password: str | None = None,
                       timeout: float = 4.0) -> tuple[int | None, str | None]:
        res: dict[str, Any] = {"rc": None, "error": None}

        def on_connect(client, userdata, flags, rc, properties=None):
            res["rc"] = rc
            try:
                client.disconnect()
            except Exception:
                pass

        client_kwargs: dict[str, Any] = {
            "client_id": f"iotsploit-{uuid.uuid4().hex[:6]}",
            "protocol": mqtt.MQTTv311,
        }
        if hasattr(mqtt, "CallbackAPIVersion"):
            client_kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION1

        try:
            client = mqtt.Client(**client_kwargs)
            client.on_connect = on_connect
            if username is not None:
                client.username_pw_set(username, password)
            client.connect(ip, port, keepalive=10)
            client.loop_start()

            waited = 0.0
            while res["rc"] is None and waited < timeout:
                time.sleep(0.05)
                waited += 0.05

            client.loop_stop()
            try:
                client.disconnect()
            except Exception:
                pass
        except Exception as exc:
            res["error"] = str(exc)

        return res["rc"], res["error"]

    # 1. Anonymous CONNECT probe
    anon_rc, _ = _probe_connect()
    if anon_rc == 0:
        fid = _new_finding_id("mqtt_anon_auth", profile.device_id)
        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_json(
                fid, "anonymous_connect",
                {"ip": ip, "port": port, "connack_rc": 0, "status": "accepted"}
            )
        findings.append(Finding(
            finding_id=fid,
            device_id=profile.device_id,
            check_name="mqtt_auth_enforcement",
            description=f"MQTT broker at {ip}:{port} accepted anonymous (unauthenticated) connection.",
            cvss=7.5,
            damage={"privacy": 2, "availability": 1, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    # 2. Declared credentials check (explicitly declared in profile only)
    creds_to_test = getattr(profile, "mqtt_credentials_to_test", []) or []
    for cred in creds_to_test:
        raw_user = cred.get("username", "")
        raw_pass = cred.get("password", "")
        rc, _ = _probe_connect(username=raw_user, password=raw_pass)

        # Mask sensitive values in output
        masked_user = (raw_user[:4] + "***") if len(raw_user) > 4 else "***"
        if rc == 0:
            fid = _new_finding_id("mqtt_cred_auth", profile.device_id)
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_json(
                    fid, "declared_credential",
                    {"ip": ip, "port": port, "username": masked_user, "connack_rc": 0, "status": "accepted"}
                )
            findings.append(Finding(
                finding_id=fid,
                device_id=profile.device_id,
                check_name="mqtt_auth_enforcement",
                description=f"MQTT broker at {ip}:{port} accepted valid credentials for account '{masked_user}'.",
                cvss=6.5,
                damage={"privacy": 2, "availability": 1, "chaining_depth": 1},
                evidence_path=evidence_path,
            ))

    return findings


def check_ble_access_control(profile: DeviceProfile, allow_state_changes: bool = False,
                             evidence_store=None) -> list[Finding]:
    """
    Audits GATT characteristic permissions metadata via passive inspection.
    Discovers device matching profile.ble_name_pattern and reads characteristic
    properties/metadata ONLY (no writes). Flags characteristics with 'write' or
    'write-without-response' that lack 'encrypt-write' or 'authenticated-signed-writes'.
    Never modifies device state.
    """
    import asyncio
    findings = []
    if not profile.supports("ble") or not profile.ble_name_pattern:
        return findings

    try:
        from bleak import BleakClient, BleakScanner
    except ImportError:
        return findings

    async def _inspect() -> list[Finding]:
        local_findings = []
        pattern = profile.ble_name_pattern.lower()
        devices = await BleakScanner.discover(timeout=5.0)
        target = next((d for d in devices if pattern in (d.name or "").lower()), None)
        if not target:
            return local_findings

        insecure_chars = []
        try:
            async with BleakClient(target.address, timeout=10.0) as client:
                for service in client.services:
                    for char in service.characteristics:
                        props = [p.lower() for p in char.properties]
                        has_write = "write" in props or "write-without-response" in props
                        has_auth = "encrypt-write" in props or "authenticated-signed-writes" in props
                        if has_write and not has_auth:
                            insecure_chars.append({
                                "service_uuid": str(service.uuid),
                                "characteristic_uuid": str(char.uuid),
                                "properties": props,
                            })
        except Exception:
            return local_findings

        if insecure_chars:
            fid = _new_finding_id("ble_access_control", profile.device_id)
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_json(
                    fid, "insecure_characteristics",
                    {
                        "device_address": target.address,
                        "device_name": target.name,
                        "characteristics": insecure_chars,
                    }
                )
            sample_uuids = ", ".join(c["characteristic_uuid"] for c in insecure_chars[:3])
            more = f" (+{len(insecure_chars) - 3} more)" if len(insecure_chars) > 3 else ""
            local_findings.append(Finding(
                finding_id=fid,
                device_id=profile.device_id,
                check_name="ble_access_control",
                description=(
                    f"GATT characteristic access control weakness: found {len(insecure_chars)} "
                    f"characteristic(s) allowing write operations without encryption/authentication: "
                    f"{sample_uuids}{more}"
                ),
                cvss=6.8,
                damage={"physical_safety": 1, "privacy": 1, "availability": 1, "chaining_depth": 1},
                evidence_path=evidence_path,
            ))
        return local_findings

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, _inspect()).result()
    else:
        return asyncio.run(_inspect())


def check_coap_auth_enforcement(profile: DeviceProfile, ip: str,
                                allow_state_changes: bool = False,
                                evidence_store=None) -> list[Finding]:
    """
    Assesses CoAP endpoint authentication enforcement.
    Sends read-only GET requests to all profile.coap_endpoints by default.
    Sends PUT/POST ONLY if allow_state_changes=True AND endpoint declares method as PUT/POST.
    Uses aiocoap Context; shuts down protocol after testing.
    """
    import asyncio
    findings = []
    if not profile.coap_endpoints:
        return findings

    try:
        import aiocoap
        from aiocoap import Message, Code
    except ImportError:
        return findings

    async def _run_coap() -> list[Finding]:
        local_findings = []
        try:
            context = await aiocoap.Context.create_client_context()
        except Exception:
            return local_findings

        try:
            for endpoint in profile.coap_endpoints:
                method = (endpoint.method or "GET").upper()

                # Dual authorization gate check for state-changing methods
                if method in ("PUT", "POST") and not allow_state_changes:
                    local_findings.append(skipped_finding(
                        "coap_auth_enforcement", profile.device_id,
                        f"state-changing {method} {endpoint.path}"
                    ))
                    continue

                code = Code.GET
                if method == "PUT" and allow_state_changes:
                    code = Code.PUT
                elif method == "POST" and allow_state_changes:
                    code = Code.POST

                uri = f"coap://{ip}/{endpoint.path.lstrip('/')}"
                request = Message(code=code, uri=uri)

                try:
                    response = await asyncio.wait_for(context.request(request).response, timeout=4.0)
                    is_success = response.code.is_successful()
                    resp_code = str(response.code)
                    payload_preview = repr(response.payload[:200])
                except Exception as exc:
                    is_success = False
                    resp_code = None
                    payload_preview = str(exc)

                fid = _new_finding_id("coap_auth", profile.device_id)
                evidence_path = None
                if evidence_store:
                    evidence_path = evidence_store.save_text(
                        fid, "response",
                        f"URI: {uri}\nMethod: {method}\nResponse Code: {resp_code}\nPayload: {payload_preview}",
                    )

                if is_success and endpoint.expect_auth:
                    local_findings.append(Finding(
                        finding_id=fid,
                        device_id=profile.device_id,
                        check_name="coap_auth_enforcement",
                        description=(
                            f"CoAP {method} {endpoint.path}: accepted WITHOUT authentication "
                            f"(response code {resp_code}) when authentication was expected."
                        ),
                        cvss=7.5,
                        damage={"physical_safety": 1, "privacy": 2, "availability": 1, "chaining_depth": 1},
                        evidence_path=evidence_path,
                    ))
        finally:
            await context.shutdown()

        return local_findings

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, _run_coap()).result()
    else:
        return asyncio.run(_run_coap())
