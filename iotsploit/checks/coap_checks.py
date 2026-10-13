"""
coap_checks.py

CoAP is the protocol several real smart-home devices (Philips Hue
bridges, some Shelly firmware variants) speak instead of HTTP. This
follows the exact same pattern as check_http_auth: send a read-only
GET to a profile-declared endpoint with no credentials, see if it's
accepted when it shouldn't be.

Deliberately GET-only. CoAP's state-changing verbs (PUT/POST) are not
sent by this check at all, authorized or not - unlike check_http_auth,
which does send its state-changing request once authorized. Confirming
a resource is *readable* without auth is still a real, citable finding
(CoAP's `/.well-known/core` resource discovery alone can leak device
capabilities), without needing to actually change anything to prove it.
"""

from __future__ import annotations

import socket
import struct
import uuid

from iotsploit.core.device_profile import DeviceProfile
from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


def _encode_coap_get(path: str, message_id: int) -> bytes:
    """Minimal CoAP GET: Ver=1, Type=CON, TKL=0, Code=0.01 (GET)."""
    header = bytes([0x40, 0x01]) + struct.pack(">H", message_id)
    options = b""
    prev_option_num = 0
    for segment in [s for s in path.split("/") if s]:
        delta = 11 - prev_option_num  # Uri-Path = option 11
        seg_bytes = segment.encode()
        if delta < 13 and len(seg_bytes) < 13:
            options += bytes([(delta << 4) | len(seg_bytes)]) + seg_bytes
        else:
            # Path segments this long/many aren't expected for the simple
            # diagnostic/resource paths this check targets - skip rather
            # than implement CoAP's extended option-length encoding.
            continue
        prev_option_num = 11
    return header + options


def _response_class(resp: bytes) -> int | None:
    if len(resp) < 2:
        return None
    code = resp[1]
    return code >> 5  # CoAP code is class.detail, e.g. 2.05 -> class 2


def check_coap_auth(profile: DeviceProfile, ip: str, port: int = 5683,
                     timeout: float = 4.0, evidence_store=None) -> list[Finding]:
    findings = []
    if not profile.coap_endpoints:
        return findings

    for endpoint in profile.coap_endpoints:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        message_id = uuid.uuid4().int & 0xFFFF
        request = _encode_coap_get(endpoint.path, message_id)

        try:
            sock.sendto(request, (ip, port))
            resp, _ = sock.recvfrom(4096)
            resp_class = _response_class(resp)
        except socket.timeout:
            resp = None
            resp_class = None
        except OSError as exc:
            findings.append(Finding(
                finding_id=_fid("coap_auth", profile.device_id), device_id=profile.device_id,
                check_name="coap_auth", description=f"CoAP request to {ip}:{port}{endpoint.path} failed: {exc}",
                cvss=None, damage={},
            ))
            continue
        finally:
            sock.close()

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("coap_auth", profile.device_id), "response",
                f"path={endpoint.path}\nresponse_class={resp_class}\nraw={resp!r}",
            )

        if resp_class is None:
            description = f"No CoAP response from {ip}:{port}{endpoint.path} (timeout or unreachable)."
            damage = {}
        elif resp_class == 2 and endpoint.expect_auth:
            description = (
                f"{endpoint.path}: CoAP GET succeeded (2.xx) with no credentials, "
                f"but this resource is expected to require auth."
            )
            damage = {"privacy": 1, "availability": 1}
        else:
            description = (
                f"{endpoint.path}: CoAP response class {resp_class}.xx - "
                + ("correctly required authentication/was rejected." if endpoint.expect_auth
                   else "reachable, as expected for a non-authenticated resource.")
            )
            damage = {}

        findings.append(Finding(
            finding_id=_fid("coap_auth", profile.device_id), device_id=profile.device_id,
            check_name="coap_auth", description=description, cvss=None,
            damage=damage, evidence_path=evidence_path,
        ))

    return findings
