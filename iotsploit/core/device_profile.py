"""
device_profile.py

Loads a device profile (YAML) and exposes it as a typed object.
This is the file that makes the tool ecosystem-agnostic: adding a new
device to the audit means writing a profile, never touching checks/
or core/. See profiles/_template.yaml for the schema with comments.
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HttpEndpoint:
    path: str
    method: str = "GET"
    expect_auth: bool = True
    description: str = ""
    # Query/form param names that take user input and might reach a
    # shell unsafely (e.g. a diagnostics page's "host" field passed
    # into ping). Left empty by default - fill in once YOU have
    # identified the real param name via source/firmware analysis or
    # by inspecting the page, not guessed. See check_http_injection.
    injectable_params: list[str] = field(default_factory=list)
    # {param_name}} is substituted with each candidate payload in turn.
    param_template: str = "{param_name}={value}"


@dataclass
class FlaggedPort:
    port: int
    reason: str
    damage: dict[str, int]


@dataclass
class KnownCve:
    id: str
    description: str
    cvss: float | None
    damage: dict[str, int]  # physical_safety, privacy, financial, availability, chaining_depth


@dataclass
class DeviceProfile:
    device_id: str
    vendor: str
    model: str
    protocols: list[str]
    http_base_url: str | None
    http_endpoints: list[HttpEndpoint]
    mqtt_topic_prefix: str | None
    mqtt_expected_tls: bool
    ble_name_pattern: str | None
    known_cves: list[KnownCve]
    flagged_ports: list[FlaggedPort]
    coap_endpoints: list[HttpEndpoint]
    authorized: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def supports(self, protocol: str) -> bool:
        return protocol in self.protocols


def _parse_http(raw: dict) -> tuple[str | None, list[HttpEndpoint]]:
    http_cfg = raw.get("network", {}).get("http")
    if not http_cfg:
        return None, []
    base_url = http_cfg.get("base_url")
    endpoints = [
        HttpEndpoint(
            path=e["path"],
            method=e.get("method", "GET"),
            expect_auth=e.get("expect_auth", True),
            description=e.get("description", ""),
            injectable_params=e.get("injectable_params", []),
        )
        for e in http_cfg.get("state_changing_endpoints", [])
    ]
    return base_url, endpoints


def _parse_mqtt(raw: dict) -> tuple[str | None, bool]:
    mqtt_cfg = raw.get("network", {}).get("mqtt")
    if not mqtt_cfg:
        return None, False
    return mqtt_cfg.get("topic_prefix"), bool(mqtt_cfg.get("expected_tls", False))


def _parse_ble(raw: dict) -> str | None:
    ble_cfg = raw.get("network", {}).get("ble")
    if not ble_cfg:
        return None
    return ble_cfg.get("name_pattern")


def _parse_cves(raw: dict) -> list[KnownCve]:
    out = []
    for c in raw.get("known_cves", []):
        out.append(
            KnownCve(
                id=c["id"],
                description=c.get("description", ""),
                cvss=c.get("cvss"),
                damage=c.get("damage_score", {}),
            )
        )
    return out


def _parse_coap(raw: dict) -> list[HttpEndpoint]:
    coap_cfg = raw.get("network", {}).get("coap")
    if not coap_cfg:
        return []
    return [
        HttpEndpoint(
            path=e["path"],
            method=e.get("method", "GET"),
            expect_auth=e.get("expect_auth", True),
            description=e.get("description", ""),
        )
        for e in coap_cfg.get("endpoints", [])
    ]


def _parse_flagged_ports(raw: dict) -> list[FlaggedPort]:
    out = []
    for p in raw.get("flagged_ports", []):
        out.append(FlaggedPort(port=p["port"], reason=p.get("reason", ""),
                                damage=p.get("damage_score", {})))
    return out


def load_profile(path: str | Path) -> DeviceProfile:
    path = Path(path)
    raw = yaml.safe_load(path.read_text())

    http_base_url, http_endpoints = _parse_http(raw)
    mqtt_prefix, mqtt_tls = _parse_mqtt(raw)
    ble_pattern = _parse_ble(raw)

    return DeviceProfile(
        device_id=raw["device_id"],
        vendor=raw.get("vendor", "unknown"),
        model=raw.get("model", "unknown"),
        protocols=raw.get("protocols", []),
        http_base_url=http_base_url,
        http_endpoints=http_endpoints,
        mqtt_topic_prefix=mqtt_prefix,
        mqtt_expected_tls=mqtt_tls,
        ble_name_pattern=ble_pattern,
        known_cves=_parse_cves(raw),
        flagged_ports=_parse_flagged_ports(raw),
        coap_endpoints=_parse_coap(raw),
        authorized=bool(raw.get("authorized", False)),
        raw=raw,
    )


def load_profiles_dir(dir_path: str | Path) -> list[DeviceProfile]:
    dir_path = Path(dir_path)
    profiles = []
    for f in sorted(dir_path.glob("*.yaml")):
        if f.name.startswith("_"):
            continue  # skip templates
        profiles.append(load_profile(f))
    return profiles
