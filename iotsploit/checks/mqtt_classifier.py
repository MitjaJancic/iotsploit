"""
mqtt_classifier.py

Advanced MQTT topic namespace classification and authentication posture assessment.
Subscribes to broker wildcards (#) to discover active communication channels,
categorizing them into functional risk tiers:
1. Actuator & Physical Access (Door/Lock/Relay commands)
2. Telemetry & Sensor Privacy (Presence/Motion/Power)
3. Bridge Administration & Pivot Points (Zigbee2MQTT/HomeAssistant configs)
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


# Categorization regex heuristics
_ACTUATOR_PATTERN = re.compile(
    r"(?i)(/relay/|/command|/set|/switch/|/lock/|/door/|/gate/|/strike/|/actuator/)"
)
_TELEMETRY_PATTERN = re.compile(
    r"(?i)(/tele/|/state|/sensor|/motion|/presence|/temperature|/power|/energy|/lux|/status)"
)
_ADMIN_BRIDGE_PATTERN = re.compile(
    r"(?i)(bridge/config|bridge/request|homeassistant/|\\$SYS/|tasmota/discovery)"
)

DEFAULT_EMBEDDED_CREDS = [
    ("", ""),
    ("mqtt", "mqtt"),
    ("admin", "admin"),
    ("root", "root"),
    ("iot", "iot"),
]


def classify_topics(topic_list: list[str]) -> dict[str, list[str]]:
    """Classifies a list of MQTT topics into functional risk tiers."""
    categorized: dict[str, list[str]] = {
        "actuator": [],
        "telemetry": [],
        "bridge_admin": [],
        "uncategorized": [],
    }

    for topic in topic_list:
        if _ACTUATOR_PATTERN.search(topic):
            categorized["actuator"].append(topic)
        elif _ADMIN_BRIDGE_PATTERN.search(topic):
            categorized["bridge_admin"].append(topic)
        elif _TELEMETRY_PATTERN.search(topic):
            categorized["telemetry"].append(topic)
        else:
            categorized["uncategorized"].append(topic)

    return categorized


def classify_mqtt_broker(target: str, port: int = 1883,
                         sample_duration: float = 2.5,
                         device_id: str | None = None,
                         evidence_store=None) -> list[Finding]:
    """
    Connects to the target MQTT broker, checks authentication enforcement,
    and samples the topic tree via wildcard (#) subscription.
    """
    device_id = device_id or f"mqtt_{target.replace('.', '_')}"
    findings: list[Finding] = []

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        return [Finding(
            finding_id=_fid("mqtt_missing_dep", device_id),
            device_id=device_id,
            check_name="mqtt_classifier",
            description="paho-mqtt library is not installed in current environment.",
            cvss=None,
            damage={},
        )]

    discovered_topics: set[str] = set()
    auth_success_creds: tuple[str, str] | None = None

    def on_message(_client, _userdata, msg):
        discovered_topics.add(msg.topic)

    # 1. Test authentication configuration
    for user, pwd in DEFAULT_EMBEDDED_CREDS:
        conn_code = None

        def on_connect(_client, _userdata, _flags, rc):
            nonlocal conn_code
            conn_code = rc

        try:
            client = mqtt.Client(client_id=f"iotsploit_{uuid.uuid4().hex[:6]}")
            client.on_connect = on_connect
            client.on_message = on_message
            if user:
                client.username_pw_set(user, pwd)

            client.connect(target, port, keepalive=10)
            client.loop_start()

            # Wait briefly for CONNACK
            start_wait = time.time()
            while conn_code is None and (time.time() - start_wait) < 1.5:
                time.sleep(0.05)

            if conn_code == 0:
                auth_success_creds = (user, pwd)
                # Subscribe to wildcard to map namespaces
                client.subscribe("#", qos=0)
                client.subscribe("$SYS/#", qos=0)
                time.sleep(sample_duration)
                client.loop_stop()
                client.disconnect()
                break

            client.loop_stop()
            client.disconnect()
        except Exception:
            continue

    if auth_success_creds is None:
        findings.append(Finding(
            finding_id=_fid("mqtt_auth_enforced", device_id),
            device_id=device_id,
            check_name="mqtt_auth_enforced",
            description=f"MQTT broker at {target}:{port} strictly rejected unauthenticated & default credentials.",
            cvss=None,
            damage={},
        ))
        return findings

    user, pwd = auth_success_creds
    cred_desc = "ANONYMOUS access" if not user else f"DEFAULT credentials ('{user}:{pwd}')"
    findings.append(Finding(
        finding_id=_fid("mqtt_access_granted", device_id),
        device_id=device_id,
        check_name="mqtt_auth_posture",
        description=f"MQTT broker at {target}:{port} accepted {cred_desc}.",
        cvss=7.5,
        damage={"privacy": 2, "chaining_depth": 1},
    ))

    # 2. Topic categorization analysis
    classified = classify_topics(sorted(list(discovered_topics)))

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_json(
            _fid("mqtt_classified", device_id),
            "classified_topics",
            {"discovered_topics": sorted(list(discovered_topics)), "classified": classified},
        )

    # A. Actuator & Lock Control Topics
    if classified["actuator"]:
        sample = "; ".join(classified["actuator"][:4])
        more = f" (+{len(classified['actuator']) - 4} more)" if len(classified["actuator"]) > 4 else ""
        findings.append(Finding(
            finding_id=_fid("mqtt_actuators", device_id),
            device_id=device_id,
            check_name="mqtt_actuator_exposure",
            description=(
                f"Discovered {len(classified['actuator'])} physical actuator/lock command topic(s): "
                f"{sample}{more}. Unauthorized publishing can actuate locks or relays."
            ),
            cvss=8.6,
            damage={"physical_safety": 3, "chaining_depth": 2, "availability": 2},
            evidence_path=evidence_path,
        ))

    # B. Bridge Administration & Hub Config Topics
    if classified["bridge_admin"]:
        sample = "; ".join(classified["bridge_admin"][:3])
        findings.append(Finding(
            finding_id=_fid("mqtt_bridge_admin", device_id),
            device_id=device_id,
            check_name="mqtt_bridge_pivot",
            description=(
                f"Discovered {len(classified['bridge_admin'])} bridge/hub administrative topic(s): {sample}. "
                f"Exposes central controller reconfiguration & RF device pairing."
            ),
            cvss=7.2,
            damage={"chaining_depth": 2, "availability": 1},
            evidence_path=evidence_path,
        ))

    # C. Telemetry & Sensor Topics
    if classified["telemetry"]:
        findings.append(Finding(
            finding_id=_fid("mqtt_telemetry", device_id),
            device_id=device_id,
            check_name="mqtt_telemetry_exposure",
            description=(
                f"Discovered {len(classified['telemetry'])} sensor/telemetry topic(s) exposing live state."
            ),
            cvss=5.3,
            damage={"privacy": 2, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    if not discovered_topics:
        findings.append(Finding(
            finding_id=_fid("mqtt_idle", device_id),
            device_id=device_id,
            check_name="mqtt_topic_summary",
            description=f"Broker at {target}:{port} connected successfully, but no retained topics or messages observed in sampling window.",
            cvss=None,
            damage={},
        ))

    return findings
