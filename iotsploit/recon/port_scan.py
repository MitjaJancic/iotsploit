"""
port_scan.py

Lightweight TCP connect-scan over a set of ports relevant to common
IoT protocols. Deliberately not vendor-specific - the PORT_MAP below
is the only place protocol-to-port knowledge lives, so extending to
a new protocol is a one-line change here, not a new module.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

PORT_MAP = {
    80: "http",
    443: "https",
    1883: "mqtt",
    8883: "mqtt-tls",
    502: "modbus",
    5683: "coap",
    554: "rtsp",
}


@dataclass
class PortResult:
    ip: str
    port: int
    protocol_guess: str
    open: bool


def scan_host(ip: str, ports: list[int] | None = None, timeout_s: float = 0.5) -> list[PortResult]:
    ports = ports or list(PORT_MAP.keys())
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        is_open = False
        try:
            sock.connect((ip, port))
            is_open = True
        except OSError:
            is_open = False
        finally:
            sock.close()
        results.append(PortResult(ip=ip, port=port,
                                   protocol_guess=PORT_MAP.get(port, "unknown"),
                                   open=is_open))
    return results


def scan_subnet(subnet_hosts: list[str], ports: list[int] | None = None) -> dict[str, list[PortResult]]:
    return {ip: scan_host(ip, ports) for ip in subnet_hosts}
