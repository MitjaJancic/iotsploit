"""
discovery.py

Generic mDNS/zeroconf discovery. Not tied to any vendor's service
name - pass in the service types you care about (e.g. Shelly
advertises _shelly._tcp, other vendors use other service types).
Extend the SERVICE_TYPES list per ecosystem rather than hardcoding
vendor logic elsewhere in the tool.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

SERVICE_TYPES = [
    "_shelly._tcp.local.",
    "_http._tcp.local.",
    "_hap._tcp.local.",   # HomeKit-accessory devices, useful if you extend beyond Shelly/Tapo
]


@dataclass
class DiscoveredDevice:
    name: str
    service_type: str
    address: str | None
    port: int | None


class _Listener(ServiceListener):
    def __init__(self):
        self.found: list[DiscoveredDevice] = []

    def add_service(self, zc, service_type, name):
        info = zc.get_service_info(service_type, name)
        if info is None:
            return
        addr = info.parsed_addresses()[0] if info.parsed_addresses() else None
        self.found.append(DiscoveredDevice(name=name, service_type=service_type,
                                            address=addr, port=info.port))

    def update_service(self, zc, service_type, name):
        pass

    def remove_service(self, zc, service_type, name):
        pass


def discover(service_types: list[str] | None = None, timeout_s: float = 5.0) -> list[DiscoveredDevice]:
    service_types = service_types or SERVICE_TYPES
    zc = Zeroconf()
    listener = _Listener()
    browsers = [ServiceBrowser(zc, st, listener) for st in service_types]
    try:
        time.sleep(timeout_s)
    finally:
        zc.close()
    return listener.found
