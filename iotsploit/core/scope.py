"""
scope.py

Network scope policy engine for iotsploit.
Ensures active checks, verification probes, and credential evaluations are strictly
confined to authorized lab CIDRs, preventing accidental external network leakage.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Sequence


class ScopeViolationError(PermissionError):
    """Raised when an operation targets an IP address outside authorized lab scope."""
    pass


DEFAULT_LAB_CIDRS = [
    "127.0.0.0/8",       # Local loopback / mock targets
    "192.168.0.0/16",    # Common RFC1918 private lab subnets
    "10.0.0.0/8",        # Private lab / virtual networks
    "172.16.0.0/12",     # Docker / private lab bridges
]


class LabContext:
    """Policy engine enforcing lab boundaries on active probes and verification actions."""

    def __init__(self, allowed_cidrs: Sequence[str] | None = None,
                 prohibited_cidrs: Sequence[str] | None = None,
                 enforce_scope: bool = True):
        self.enforce_scope = enforce_scope
        self.allowed_networks = [
            ipaddress.ip_network(cidr.strip(), strict=False) for cidr in (allowed_cidrs or DEFAULT_LAB_CIDRS)
        ]
        self.prohibited_networks = [
            ipaddress.ip_network(cidr.strip(), strict=False) for cidr in (prohibited_cidrs or [])
        ]

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> LabContext:
        """Loads scope config from YAML file or falls back to default lab scope."""
        path = Path(config_path) if config_path else Path("lab_context.yaml")
        if path.exists():
            try:
                import yaml
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                allowed = data.get("allowed_cidrs") or DEFAULT_LAB_CIDRS
                prohibited = data.get("prohibited_cidrs") or []
                enforce = data.get("enforce_scope", True)
                return cls(allowed_cidrs=allowed, prohibited_cidrs=prohibited, enforce_scope=enforce)
            except ImportError:
                # Basic line parsing fallback when PyYAML is not installed
                try:
                    text = path.read_text(encoding="utf-8")
                    allowed = []
                    in_allowed = False
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("allowed_cidrs:"):
                            in_allowed = True
                            continue
                        elif stripped and stripped.endswith(":") and not stripped.startswith("-"):
                            in_allowed = False
                        if in_allowed and stripped.startswith("- "):
                            val = stripped[2:].strip().strip("\"'")
                            if val:
                                allowed.append(val)
                    if allowed:
                        return cls(allowed_cidrs=allowed)
                except Exception:
                    pass
            except Exception:
                pass
        return cls()

    def resolve_ip(self, host: str) -> str:
        """Resolves target hostname to IPv4 address."""
        try:
            return socket.gethostbyname(host)
        except socket.error:
            return host

    def is_in_scope(self, target: str) -> bool:
        if not self.enforce_scope:
            return True
        resolved = self.resolve_ip(target)
        try:
            ip = ipaddress.ip_address(resolved)
        except ValueError:
            return False

        # Target must NOT belong to any prohibited network
        for prob in self.prohibited_networks:
            if ip in prob:
                return False

        # Target MUST belong to at least one allowed network
        return any(ip in net for net in self.allowed_networks)

    def assert_in_scope(self, target: str, action_desc: str = "active probe"):
        if not self.is_in_scope(target):
            resolved = self.resolve_ip(target)
            allowed_str = ", ".join(str(n) for n in self.allowed_networks)
            raise ScopeViolationError(
                f"Scope Violation: Target '{target}' (resolved: {resolved}) is outside authorized lab scope. "
                f"Operation '{action_desc}' was halted to prevent unintended network leakage. "
                f"Configured allowed CIDRs: [{allowed_str}]."
            )
