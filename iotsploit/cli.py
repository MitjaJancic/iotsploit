#!/usr/bin/env python3
"""
cli.py

Metasploit-style dispatch: `iotsploit <module> <action> [target] [options]`

Examples:
    iotsploit profiles list
    iotsploit profiles show owasp_iotgoat
    iotsploit http check 192.168.42.129 --device-id owasp_iotgoat
    iotsploit ports scan 192.168.42.129 --device-id owasp_iotgoat
    iotsploit cve list --device-id owasp_iotgoat
    iotsploit ble scan --device-id shelly_blu_dw
    iotsploit mqtt anon-check 192.168.42.129
    iotsploit modbus check 192.168.20.14 --port 502
    iotsploit upnp enum --location http://192.168.42.129:5000/
    iotsploit firmware scan ./extracted-firmware --device-id owasp_iotgoat
    iotsploit audit run 192.168.20.11 --device-id shelly_1pm_gen4

Authorization: state-changing checks (currently just `http check`) need
either --authorized on the command line, or `authorized: true` written
into the matched profile's YAML. Put it in the profile once for any
device you actually own, and you never need the flag again for that
device - see profiles/_template.yaml.

Every module/action maps straight onto a function in checks/ - this
file is dispatch and output formatting only. Adding a new action means
adding one entry to MODULES below and, if it's genuinely new logic,
one function in the relevant checks module. It does not mean inventing
a new flag scheme.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from iotsploit.core.device_profile import load_profiles_dir, load_profile, DeviceProfile
from iotsploit.core.evidence import EvidenceStore
from iotsploit.core.scoring import load_weights, Finding
from iotsploit.core.scope import LabContext, ScopeViolationError
from iotsploit.core.report import write_reports
from iotsploit.checks.capability_checks import (
    check_http_auth,
    check_http_injection,
    check_mqtt_tls,
    check_ble_advertising,
    check_known_cves,
    check_flagged_ports,
    check_mqtt_auth_enforcement,
    check_ble_access_control,
    check_coap_auth_enforcement,
    _new_finding_id,
)
from iotsploit.checks.book_checks import (
    check_mqtt_anonymous,
    upnp_enum,
    upnp_wan_exposure,
    wsd_scan,
    check_modbus_unauth_read,
)
from iotsploit.checks.firmware_checks import check_firmware_credentials
from iotsploit.checks.firmware_audit import scan_for_secrets, map_firmware_services
from iotsploit.checks.coap_checks import check_coap_auth
from iotsploit.checks.shelly_checks import check_shelly_endpoints, check_shelly_open_ap
from iotsploit.checks.mqtt_classifier import classify_mqtt_broker

# module -> {action: one-line help}, purely for --help / listing.
# The actual behaviour for each lives in _run_action() below.
MODULES = {
    "http": {
        "check": "Probe state-changing HTTP endpoints for missing authentication. (needs authorization)",
        "injection-check": "Time-based blind command-injection probe of injectable_params. (needs authorization)",
    },
    "mqtt": {
        "test": "Check whether a broker expected to use TLS still accepts plaintext.",
        "anon-check": "Attempt a full anonymous CONNECT against a broker (Practical IoT Hacking, ch.4).",
        "auth-check": "Test MQTT anonymous access and profile-declared credentials (CONNECT-only).",
        "classify": "Sample topic namespaces (#) and classify actuator, telemetry, and bridge-admin risks.",
    },
    "shelly": {
        "check": "Audit Shelly Gen 1 / Gen 2 endpoints for missing authentication.",
        "verify": "Safely actuate physical test relay/solenoid via auto-reverting momentary 1-second pulse.",
        "ap-check": "Audit for Gen 4 persistent unencrypted Setup Access Point flaw (default: 192.168.33.1).",
    },
    "upnp": {
        "enum": "SSDP-discover UPnP devices and fingerprint via description XML (ch.4 + ch.6).",
        "wan-check": "Read-only probe of a WANIPConnection/WANPPPConnection service (ch.6).",
    },
    "wsd": {
        "scan": "WS-Discovery Probe for ONVIF-style devices (ch.6, passive half only).",
    },
    "modbus": {
        "check": "Unauthenticated read-only Modbus holding-register probe.",
    },
    "coap": {
        "check": "CoAP authentication enforcement probe (GET by default, PUT/POST needs authorization).",
    },
    "firmware": {
        "scan": "Static credential scan of an already-extracted firmware filesystem (ch.9).",
        "audit": "Static scan for API keys, tokens, and high-entropy strings.",
    },
    "ble": {
        "scan": "Passive BLE advertisement scan matching the profile's name pattern.",
        "access-check": "Audit GATT characteristic write permissions for missing encryption/auth.",
    },
    "ports": {
        "scan": "Connect-scan the profile's flagged_ports list.",
    },
    "cve": {
        "list": "Surface known_cves entries from the profile(s).",
    },
    "audit": {
        "run": "Run every applicable check for the matched profile(s) in one pass. (needs authorization for the http part)",
    },
    "profiles": {
        "list": "List device profiles found in --profiles-dir.",
        "show": "Show everything one profile declares.",
    },
}


def _modules_help() -> str:
    lines = ["Modules and actions:"]
    for module, actions in MODULES.items():
        for action, desc in actions.items():
            lines.append(f"  {module:<9} {action:<10} {desc}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iotsploit",
        description="Config-driven IoT damage/vulnerability audit tool.",
        epilog=_modules_help(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("module", choices=MODULES.keys(), help="Which capability area to use.")
    p.add_argument("action", help="Which action within that module (see below for the list per module).")
    p.add_argument("target", nargs="?", default=None,
                    help="Device IP/hostname (or a filesystem path, for 'firmware scan'). "
                         "Required for http/mqtt/ports/modbus/audit/firmware; not used by ble/cve/profiles/wsd.")

    profile_group = p.add_argument_group("profile selection")
    profile_group.add_argument("--profiles-dir", default="profiles",
                                help="Directory of device profile YAML files (default: ./profiles)")
    profile_group.add_argument("--profile", default=None,
                                help="Path to a single profile file. Overrides --device-id/--profiles-dir.")
    profile_group.add_argument("--device-id", default=None,
                                help="device_id to look up in --profiles-dir, e.g. owasp_iotgoat. "
                                     "If omitted, the action runs against every profile in --profiles-dir "
                                     "that supports the relevant capability. For profile-independent modules "
                                     "(mqtt/upnp/wsd/modbus/firmware), this only labels the finding.")

    opts = p.add_argument_group("module options")
    opts.add_argument("--port", type=int, default=None,
                       help="Override the default port for mqtt (1883) or modbus (502).")
    opts.add_argument("--unit", type=int, default=1, help="Modbus unit/device ID (default: 1).")
    opts.add_argument("--location", default=None,
                       help="UPnP device description URL, to skip SSDP discovery and fetch it directly "
                            "(e.g. http://192.168.1.1:5000/rootDesc.xml). Required for 'upnp wan-check'.")
    opts.add_argument("--weights", default=None, help="Path to a custom damage-score weights YAML.")
    opts.add_argument("--evidence", default="evidence", help="Directory to store raw evidence files in.")
    opts.add_argument("--output", default=None,
                       help="If set, also write JSON/HTML reports to this directory "
                            "(otherwise results only print to screen).")
    opts.add_argument(
        "--authorized", action="store_true",
        help="Confirms you own/are authorized to test this target for THIS run. Only needed for "
             "state-changing checks (currently 'http check'), and only if the matched profile doesn't "
             "already set 'authorized: true' itself - put it there once per device instead of passing "
             "this every time.",
    )
    opts.add_argument(
        "--dev", action="store_true",
        help="Development/lab mode: automatically treats all targets as authorized for this run "
             "to streamline rapid testing and iteration without editing profile YAMLs.",
    )
    opts.add_argument(
        "--scope-config", default=None,
        help="Path to lab scope YAML policy file (default: lab_context.yaml if present).",
    )
    opts.add_argument(
        "--no-scope-check", action="store_true",
        help="Disable lab network scope validation boundaries.",
    )
    opts.add_argument(
        "--verify", action="store_true",
        help="Safely perform non-destructive active verification (timed auto-reverting 1s pulse) on actuator targets.",
    )
    opts.add_argument("--json", action="store_true", help="Print findings as JSON instead of a table.")
    opts.add_argument("-v", "--verbose", action="store_true", help="Print profile load / skip notes to stderr.")

    return p


def _resolve_profiles(args) -> list[DeviceProfile]:
    if args.profile:
        return [load_profile(args.profile)]
    all_profiles = load_profiles_dir(args.profiles_dir)
    if args.device_id:
        matched = [p for p in all_profiles if p.device_id == args.device_id]
        if not matched:
            print(f"No profile with device_id '{args.device_id}' found in {args.profiles_dir}", file=sys.stderr)
            sys.exit(1)
        return matched
    return all_profiles


def _is_authorized(args, profile: DeviceProfile | None = None) -> bool:
    """A profile's own authorized: true satisfies the gate permanently;
    --authorized, --verify or --dev satisfies it for this run (streamlining lab development)."""
    prof_auth = profile.authorized if (profile is not None) else False
    return getattr(args, "dev", False) or getattr(args, "verify", False) or getattr(args, "authorized", False) or prof_auth


def _note(args, msg: str):
    if args.verbose:
        print(f"Note: {msg}", file=sys.stderr)


async def _run_ble(profiles, evidence) -> list[Finding]:
    findings = []
    for profile in profiles:
        findings += await check_ble_advertising(profile, evidence_store=evidence)
    return findings


def _print_findings(findings: list[Finding], weights: dict, as_json: bool):
    if as_json:
        print(json.dumps([f.to_dict(weights) for f in findings], indent=2, default=str))
        return

    if not findings:
        print("No findings.")
        return

    # Clean index-based columnar output
    header = f"{'#':<3} {'CHECK':<24} {'FINDING / USER:PASS / SERVICE':<65} {'SCORE':<5}"
    print(header)
    print("-" * len(header))
    for idx, f in enumerate(findings, start=1):
        desc = f.description.strip().replace("\n", " ")
        if len(desc) > 65:
            desc = desc[:62] + "…"
        print(f"{idx:<3} {f.check_name:<24} {desc:<65} {f.damage_score(weights):<5.1f}")
    print("-" * len(header))
    print(f"Total: {len(findings)} finding(s)")


def _require_target(args, what: str = "a target IP/hostname"):
    if not args.target:
        print(f"'{args.module} {args.action}' needs {what}.", file=sys.stderr)
        sys.exit(1)


def _run_action(args) -> list[Finding]:
    evidence = EvidenceStore(args.evidence)
    findings: list[Finding] = []
    scope = LabContext.load(getattr(args, "scope_config", None))
    if getattr(args, "no_scope_check", False):
        scope.enforce_scope = False

    try:
        # --- profiles module: informational, no findings ---
        if args.module == "profiles":
            all_profiles = load_profiles_dir(args.profiles_dir)
            if args.action == "list":
                for p in all_profiles:
                    auth_tag = " [authorized]" if p.authorized else ""
                    print(f"{p.device_id:<20} {p.vendor:<12} {p.model:<20} "
                          f"protocols={','.join(p.protocols)}{auth_tag}")
                return []
            if args.action == "show":
                device_id = args.device_id or args.target
                if not device_id:
                    print("Usage: iotsploit profiles show <device_id>", file=sys.stderr)
                    sys.exit(1)
                matched = [p for p in all_profiles if p.device_id == device_id]
                if not matched:
                    print(f"No profile with device_id '{device_id}'", file=sys.stderr)
                    sys.exit(1)
                print(json.dumps(matched[0].raw, indent=2))
                return []

        # --- shelly module: independent auditor & active verification ---
        if args.module == "shelly" and args.action in ("check", "verify"):
            _require_target(args)
            scope.assert_in_scope(args.target, f"shelly {args.action}")
            allow_verify = (args.action == "verify") or _is_authorized(args, None)
            return check_shelly_endpoints(
                args.target,
                port=args.port or 80,
                allow_active_verification=allow_verify,
                device_id=args.device_id,
                evidence_store=evidence,
            )

        if args.module == "shelly" and args.action == "ap-check":
            target = args.target or "192.168.33.1"
            scope.assert_in_scope(target, "shelly ap-check")
            return check_shelly_open_ap(
                target=target,
                device_id=args.device_id,
                evidence_store=evidence,
            )

        # --- profile-independent modules: no DeviceProfile required ---
        # (--device-id here, if given, is used only to label findings - it is
        # never looked up against --profiles-dir, so these work with zero
        # profiles configured.)
        if args.module == "mqtt" and args.action == "classify":
            _require_target(args)
            scope.assert_in_scope(args.target, "mqtt classify")
            return classify_mqtt_broker(
                args.target,
                port=args.port or 1883,
                device_id=args.device_id,
                evidence_store=evidence,
            )

        if args.module == "mqtt" and args.action == "anon-check":
            _require_target(args)
            scope.assert_in_scope(args.target, "mqtt anon-check")
            device_id = args.device_id or args.target
            return check_mqtt_anonymous(args.target, args.port or 1883, device_id=device_id,
                                         evidence_store=evidence)

        if args.module == "upnp" and args.action == "enum":
            device_id = args.device_id or args.target
            return upnp_enum(target_location=args.location, device_id=device_id, evidence_store=evidence)

        if args.module == "upnp" and args.action == "wan-check":
            if not args.location:
                print("'upnp wan-check' needs --location (the device description URL).", file=sys.stderr)
                sys.exit(1)
            device_id = args.device_id or args.target or args.location
            return upnp_wan_exposure(args.location, device_id=device_id, evidence_store=evidence)

        if args.module == "wsd" and args.action == "scan":
            return wsd_scan()

        if args.module == "modbus" and args.action == "check":
            _require_target(args)
            scope.assert_in_scope(args.target, "modbus check")
            device_id = args.device_id or args.target
            return check_modbus_unauth_read(args.target, port=args.port or 502, unit_id=args.unit,
                                             device_id=device_id, evidence_store=evidence)

        if args.module == "firmware" and args.action == "scan":
            _require_target(args, "a path to an extracted firmware filesystem")
            device_id = args.device_id or args.target
            return check_firmware_credentials(args.target, device_id=device_id, evidence_store=evidence)

        if args.module == "firmware" and args.action == "audit":
            from pathlib import Path
            _require_target(args, "a path to an extracted firmware filesystem")
            device_id = args.device_id or args.target
            target_path = Path(args.target)

            # Firmware audit: ONLY for active service and daemon configurations
            service_hits = map_firmware_services(target_path)
            findings = []
            if service_hits:
                evidence_path = None
                if evidence:
                    evidence_path = evidence.save_json(
                        _new_finding_id("firmware_services", device_id),
                        "service_mapping",
                        {"services": service_hits},
                    )
                for s in service_hits:
                    svc_name = s.get("service", "Service")
                    cfg = s.get("config_file") or s.get("script") or ""
                    port = s.get("default_port")
                    port_str = f":{port}" if port else ""
                    extra = []
                    if s.get("root_login_allowed"):
                        extra.append("RootLogin=yes")
                    if s.get("password_auth_enabled"):
                        extra.append("PasswordAuth=yes")
                    if s.get("masked_value"):
                        extra.append(f"Key={s['masked_value']}")
                    extra_str = f" ({', '.join(extra)})" if extra else ""

                    findings.append(Finding(
                        finding_id=_new_finding_id("firmware_service", device_id),
                        device_id=device_id,
                        check_name="firmware_service",
                        description=f"{svc_name}{port_str} [{cfg}]{extra_str}",
                        cvss=5.3,
                        damage={"availability": 1, "chaining_depth": 1},
                        evidence_path=evidence_path,
                    ))

            if not findings:
                findings.append(Finding(
                    finding_id=_new_finding_id("firmware_audit", device_id),
                    device_id=device_id,
                    check_name="firmware_audit",
                    description=f"No active service or daemon configurations identified under {args.target}.",
                    cvss=None,
                    damage={},
                ))
            return findings

        # --- profile-driven modules below ---
        profiles = _resolve_profiles(args)

        if args.module == "http" and args.action == "check":
            _require_target(args)
            scope.assert_in_scope(args.target, "http check")
            for p in profiles:
                if not p.supports("http"):
                    _note(args, f"{p.device_id} does not declare http, skipping")
                    continue
                if not _is_authorized(args, p):
                    _note(args, f"{p.device_id} not authorized (pass --authorized, --verify or set authorized: true "
                                f"in its profile) - state-changing request will be skipped")
                findings += check_http_auth(p, args.target, allow_state_changes=_is_authorized(args, p),
                                             evidence_store=evidence)
            return findings

        if args.module == "http" and args.action == "injection-check":
            _require_target(args)
            scope.assert_in_scope(args.target, "http injection-check")
            for p in profiles:
                if not p.supports("http"):
                    _note(args, f"{p.device_id} does not declare http, skipping")
                    continue
                if not any(e.injectable_params for e in p.http_endpoints):
                    _note(args, f"{p.device_id} has no endpoints with injectable_params set, skipping")
                    continue
                if not _is_authorized(args, p):
                    _note(args, f"{p.device_id} not authorized - injection probes will be skipped")
                findings += check_http_injection(p, args.target, allow_state_changes=_is_authorized(args, p),
                                                  evidence_store=evidence)
            return findings

        if args.module == "coap" and args.action == "check":
            _require_target(args)
            scope.assert_in_scope(args.target, "coap check")
            for p in profiles:
                if not p.coap_endpoints:
                    _note(args, f"{p.device_id} has no coap endpoints declared, skipping")
                    continue
                try:
                    findings += check_coap_auth_enforcement(
                        p, args.target, allow_state_changes=_is_authorized(args, p), evidence_store=evidence
                    )
                except Exception:
                    findings += check_coap_auth(p, args.target, port=args.port or 5683, evidence_store=evidence)
            return findings

        if args.module == "mqtt" and args.action == "test":
            _require_target(args)
            scope.assert_in_scope(args.target, "mqtt test")
            for p in profiles:
                if not p.supports("mqtt"):
                    _note(args, f"{p.device_id} does not declare mqtt, skipping")
                    continue
                findings += check_mqtt_tls(p, args.target, args.port or 1883, evidence_store=evidence)
            return findings

        if args.module == "mqtt" and args.action == "auth-check":
            _require_target(args)
            scope.assert_in_scope(args.target, "mqtt auth-check")
            for p in profiles:
                if not p.supports("mqtt"):
                    _note(args, f"{p.device_id} does not declare mqtt, skipping")
                    continue
                findings += check_mqtt_auth_enforcement(p, args.target, args.port or 1883, evidence_store=evidence)
            return findings

        if args.module == "ble" and args.action == "scan":
            ble_profiles = [p for p in profiles if p.supports("ble")]
            if not ble_profiles:
                _note(args, "no profile in scope declares ble")
            return asyncio.run(_run_ble(ble_profiles, evidence))

        if args.module == "ble" and args.action == "access-check":
            ble_profiles = [p for p in profiles if p.supports("ble")]
            if not ble_profiles:
                _note(args, "no profile in scope declares ble")
            for p in ble_profiles:
                findings += check_ble_access_control(
                    p, allow_state_changes=_is_authorized(args, p), evidence_store=evidence
                )
            return findings

        if args.module == "ports" and args.action == "scan":
            _require_target(args)
            scope.assert_in_scope(args.target, "ports scan")
            for p in profiles:
                if not p.flagged_ports:
                    _note(args, f"{p.device_id} has no flagged_ports, skipping")
                    continue
                findings += check_flagged_ports(p, args.target, evidence_store=evidence)
            return findings

        if args.module == "cve" and args.action == "list":
            for p in profiles:
                findings += check_known_cves(p)
            return findings

        if args.module == "audit" and args.action == "run":
            _require_target(args)
            scope.assert_in_scope(args.target, "audit run")
            for p in profiles:
                findings += check_known_cves(p)
                if p.supports("http"):
                    if not _is_authorized(args, p):
                        _note(args, f"{p.device_id} not authorized - http check will skip its state-changing request")
                    findings += check_http_auth(p, args.target, allow_state_changes=_is_authorized(args, p),
                                                 evidence_store=evidence)
                    if any(e.injectable_params for e in p.http_endpoints):
                        findings += check_http_injection(p, args.target, allow_state_changes=_is_authorized(args, p),
                                                          evidence_store=evidence)
                if p.supports("mqtt"):
                    findings += check_mqtt_tls(p, args.target, args.port or 1883, evidence_store=evidence)
                    findings += check_mqtt_anonymous(args.target, args.port or 1883, device_id=p.device_id,
                                                      evidence_store=evidence)
                    findings += check_mqtt_auth_enforcement(p, args.target, args.port or 1883, evidence_store=evidence)
                if p.coap_endpoints:
                    findings += check_coap_auth_enforcement(p, args.target, allow_state_changes=_is_authorized(args, p),
                                                             evidence_store=evidence)
                if p.flagged_ports:
                    findings += check_flagged_ports(p, args.target, evidence_store=evidence)
            ble_profiles = [p for p in profiles if p.supports("ble")]
            if ble_profiles:
                findings += asyncio.run(_run_ble(ble_profiles, evidence))
                for p in ble_profiles:
                    findings += check_ble_access_control(p, allow_state_changes=_is_authorized(args, p),
                                                         evidence_store=evidence)
            return findings

        return findings

    except ScopeViolationError as exc:
        print(f"\n[!] Scope Boundary Rejection: {exc}\n", file=sys.stderr)
        return [Finding(
            finding_id=_new_finding_id("scope_violation", getattr(args, "device_id", None) or getattr(args, "target", None) or "target"),
            device_id=getattr(args, "device_id", None) or getattr(args, "target", None) or "target",
            check_name="scope_violation",
            description=str(exc),
            cvss=None,
            damage={},
        )]


def main():
    args = build_arg_parser().parse_args()

    if args.action not in MODULES.get(args.module, {}):
        print(f"Unknown action '{args.action}' for module '{args.module}'.\n", file=sys.stderr)
        print(_modules_help(), file=sys.stderr)
        sys.exit(1)

    findings = _run_action(args)
    weights = load_weights(args.weights)

    if args.module != "profiles":
        _print_findings(findings, weights, args.json)

    if args.module != "profiles" and findings:
        from pathlib import Path
        out_dir = Path(args.output) if args.output else Path(".")
        paths = write_reports(findings, weights, out_dir)
        print(f"\n[+] Saved human-readable report: {paths['txt']}")
        if args.output:
            print(f"[+] Saved HTML report: {paths['html']}")
            print(f"[+] Saved JSON report: {paths['json']}")


if __name__ == "__main__":
    main()
