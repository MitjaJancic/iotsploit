# iotsploit

A config-driven IoT security/damage audit tool, built for a thesis
project assessing achievable damage in smart-home deployments, but
designed to generalize past the original Shelly/Tapo lab set.

See `docs/USAGE.md` for what each file does and how to run it.

## Design principles

1. **Device knowledge lives in YAML, not code.** `profiles/*.yaml`.
2. **Checks are written against capabilities, not vendors.** `checks/capability_checks.py`.
3. **Scoring weights are a runtime parameter.** `weights/default.yaml`, `--weights`.
4. **Evidence is preserved alongside scores**, so findings are re-scorable without re-running checks. `core/evidence.py`.
5. **Non-destructive by default.** Any check that could change device state requires authorization — `authorized: true` set once in the device's profile, or `--authorized` for a one-off run — and only runs against profiles/IPs you explicitly supply. There is no default scan target.
6. **Protocol-level exploitation is out of scope for this codebase on purpose** — see "What this tool deliberately does NOT do" in `docs/USAGE.md`.

## Status

Scaffolding and non-destructive checks (HTTP missing-auth, MQTT TLS
enforcement, BLE advertisement discovery, known-CVE reporting) are
implemented and runnable. State-changing/chaining scenarios specific
to your lab (e.g. BLE event spoofing through the ESPHome proxy) are
intentionally left for you to design — see the note in
`profiles/shelly_blu_dw.yaml` and the corresponding section in
`docs/USAGE.md`.
