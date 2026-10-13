# USAGE

## What this tool is

A config-driven IoT security/damage audit tool. It is **not** hardcoded
to Shelly or Tapo devices — every piece of device-specific knowledge
(HTTP endpoints, MQTT expectations, BLE name patterns, known CVEs)
lives in a YAML **profile** under `profiles/`. The code in `core/`,
`recon/`, and `checks/` only ever reads generic *capabilities*
("this device has HTTP endpoints that should require auth", "this
device should use MQTT-over-TLS") — it never contains a vendor name.

Adding device #6 to your audit means writing a new YAML file. It does
not mean writing new Python.

## What each folder/file does

| Path | What it does |
|---|---|
| `profiles/*.yaml` | One file per device. The only place vendor/model-specific detail lives. |
| `profiles/_template.yaml` | Copy this to start a new device profile — every field is commented. |
| `weights/default.yaml` | Damage Score weighting. Copy and adjust to model a different household risk posture; re-score without re-running checks. |
| `iotsploit/core/device_profile.py` | Loads a YAML profile into a typed `DeviceProfile` object. |
| `core/scoring.py` | The `Finding` class and the Damage Score formula. Weights are runtime-loaded, not hardcoded. |
| `core/evidence.py` | Saves raw evidence (HTTP responses, PCAPs, BLE scan results) next to each finding so results are reproducible and re-scorable. |
| `core/report.py` | Turns a list of findings into a JSON report (for your data analysis) and an HTML report (for a human reader). |
| `recon/discovery.py` | Generic mDNS discovery — the service-type list is the only ecosystem-specific part, and it's a one-line list, not logic. |
| `recon/port_scan.py` | Generic TCP port scan with a protocol-guess map (port 1883 → "mqtt", etc.) — again, just a lookup table, not per-vendor code. |
| `iotsploit/checks/capability_checks.py` | The actual checks. Each one is written against a *capability* a profile declares, so it runs against any device whose profile fills in the matching fields. |
| `iotsploit/cli.py` | Ties it all together: load profiles → run checks → score → write reports. |

## Command syntax

Metasploit-style: `iotsploit <module> <action> [target] [options]`

| Module | Action | Target needed? | What it does |
|---|---|---|---|
| `http` | `check` | yes (IP) | `check_http_auth` — probes state-changing endpoints for missing auth |
| `mqtt` | `test` | yes (broker IP) | `check_mqtt_tls` — checks for plaintext MQTT where TLS is expected |
| `ble` | `scan` | no | `check_ble_advertising` — passive scan matching the profile's name pattern |
| `ports` | `scan` | yes (IP) | `check_flagged_ports` — connect-scan of the profile's `flagged_ports` |
| `cve` | `list` | no | `check_known_cves` — surfaces documented findings from the profile |
| `audit` | `run` | yes (IP) | runs every applicable module above in one pass |
| `profiles` | `list` / `show` | no | discovery — list profiles, or dump one profile's full YAML as JSON |
| `mqtt` | `anon-check` | yes (IP) | full anonymous CONNECT attempt (not just a TCP probe) — from *Practical IoT Hacking* ch.4 |
| `upnp` | `enum` | no (or `--location`) | SSDP-discover + fingerprint via description XML — ch.4 + ch.6 |
| `upnp` | `wan-check` | needs `--location` | read-only WANIPConnection probe — ch.6 |
| `wsd` | `scan` | no | WS-Discovery Probe for ONVIF-style devices — ch.6 |
| `modbus` | `check` | yes (IP) | unauthenticated read-only holding-register probe |
| `firmware` | `scan` | yes (filesystem path) | static passwd/shadow/hardcoded-credential scan — ch.9 |
| `coap` | `check` | yes (IP) | read-only CoAP GET missing-auth probe (GET only, never PUT/POST) |

The last six are **profile-independent** — `--device-id` only labels the finding, it's never looked up against `--profiles-dir`, so these work against any target with zero profiles configured. See "Checks from *Practical IoT Hacking*" below for what each is actually testing and why it stops where it does.

Run `iotsploit --help` any time for this table plus every flag.

**Selecting which profile(s) a command applies to:**
- `--device-id <id>` — run against exactly one profile (matched by its `device_id` field). This is the normal case.
- no `--device-id` — run against every profile in `--profiles-dir` that declares the relevant capability (e.g. `http check` with no `--device-id` runs against every HTTP-capable profile). Useful for `audit run` across a whole lab in one pass, since `target` would then need to be the same IP for all of them — in practice you'll usually still pass `--device-id` per device.
- `--profile <path>` — bypass device-id lookup entirely and point straight at one YAML file.

## Authorization

One check (`http check`, and the http part of `audit run`) sends a real state-changing request. It only fires if the matched profile is authorized, which happens either way:

- **Permanently, in the profile** — set `authorized: true` in a device's YAML (every shipped profile in `profiles/` already has this, since they're all devices you've confirmed you own). Do this once per device; every future command against that profile just works, no flag needed.
- **For one run, on the command line** — pass `--authorized`. Useful for a profile you haven't marked yet, a profile-less `--profile /tmp/whatever.yaml` test, or deliberately overriding a profile that doesn't have it set.

Without either, the check still runs but skips the state-changing part and reports a "skipped" finding instead — it won't silently do nothing with no explanation. `-v`/`--verbose` prints a note to stderr explaining why it skipped.

This exists because `http check` doesn't know in advance whether the IP you typed is the lab device you meant or a typo — the written, version-controlled `authorized: true` is the record that you made that call deliberately for this specific device, not just that you remembered a flag on a given day.

## Checks included, and what they detect

- **`http check` → `check_http_auth`** — for each HTTP endpoint a profile marks `expect_auth: true`, sends an unauthenticated request and records whether the device accepted it anyway (missing-authentication finding). Gated by authorization (see above) because it can change device state (e.g. toggle a relay).
- **`mqtt test` → `check_mqtt_tls`** — for devices whose profile says `expected_tls: true`, checks whether a plaintext connection to the configured broker port succeeds when it shouldn't.
- **`ble scan` → `check_ble_advertising`** — passive BLE scan matching a profile's `name_pattern`; reports what's being advertised. Never connects or writes to a characteristic.
- **`ports scan` → `check_flagged_ports`** — connect-scans whatever ports a profile lists under `flagged_ports` (e.g. a documented backdoor port), using `recon/port_scan.py`.
- **`cve list` → `check_known_cves`** — surfaces whatever CVEs/architectural issues you've documented in a profile's `known_cves` list as findings, so your literature-review findings and your live-test findings end up in the same report format.
- **`audit run`** — all of the above for the matched profile(s) in one command; this is the closest equivalent to the old (pre-rewrite) default behavior.
- **`http injection-check` → `check_http_injection`** — time-based blind command-injection detection. For each `injectable_params` entry on a profile's HTTP endpoints, sends a handful of `sleep N`-style payloads and compares response latency to an unmodified baseline. A response that takes ~N seconds longer indicates the payload executed server-side — no command output is ever read, so this stays non-destructive by the same definition as the rest of the tool, but it's still gated by authorization like `http check` since it sends real requests to a live state-changing surface. Requires `injectable_params` to actually be filled in on the profile first — the check never guesses parameter names itself (see `core/device_profile.py`'s `HttpEndpoint` docstring for why).

- **`coap check` → `check_coap_auth`** — same missing-authentication pattern as `http check`, applied to CoAP (the protocol several real smart-home devices, e.g. Philips Hue bridges, speak instead of HTTP). Deliberately **GET-only**: it never sends PUT/POST, even when authorized, since confirming a resource is readable without credentials is already a citable finding on its own, with no need to actually change device state to prove it.

**Why MQTT/Modbus injection isn't automated the same way:** HTTP and UPnP give you a request/response round trip to time. MQTT pub/sub doesn't reliably give you one back, and you don't know if *anything* is subscribed to a given topic without firmware analysis first (see `docs/research-log.md`'s section 5–6). Automatically spraying topics with injection payloads isn't detection, it's guessing — stays a manual, deliberate test once you've confirmed a real consumer via `firmware scan` or source analysis, same reasoning as not automating MQTT credential brute-forcing.

## Checks from *Practical IoT Hacking* (Chantzis, Stais, Calderon, Deirmentzoglou, Woods)

These live in `checks/book_checks.py`, separate from `capability_checks.py`, because they're closer to the book's own standalone recon techniques than to the profile-capability pattern. Each docstring names its chapter.

- **`mqtt anon-check` → `check_mqtt_anonymous`** (ch.4, "Attacking MQTT") — the book builds a full dictionary/online credential-cracking Ncrack module; this implements the much narrower, non-destructive question that should come *before* reaching for a cracker at all: does the broker accept a fully anonymous CONNECT, with no credentials attempted? If yes, cracking is moot.
- **`upnp enum` → `upnp_enum`** (ch.4's service-fingerprinting technique + ch.6, "Exploiting UPnP") — SSDP-discovers UPnP devices and fetches their description XML, exactly the technique the book uses to identify a webcam's make/model/firmware from one unauthenticated request.
- **`upnp wan-check` → `upnp_wan_exposure`** (ch.6, "Abusing UPnP Through WAN interfaces") — finds a WANIPConnection/WANPPPConnection service and calls the read-only `GetExternalIPAddress` action with no credentials. Deliberately stops there: it does not call `AddPortMapping` (the book's actual firewall-hole-punching example), since that changes router state.
- **`wsd scan` → `wsd_scan`** (ch.6, "Exploiting WS-Discovery") — sends a WS-Discovery Probe and parses ProbeMatch responses. Only the passive enumeration half; the book's active "Faking Cameras on Your Network" (spoofing responses) is not implemented.
- **`modbus check` → `check_modbus_unauth_read`** — not its own book chapter, but the same "protocol with no built-in authentication" pattern the book applies to MQTT and UPnP, extended to Modbus since it's directly relevant to the Pro 3EM target from the original hardware shortlist. Read-only by construction — it only ever calls Read Holding Registers, never a write function code.

**Deliberately not implemented**, and why — covered in detail in the module docstring at the top of `book_checks.py`:
- MQTT credential brute-forcing (ch.4's actual Ncrack module)
- VLAN hopping / switch spoofing / double-tagging (ch.4) — manipulates network segmentation itself; a one-off manual exercise with Yersinia/Scapy in your own lab, not a reusable scanner feature
- mDNS probing-phase abuse and MITM (ch.6) — active response spoofing against other hosts' traffic
- Everything in Parts III–IV except the firmware credential scan below (UART/JTAG/SWD, SPI/I2C, RFID, BLE exploitation beyond passive scanning, Wi-Fi attacks, LPWAN) — these need physical hardware or RF equipment and don't have a meaningful pure-software VM equivalent; see `docs/TESTING.md` for how each maps to your lab plan once hardware is available.

### `firmware scan` → `check_firmware_credentials` (ch.9, "Statically Analyzing the Filesystem Contents")

The one Part III/IV technique that's pure static analysis, so it needs no hardware at all - just an already-extracted firmware filesystem (`binwalk -e firmware.bin`, or the live filesystem of a VM you have console access to). Target is a filesystem path, not an IP:

```bash
iotsploit firmware scan ./extracted-firmware --device-id owasp_iotgoat
```

It looks for:
- `/etc/passwd` accounts with UID 0 other than `root` — a classic hidden-backdoor-account pattern
- `/etc/shadow` entries with no password at all (empty hash field), and entries with a hash — named by type (MD5/SHA-256/SHA-512 crypt, bcrypt), not cracked
- Credential-shaped strings in scripts/configs (`password=...`, `backdoor`, a `telnetd` dropping straight to a shell), via broad regex matching — expect some false positives, this is a lead generator for manual review, not a verdict

**Deliberately stops there**: it never runs `john`/`hashcat` against a found hash, and never tries a found credential against a live device. Identifying a crackable hash and actually cracking it are two different actions — same reasoning as not auto-brute-forcing MQTT credentials elsewhere in this tool.

## What this tool deliberately does NOT do

It does not implement protocol-level exploitation (crafting malformed packets, bypassing cryptographic protections, redirecting firmware OTA, or writing arbitrary BLE GATT characteristics). Those are legitimate parts of a damage-assessment methodology, but they are scenario-specific, higher-risk, and the judgment calls about what's safe to run belong with you and your advisor — not pre-baked into a tool. The `Finding` and `EvidenceStore` classes are there so that whatever you build for those scenarios slots into the same scoring/reporting pipeline as everything else.

## Setup

Either a plain venv:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m iotsploit.cli --help
```

or install it as a standalone command with pipx (recommended on Kali —
see `docs/TESTING.md` for the full walkthrough, including testing it
with mock devices before you have real hardware wired up):

```bash
pipx install .
iotsploit --help
```

BLE checks additionally need a Bluetooth adapter accessible to the OS running this (not inside a VM without USB passthrough of the adapter). PCAP evidence capture needs `tshark` on PATH; without it, evidence falls back to a text note.

## Running it

1. Copy `profiles/_template.yaml` for any device not already covered, fill in its fields.
2. Commission your devices on the lab network as per the project plan, note their IPs.
3. See what's available:

```bash
iotsploit profiles list
iotsploit profiles show shelly_1pm_gen4
```

4. Run individual modules against a device, or everything at once with `audit run`:

```bash
# one check at a time
iotsploit cve list --device-id shelly_trv
iotsploit http check 192.168.20.11 --device-id shelly_1pm_gen4
iotsploit mqtt test 192.168.20.5 --device-id shelly_plug_s_gen3

# everything this profile supports, in one pass
iotsploit audit run 192.168.20.11 --device-id shelly_1pm_gen4
```

Without `--authorized`, `http check` reports a "skipped" finding instead of sending the state-changing request — this is expected on a first pass.

5. Once you're ready to run the state-changing checks against your own devices, add the flag:

```bash
iotsploit audit run 192.168.20.11 --device-id shelly_1pm_gen4 --authorized
```

6. Results print to the terminal by default. Add `--output-dir reports` to also write JSON/HTML report files, or `--json` to print machine-readable output instead of the table.

7. To re-score the same findings under a different risk posture, copy `weights/default.yaml`, adjust it, and pass `--weights your_weights.yaml` on any command — no need to re-run the checks.

## Extending to a new device or protocol

- **New device, existing protocol(s):** copy `_template.yaml`, fill in the fields, done.
- **New protocol entirely (e.g. Zigbee, Z-Wave):** add a `network.<protocol>` section to the profile schema in `iotsploit/core/device_profile.py`, write one new function in `iotsploit/checks/capability_checks.py` following the existing pattern (profile capability in, `Finding` objects out), and wire it into `iotsploit/cli.py`. Everything else — scoring, evidence, reporting — is already protocol-agnostic and needs no changes.
