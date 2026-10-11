# Testing in a VM, and installing with pipx

## Installing on Kali with pipx

This is a normal Python package (`pyproject.toml` with a console-script
entry point), so pipx works exactly as it would for any CLI tool — no
PyPI publishing required, pipx installs straight from a local directory:

```bash
# unzip the project somewhere on your Kali VM first
unzip iotsploit.zip
cd iotsploit

# pipx needs its own interpreter management; make sure it's present
sudo apt install -y pipx
pipx ensurepath
# open a new shell so PATH picks up ~/.local/bin

pipx install .
```

This installs the `iotsploit` command into its own isolated
venv (pipx's whole point) and puts it on PATH. Verify with:

```bash
iotsploit --help
```

**Important:** `profiles/`, `weights/`, and `docs/` are deliberately
*not* bundled inside the installed package — they're your editable
config, not code. After `pipx install .`, keep the unzipped project
folder around and run the command from inside it (or pass
`--profiles-dir /full/path/to/iotsploit/profiles`):

```bash
cd iotsploit   # the folder with profiles/ in it
iotsploit profiles list
```

If you later edit a profile, there's nothing to reinstall — the
installed command just reads the YAML file again next run.

### Updating after you edit the code

Because step above used `pipx install .` (not `pipx install
--editable .`), edits to the Python files won't be picked up until you
reinstall:

```bash
pipx install . --force
```

For active development, use editable mode instead so code edits take
effect immediately:

```bash
pipx install --editable .
```

## Testing in a VM before you have real devices

You don't need the Shelly/Tapo hardware commissioned to exercise most
of the tool's logic — only the HTTP-auth and MQTT-TLS checks need
anything network-reachable at all, and both can be pointed at a
throwaway mock instead of a real device.

### 1. A mock "vulnerable" HTTP device

This simulates a device that accepts a state-changing request without
authentication — exactly the condition `check_http_auth` is designed
to catch:

```bash
python3 -m http.server 8099 --bind 127.0.0.1
```

Then edit a *copy* of a profile (don't edit the shipped ones) so its
`base_url` points at `http://{ip}:8099`, and run:

```bash
iotsploit http check 127.0.0.1:8099 --profile profiles/shelly_1pm.yaml
# no --authorized needed - shelly_1pm.yaml already sets authorized: true
```

Python's `http.server` returns 200 for anything, so this should
produce an "accepted WITHOUT authentication" finding — if it does,
the detection logic is working correctly end to end before you ever
touch real hardware.

### 2. A mock MQTT broker for the TLS check

Run a plain Mosquitto container with no TLS configured at all, to
simulate the "should be TLS but isn't" condition:

```bash
docker run -d --name mock-broker -p 1883:1883 eclipse-mosquitto \
  mosquitto -c /mosquitto-no-auth.conf
```

(If you don't have a no-auth config handy, the default Mosquitto
image refuses anonymous connections — that's fine, it just means the
check will report "plaintext connection refused," which is also a
valid thing to verify your check handles correctly.)

```bash
iotsploit mqtt test 127.0.0.1 --profile profiles/shelly_trv.yaml --port 1883
```

### 3. Full VM lab layout

Once you're past dry-run testing, the natural split for your actual
VM environment (matching the project plan's network design):

| VM/host | Role |
|---|---|
| Kali VM (VLAN 30 / Pentest) | Runs `iotsploit` via pipx |
| Home Assistant + Mosquitto VM (VLAN 20 / IoT) | The hub, as already planned |
| Physical Shelly/Tapo devices (VLAN 20) | Real targets, once commissioned |

Run the mock tests above *on the Kali VM itself* first (no VLAN
needed yet — `127.0.0.1` is enough) to confirm the tool behaves
correctly, then point the `target` argument at the real VLAN 20
addresses once your lab network is up.

### 4. Testing against OWASP IoTGoat (recommended before real hardware)

[IoTGoat](https://github.com/OWASP/IoTGoat) is OWASP's own deliberately
insecure router firmware, built specifically for this kind of testing.
It's a genuinely useful validation step for your thesis: it's a
completely different device class from Shelly/Tapo (OpenWrt-based
router firmware, not a relay/camera), so if the tool's generic checks
work against it with zero code changes — only a new YAML profile
(`profiles/owasp_iotgoat.yaml`, included) — that's real evidence the
"capability, not vendor" design generalizes, not just a claim in your
methodology chapter.

**Getting it running** (simplest path for a VM-based lab):
1. Download the latest `IoTGoat-x86.vmdk` from the [releases page](https://github.com/OWASP/IoTGoat/releases).
2. Create a VM (VirtualBox/VMware), attach the vmdk, boot it, and run `ifconfig br-lan` inside the IoTGoat console to get its IP.
3. Put it on the same network/VLAN segment as your attack VM.

**Running the tool against it:**
```bash
iotsploit audit run <IOTGOAT_IP> --profile profiles/owasp_iotgoat.yaml
# no --authorized needed - owasp_iotgoat.yaml already sets authorized: true
```

**What to expect, per the official OWASP challenge write-up** (worth
knowing in advance so you can tell a correct result from a broken one):
- The `http_auth` check on the hidden diagnostics page should report
  "correctly required authentication" — OWASP's own walkthrough
  confirms that page needs a logged-in session. This is a **true
  negative** you want to see, not a bug in the check.
- `flagged_port` for port 5515 should report **open** — IoTGoat ships
  a documented raw-TCP backdoor there with no HTTP/MQTT surface at
  all. This is the case that specifically validates `check_flagged_ports`
  earns its place in the tool: nothing else would have caught it.
- Port 5000 (MiniUPnP) should also report open; whether that's worth
  treating as a finding versus a normal service is a judgment call
  you can document in your methodology (the profile's `damage_score`
  for it is a starting guess, not gospel — adjust it if your review
  of the MiniUPnP CVE history suggests otherwise).
- The hardcoded-credentials and XSS entries are literature-sourced
  (`known_cves` in the profile), not live-detected — the tool reports
  them for completeness in the output, same as it would for a Shelly
  CVE, but doesn't attempt to brute-force or exploit them itself.

If you want to go further and actually work through IoTGoat's
challenges by hand (cracking the hardcoded credentials, triggering
the XSS, interacting with the port-5515 backdoor), the official
[Challenge solutions wiki page](https://github.com/OWASP/IoTGoat/wiki/Challenge-solutions)
walks through each one — useful for sanity-checking your damage-scoring
rubric against a known-answer case before you rely on it for your
own novel findings later in the semester.

### 5. Testing the *Practical IoT Hacking* modules

All four are fully testable in a VM with no physical hardware at all —
unlike the UART/JTAG/firmware/RFID/Wi-Fi/LPWAN chapters, which
genuinely need real hardware or RF equipment (see the "deliberately
not implemented" list in `docs/USAGE.md` for the full mapping). These
were verified exactly this way before being added to the tool.

**`mqtt anon-check`** — install Mosquitto directly on your Kali VM
(`apt install mosquitto mosquitto-clients`, works fine in a plain VM,
no container needed) and toggle `allow_anonymous` in its config to
see both outcomes:
```bash
# allow_anonymous true in /etc/mosquitto/mosquitto.conf, then restart mosquitto
iotsploit mqtt anon-check 127.0.0.1 --device-id test-broker
# → "accepted an anonymous CONNECT"

# allow_anonymous false + a password_file, restart again
iotsploit mqtt anon-check 127.0.0.1 --device-id test-broker
# → "rejected an anonymous CONNECT"
```

**`modbus check`** — `pip install pymodbus` and run a throwaway test
server (pymodbus ships exactly this for its own test suite):
```python
# save as modbus_server.py, then: python3 modbus_server.py
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusDeviceContext, ModbusServerContext
from pymodbus.server import StartTcpServer
block = ModbusSequentialDataBlock(1, [111, 222, 333, 444])
context = ModbusServerContext(devices=ModbusDeviceContext(hr=block), single=True)
StartTcpServer(context=context, address=("127.0.0.1", 5020))
```
```bash
iotsploit modbus check 127.0.0.1 --port 5020 --device-id test-modbus
```

**`upnp enum` / `upnp wan-check`** — rather than standing up a full
miniupnpd, the fastest VM-friendly test is a tiny mock HTTP server
that serves a UPnP description XML and answers the SOAP call — this
is exactly how the check was validated before shipping. Point
`--location` straight at it to skip SSDP discovery:
```bash
iotsploit upnp enum --location http://<ip>:<port>/desc.xml --device-id mock-router
iotsploit upnp wan-check --location http://<ip>:<port>/desc.xml --device-id mock-router
```
Against **real** IoTGoat, point `--location` at its documented
port-5000 MiniUPnPd service once you confirm the actual description
path (`curl http://<iotgoat-ip>:5000/` first — IoTGoat's build may
not use the conventional `/rootDesc.xml`).

**`wsd scan`** — needs something answering WS-Discovery Probes on
your network segment. The simplest test is a real ONVIF camera (the
Tapo C100 already in your device list) once your lab is up; without
hardware yet, a minimal UDP responder that joins the
`239.255.255.250:3702` multicast group and replies to any datagram
with a ProbeMatch envelope is enough to validate the parsing logic —
this is how it was tested here too.

### 6. Known rough edge: BLE checks and VMs

`check_ble_advertising` needs a Bluetooth adapter the OS can see
directly. A VM's virtual NIC doesn't give you that — you'd need USB
passthrough of a physical BLE adapter (or run that one check on the
Kali host directly rather than inside the VM, if Kali is itself a VM
with no USB passthrough configured). Worth testing this specific path
early, since it's the one piece that doesn't "just work" from inside
a VM.
