"""
book_checks.py

Checks added directly from *Practical IoT Hacking* (Chantzis, Stais,
Calderon, Deirmentzoglou, Woods — No Starch Press, 2021), one function
per technique, each tied to the specific chapter it comes from in its
docstring. These are deliberately kept separate from
capability_checks.py: those are written against a DeviceProfile's
declared fields, while these are closer to the book's own standalone
recon/analysis techniques and work directly against a target with an
optional profile for context. All of them are read-only/passive by
design - none sends a write, a brute-force attempt, or a credential
guess; see the module-level note in capability_checks.py for the
reasoning behind that boundary, which applies here too.

What's intentionally NOT implemented here, and why:
- Ch4's MQTT "Authentication-Cracking Module" (dictionary/online
  brute force) - implementing a generic credential-brute-forcer is a
  different risk category from a detection check, and is exactly the
  kind of tool that's dangerous to hand to someone else's hardware.
  check_mqtt_anonymous below tests the much narrower, non-destructive
  question "does this broker allow a fully anonymous CONNECT", which
  is the thing worth automating; actual password cracking against a
  broker you own is a deliberate exercise you run yourself with
  Ncrack/Hydra, same as the IoTGoat credential exercise earlier.
- Ch4's VLAN hopping / switch spoofing (DTP abuse, double-tagging) -
  this manipulates network segmentation itself, not a device, and
  doing it wrong on a network you don't fully control can cause
  outages. It's a one-off manual exercise with Yersinia/Scapy in your
  own lab, not something to bake into a reusable scanner.
- Ch6's mDNS/DNS-SD probing-phase and MITM attacks - active spoofing
  of another host's responses. recon/discovery.py already does the
  passive mDNS *enumeration* half of this chapter; the active half is
  a deliberate exercise, not a default-on check.
"""

from __future__ import annotations

import socket
import struct
import uuid
import xml.etree.ElementTree as ET

import requests

from iotsploit.core.scoring import Finding

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
WSD_ADDR = "239.255.255.250"
WSD_PORT = 3702


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Chapter 4: "Attacking MQTT" - narrowed to the non-destructive half.
# ---------------------------------------------------------------------------

def check_mqtt_anonymous(ip: str, port: int = 1883, device_id: str | None = None,
                          timeout: float = 4.0, evidence_store=None) -> list[Finding]:
    """
    Attempts a full MQTT CONNECT (not just a TCP handshake, unlike
    core's check_mqtt_tls) with no username/password, and records
    whether the broker's CONNACK accepts it. This is the detection
    counterpart to the book's "Attacking MQTT" chapter: before you'd
    ever reach for a credential-cracking tool against a broker that
    rejects anonymous access, this tells you whether that step is
    even necessary - some brokers skip authentication entirely.
    """
    import paho.mqtt.client as mqtt

    device_id = device_id or ip
    result = {"rc": None, "error": None}

    def on_connect(client, userdata, flags, rc, properties=None):
        result["rc"] = rc
        client.disconnect()

    client_kwargs = {"client_id": f"iotsploit-{uuid.uuid4().hex[:6]}", "protocol": mqtt.MQTTv311}
    if hasattr(mqtt, "CallbackAPIVersion"):
        # paho-mqtt 2.x requires an explicit callback API version
        client_kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION1
    client = mqtt.Client(**client_kwargs)
    client.on_connect = on_connect
    try:
        client.connect(ip, port, keepalive=60)
        client.loop_start()
        import time
        waited = 0.0
        while result["rc"] is None and waited < timeout:
            time.sleep(0.1)
            waited += 0.1
        client.loop_stop()
        client.disconnect()
    except Exception as exc:
        result["error"] = str(exc)

    anonymous_accepted = result["rc"] == 0

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_text(
            _fid("mqtt_anon", device_id), "result",
            f"ip={ip}:{port} connack_rc={result['rc']} error={result['error']}",
        )

    if result["error"] and result["rc"] is None:
        description = f"Could not complete an MQTT handshake with {ip}:{port}: {result['error']}"
        damage = {}
    elif anonymous_accepted:
        description = f"Broker at {ip}:{port} accepted an anonymous CONNECT (no username/password)."
        damage = {"privacy": 2, "financial": 1, "availability": 1, "chaining_depth": 1}
    else:
        description = (
            f"Broker at {ip}:{port} rejected an anonymous CONNECT "
            f"(CONNACK reason code {result['rc']}) - correctly requires credentials."
        )
        damage = {}

    return [Finding(
        finding_id=_fid("mqtt_anon", device_id),
        device_id=device_id,
        check_name="mqtt_anonymous",
        description=description,
        cvss=None,
        damage=damage,
        evidence_path=evidence_path,
    )]


# ---------------------------------------------------------------------------
# Chapter 6: "Exploiting UPnP" + the Ch4 fingerprinting technique of
# fetching a device's UPnP description XML to identify it.
# ---------------------------------------------------------------------------

def upnp_discover(timeout: float = 3.0) -> list[dict]:
    """
    SSDP M-SEARCH broadcast (the standard UPnP discovery mechanism
    covered in "The UPnP Stack"). Returns a list of
    {location, raw_headers} for every device that responds - purely
    passive listening after one multicast send, same technique
    IoTGoat's own broadcast-upnp-info nmap script uses.
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))

    devices = []
    try:
        while True:
            data, addr = sock.recvfrom(8192)
            text = data.decode(errors="replace")
            location = None
            for line in text.split("\r\n"):
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
            devices.append({"from": addr[0], "location": location, "raw": text})
    except socket.timeout:
        pass
    finally:
        sock.close()
    return devices


def upnp_enum(target_location: str | None = None, device_id: str | None = None,
              evidence_store=None) -> list[Finding]:
    """
    Discovers UPnP devices (or, if target_location is already known -
    e.g. from a prior scan - fetches it directly) and parses the
    device description XML for friendlyName/manufacturer/modelName.
    This is exactly the Chapter 4 fingerprinting technique: a UPnP
    description response can identify a device's make and model from
    a single unauthenticated HTTP GET, same as the book's webcam
    example.
    """
    findings = []
    locations = [target_location] if target_location else [
        d["location"] for d in upnp_discover() if d.get("location")
    ]

    if not locations:
        return [Finding(
            finding_id=_fid("upnp_enum", device_id or "upnp"),
            device_id=device_id or "upnp",
            check_name="upnp_enum",
            description="No UPnP devices responded to SSDP discovery.",
            cvss=None,
            damage={},
        )]

    for location in set(locations):
        dev_id = device_id or location
        try:
            resp = requests.get(location, timeout=4)
            root = ET.fromstring(resp.text)
            ns = {"u": "urn:schemas-upnp-org:device-1-0"}
            friendly = root.findtext(".//u:friendlyName", namespaces=ns) or "unknown"
            manufacturer = root.findtext(".//u:manufacturer", namespaces=ns) or "unknown"
            model = root.findtext(".//u:modelName", namespaces=ns) or "unknown"
            description = (
                f"UPnP device at {location}: friendlyName='{friendly}', "
                f"manufacturer='{manufacturer}', model='{model}' - "
                f"identifiable from a single unauthenticated request."
            )
            damage = {"privacy": 1}
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_text(
                    _fid("upnp_enum", dev_id), "description_xml", resp.text,
                )
        except Exception as exc:
            description = f"UPnP device description at {location} could not be parsed: {exc}"
            damage = {}
            evidence_path = None

        findings.append(Finding(
            finding_id=_fid("upnp_enum", dev_id),
            device_id=dev_id,
            check_name="upnp_enum",
            description=description,
            cvss=None,
            damage=damage,
            evidence_path=evidence_path,
        ))
    return findings


def upnp_wan_exposure(target_location: str, device_id: str | None = None,
                       evidence_store=None) -> list[Finding]:
    """
    Fetches the device description, finds a WANIPConnection or
    WANPPPConnection service (the service type the book's "Abusing
    UPnP Through WAN interfaces" section targets), and calls the
    read-only GetExternalIPAddress action on it with no credentials -
    UPnP has no authentication model on the LAN by design, so this
    documents that exposure rather than "discovering" a bug. It
    deliberately does NOT call AddPortMapping or anything else that
    changes router state; firewall-hole-punching itself is the book's
    worked example, not something this tool replays automatically.
    """
    dev_id = device_id or target_location
    try:
        resp = requests.get(target_location, timeout=4)
        root = ET.fromstring(resp.text)
        ns = {"u": "urn:schemas-upnp-org:device-1-0"}
        wan_service = None
        control_url = None
        service_type = None
        for service in root.findall(".//u:service", namespaces=ns):
            st = service.findtext("u:serviceType", namespaces=ns) or ""
            if "WANIPConnection" in st or "WANPPPConnection" in st:
                wan_service = service
                service_type = st
                control_url = service.findtext("u:controlURL", namespaces=ns)
                break

        if not wan_service or not control_url:
            return [Finding(
                finding_id=_fid("upnp_wan", dev_id), device_id=dev_id,
                check_name="upnp_wan_exposure",
                description=f"No WANIPConnection/WANPPPConnection service found at {target_location}.",
                cvss=None, damage={},
            )]

        base = target_location.split("/", 3)[0] + "//" + target_location.split("/", 3)[2]
        soap_url = base + control_url
        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            f'<u:GetExternalIPAddress xmlns:u="{service_type}"/>'
            "</s:Body></s:Envelope>"
        )
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPACTION": f'"{service_type}#GetExternalIPAddress"',
        }
        soap_resp = requests.post(soap_url, data=soap_body, headers=headers, timeout=4)
        reachable_unauthenticated = soap_resp.status_code < 400

        evidence_path = None
        if evidence_store:
            evidence_path = evidence_store.save_text(
                _fid("upnp_wan", dev_id), "soap_response",
                f"url={soap_url}\nstatus={soap_resp.status_code}\nbody={soap_resp.text[:1000]}",
            )

        description = (
            f"{service_type} control at {soap_url} answered GetExternalIPAddress "
            + ("with no credentials (expected - UPnP has no LAN-side auth; "
               "the real question for your methodology is whether this is reachable "
               "from the WAN side at all, which this check cannot determine from inside the LAN)."
               if reachable_unauthenticated else
               f"with status {soap_resp.status_code}.")
        )
        damage = {"availability": 1, "financial": 1} if reachable_unauthenticated else {}

    except Exception as exc:
        description = f"UPnP WAN exposure check against {target_location} failed: {exc}"
        damage = {}
        evidence_path = None

    return [Finding(
        finding_id=_fid("upnp_wan", dev_id), device_id=dev_id,
        check_name="upnp_wan_exposure", description=description,
        cvss=None, damage=damage, evidence_path=evidence_path,
    )]


# ---------------------------------------------------------------------------
# Chapter 6: "Exploiting WS-Discovery" - the passive half (enumeration),
# not "Faking Cameras on Your Network" (that's active spoofing).
# ---------------------------------------------------------------------------

def wsd_scan(timeout: float = 3.0) -> list[Finding]:
    """
    Sends a WS-Discovery Probe (the multicast SOAP message ONVIF
    cameras - like the Tapo profile already in this tool - listen
    for) and parses ProbeMatch responses for device XAddrs/Types.
    Pure reconnaissance: no cameras are "faked" and no existing
    device's probe-phase is interfered with, unlike the book's
    active "Faking Cameras" and MITM sections.
    """
    msg_id = str(uuid.uuid4())
    probe = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    sock.sendto(probe.encode(), (WSD_ADDR, WSD_PORT))

    findings = []
    try:
        while True:
            data, addr = sock.recvfrom(8192)
            text = data.decode(errors="replace")
            xaddrs = None
            try:
                root = ET.fromstring(text)
                for elem in root.iter():
                    if elem.tag.endswith("XAddrs"):
                        xaddrs = elem.text
            except ET.ParseError:
                pass
            findings.append(Finding(
                finding_id=_fid("wsd_scan", addr[0]),
                device_id=addr[0],
                check_name="wsd_scan",
                description=f"WS-Discovery ProbeMatch from {addr[0]}: XAddrs={xaddrs or 'unparsed'}",
                cvss=None,
                damage={"privacy": 1},
            ))
    except socket.timeout:
        pass
    finally:
        sock.close()

    if not findings:
        findings.append(Finding(
            finding_id=_fid("wsd_scan", "none"), device_id="none",
            check_name="wsd_scan", description="No WS-Discovery ProbeMatch responses received.",
            cvss=None, damage={},
        ))
    return findings


# ---------------------------------------------------------------------------
# Modbus: not its own chapter, but the same "protocol with no built-in
# authentication" pattern the book applies repeatedly (MQTT, UPnP) -
# included because it's directly relevant to the Pro 3EM target from
# your original hardware shortlist.
# ---------------------------------------------------------------------------

def check_modbus_unauth_read(ip: str, port: int = 502, unit_id: int = 1,
                              address: int = 0, count: int = 2,
                              device_id: str | None = None,
                              evidence_store=None) -> list[Finding]:
    """
    Attempts a read-only Modbus TCP request (Read Holding Registers,
    function code 3) with no credentials - Modbus has no native
    authentication at all, so a successful read simply confirms the
    device is reachable and the protocol's lack of auth is exposed on
    this network segment. Read-only by construction: never issues a
    write function code.
    """
    from pymodbus.client import ModbusTcpClient

    device_id = device_id or ip
    client = ModbusTcpClient(ip, port=port, timeout=4)
    try:
        connected = client.connect()
        if not connected:
            description = f"Could not open a TCP connection to {ip}:{port}."
            damage = {}
            evidence_path = None
        else:
            try:
                # pymodbus >=3.7 renamed the unit-id kwarg to device_id
                result = client.read_holding_registers(address=address, count=count, device_id=unit_id)
            except TypeError:
                result = client.read_holding_registers(address=address, count=count, slave=unit_id)
            if result.isError():
                description = (
                    f"Modbus TCP reachable at {ip}:{port} but the read request errored "
                    f"({result})."
                )
                damage = {}
            else:
                description = (
                    f"Modbus TCP at {ip}:{port} answered an unauthenticated read of "
                    f"holding registers {address}-{address + count - 1}: {result.registers}. "
                    f"Modbus has no built-in authentication, so this is expected protocol "
                    f"behavior, not a bug in this device specifically - treat it as a "
                    f"network-exposure finding, same framing as the UPnP WAN check."
                )
                damage = {"privacy": 1, "financial": 1, "availability": 1}
            evidence_path = None
            if evidence_store:
                evidence_path = evidence_store.save_text(
                    _fid("modbus", device_id), "result", description,
                )
    except Exception as exc:
        description = f"Modbus check against {ip}:{port} failed: {exc}"
        damage = {}
        evidence_path = None
    finally:
        client.close()

    return [Finding(
        finding_id=_fid("modbus", device_id), device_id=device_id,
        check_name="modbus_unauth_read", description=description,
        cvss=None, damage=damage, evidence_path=evidence_path,
    )]
