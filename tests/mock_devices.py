"""
mock_devices.py

Lightweight mock servers (HTTP, MQTT, CoAP) for rapid local testing
without requiring physical smart-home hardware online.
"""

from __future__ import annotations

import http.server
import threading
from typing import Optional


class MockDeviceHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Simple mock HTTP handler simulating authenticated vs unauthenticated IoT endpoints."""

    def do_GET(self):
        # Simulate open endpoint (e.g. missing auth)
        if "/status" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"relays": [{"ison": false, "has_timer": false}], "mac": "AABBCCDDEEFF"}')
        elif "/settings" in self.path and "/secure" not in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"login": {"enabled": false}, "device": {"type": "SHSW-1"}}')
        elif "/relay/0" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ison": true, "has_timer": true}')
        elif "/secure/settings" in self.path:
            # Requires auth (401)
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if "/relay/toggle" in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "toggled"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence default stderr logging during test runs
        pass


class MockHTTPServer:
    """Convenience context manager to start and stop a background mock HTTP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        self.host = host
        self.port = port
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.server = http.server.HTTPServer((self.host, self.port), MockDeviceHTTPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
