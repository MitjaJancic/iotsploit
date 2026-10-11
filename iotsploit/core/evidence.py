"""
evidence.py

Saves raw evidence (packet captures, HTTP response bodies, MQTT
message logs) alongside scored findings, so someone re-running the
tool against different hardware can re-derive scores under a
different rubric without re-running the check.

PCAP capture requires tshark on PATH. If it isn't available, falls
back to saving a plain-text log instead and records that fallback in
the evidence metadata.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path


class EvidenceStore:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_text(self, finding_id: str, label: str, content: str) -> str:
        path = self.output_dir / f"{finding_id}_{label}.txt"
        path.write_text(content)
        return str(path)

    def save_json(self, finding_id: str, label: str, data: dict) -> str:
        path = self.output_dir / f"{finding_id}_{label}.json"
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def capture_packets(self, finding_id: str, iface: str, duration_s: int = 10,
                         bpf_filter: str = "") -> str:
        """Capture a short PCAP during a check. Requires tshark."""
        out_path = self.output_dir / f"{finding_id}_capture.pcap"
        if shutil.which("tshark") is None:
            note = (
                f"tshark not found on PATH at {time.ctime()}; "
                f"no packet capture taken for {finding_id}."
            )
            return self.save_text(finding_id, "capture_unavailable", note)

        cmd = ["tshark", "-i", iface, "-a", f"duration:{duration_s}", "-w", str(out_path)]
        if bpf_filter:
            cmd += ["-f", bpf_filter]
        subprocess.run(cmd, check=False, capture_output=True)
        return str(out_path)
