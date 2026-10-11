"""
report.py

Turns a list of Finding objects into a JSON report (machine-readable,
for your thesis data analysis) and an HTML report (human-readable,
for the "usable in the real world" requirement).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .scoring import Finding, aggregate

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IoT Damage Audit Report</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #222; }}
  h1 {{ font-size: 1.4rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 0.9rem; }}
  th {{ background: #f2f2f2; }}
  .high {{ background: #fdecea; }}
  .medium {{ background: #fff6e0; }}
  .low {{ background: #eefaf0; }}
</style>
</head>
<body>
<h1>IoT Damage Audit Report</h1>
<p>Generated: {generated_at}</p>

<h2>Device Summary</h2>
<table>
<tr><th>Device</th><th>Findings</th><th>Total Damage Score</th><th>Max Damage Score</th><th>Max CVSS</th></tr>
{device_rows}
</table>

<h2>Findings</h2>
<table>
<tr><th>ID</th><th>Device</th><th>Check</th><th>Description</th><th>CVSS</th><th>Damage Score</th><th>Evidence</th></tr>
{finding_rows}
</table>
</body>
</html>
"""


def _severity_class(score: float) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def write_reports(findings: list[Finding], weights: dict, output_dir: str | Path,
                   basename: str = "report") -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = aggregate(findings, weights)
    generated_at = datetime.now(timezone.utc).isoformat()

    json_payload = {
        "generated_at": generated_at,
        "weights": weights,
        "device_summary": summary,
        "findings": [f.to_dict(weights) for f in findings],
    }
    json_path = output_dir / f"{basename}.json"
    json_path.write_text(json.dumps(json_payload, indent=2, default=str))

    device_rows = "\n".join(
        f"<tr><td>{dev}</td><td>{s['finding_count']}</td>"
        f"<td>{s['total_damage_score']:.1f}</td><td>{s['max_damage_score']:.1f}</td>"
        f"<td>{s['max_cvss']:.1f}</td></tr>"
        for dev, s in summary.items()
    )

    finding_rows = "\n".join(
        f'<tr class="{_severity_class(f.damage_score(weights))}">'
        f"<td>{f.finding_id}</td><td>{f.device_id}</td><td>{f.check_name}</td>"
        f"<td>{f.description}</td><td>{f.cvss or '-'}</td>"
        f"<td>{f.damage_score(weights):.1f}</td>"
        f"<td>{Path(f.evidence_path).name if f.evidence_path else '-'}</td></tr>"
        for f in findings
    )

    html_path = output_dir / f"{basename}.html"
    html_path.write_text(
        HTML_TEMPLATE.format(
            generated_at=generated_at,
            device_rows=device_rows or "<tr><td colspan='5'>No devices scanned</td></tr>",
            finding_rows=finding_rows or "<tr><td colspan='7'>No findings</td></tr>",
        )
    )

    return {"json": str(json_path), "html": str(html_path)}
