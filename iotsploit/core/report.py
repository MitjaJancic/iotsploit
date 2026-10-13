"""
report.py

Turns a list of Finding objects into a JSON report (machine-readable,
for your thesis data analysis) and an HTML report (human-readable,
for the "usable in the real world" requirement).
"""

from __future__ import annotations

import json
import re
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


def _parse_finding_cred(f: Finding) -> dict | None:
    if f.check_name in ("firmware_shadow", "firmware_shadow_nopw", "firmware_shadow_hash",
                        "firmware_passwd_cred", "firmware_backdoor_uid0", "firmware_passwd"):
        desc = f.description.strip()
        # Pattern: user:hash (type) [file]
        m = re.match(r"^([^:\s]+):([^\s\[]+)(?:\s*\(([^)]+)\))?(?:\s*\[([^\]]+)\])?", desc)
        if m:
            u, h, t, loc = m.groups()
            loc_clean = loc.replace("empty password in ", "").strip() if loc else "-"
            return {
                "cred": f"{u}:{h}",
                "type": t or ("Empty password" if "<NO_PASSWORD>" in h else "Password/Hash"),
                "location": loc_clean,
            }
        # Backdoor UID 0
        m_bd = re.search(r"Backdoor.*:\s*([^:\s]+):(\d+)\s*\[([^\]]+)\]", desc)
        if m_bd:
            return {
                "cred": f"{m_bd.group(1)}:0 (UID 0)",
                "type": "Hidden Backdoor (UID 0)",
                "location": m_bd.group(3),
            }
        # Fallback for unit tests (e.g. "Account 'root' has a crackable DES hash in /etc/shadow")
        if " in " in desc and not "accounts in" in desc:
            return {
                "cred": desc.split(" in ")[0],
                "type": "Credential Finding",
                "location": desc.split(" in ")[1],
            }
    return None


def _parse_finding_service(f: Finding) -> dict | None:
    if f.check_name in ("firmware_service", "firmware_services", "firmware_wifi_key"):
        desc = f.description.strip()
        m = re.match(r"^([^:\[]+)(?::(\d+))?\s*(?:\[([^\]]*)\])?(?:\s*\(([^)]*)\))?", desc)
        if m:
            svc, port, cfg, extra = m.groups()
            return {
                "service": svc.strip(),
                "port": port or "-",
                "config": cfg or "-",
                "details": extra or "-",
            }
        parts = desc.split("[")
        return {
            "service": parts[0].strip(),
            "port": "-",
            "config": parts[1].rstrip("]") if len(parts) > 1 else "-",
            "details": "-",
        }
    return None


def _parse_finding_secret(f: Finding) -> dict | None:
    if f.check_name in ("firmware_secret", "firmware_secrets", "firmware_grep", "firmware_hardcoded_strings"):
        desc = f.description.strip()
        m = re.match(r"^([^:\s]+):\s*([^\s\[]+)\s*\[([^\]]+)\]", desc)
        if m:
            stype, sval, sloc = m.groups()
            return {
                "type": stype.strip(),
                "value": sval.strip(),
                "location": sloc.strip(),
            }
        parts = desc.split("[")
        return {
            "type": f.check_name,
            "value": parts[0].strip() if len(parts) > 1 else desc[:45],
            "location": parts[1].rstrip("]") if len(parts) > 1 else "-",
        }
    return None


def generate_markdown_report(findings: list[Finding], weights: dict, generated_at: str) -> str:
    summary = aggregate(findings, weights)
    lines = [
        "# IoT Security & Damage Assessment Report",
        f"**Generated:** {generated_at}  ",
        f"**Total Findings:** {len(findings)}  ",
        "",
    ]

    sec_num = 1

    # --- Discovered Credentials & Accounts Table (pure user:hash) ---
    cred_items = []
    for f in findings:
        parsed = _parse_finding_cred(f)
        if parsed:
            score = f.damage_score(weights)
            severity = "CRITICAL" if (f.cvss and f.cvss >= 9.0) or "<NO_PASSWORD>" in parsed["cred"] or "Backdoor" in parsed["type"] else (
                "HIGH" if score >= 6 else ("MEDIUM" if score >= 3 else "LOW")
            )
            cred_items.append((parsed, severity, score))

    if cred_items:
        lines.extend([
            f"## {sec_num}. Discovered Credentials & Accounts",
            "| # | Account / Credential (`user:hash` or `user:password`) | Status / Type | Source Location | Severity |",
            "| :---: | :--- | :--- | :--- | :---: |",
        ])
        for idx, (c, sev, sc) in enumerate(cred_items, start=1):
            lines.append(f"| {idx} | `{c['cred']}` | {c['type']} | `{c['location']}` | **{sev}** |")
        lines.extend(["", "---", ""])
        sec_num += 1

    # --- Discovered Services & Network Daemons Table ---
    svc_items = []
    for f in findings:
        parsed = _parse_finding_service(f)
        if parsed:
            svc_items.append(parsed)

    if svc_items:
        lines.extend([
            f"## {sec_num}. Discovered Services & Network Daemons",
            "| # | Service | Default Port | Config / Script | Access & Security Details |",
            "| :---: | :--- | :---: | :--- | :--- |",
        ])
        for idx, s in enumerate(svc_items, start=1):
            lines.append(f"| {idx} | **{s['service']}** | `{s['port']}` | `{s['config']}` | {s['details']} |")
        lines.extend(["", "---", ""])
        sec_num += 1

    # --- Discovered Hardcoded Secrets & Tokens Table ---
    secret_items = []
    for f in findings:
        parsed = _parse_finding_secret(f)
        if parsed:
            secret_items.append((parsed, f.damage_score(weights)))

    if secret_items:
        lines.extend([
            f"## {sec_num}. Discovered Hardcoded Tokens & API Keys",
            "| # | Token Type | Masked Secret / Value | Location | Damage Score |",
            "| :---: | :--- | :--- | :--- | :---: |",
        ])
        for idx, (sec, sc) in enumerate(secret_items, start=1):
            lines.append(f"| {idx} | `{sec['type']}` | `{sec['value']}` | `{sec['location']}` | {sc:.1f} |")
        lines.extend(["", "---", ""])
        sec_num += 1

    # --- All Findings Index Table ---
    lines.extend([
        f"## {sec_num}. Assessment Summary & Findings Index",
        "| # | Check Module | Finding Summary (`user:pass` / Service / Vector) | Damage Score | CVSS | Severity |",
        "| :---: | :--- | :--- | :---: | :---: | :---: |",
    ])
    sec_num += 1
    if not findings:
        lines.append("| - | *None* | No findings detected | 0.0 | - | INFO |")
    else:
        for idx, f in enumerate(findings, start=1):
            short_desc = f.description.strip().replace("\n", " ")
            if len(short_desc) > 85:
                short_desc = short_desc[:82] + "…"
            cvss_str = str(f.cvss) if f.cvss is not None else "-"
            score = f.damage_score(weights)
            severity = "CRITICAL" if (f.cvss and f.cvss >= 9.0) else (
                "HIGH" if score >= 6 else ("MEDIUM" if score >= 3 else "LOW")
            )
            lines.append(f"| {idx} | `{f.check_name}` | {short_desc} | {score:.1f} | {cvss_str} | **{severity}** |")

    # --- Device Summary ---
    lines.extend([
        "",
        "---",
        "",
        f"## {sec_num}. Device Summary",
        "| Device ID | Findings Count | Total Damage Score | Max Damage Score | Max CVSS |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ])
    sec_num += 1
    if summary:
        for dev, s in summary.items():
            lines.append(
                f"| `{dev}` | {s['finding_count']} | {s['total_damage_score']:.1f} | {s['max_damage_score']:.1f} | {s['max_cvss']:.1f} |"
            )
    else:
        lines.append("| *None* | 0 | 0.0 | 0.0 | 0.0 |")

    # --- Detailed Technical Findings ---
    lines.extend([
        "",
        "---",
        "",
        f"## {sec_num}. Detailed Technical Findings & Evidence",
        "",
    ])

    if not findings:
        lines.append("*No security findings detected.*")
    else:
        for i, f in enumerate(findings, start=1):
            score = f.damage_score(weights)
            severity = "HIGH" if score >= 6 else ("MEDIUM" if score >= 3 else "LOW")
            if f.cvss and f.cvss >= 9.0:
                severity = "CRITICAL"

            lines.extend([
                f"### {i}. [{severity}] `{f.check_name}` (Device: `{f.device_id}`)",
                f"- **Finding ID:** `{f.finding_id}`",
                f"- **CVSS Base Score:** {f.cvss if f.cvss is not None else 'N/A'} | **Calculated Damage Score:** {score:.1f}",
            ])

            if f.damage:
                damage_items = ", ".join(f"{k}: {v}" for k, v in f.damage.items())
                lines.append(f"- **Damage Dimensions:** {damage_items}")

            if f.evidence_path:
                lines.append(f"- **Evidence File:** `{f.evidence_path}`")

            lines.extend([
                "- **Full Description:**",
                f"  > {f.description.strip()}",
                "",
            ])

    return "\n".join(lines) + "\n"


def generate_text_report(findings: list[Finding], weights: dict, generated_at: str) -> str:
    summary = aggregate(findings, weights)
    lines = [
        "=" * 72,
        "IoT Security Assessment Report",
        f"Generated: {generated_at}",
        f"Total Findings: {len(findings)}",
        "=" * 72,
        "",
    ]

    # --- 1. Discovered Credentials (pure user:hash list) ---
    cred_items = []
    for f in findings:
        parsed = _parse_finding_cred(f)
        if parsed:
            score = f.damage_score(weights)
            severity = "CRITICAL" if (f.cvss and f.cvss >= 9.0) or "<NO_PASSWORD>" in parsed["cred"] or "Backdoor" in parsed["type"] else (
                "HIGH" if score >= 6 else ("MEDIUM" if score >= 3 else "LOW")
            )
            cred_items.append((parsed, severity, score))

    if cred_items:
        lines.extend([
            "[DISCOVERED CREDENTIALS (USER:HASH)]",
        ])
        for c, _, _ in cred_items:
            lines.append(f"{c['cred']}")
        lines.extend([
            "",
            "[CREDENTIAL DETAILS]",
            f"{'#':<3} {'ACCOUNT / HASH':<48} {'TYPE':<16} {'SOURCE':<14} {'SEVERITY':<8}",
            "-" * 92,
        ])
        for idx, (c, sev, sc) in enumerate(cred_items, start=1):
            cred_col = c['cred']
            if len(cred_col) > 46:
                cred_col = cred_col[:43] + "..."
            lines.append(f"{idx:<3} {cred_col:<48} {c['type']:<16} {c['location']:<14} {sev:<8}")
        lines.extend(["-" * 92, ""])

    # --- 2. Discovered Services ---
    svc_items = []
    for f in findings:
        parsed = _parse_finding_service(f)
        if parsed:
            svc_items.append(parsed)

    if svc_items:
        lines.extend([
            "[DISCOVERED SERVICES & NETWORK DAEMONS]",
            f"{'#':<3} {'SERVICE':<24} {'PORT':<6} {'CONFIG / SCRIPT':<24} {'DETAILS'}",
            "-" * 80,
        ])
        for idx, s in enumerate(svc_items, start=1):
            lines.append(f"{idx:<3} {s['service']:<24} {s['port']:<6} {s['config']:<24} {s['details']}")
        lines.extend(["-" * 80, ""])

    # --- 3. Hardcoded Secrets ---
    secret_items = []
    for f in findings:
        parsed = _parse_finding_secret(f)
        if parsed:
            secret_items.append((parsed, f.damage_score(weights)))

    if secret_items:
        lines.extend([
            "[HARDCODED TOKENS & SECRETS]",
            f"{'#':<3} {'TYPE':<22} {'MASKED VALUE':<26} {'LOCATION':<20} {'SCORE'}",
            "-" * 80,
        ])
        for idx, (sec, sc) in enumerate(secret_items, start=1):
            lines.append(f"{idx:<3} {sec['type']:<22} {sec['value']:<26} {sec['location']:<20} {sc:.1f}")
        lines.extend(["-" * 80, ""])

    # --- 4. Summary Table ---
    lines.extend([
        "[FINDINGS SUMMARY]",
        f"{'#':<3} {'CHECK':<22} {'SUMMARY':<46} {'SCORE':<6} {'CVSS':<6} {'SEVERITY'}",
        "-" * 92,
    ])
    for idx, f in enumerate(findings, start=1):
        s_desc = f.description.strip().replace("\n", " ")
        if len(s_desc) > 44:
            s_desc = s_desc[:41] + "..."
        cvss_str = str(f.cvss) if f.cvss is not None else "-"
        score = f.damage_score(weights)
        severity = "CRITICAL" if (f.cvss and f.cvss >= 9.0) else (
            "HIGH" if score >= 6 else ("MEDIUM" if score >= 3 else "LOW")
        )
        lines.append(f"{idx:<3} {f.check_name:<22} {s_desc:<46} {score:<6.1f} {cvss_str:<6} {severity}")
    lines.extend(["-" * 92, ""])

    return "\n".join(lines) + "\n"


def write_reports(findings: list[Finding], weights: dict, output_dir: str | Path,
                   basename: str = "report") -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = aggregate(findings, weights)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    json_payload = {
        "generated_at": generated_at,
        "weights": weights,
        "device_summary": summary,
        "findings": [f.to_dict(weights) for f in findings],
    }
    json_path = output_dir / f"{basename}.json"
    json_path.write_text(json.dumps(json_payload, indent=2, default=str), encoding="utf-8")

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
        ),
        encoding="utf-8"
    )

    # Save Markdown report
    md_path = output_dir / f"{basename}.md"
    md_content = generate_markdown_report(findings, weights, generated_at)
    md_path.write_text(md_content, encoding="utf-8")

    # Save Text report (.txt)
    txt_path = output_dir / f"{basename}.txt"
    txt_content = generate_text_report(findings, weights, generated_at)
    txt_path.write_text(txt_content, encoding="utf-8")

    return {"json": str(json_path), "html": str(html_path), "md": str(md_path), "txt": str(txt_path)}
