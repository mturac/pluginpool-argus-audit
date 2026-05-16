"""Report renderers for argus-audit. Three formats: text / json / markdown."""

from __future__ import annotations

import io
import json
import time

from .findings import FindingSet, Severity


def _severity_glyph(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "[!!]",
        Severity.HIGH: "[H ]",
        Severity.MEDIUM: "[M ]",
        Severity.LOW: "[L ]",
        Severity.INFO: "[i ]",
    }.get(sev, "[? ]")


def render_text(fs: FindingSet, target_label: str = "") -> str:
    buf = io.StringIO()
    summary = fs.summary()
    worst = fs.worst()
    header = "argus-audit report"
    if target_label:
        header += f" — {target_label}"
    buf.write(header + "\n")
    buf.write("=" * len(header) + "\n\n")
    buf.write(f"Worst severity: {worst.name}\n")
    counts = "  ".join(f"{n}={summary[n]}" for n in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    buf.write(f"Counts: {counts}\n")
    buf.write(f"Total findings: {len(fs.findings)}\n\n")
    if not fs.findings:
        buf.write("No findings.\n")
        return buf.getvalue()
    for f in fs.sorted():
        buf.write(f"{_severity_glyph(f.severity)} {f.rule_id}  {f.title}\n")
        buf.write(f"     surface : {f.surface}\n")
        buf.write(f"     target  : {f.target}\n")
        if f.location:
            buf.write(f"     where   : {f.location}\n")
        if f.evidence:
            buf.write(f"     evidence: {f.evidence}\n")
        if f.cvss is not None:
            buf.write(f"     CVSS    : {f.cvss}\n")
        if f.epss is not None:
            buf.write(f"     EPSS    : {f.epss:.3f}\n")
        if f.kev:
            buf.write("     KEV     : in CISA KEV catalog\n")
        if f.cwe:
            buf.write(f"     CWE     : {f.cwe}\n")
        if f.remediation:
            buf.write(f"     fix     : {f.remediation}\n")
        for ref in f.references:
            buf.write(f"     ref     : {ref}\n")
        buf.write("\n")
    return buf.getvalue()


def render_json(fs: FindingSet, target_label: str = "") -> str:
    payload = {
        "tool": "argus-audit",
        "target": target_label,
        "generated_at": int(time.time()),
        "summary": fs.summary(),
        "worst": fs.worst().name,
        "findings": [f.to_dict() for f in fs.sorted()],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_markdown(fs: FindingSet, target_label: str = "") -> str:
    buf = io.StringIO()
    buf.write("# argus-audit report\n\n")
    if target_label:
        buf.write(f"**Target:** `{target_label}`\n\n")
    summary = fs.summary()
    buf.write(f"**Worst severity:** `{fs.worst().name}`\n\n")
    buf.write("| Severity | Count |\n| --- | ---: |\n")
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        buf.write(f"| {name} | {summary[name]} |\n")
    buf.write(f"\n**Total findings:** {len(fs.findings)}\n\n")
    if not fs.findings:
        buf.write("_No findings._\n")
        return buf.getvalue()
    buf.write("## Findings\n\n")
    for f in fs.sorted():
        buf.write(f"### {_severity_glyph(f.severity)} `{f.rule_id}` — {f.title}\n\n")
        buf.write(f"- Surface: `{f.surface}`\n")
        buf.write(f"- Target: `{f.target}`\n")
        if f.location:
            buf.write(f"- Location: `{f.location}`\n")
        if f.evidence:
            buf.write(f"- Evidence: `{f.evidence}`\n")
        if f.cvss is not None:
            buf.write(f"- CVSS: **{f.cvss}**\n")
        if f.epss is not None:
            buf.write(f"- EPSS: **{f.epss:.3f}**\n")
        if f.kev:
            buf.write("- **KEV-listed**\n")
        if f.cwe:
            buf.write(f"- CWE: `{f.cwe}`\n")
        if f.remediation:
            buf.write(f"- Remediation: {f.remediation}\n")
        if f.references:
            buf.write("- References:\n")
            for ref in f.references:
                buf.write(f"  - <{ref}>\n")
        buf.write("\n")
    return buf.getvalue()


def render(fs: FindingSet, fmt: str, target_label: str = "") -> str:
    fmt = fmt.lower()
    if fmt == "text":
        return render_text(fs, target_label)
    if fmt == "json":
        return render_json(fs, target_label)
    if fmt in {"md", "markdown"}:
        return render_markdown(fs, target_label)
    raise ValueError(f"unknown report format: {fmt}")
