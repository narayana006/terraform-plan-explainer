"""Render the summary as plain text, Markdown or JSON."""

from __future__ import annotations

import json

from .plan import KINDS, Change, group_by_kind
from .risks import SEVERITIES, Finding

SYMBOLS = {"create": "+", "update": "~", "replace": "-/+", "destroy": "-"}
HEADINGS = {"create": "Create", "update": "Update in place", "replace": "Replace", "destroy": "Destroy"}


def headline(changes: list[Change]) -> str:
    groups = group_by_kind(changes)
    if not changes:
        return "No changes. The infrastructure matches the configuration."
    parts = [f"{len(groups[k])} to {k}" for k in ("create", "update", "replace", "destroy")]
    return f"{len(changes)} resource change{'s' if len(changes) != 1 else ''}: " + ", ".join(parts) + "."


def verdict(findings: list[Finding]) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    if counts["high"]:
        return (f"Verdict: STOP AND REVIEW. {counts['high']} high-risk finding"
                f"{'s' if counts['high'] != 1 else ''}; read the risks above before applying.")
    if counts["medium"]:
        return f"Verdict: review advised. {counts['medium']} medium-risk finding{'s' if counts['medium'] != 1 else ''}."
    if counts["low"]:
        return "Verdict: looks routine. Only low-risk findings."
    return "Verdict: looks routine. No destructive or high-risk changes detected."


def render_text(changes: list[Change], findings: list[Finding]) -> str:
    lines = [headline(changes), ""]
    if findings:
        lines.append(f"RISKS ({len(findings)})")
        for f in findings:
            lines.append(f"  [{f.severity.upper():<6}] {f.address}")
            lines.append(f"           {f.category}: {f.message}")
        lines.append("")
    groups = group_by_kind(changes)
    if changes:
        lines.append("CHANGES")
        for kind in KINDS:
            if groups[kind]:
                lines.append(f"  {HEADINGS[kind]} ({len(groups[kind])})")
                lines.extend(f"    {SYMBOLS[kind]:>3} {c.address}" for c in groups[kind])
        lines.append("")
    lines.append(verdict(findings))
    return "\n".join(lines) + "\n"


def render_markdown(changes: list[Change], findings: list[Finding]) -> str:
    lines = ["## Terraform plan summary", "", headline(changes), ""]
    if findings:
        lines += ["### Risks", "", "| Severity | Resource | Category | What |", "|---|---|---|---|"]
        for f in findings:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| **{f.severity.upper()}** | `{f.address}` | {f.category} | {msg} |")
        lines.append("")
    groups = group_by_kind(changes)
    for kind in KINDS:
        if groups[kind]:
            lines += [f"### {HEADINGS[kind]} ({len(groups[kind])})", ""]
            lines += [f"- `{c.address}`" for c in groups[kind]]
            lines.append("")
    lines.append(f"**{verdict(findings)}**")
    return "\n".join(lines) + "\n"


def render_json(changes: list[Change], findings: list[Finding]) -> str:
    groups = group_by_kind(changes)
    doc = {
        "summary": headline(changes),
        "counts": {k: len(groups[k]) for k in KINDS},
        "changes": {k: [c.address for c in groups[k]] for k in KINDS},
        "findings": [
            {"severity": f.severity, "category": f.category, "address": f.address, "message": f.message}
            for f in findings
        ],
        "verdict": verdict(findings),
    }
    return json.dumps(doc, indent=2) + "\n"


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json}
