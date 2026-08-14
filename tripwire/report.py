"""Rendering the audit.

The report leads with the capability inventory, not the findings. That order is
deliberate: most people have never seen the union of what their agent can do,
and the inventory is useful even when nothing is wrong. Findings follow,
severity first, each with the mechanism attached — a scanner that says
"potential risk" and stops trains people to close it.
"""

from __future__ import annotations

import json
from typing import Dict, List, Sequence

from .inventory import Inventory
from .rules import SEVERITIES, Finding, summarize_capabilities

__all__ = ["render_json", "render_text"]

_MARK = {"high": "!!", "medium": " !", "low": " ·", "info": " ·"}


def render_text(
    inventory: Inventory,
    findings: Sequence[Finding],
    show_info: bool = False,
    width: int = 72,
) -> str:
    rule = "─" * width
    lines: List[str] = []
    caps = summarize_capabilities(inventory)

    lines.append(rule)
    lines.append("  tripwire — what your agent can currently do")
    lines.append(rule)
    lines.append("")
    lines.append("  %-34s %d" % ("skills installed", caps["skills_total"]))
    lines.append(
        "  %-34s %d" % ("  from outside this machine", caps["skills_third_party"])
    )
    lines.append(
        "  %-34s %d" % ("  shipping executable code", caps["skills_with_scripts"])
    )
    lines.append("  %-34s %d" % ("MCP servers configured", caps["servers_total"]))
    lines.append("  %-34s %d" % ("  reached over the network", caps["servers_remote"]))
    lines.append("  %-34s %d" % ("automatic hooks", caps["hooks_total"]))
    if caps["hook_events"]:
        lines.append("  %-34s %s" % ("  firing on", ", ".join(caps["hook_events"])))
    lines.append("  %-34s %d" % ("settings files", caps["settings_files"]))
    if caps["unreadable"]:
        lines.append("  %-34s %d" % ("unreadable files (skipped)", caps["unreadable"]))
    lines.append("")

    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    shown = [f for f in findings if show_info or f.severity != "info"]

    lines.append(rule)
    lines.append(
        "  %d high · %d medium · %d low · %d informational"
        % (counts["high"], counts["medium"], counts["low"], counts["info"])
    )
    lines.append(rule)

    if not shown:
        lines.append("")
        lines.append("  Nothing to flag. Run with --info to see the full inventory.")
        lines.append("")
        return "\n".join(lines)

    current = None
    for finding in shown:
        if finding.severity != current:
            current = finding.severity
            lines.append("")
            lines.append("  %s" % current.upper())
            lines.append("")
        lines.append("  %s %s" % (_MARK.get(finding.severity, " ·"), finding.title))
        lines.append("     %s" % finding.detail)
        if finding.mechanism:
            lines.append("     Why it matters: %s" % finding.mechanism)
        if finding.evidence:
            lines.append("     > %s" % finding.evidence)
        lines.append("     %s" % _short_path(finding.location))
        if finding.remediation:
            lines.append("     → %s" % finding.remediation)
        lines.append("")

    lines.append(rule)
    lines.append("  This is a static read of local config. It proves nothing is")
    lines.append("  obviously wrong, not that nothing is wrong.")
    lines.append("")
    return "\n".join(lines)


def render_json(inventory: Inventory, findings: Sequence[Finding], version: str) -> str:
    counts: Dict[str, int] = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return json.dumps(
        {
            "tool": "tripwire",
            "version": version,
            "capabilities": summarize_capabilities(inventory),
            "counts": counts,
            "findings": [f.to_dict() for f in findings],
            "inventory": inventory.to_dict(),
        },
        indent=2,
    )


def _short_path(path: str) -> str:
    import os

    home = os.path.expanduser("~")
    return path.replace(home, "~") if path.startswith(home) else path
