"""Acknowledging findings you have already reviewed, and spotting what is new.

A scanner with no way to say "I looked at this and it is fine" has exactly one
outcome: someone runs it, sees six findings they have already judged, and stops
running it. The findings that matter then arrive into a report nobody opens.

Two mechanisms, and the distinction between them is the useful part.

``.tripwireignore``
    A permanent, reviewed decision. "This hook is mine, I wrote it, stop
    telling me." Entries are matched on rule id plus location, carry a reason,
    and the count of suppressed findings is always printed — a suppression you
    cannot see is indistinguishable from a scanner that missed something.

``--baseline`` / ``--update-baseline``
    A snapshot of the current state, so the next run can answer the question
    security work actually turns on: *what changed?* A finding present in the
    baseline is reported as known; anything absent is new and gets the reader's
    attention. This is how a weekly audit stays readable as the config grows.

Neither mechanism can hide a finding silently. Both report their own effect.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "BASELINE_FILE",
    "IGNORE_FILE",
    "BaselineError",
    "Ignore",
    "apply_ignores",
    "diff_against_baseline",
    "finding_key",
    "load_baseline",
    "load_ignores",
    "write_baseline",
]

IGNORE_FILE = ".tripwireignore"
BASELINE_FILE = ".tripwire-baseline.json"


class BaselineError(ValueError):
    """Raised when an ignore or baseline file cannot be used."""


def finding_key(finding) -> str:
    """A stable identity for a finding across runs.

    Rule plus location plus a short digest of the title. Deliberately *not*
    the evidence: evidence contains line excerpts that shift when a file is
    edited, and a key that changes on every edit would make the baseline
    useless within a day.
    """
    basis = "%s|%s|%s" % (
        finding.rule,
        _normalize_location(finding.location),
        finding.title,
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return "%s:%s" % (finding.rule, digest)


def _normalize_location(location: str) -> str:
    """Make a location comparable across machines.

    Home directories differ between the laptop that wrote the baseline and the
    CI runner that reads it, so an absolute path would make every finding look
    new. Windows separators are normalized for the same reason.
    """
    text = (location or "").replace(os.sep, "/").replace("\\", "/")
    home = os.path.expanduser("~").replace(os.sep, "/")
    if home and text.startswith(home):
        text = "~" + text[len(home) :]
    # Temp directories carry a random component; collapse it so fixtures and
    # CI runs produce stable keys.
    text = re.sub(r"/(tripwire|agentsmith|burnrate)-test-[A-Za-z0-9_]+", "/<tmp>", text)
    return text


class Ignore:
    """One reviewed decision to suppress a finding."""

    __slots__ = ("pattern", "reason", "rule")

    def __init__(self, rule: str, pattern: Optional[str], reason: str) -> None:
        self.rule = rule
        self.pattern = pattern
        self.reason = reason

    def matches(self, finding) -> bool:
        if self.rule not in ("*", finding.rule):
            return False
        if not self.pattern:
            return True
        return self.pattern in _normalize_location(finding.location)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Ignore(%r, %r)" % (self.rule, self.pattern)


def load_ignores(path: str) -> List[Ignore]:
    """Read a ``.tripwireignore``.

    Format, one rule per line::

        # comments and blank lines are skipped
        hook.command                          # suppress everywhere
        skill.bundled-scripts  plugins/mine   # suppress under a path
        settings.wildcard-allow  *  I run this in a container only

    Anything after the rule and optional path is treated as the reason, which
    is printed when the suppression is reported. A reason is not required, but
    a suppression without one is a decision nobody can audit later.
    """
    if not os.path.isfile(path):
        return []
    out: List[Ignore] = []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise BaselineError("could not read %s: %s" % (path, exc)) from exc

    for number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 2)
        rule = parts[0]
        pattern = parts[1] if len(parts) > 1 and parts[1] != "*" else None
        reason = parts[2] if len(parts) > 2 else ""
        # Rule ids are always `namespace.name` (or the `*` wildcard). Requiring
        # that shape catches the common mistake of writing prose into the file
        # and expecting it to work — a suppression that silently matches
        # nothing leaves the reader believing they handled something.
        if rule != "*" and not re.match(r"^[\w-]+\.[\w.*-]+$", rule):
            raise BaselineError(
                "%s line %d: %r is not a rule id. Expected `namespace.name` — "
                "for example `hook.command` or `settings.wildcard-allow` — or "
                "`*` to match every rule. Rule ids appear in `--format json`."
                % (path, number, rule)
            )
        out.append(Ignore(rule=rule, pattern=pattern, reason=reason))
    return out


def apply_ignores(findings: Sequence, ignores: Sequence[Ignore]) -> Tuple[List, List]:
    """Split findings into (kept, suppressed)."""
    if not ignores:
        return list(findings), []
    kept, suppressed = [], []
    for finding in findings:
        matched = next((i for i in ignores if i.matches(finding)), None)
        if matched is None:
            kept.append(finding)
        else:
            finding.suppressed_by = matched  # type: ignore[attr-defined]
            suppressed.append(finding)
    return kept, suppressed


def load_baseline(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError("could not read baseline %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise BaselineError("%s is not a tripwire baseline" % path)
    return data


def write_baseline(path: str, findings: Sequence, version: str) -> int:
    """Record the current findings as accepted. Returns how many were stored."""
    payload = {
        "tool": "tripwire",
        "version": version,
        "note": (
            "Findings accepted as known. Anything absent from this file is "
            "reported as new on the next run. Regenerate with "
            "--update-baseline after reviewing."
        ),
        "findings": sorted(
            {
                finding_key(f): {
                    "key": finding_key(f),
                    "rule": f.rule,
                    "severity": f.severity,
                    "title": f.title,
                    "location": _normalize_location(f.location),
                }
                for f in findings
            }.values(),
            key=lambda item: item["key"],
        ),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return len(payload["findings"])


def diff_against_baseline(findings: Sequence, baseline: Dict[str, Any]):
    """Split findings into (new, known), and list baseline entries now absent."""
    known_keys = {
        item.get("key")
        for item in baseline.get("findings", [])
        if isinstance(item, dict)
    }
    new, known = [], []
    for finding in findings:
        (known if finding_key(finding) in known_keys else new).append(finding)

    present = {finding_key(f) for f in findings}
    resolved = [
        item
        for item in baseline.get("findings", [])
        if isinstance(item, dict) and item.get("key") not in present
    ]
    return new, known, resolved
