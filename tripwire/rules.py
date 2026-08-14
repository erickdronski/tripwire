"""The checks.

Two categories, and the distinction matters more than any individual rule:

**Capability findings** describe what your agent can do. They are not bugs.
A hook that runs a shell command is a hook working correctly; the point of
listing it is that almost nobody can recite what their hooks do, and you cannot
reason about an attack surface you cannot see. These are reported at ``info``.

**Risk findings** describe a specific way the configuration can be turned
against you: approval switched off, an instruction hidden in text the model
reads, a credential sitting in a config file, a server installed from an
unpinned source at launch time. These carry real severities.

Every rule states the mechanism — what would actually have to happen for the
finding to hurt you. A scanner that says "potential security risk" and stops
teaches the reader to ignore it.

Nothing here executes anything or resolves anything over the network. The
checks are string and structure inspection on files already on disk.
"""

from __future__ import annotations

import os
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .inventory import Hook, Inventory, Server, Skill

__all__ = ["Finding", "run_all", "SEVERITIES"]

SEVERITIES = ("high", "medium", "low", "info")


class Finding:
    __slots__ = (
        "rule",
        "severity",
        "title",
        "detail",
        "mechanism",
        "location",
        "evidence",
        "remediation",
    )

    def __init__(
        self,
        rule: str,
        severity: str,
        title: str,
        detail: str,
        location: str,
        mechanism: Optional[str] = None,
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> None:
        self.rule = rule
        self.severity = severity
        self.title = title
        self.detail = detail
        self.mechanism = mechanism
        self.location = location
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
        }
        for key in ("mechanism", "evidence", "remediation"):
            value = getattr(self, key)
            if value:
                payload[key] = value
        return payload

    @property
    def rank(self) -> int:
        try:
            return SEVERITIES.index(self.severity)
        except ValueError:
            return len(SEVERITIES)


# -- injection surface ----------------------------------------------------

#: Phrases that read as instructions aimed at a model rather than
#: documentation aimed at a person, each with its own base severity.
#:
#: The severity split is the whole design. A skill that *documents* reading a
#: `.env` file, or shows `rm -rf` inside a regex example, is doing its job —
#: flagging those at high severity is how a scanner becomes noise that people
#: mute. High severity is reserved for constructions with no legitimate
#: documentation use: overriding prior instructions, hiding activity from the
#: user, or shipping data to a fixed endpoint.
_IMPERATIVE_PATTERNS = (
    (r"ignore (all |any )?(previous|prior|earlier|above) (instructions|prompts|rules)",
     "override of prior instructions", "high"),
    (r"disregard (all |any )?(previous|prior|the above) (instructions|prompts|rules)",
     "override of prior instructions", "high"),
    (r"do not (tell|inform|mention to|reveal to) the user",
     "concealment from the user", "high"),
    (r"without (telling|informing|notifying) the user",
     "concealment from the user", "high"),
    (r"never (mention|reveal|disclose) (this|these|the) (instruction|prompt|file|skill)",
     "concealment of its own contents", "high"),
    (r"new (system )?(instructions|prompt)\s*:", "injected system prompt", "high"),
    (r"(send|post|upload|exfiltrate|transmit) .{0,40}(to|at) https?://",
     "outbound transmission to a fixed endpoint", "high"),
    (r"you are now\b", "identity override", "medium"),
    (r"\b(curl|wget)\b.{0,60}\|\s*(ba|z)?sh", "pipe-to-shell execution", "medium"),
    (r"(cat|read|print|open).{0,30}(\.env\b|id_rsa|\.aws/|\.ssh/|credentials\b)",
     "reads a credential file", "low"),
    (r"rm\s+-rf?\s+[~/]", "destructive filesystem command", "low"),
)

_INJECTION_RE = tuple(
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, label, severity in _IMPERATIVE_PATTERNS
)

#: Patterns that, in combination, mean much more than either does alone.
#: Reading a credential file is ordinary. Reading one and sending it somewhere
#: is the thing worth waking up for.
_CREDENTIAL_RE = re.compile(
    r"(\.env\b|id_rsa|\.aws/|\.ssh/|credentials\b|api[_-]?key)", re.IGNORECASE
)
_EXFIL_RE = re.compile(
    r"(https?://|curl\s|wget\s|nc\s|\bfetch\(|requests\.post)", re.IGNORECASE
)

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _strip_code(text: str) -> str:
    """Remove fenced blocks and inline code spans.

    Documentation quotes dangerous commands constantly — a hook-authoring
    skill showing ``rm\s+-rf`` as a regex example is not an attack, and a
    scanner that cannot tell prose from a code sample is one nobody keeps
    installed.
    """
    return _INLINE_CODE_RE.sub(" ", _FENCE_RE.sub(" ", text))


#: Characters that render as nothing but are read by the model. Text containing
#: them is, by construction, saying something to the model that it is not
#: saying to you.
_INVISIBLE = {
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "⁠": "word joiner",
    "﻿": "zero-width no-break space",
    "­": "soft hyphen",
    "‪": "bidirectional override",
    "‫": "bidirectional override",
    "‭": "bidirectional override",
    "‮": "bidirectional override",
    "⁦": "bidirectional isolate",
    "⁧": "bidirectional isolate",
}

#: Tag characters — an entire invisible Unicode alphabet. Their only realistic
#: use in a config file is hiding text from a human reader.
_TAG_RANGE = (0xE0000, 0xE007F)


def _scan_text_for_injection(
    text: str, location: str, rule_prefix: str, trusted: bool
) -> List[Finding]:
    findings: List[Finding] = []
    if not text:
        return findings

    prose = _strip_code(text)

    for pattern, label, base_severity in _INJECTION_RE:
        match = pattern.search(prose)
        if not match:
            continue

        severity = base_severity
        # A local path is not proof of authorship — skills land in the user
        # directory via install scripts, package managers, and other agents.
        # So the trust downgrade applies only to patterns that local authorship
        # genuinely explains: documenting a credential file, quoting a
        # destructive command, describing a pipe-to-shell install.
        #
        # The high-severity patterns get no such discount. There is no
        # legitimate reason to write "ignore all previous instructions" or
        # "do not tell the user" into your own skill either, so a match stays
        # high wherever the file lives.
        if trusted and base_severity != "high":
            severity = "info" if base_severity == "low" else "low"

        findings.append(
            Finding(
                rule="%s.imperative" % rule_prefix,
                severity=severity,
                title="Instruction-shaped text: %s" % label,
                detail=(
                    "Text the model reads contains an instruction to the model "
                    "rather than documentation for you."
                    + (
                        " Authored locally, so most likely intentional."
                        if trusted
                        else " This content came from outside your machine."
                    )
                ),
                mechanism=(
                    "Instructions in installed content are read with the same "
                    "authority as your own. An agent following them acts with "
                    "your tools and your credentials."
                ),
                location=location,
                evidence=_excerpt(prose, match.start(), match.end()),
                remediation=(
                    "Read the surrounding text. If it is not something you would "
                    "have written, remove the skill."
                ),
            )
        )

    # Credential access is unremarkable on its own and serious next to an
    # outbound call. Only the combination is escalated — and it is escalated
    # regardless of where the file lives, for the reason above.
    if True:
        credential = _CREDENTIAL_RE.search(prose)
        if credential:
            window = prose[max(0, credential.start() - 400) : credential.end() + 400]
            exfil = _EXFIL_RE.search(window)
            if exfil:
                findings.append(
                    Finding(
                        rule="%s.credential-exfiltration" % rule_prefix,
                        severity="high",
                        title="Credential access near an outbound call",
                        detail=(
                            "Text referencing a credential file appears within a "
                            "few lines of a network call."
                        ),
                        mechanism=(
                            "Reading a credential is ordinary setup. Reading one "
                            "and sending it somewhere is the shape of "
                            "exfiltration, and the two appearing together is "
                            "worth reading before you trust the skill."
                        ),
                        location=location,
                        evidence=_excerpt(
                            prose, credential.start(), credential.end()
                        ),
                        remediation=(
                            "Read the whole section. Confirm the network call is "
                            "to the service the credential belongs to."
                        ),
                    )
                )

    invisible = _find_invisible(text)
    if invisible:
        kinds = ", ".join(sorted({name for _, name in invisible}))
        findings.append(
            Finding(
                rule="%s.hidden-characters" % rule_prefix,
                severity="high",
                title="Invisible characters in model-visible text",
                detail=(
                    "%d character(s) that render as nothing (%s) appear in text "
                    "the model reads." % (len(invisible), kinds)
                ),
                mechanism=(
                    "Invisible characters let a file say one thing to a human "
                    "reviewer and another to the model. There is no legitimate "
                    "reason for them in a skill or tool description."
                ),
                location=location,
                remediation="Strip the characters, or remove the content entirely.",
            )
        )
    return findings


def _find_invisible(text: str) -> List[tuple]:
    found: List[tuple] = []
    for index, char in enumerate(text):
        if char in _INVISIBLE:
            found.append((index, _INVISIBLE[char]))
        elif _TAG_RANGE[0] <= ord(char) <= _TAG_RANGE[1]:
            found.append((index, "Unicode tag character"))
    return found


def _excerpt(text: str, start: int, end: int, window: int = 60) -> str:
    begin = max(0, start - window)
    finish = min(len(text), end + window)
    snippet = text[begin:finish].replace("\n", " ")
    return ("..." if begin else "") + snippet.strip() + ("..." if finish < len(text) else "")


# -- skills ---------------------------------------------------------------


def check_skills(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for skill in inventory.skills:
        trusted = skill.source in ("user", "project")
        findings.extend(
            _scan_text_for_injection(
                skill.text, skill.path, "skill", trusted=trusted
            )
        )

        if skill.scripts:
            findings.append(
                Finding(
                    rule="skill.bundled-scripts",
                    severity="info" if trusted else "medium",
                    title="Skill ships executable code: %s" % skill.name,
                    detail="%d bundled script(s): %s"
                    % (
                        len(skill.scripts),
                        ", ".join(skill.scripts[:6])
                        + (" ..." if len(skill.scripts) > 6 else ""),
                    ),
                    mechanism=(
                        "A skill's scripts run with your user's privileges when "
                        "the agent invokes them. They are code you installed, "
                        "usually without reading."
                    ),
                    location=skill.path,
                    remediation=(
                        "Read the scripts once."
                        if not trusted
                        else "No action — you wrote these."
                    ),
                )
            )

        if not skill.description:
            findings.append(
                Finding(
                    rule="skill.no-description",
                    severity="low",
                    title="Skill has no description: %s" % skill.name,
                    detail=(
                        "Without a description this skill will rarely trigger, "
                        "and you cannot tell what it is for without opening it."
                    ),
                    location=skill.path,
                    remediation="Add a description, or remove the skill.",
                )
            )
    return findings


# -- MCP servers ----------------------------------------------------------

#: Values that look like credentials rather than configuration.
_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|"
    r"access[_-]?key|auth)",
    re.IGNORECASE,
)

#: A value that is clearly a reference rather than a literal secret.
_REFERENCE_RE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$|^\$\(|^<|^\{\{")

_AUTO_INSTALL_RE = re.compile(r"\bnpx\b.*\s-{1,2}y(es)?\b|\buvx\b|\bpipx run\b")


def check_servers(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for server in inventory.servers:
        command_line = server.command_line

        if _AUTO_INSTALL_RE.search(command_line):
            pinned = bool(re.search(r"@\d+\.\d+", command_line))
            findings.append(
                Finding(
                    rule="server.auto-install",
                    severity="low" if pinned else "medium",
                    title="Server installs its own code at launch: %s" % server.name,
                    detail=(
                        "The command fetches and runs a package every time the "
                        "server starts%s."
                        % (
                            ", pinned to a version" if pinned else ", unpinned"
                        )
                    ),
                    mechanism=(
                        "An unpinned auto-installing command runs whatever the "
                        "registry serves at launch time. A compromised or "
                        "hijacked package becomes code on your machine with no "
                        "install step you would notice."
                    ),
                    location=server.source,
                    evidence=command_line[:160],
                    remediation=(
                        "Pin the version, or install the package explicitly and "
                        "point the command at the installed binary."
                    ),
                )
            )

        for key, value in server.env.items():
            if not _SECRET_KEY_RE.search(key):
                continue
            if _REFERENCE_RE.match(value.strip()):
                continue
            if len(value.strip()) < 8:
                continue
            findings.append(
                Finding(
                    rule="server.literal-secret",
                    severity="high",
                    title="Credential stored in plaintext config: %s" % server.name,
                    detail=(
                        "The environment variable %s holds a literal value rather "
                        "than a reference." % key
                    ),
                    mechanism=(
                        "Config files get committed, synced, backed up, and read "
                        "by any agent with filesystem access. A literal secret "
                        "here is a secret in all of those places."
                    ),
                    location=server.source,
                    evidence="%s=%s" % (key, _redact(value)),
                    remediation=(
                        "Replace the value with an environment reference such as "
                        "${%s} and set it in your shell." % key
                    ),
                )
            )

        if server.url and server.url.startswith("http://"):
            findings.append(
                Finding(
                    rule="server.plaintext-transport",
                    severity="medium" if _is_local(server.url) else "high",
                    title="Server reached over unencrypted HTTP: %s" % server.name,
                    detail="Configured URL is %s." % server.url,
                    mechanism=(
                        "Tool calls and their results — including anything the "
                        "agent read from your filesystem — cross the network in "
                        "the clear, and the responses can be modified in transit."
                    ),
                    location=server.source,
                    remediation="Use https, or bind the server to localhost.",
                )
            )
    return findings


def _is_local(url: str) -> bool:
    return bool(re.match(r"https?://(localhost|127\.0\.0\.1|\[::1\])", url))


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


# -- hooks ----------------------------------------------------------------

_DANGEROUS_COMMAND_RE = (
    (re.compile(r"\brm\s+-rf?\b"), "recursive delete"),
    (re.compile(r"\bcurl\b.{0,80}\|\s*(ba|z)?sh"), "pipe-to-shell"),
    (re.compile(r"\bwget\b.{0,80}\|\s*(ba|z)?sh"), "pipe-to-shell"),
    (re.compile(r"\beval\b"), "eval of a constructed string"),
    (re.compile(r"\bgit\s+push\b"), "pushes to a remote"),
    (re.compile(r"\bsudo\b"), "elevates privileges"),
    (re.compile(r">\s*/dev/(tcp|udp)/"), "raw network socket"),
)


def check_hooks(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for hook in inventory.hooks:
        matched = [
            label for pattern, label in _DANGEROUS_COMMAND_RE
            if pattern.search(hook.command)
        ]

        severity = "medium" if matched else "info"
        detail = "Runs automatically on %s%s." % (
            hook.event,
            " for %s" % hook.matcher if hook.matcher and hook.matcher != "*" else "",
        )
        if matched:
            detail += " Command %s." % ", ".join(matched)

        findings.append(
            Finding(
                rule="hook.command",
                severity=severity,
                title="Automatic command on %s" % hook.event,
                detail=detail,
                mechanism=(
                    "Hooks run without approval, on every matching event, with "
                    "your shell and your credentials. They are the highest-"
                    "privilege thing in the configuration and the least visible."
                ),
                location=hook.source,
                evidence=_one_line(hook.command),
                remediation=(
                    "Confirm you wrote this and that it still does what you "
                    "intended."
                ),
            )
        )
    return findings


def _one_line(command: str, width: int = 150) -> str:
    collapsed = " ".join(command.split())
    return collapsed[:width] + ("..." if len(collapsed) > width else "")


# -- permission settings --------------------------------------------------

_WILDCARD_RE = re.compile(r"^(Bash|Write|Edit|Read)\s*\(\s*\*?\s*\)$|^\*$")


def check_settings(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for settings in inventory.settings:
        data = settings.data

        for flag, title in (
            ("dangerouslySkipPermissions", "Approval prompts are disabled"),
            ("bypassPermissions", "Approval prompts are bypassed"),
        ):
            if data.get(flag) is True:
                findings.append(
                    Finding(
                        rule="settings.approval-disabled",
                        severity="high",
                        title=title,
                        detail="`%s` is set to true." % flag,
                        mechanism=(
                            "Every tool call runs without asking — including "
                            "commands an agent was steered into by content it "
                            "read from a web page, a file, or an installed "
                            "skill. This setting removes the last check between "
                            "a prompt injection and your shell."
                        ),
                        location=settings.path,
                        remediation=(
                            "Remove the flag and use a scoped allow-list, or keep "
                            "it only inside a disposable container."
                        ),
                    )
                )

        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            allow = permissions.get("allow")
            if isinstance(allow, list):
                wildcards = [
                    entry for entry in allow
                    if isinstance(entry, str) and _WILDCARD_RE.match(entry.strip())
                ]
                if wildcards:
                    findings.append(
                        Finding(
                            rule="settings.wildcard-allow",
                            severity="medium",
                            title="Unrestricted tool permission granted",
                            detail="Allow-list contains: %s" % ", ".join(wildcards),
                            mechanism=(
                                "A wildcard allow entry pre-approves every "
                                "invocation of that tool, which makes the "
                                "allow-list decorative for it."
                            ),
                            location=settings.path,
                            remediation=(
                                "Narrow to the specific commands or paths you "
                                "actually want pre-approved."
                            ),
                        )
                    )
                if len(allow) > 40:
                    findings.append(
                        Finding(
                            rule="settings.large-allow-list",
                            severity="low",
                            title="Allow-list has grown to %d entries" % len(allow),
                            detail=(
                                "Long allow-lists accumulate one prompt at a "
                                "time and are rarely reviewed as a whole."
                            ),
                            mechanism=(
                                "Nobody can hold 40 pre-approved commands in "
                                "their head, so the list stops representing a "
                                "decision anyone actually made."
                            ),
                            location=settings.path,
                            remediation="Read it once and delete what you no longer need.",
                        )
                    )
    return findings


# -- capability inventory -------------------------------------------------


def summarize_capabilities(inventory: Inventory) -> Dict[str, Any]:
    """What this configuration can do, counted.

    This is the part people actually act on. Not a list of problems — a plain
    statement of reach.
    """
    shell_capable = [h for h in inventory.hooks]
    third_party_skills = [
        s for s in inventory.skills if s.source not in ("user", "project")
    ]
    skills_with_scripts = [s for s in inventory.skills if s.scripts]

    return {
        "skills_total": len(inventory.skills),
        "skills_third_party": len(third_party_skills),
        "skills_with_scripts": len(skills_with_scripts),
        "servers_total": len(inventory.servers),
        "servers_remote": len([s for s in inventory.servers if s.url]),
        "hooks_total": len(inventory.hooks),
        "hook_events": sorted({h.event for h in inventory.hooks}),
        "settings_files": len(inventory.settings),
        "unreadable": len(inventory.unreadable),
    }


def run_all(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_settings(inventory))
    findings.extend(check_servers(inventory))
    findings.extend(check_skills(inventory))
    findings.extend(check_hooks(inventory))
    findings.sort(key=lambda f: (f.rank, f.rule, f.location))
    return findings
