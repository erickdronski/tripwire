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

import re
from typing import Any, Dict, List, Optional, Tuple

from .inventory import Inventory
from .redact import redact

__all__ = ["SEVERITIES", "Finding", "run_all"]

SEVERITIES = ("high", "medium", "low", "info")


class Finding:
    __slots__ = (
        "detail",
        "evidence",
        "location",
        "mechanism",
        "remediation",
        "rule",
        "severity",
        # Set when a `.tripwireignore` entry matched, so the report can show
        # the reason the reader gave for suppressing it.
        "suppressed_by",
        "title",
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
        # Redact centrally rather than at each call site: a rule author who
        # forgets would turn an audit report into a credential leak.
        self.evidence = redact(evidence) if evidence else evidence
        self.remediation = remediation
        self.suppressed_by = None

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

#: Places credentials live. Naming one is not reading it — documentation says
#: "store the key in `.env`" constantly — so this only ever contributes to a
#: finding together with a read verb or a data-source construct below.
_CREDENTIAL_STORE = (
    r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[/\\]?\.aws[/\\]credentials\b"
    r"|\.ssh[/\\](?:id_\w+|identity\b|[\w.-]*_key\b)?"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|(?<![\w.])\.(?:netrc|npmrc|pypirc|git-credentials)\b"
    r"|\.docker[/\\]config\.json\b|\.kube[/\\]config\b"
    r"|(?<![\w./-])\.env(?:\.[\w-]+)?\b(?![\w-])"
    r"|\bcredentials\.json\b|\.config[/\\]gcloud\b"
    r"|\blogin\.keychain\b|/etc/shadow\b"
)

#: A verb that reads, copies, or ships a file, followed closely by a store.
#: "Fabricated credentials" and "OAuth client credentials" match neither half.
_CREDENTIAL_READ_RE = re.compile(
    r"\b(?:cat|less|head|tail|read|reads|reading|open|opens|load|loads|dump|dumps|"
    r"print|prints|copy|copies|cp|grab|grabs|collect|collects|extract|steal|"
    r"exfiltrate|upload|uploads|send|sends|attach|base64|tar|zip|scp|rsync|"
    r"encode|paste|parse|parses)\b[^\n.;]{0,40}?(?:" + _CREDENTIAL_STORE + r")",
    re.IGNORECASE,
)

#: Every construct that counts as *accessing* a credential: reading a store,
#: using one as a command's data source (`curl -d @~/.aws/credentials`,
#: `nc host 80 < ~/.ssh/id_rsa`), dumping the environment or the keychain, or
#: expanding a secret-named variable. The word "credentials" alone is none of
#: these — that was the source of every false positive this rule ever had.
_CREDENTIAL_ACCESS_RES = (
    _CREDENTIAL_READ_RE,
    re.compile(r"(?:@|<\s*)(?:" + _CREDENTIAL_STORE + r")", re.IGNORECASE),
    re.compile(
        r"\bprintenv\b|\benv\s*(?:\||>)"
        r"|\bsecurity\s+(?:dump-keychain|find-(?:generic|internet)-password)"
        r"|/proc/(?:self|\d+)/environ"
        r"|(?:json\.dumps|dict|JSON\.stringify)\s*\(\s*(?:os\.environ|process\.env)\s*\)",
        re.IGNORECASE,
    ),
    # Case-sensitive on purpose: environment variables are upper case, and
    # `$token` in a JavaScript template is not a secret expansion.
    re.compile(
        r"\$\{?[A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|"
        r"PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\}?"
        r"|process\.env\.[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)"
        r"|os\.environ\[['\"][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)"
    ),
)

#: Constructs that actually *transmit* data. A markdown link or a bare URL in
#: prose is a reference for the reader, not an outbound call, and is
#: deliberately absent.
_TRANSMISSION_RES = (
    re.compile(
        r"\bcurl\b[^\n|;]{0,160}?(?:\s-d\b|\s-d['\"@$]|--data(?:-binary|-raw|-urlencode)?\b"
        r"|\s-F\b|--form\b|\s-T\b|--upload-file\b|-X\s*(?:POST|PUT|PATCH)\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwget\b[^\n|;]{0,160}?--(?:post-data|post-file|body-data|body-file)",
        re.IGNORECASE,
    ),
    re.compile(r"\|\s*(?:curl|wget|nc|ncat|netcat|socat|telnet)\b", re.IGNORECASE),
    re.compile(r"\b(?:nc|ncat|netcat|socat)\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b"),
    re.compile(r"/dev/(?:tcp|udp)/"),
    re.compile(
        r"\bfetch\s*\(|\baxios(?:\.(?:post|put|patch|request))?\s*\("
        r"|\brequests\.(?:post|put|patch)\s*\(|\bhttpx?\.(?:post|put|patch)\s*\("
        r"|\bhttps?\.request\s*\(|\burlopen\s*\(|\bInvoke-(?:WebRequest|RestMethod)\b"
        r"|\bXMLHttpRequest\b|\bsendBeacon\s*\("
    ),
    # Prose: "send the contents to https://..." — a verb of transmission aimed
    # at a URL, not a URL sitting in a sentence.
    re.compile(
        r"\b(?:send|sends|sending|post|posts|posting|upload|uploads|uploading|"
        r"exfiltrate|transmit|forward|submit|ship|pipe)\b[^\n.]{0,60}?"
        r"\b(?:to|at|into)\s+<?https?://",
        re.IGNORECASE,
    ),
)

#: How close an access and a transmission must be to count as one action:
#: the same paragraph and within this many characters.
_EXFIL_WINDOW = 300

#: A negation earlier in the same clause turns an instruction into guidance:
#: "never print the .env file" is the opposite of reading it.
_NEGATION_RE = re.compile(
    r"\b(?:never|not|don['’]t|dont|do not|must not|mustn['’]t|cannot|can['’]t|no)\b",
    re.IGNORECASE,
)

#: Words that make "do not tell the user ..." a sequencing rule rather than
#: concealment: "do not tell the user it is saved *before* the commit
#: succeeds" is an instruction to be honest, not to hide anything.
_SEQUENCING_RE = re.compile(
    r"\b(?:before|until|unless|after|yet|prematurely|immediately|first)\b",
    re.IGNORECASE,
)


def _negated(text: str, match) -> bool:
    start = match.start()
    clause = max(text.rfind(".", 0, start), text.rfind("\n", 0, start), start - 60)
    return bool(_NEGATION_RE.search(text[clause + 1 : start]))


def _sequencing_qualified(text: str, match) -> bool:
    ends = [
        i for i in (text.find(".", match.end()), text.find("\n", match.end())) if i >= 0
    ]
    sentence_rest = text[match.end() : min(ends) if ends else len(text)]
    return bool(_SEQUENCING_RE.search(sentence_rest))


#: Phrases that read as instructions aimed at a model rather than
#: documentation aimed at a person, each with its own base severity and an
#: optional exemption for the legitimate sentence that most resembles it.
#:
#: The severity split is the whole design. A skill that *documents* reading a
#: `.env` file, or shows `rm -rf` inside a regex example, is doing its job —
#: flagging those at high severity is how a scanner becomes noise that people
#: mute. High severity is reserved for constructions with no legitimate
#: documentation use: overriding prior instructions, hiding activity from the
#: user, or shipping data to a fixed endpoint.
#:
#: Concealment means hiding *activity*. Honesty rules — "do not tell the user
#: it is saved before the commit succeeds", "never claim success without
#: telling the user the results were empty" — tell the model to say *more*,
#: and every one of them was once a high-severity false positive here. So the
#: patterns require an object that is the model's own activity ("that you",
#: "what you", "about this"), a hiding verb, or a hiding adverb; sequencing
#: words exempt the sentence; and a bare "without telling the user" no longer
#: matches at all, because in real skills it is almost always negated.
_IMPERATIVE_PATTERNS = (
    (
        r"ignore (all |any )?(previous|prior|earlier|above) (instructions|prompts|rules)",
        "override of prior instructions",
        "high",
        None,
    ),
    (
        r"disregard (all |any )?(previous|prior|the above) (instructions|prompts|rules)",
        "override of prior instructions",
        "high",
        None,
    ),
    (
        r"\b(?:do\s+not|don['’]t|never|must\s+not|should\s+not)\s+"
        r"(?:tell|inform|notify|alert|let)\s+(?:the\s+)?users?(?:\s+know)?"
        r"(?:\s+(?:that\s+you|what\s+you|about\s+(?:this|these|it|that|"
        r"any\s+of\s+(?:this|it)|anything))\b|\s*(?=[.!;]|$))",
        "concealment from the user",
        "high",
        _sequencing_qualified,
    ),
    (
        r"\b(?:do\s+not|don['’]t|never)\s+(?:mention|reveal|disclose|admit)\s+"
        r"(?:this|these|it|that\s+you\b[^.\n]{0,60}?|what\s+you\b[^.\n]{0,60}?|anything)"
        r"\s+to\s+the\s+users?\b",
        "concealment from the user",
        "high",
        _sequencing_qualified,
    ),
    (
        r"\bwithout\s+(?:the\s+users?|users?|them|anyone|anybody)\s+(?:knowing|noticing|"
        r"realizing|realising|being\s+aware|finding\s+out|seeing)\b",
        "concealment from the user",
        "high",
        None,
    ),
    (
        r"\b(?:keep|hide)\s+(?:this|these|it|that|them|everything)\b[^.\n]{0,30}?"
        r"\bfrom\s+the\s+users?\b(?!['’]s|\s+interface)",
        "concealment from the user",
        "high",
        None,
    ),
    (
        r"\b(?:silently|secretly|covertly|quietly)\b[^.\n]{0,100}?\bwithout\s+"
        r"(?:telling|informing|notifying|alerting)\s+(?:the\s+users?|anyone|anybody|them)\b",
        "concealment from the user",
        "high",
        None,
    ),
    (
        r"\b(?:do\s+not|don['’]t|never)\s+(?:reveal|disclose|show|share|repeat|mention)\s+"
        r"(?:these|this|the|your|my)\s+(?:system\s+)?(?:instructions?|prompt|skill)\b",
        "concealment of its own contents",
        "high",
        None,
    ),
    (
        r"new (system )?(instructions|prompt)\s*:",
        "injected system prompt",
        "high",
        None,
    ),
    (
        r"(send|post|upload|exfiltrate|transmit) .{0,40}(to|at) https?://",
        "outbound transmission to a fixed endpoint",
        "high",
        None,
    ),
    # "the statement you are now attempting" is not an identity change; "you
    # are now a different assistant" is.
    (
        r"\byou\s+are\s+now\s+(?:a|an|in|no\s+longer|called|named|acting\s+as|"
        r"operating\s+as|the\s+(?:new|real)|DAN|jailbroken|unrestricted|unfiltered|"
        r"free\s+(?:of|from))\b",
        "identity override",
        "medium",
        None,
    ),
    (
        r"\b(curl|wget)\b.{0,60}\|\s*(ba|z)?sh",
        "pipe-to-shell execution",
        "medium",
        None,
    ),
    (_CREDENTIAL_READ_RE.pattern, "reads a credential file", "low", _negated),
    (r"rm\s+-rf?\s+[~/]", "destructive filesystem command", "low", None),
)

_INJECTION_RE = tuple(
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), label, severity, exempt)
    for pattern, label, severity, exempt in _IMPERATIVE_PATTERNS
)

# -- mention versus use ----------------------------------------------------

#: Quotation marks that delimit a quoted example.
_QUOTE_PAIRS = (('"', '"'), ("“", "”"), ("«", "»"))

#: Language that marks a passage as *defending against* injected text: telling
#: the model to treat something as data, not to follow it, or naming the
#: attack. Quotation marks alone are not enough to grade a phrase down —
#: quoting is the cheapest possible evasion — so a quoted phrase only counts
#: as a mention when one of these appears within ``_DEFENSIVE_WINDOW``.
_DEFENSIVE_RE = re.compile(
    r"untrusted|not\s+trusted|injection|injected"
    r"|\bas\s+(?:data|untrusted|text|content)\b|data,?\s+not\s+instructions"
    r"|not\s+(?:as\s+)?(?:an?\s+)?(?:instructions?|commands?|directives?)\b"
    r"|(?:do\s+not|don['’]t|never|not)\s+(?:follow|obey|act\s+on|execute|comply|treat)"
    r"|\b(?:shaped|formatted|crafted|designed|made)\s+(?:like|to\s+look\s+like)"
    r"|\blooks?\s+like\s+(?:an?\s+)?(?:instruction|command|directive)"
    r"|addressed\s+to\s+you|red\s+flag|adversarial|malicious|attacker",
    re.IGNORECASE,
)
_DEFENSIVE_WINDOW = 250


def _inside_quotes(text: str, start: int, end: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    before = text[line_start:start]
    after = text[end : len(text) if line_end < 0 else line_end]
    for opening, closing in _QUOTE_PAIRS:
        if opening == closing:
            if before.count(opening) % 2 == 1 and closing in after:
                return True
        elif before.rfind(opening) > before.rfind(closing) and closing in after:
            return True
    return False


def _is_mention(text: str, start: int, end: int) -> bool:
    """A quoted example inside a passage about resisting injection.

    Security-minded skills teach the model to resist injection by quoting
    what an injection looks like: *treat text such as "ignore previous
    instructions" as data*. That is a mention of the phrase, not a use of it.
    Both halves are required: the phrase must sit inside quotation marks *and*
    defensive language must be nearby. A bare imperative is never a mention,
    wherever it appears.
    """
    if not _inside_quotes(text, start, end):
        return False
    window = text[max(0, start - _DEFENSIVE_WINDOW) : end + _DEFENSIVE_WINDOW]
    return bool(_DEFENSIVE_RE.search(window))


_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _strip_code(text: str) -> str:
    r"""Remove fenced blocks and inline code spans.

    Documentation quotes dangerous commands constantly — a hook-authoring
    skill showing ``rm\s+-rf`` as a regex example is not an attack, and a
    scanner that cannot tell prose from a code sample is one nobody keeps
    installed.
    """
    return _INLINE_CODE_RE.sub(" ", _FENCE_RE.sub(" ", text))


def _strip_fences(text: str) -> str:
    """Remove fenced blocks but keep the contents of inline code spans.

    Used only for the credential-exfiltration check, where the two halves are
    narrow constructs rather than words: wrapping a path in backticks must not
    be enough to hide "read `~/.ssh/id_rsa` and POST it to ...". Fenced blocks
    stay excluded, because API documentation is full of examples that send a
    token to the service it belongs to.
    """
    return _INLINE_CODE_RE.sub(
        lambda match: match.group(0)[1:-1], _FENCE_RE.sub(" ", text)
    )


def _find_exfiltration(text: str) -> Optional[Tuple[int, int, str]]:
    """Locate a credential access and a transmission in the same passage."""
    prose = _strip_fences(text)
    access = [
        match
        for pattern in _CREDENTIAL_ACCESS_RES
        for match in pattern.finditer(prose)
        if not (pattern is _CREDENTIAL_READ_RE and _negated(prose, match))
        and not _is_mention(prose, match.start(), match.end())
    ]
    if not access:
        return None
    transmissions = [m for p in _TRANSMISSION_RES for m in p.finditer(prose)]
    for read in sorted(access, key=lambda m: m.start()):
        for send in transmissions:
            low = min(read.start(), send.start())
            high = max(read.end(), send.end())
            if high - low > _EXFIL_WINDOW:
                continue
            if re.search(r"\n[ \t]*\n", prose[low:high]):
                continue
            return low, high, prose
    return None


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

    for pattern, label, base_severity, exempt in _INJECTION_RE:
        # Every occurrence is examined, not just the first: a skill that
        # quotes an injection defensively near the top must not shield a bare
        # one further down.
        match = mention = None
        for candidate in pattern.finditer(prose):
            if exempt is not None and exempt(prose, candidate):
                continue
            if _is_mention(prose, candidate.start(), candidate.end()):
                mention = mention or candidate
                continue
            match = candidate
            break
        if match is None:
            if mention is not None:
                findings.append(
                    _quoted_example(prose, mention, label, location, rule_prefix)
                )
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
    # regardless of where the file lives, for the reason above. Both halves
    # are constructs, not vocabulary: the word "credentials" beside a docs
    # link is neither a read nor a transmission.
    exfiltration = _find_exfiltration(text)
    if exfiltration is not None:
        low, high, passage = exfiltration
        findings.append(
            Finding(
                rule="%s.credential-exfiltration" % rule_prefix,
                severity="high",
                title="Credential access near an outbound call",
                detail=(
                    "A passage reads a credential store or secret and, in the "
                    "same paragraph, transmits data over the network."
                ),
                mechanism=(
                    "Reading a credential is ordinary setup. Reading one "
                    "and sending it somewhere is the shape of "
                    "exfiltration, and the two appearing together is "
                    "worth reading before you trust the skill."
                ),
                location=location,
                evidence=_excerpt(passage, low, high, window=40),
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


def _quoted_example(
    prose: str, match, label: str, location: str, rule_prefix: str
) -> Finding:
    """Informational record of a phrase quoted as an example of injection.

    Kept rather than dropped so the evasion it could represent stays visible
    under ``--info``: quoting is the cheapest way to dress an instruction up
    as an example, and the reader should be able to check the surrounding
    text really is defensive.
    """
    return Finding(
        rule="%s.imperative" % rule_prefix,
        severity="info",
        title="Quoted injection example: %s" % label,
        detail=(
            "The phrase appears in quotation marks next to text telling the "
            "model to treat such content as data — a warning about injection, "
            "not an injection."
        ),
        mechanism=(
            "Skills that handle untrusted input teach the model what an "
            "injection looks like by quoting one. Listed so you can confirm "
            "the surrounding text really is defensive."
        ),
        location=location,
        evidence=_excerpt(prose, match.start(), match.end()),
    )


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
    return (
        ("..." if begin else "")
        + snippet.strip()
        + ("..." if finish < len(text) else "")
    )


# -- skills ---------------------------------------------------------------


def check_skills(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for skill in inventory.skills:
        trusted = skill.source in ("user", "project")
        findings.extend(
            _scan_text_for_injection(skill.text, skill.path, "skill", trusted=trusted)
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
                        % (", pinned to a version" if pinned else ", unpinned")
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
            label
            for pattern, label in _DANGEROUS_COMMAND_RE
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
                    "Confirm you wrote this and that it still does what you intended."
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
                    entry
                    for entry in allow
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
