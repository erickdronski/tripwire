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
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .inventory import Inventory
from .redact import redact

__all__ = ["SEVERITIES", "Finding", "merge_copies", "run_all"]

SEVERITIES = ("high", "medium", "low", "info")


class Finding:
    __slots__ = (
        "detail",
        "evidence",
        # What makes two findings without evidence the same finding — the
        # content digest of the skill or server they describe.
        "fingerprint",
        "location",
        # Every place this exact finding occurs. The same skill is often on
        # disk several times (installed, synced, re-synced); reporting it once
        # per copy buries everything else.
        "locations",
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
        fingerprint: Optional[str] = None,
    ) -> None:
        self.rule = rule
        self.severity = severity
        self.title = title
        self.detail = detail
        self.mechanism = mechanism
        self.location = location
        self.locations = [location]
        self.fingerprint = fingerprint
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
        payload["copies"] = len(self.locations)
        payload["locations"] = list(self.locations)
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
#:
#: Every alternative starts with a literal character, and word-boundary
#: checks sit *after* it as lookbehinds (``i(?<!\wi)d_`` is ``\bid_``). That
#: lets the regex engine skip straight to candidate characters instead of
#: trying every alternative at every position, which halves the cost of the
#: most frequently run pattern in the scanner.
_CREDENTIAL_STORE = (
    r"\.aws[/\\]credentials\b"
    r"|\.ssh[/\\](?:id_\w+|identity\b|[\w.-]*_key\b)?"
    r"|\.(?<![\w.]\.)(?:netrc|npmrc|pypirc|git-credentials)\b"
    r"|\.docker[/\\]config\.json\b|\.kube[/\\]config\b"
    r"|\.(?<![\w./-]\.)env(?:\.[\w-]+)?\b(?![\w-])"
    r"|\.config[/\\]gcloud\b"
    r"|i(?<!\wi)d_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|c(?<!\wc)redentials\.json\b"
    r"|l(?<!\wl)ogin\.keychain\b"
    r"|/etc/shadow\b"
)
_CREDENTIAL_STORE_RE = re.compile(_CREDENTIAL_STORE, re.IGNORECASE)

#: A verb that reads, copies, or ships a file, ending just before a store.
_READ_VERB_BEFORE_RE = re.compile(
    r"\b(?:cat|less|head|tail|read|reads|reading|open|opens|load|loads|dump|dumps|"
    r"print|prints|copy|copies|cp|grab|grabs|collect|collects|extract|steal|"
    r"exfiltrate|upload|uploads|send|sends|attach|base64|tar|zip|scp|rsync|"
    r"encode|paste|parse|parses)\b[^\n.;]{0,40}$",
    re.IGNORECASE,
)


class _Span:
    """The part of ``re.Match`` the scanners use, for matches built by hand."""

    __slots__ = ("_end", "_start", "_text")

    def __init__(self, text: str, start: int, end: int) -> None:
        self._text, self._start, self._end = text, start, end

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self, _index: int = 0) -> str:
        return self._text[self._start : self._end]


class _CredentialReads:
    """``<read verb> ... <credential store>`` — "cat ~/.aws/credentials".

    Matched store-first: a store is a rare, distinctive token, while the verb
    list is common English, and trying the verbs at every position of ~7 MB
    of skills was the single slowest thing in a run. "Fabricated
    credentials" and "OAuth client credentials" match neither half.
    """

    def finditer(self, text: str) -> Iterator[_Span]:
        for store in _CREDENTIAL_STORE_RE.finditer(text):
            begin = max(0, store.start() - 48)
            verb = _READ_VERB_BEFORE_RE.search(text, begin, store.start())
            if verb:
                yield _Span(text, verb.start(), store.end())


_CREDENTIAL_READ_RE = _CredentialReads()

#: Every construct that counts as *accessing* a credential: reading a store,
#: using one as a command's data source (`curl -d @~/.aws/credentials`,
#: `nc host 80 < ~/.ssh/id_rsa`), dumping the environment or the keychain, or
#: expanding a secret-named variable. The word "credentials" alone is none of
#: these — that was the source of every false positive this rule ever had.
_CREDENTIAL_ACCESS_RES = (
    _CREDENTIAL_READ_RE,
    # A store used as a command's input: `-d @~/.aws/credentials`, `< .env`.
    re.compile(r"[@<]\s*[^\s'\"]{0,60}?(?:" + _CREDENTIAL_STORE + r")", re.IGNORECASE),
    re.compile(
        r"\b(?:printenv\b|env\s*[|>]"
        r"|security\s+(?:dump-keychain|find-(?:generic|internet)-password))"
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
    (_CREDENTIAL_READ_RE, "reads a credential file", "low", _negated),
    (r"rm\s+-rf?\s+[~/]", "destructive filesystem command", "low", None),
)

_INJECTION_RE = tuple(
    (
        re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        if isinstance(pattern, str)
        else pattern,
        label,
        severity,
        exempt,
    )
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
    text: str,
    location: str,
    rule_prefix: str,
    trusted: bool,
    fingerprint: Optional[str] = None,
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
                fingerprint=fingerprint,
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


_INVISIBLE_RE = re.compile(
    "[%s\\U%08x-\\U%08x]" % ("".join(_INVISIBLE), _TAG_RANGE[0], _TAG_RANGE[1])
)


def _find_invisible(text: str) -> List[tuple]:
    return [
        (match.start(), _INVISIBLE.get(match.group(0), "Unicode tag character"))
        for match in _INVISIBLE_RE.finditer(text)
    ]


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

#: Sources written on this machine. Everything else — plugins, marketplaces,
#: skills synced from an account — came from somewhere else.
_LOCAL_SOURCES = ("user", "project", "scheduled-task")


def check_skills(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for skill in inventory.skills:
        trusted = skill.source in _LOCAL_SOURCES
        findings.extend(
            _scan_text_for_injection(
                skill.text,
                skill.path,
                "skill",
                trusted=trusted,
                fingerprint=skill.digest,
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
                    fingerprint=skill.digest,
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
                    fingerprint=skill.digest,
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
_PINNED_RE = re.compile(r"@\d+\.\d+|==\d")

#: An auth scheme in front of a header value: `Bearer ${TOKEN}` is a
#: reference, `Bearer sk-...` is not, and the scheme word decides neither.
_AUTH_SCHEME_RE = re.compile(r"^(?:bearer|basic|token)\s+", re.IGNORECASE)


def _literal_credentials(server) -> List[Tuple[str, str, str]]:
    """(kind, name, value) for every secret-named entry holding a literal."""
    found: List[Tuple[str, str, str]] = []
    for kind, values in (
        ("environment variable", server.env),
        ("header", getattr(server, "headers", {}) or {}),
    ):
        for key, value in values.items():
            if not _SECRET_KEY_RE.search(key):
                continue
            literal = _AUTH_SCHEME_RE.sub("", value.strip())
            if _REFERENCE_RE.match(literal) or len(literal) < 8:
                continue
            found.append((kind, key, literal))
    return found


def check_servers(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for server in inventory.servers:
        command_line = server.command_line
        label = server.label
        # Identical servers in two copies of a plugin are one finding.
        fingerprint = "%s|%s|%s|%s" % (
            server.agent,
            server.scope,
            server.name,
            command_line,
        )

        if _AUTO_INSTALL_RE.search(command_line):
            pinned = bool(_PINNED_RE.search(command_line))
            findings.append(
                Finding(
                    rule="server.auto-install",
                    severity="low" if pinned else "medium",
                    title="Server installs its own code at launch: %s" % server.name,
                    detail=(
                        "%s. The command fetches and runs a package every time "
                        "the server starts%s."
                        % (label, ", pinned to a version" if pinned else ", unpinned")
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
                    fingerprint=fingerprint,
                )
            )

        for kind, key, value in _literal_credentials(server):
            findings.append(
                Finding(
                    rule="server.literal-secret",
                    severity="high",
                    title="Credential stored in plaintext config: %s" % server.name,
                    detail=(
                        "%s. The %s %s holds a literal value rather than a "
                        "reference." % (label, kind, key)
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
                        "${%s} and set it in your shell." % _env_name(key)
                    ),
                    fingerprint=fingerprint,
                )
            )

        if getattr(server, "secret_on_command_line", False):
            findings.append(
                Finding(
                    rule="server.literal-secret",
                    severity="high",
                    title="Credential on a server's command line: %s" % server.name,
                    detail=(
                        "%s. The command line or URL contains a credential-shaped "
                        "value, masked below." % label
                    ),
                    mechanism=(
                        "A token in arguments or a URL is stored in plaintext in "
                        "the config file, and is also visible to every process "
                        "that can list command lines while the server runs."
                    ),
                    location=server.source,
                    evidence=command_line[:160],
                    remediation=(
                        "Pass the credential through an environment reference "
                        "instead of the command line."
                    ),
                    fingerprint=fingerprint,
                )
            )

        if server.url and server.url.startswith("http://"):
            findings.append(
                Finding(
                    rule="server.plaintext-transport",
                    severity="medium" if _is_local(server.url) else "high",
                    title="Server reached over unencrypted HTTP: %s" % server.name,
                    detail="%s. Configured URL is %s." % (label, server.url),
                    mechanism=(
                        "Tool calls and their results — including anything the "
                        "agent read from your filesystem — cross the network in "
                        "the clear, and the responses can be modified in transit."
                    ),
                    location=server.source,
                    remediation="Use https, or bind the server to localhost.",
                    fingerprint=fingerprint,
                )
            )
    return findings


def _env_name(key: str) -> str:
    """A plausible environment variable name for a header or env key."""
    return re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper() or "SECRET"


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
        agent = getattr(hook, "agent", "claude-code")
        scope = getattr(hook, "scope", "user")
        if agent == "codex" and hook.event == "notify":
            title = "Automatic command after every Codex turn"
            detail = "Codex runs `notify` after each agent turn."
        else:
            title = "Automatic command on %s" % hook.event
            detail = "Runs automatically on %s%s." % (
                hook.event,
                " for %s" % hook.matcher
                if hook.matcher and hook.matcher != "*"
                else "",
            )
        if scope.startswith("plugin:"):
            detail += " Installed by plugin %s." % scope[len("plugin:") :]
        if matched:
            detail += " Command %s." % ", ".join(matched)

        findings.append(
            Finding(
                rule="hook.command",
                severity=severity,
                title=title,
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

_APPROVAL_OFF = (
    "Every tool call runs without asking — including commands an agent was "
    "steered into by content it read from a web page, a file, or an installed "
    "skill. This setting removes the last check between a prompt injection "
    "and your shell."
)


def check_settings(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    for settings in inventory.settings:
        if getattr(settings, "agent", "claude-code") == "codex":
            if getattr(settings, "kind", "settings") == "app-state":
                findings.extend(_check_codex_app(settings))
            else:
                findings.extend(_check_codex_config(settings))
            continue

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
                        mechanism=_APPROVAL_OFF,
                        location=settings.path,
                        remediation=(
                            "Remove the flag and use a scoped allow-list, or keep "
                            "it only inside a disposable container."
                        ),
                    )
                )

        permissions = data.get("permissions")
        mode = permissions.get("defaultMode") if isinstance(permissions, dict) else None
        if mode == "bypassPermissions":
            findings.append(
                Finding(
                    rule="settings.approval-disabled",
                    severity="high",
                    title="Approval prompts are bypassed by default",
                    detail="`permissions.defaultMode` is `bypassPermissions`.",
                    mechanism=_APPROVAL_OFF,
                    location=settings.path,
                    remediation=(
                        "Use `default` or `acceptEdits` with a scoped allow-list, "
                        "or keep bypass mode inside a disposable container."
                    ),
                )
            )
        elif mode == "acceptEdits":
            findings.append(
                Finding(
                    rule="settings.accept-edits",
                    severity="low",
                    title="File edits are approved automatically",
                    detail="`permissions.defaultMode` is `acceptEdits`.",
                    mechanism=(
                        "Edits are applied without asking. They are visible and "
                        "reversible, which is why this is low — but an edit to a "
                        "script, a hook, or a config that runs later is a "
                        "command waiting to happen."
                    ),
                    location=settings.path,
                    remediation="Keep it if you review diffs; otherwise use `default`.",
                )
            )

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


# -- Codex ------------------------------------------------------------------

#: Codex's two independent checks. `approval_policy = "never"` removes the
#: prompt; `sandbox_mode = "danger-full-access"` removes the sandbox. Either
#: alone leaves the other standing. Both together are the equivalent of
#: Claude Code's `dangerouslySkipPermissions`, and the only high case.
_CODEX_KEYS = ("approval_policy", "sandbox_mode")
_CODEX_NO_SANDBOX = "danger-full-access"
#: Automation states that will not run until someone resumes them.
_CODEX_STOPPED = ("PAUSED", "DISABLED", "ARCHIVED", "DELETED")
_SEVERITY_CAP = {"high": "medium"}


def _codex_mode(
    conf: Dict[str, Any], path: str, subject: str, capped: bool
) -> List[Finding]:
    approval, sandbox = conf.get("approval_policy"), conf.get("sandbox_mode")
    if approval == "never" and sandbox == _CODEX_NO_SANDBOX:
        severity, rule = "high", "settings.approval-disabled"
        title = "%s runs with no sandbox and no approval prompts" % subject
        detail = (
            '`approval_policy = "never"` and `sandbox_mode = "danger-full-access"`.'
        )
        mechanism = _APPROVAL_OFF + (
            " Without the sandbox, nothing limits what that command can read, "
            "write, or send."
        )
    elif sandbox == _CODEX_NO_SANDBOX:
        severity, rule = "medium", "settings.sandbox-disabled"
        title = "%s runs commands without a sandbox" % subject
        detail = '`sandbox_mode = "danger-full-access"`; approval policy is %s.' % (
            "`%s`" % approval if approval else "the default"
        )
        mechanism = (
            "Commands run with your user's full filesystem and network access. "
            "Only the approval policy stands between an injected instruction "
            "and execution."
        )
    elif approval == "never":
        severity, rule = "low", "settings.approval-disabled"
        title = "%s never asks for approval" % subject
        detail = '`approval_policy = "never"`; commands stay inside the %s sandbox.' % (
            "`%s`" % sandbox if sandbox else "default"
        )
        mechanism = (
            "Nothing is ever put to you, so the sandbox is the only check. It "
            "still limits writes and network access, which is why this is low."
        )
    else:
        return []
    if capped:
        severity = _SEVERITY_CAP.get(severity, severity)
    return [
        Finding(
            rule=rule,
            severity=severity,
            title=title,
            detail=detail,
            mechanism=mechanism,
            location=path,
            remediation=(
                "Keep the sandbox (`workspace-write`) and let Codex ask, or keep "
                "full access for a disposable container."
            ),
        )
    ]


def _check_codex_config(settings) -> List[Finding]:
    """``approval_policy`` / ``sandbox_mode``, at the top level and per profile.

    The active profile (``profile = "name"``) overrides the top level and is
    graded in full. Other profiles that loosen either setting are one flag
    away (``codex --profile name``), so they are reported, capped at medium.
    """
    data = settings.data
    top = {key: data.get(key) for key in _CODEX_KEYS}
    profiles = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}
    active = data.get("profile") if isinstance(data.get("profile"), str) else None

    def merged(profile: Any) -> Dict[str, Any]:
        result = dict(top)
        if isinstance(profile, dict):
            result.update(
                {k: profile[k] for k in _CODEX_KEYS if profile.get(k) is not None}
            )
        return result

    subject = "Codex (profile `%s`)" % active if active in profiles else "Codex"
    findings = _codex_mode(merged(profiles.get(active)), settings.path, subject, False)
    for name in sorted(profiles):
        profile = profiles[name]
        if name == active or not isinstance(profile, dict):
            continue
        if any(profile.get(key) is not None for key in _CODEX_KEYS):
            findings.extend(
                _codex_mode(
                    merged(profile), settings.path, "Codex profile `%s`" % name, True
                )
            )

    projects = data.get("projects")
    trusted = sorted(
        path
        for path, conf in (projects.items() if isinstance(projects, dict) else [])
        if isinstance(conf, dict) and conf.get("trust_level") == "trusted"
    )
    if trusted:
        home = os.path.expanduser("~").rstrip("/\\")
        broad = [p for p in trusted if p.rstrip("/\\") in ("", "~", home)]
        findings.append(
            Finding(
                rule="settings.trusted-projects",
                severity="medium" if broad else "info",
                title=(
                    "Codex trusts your entire home directory"
                    if broad
                    else "Codex trusts %d project director%s"
                    % (len(trusted), "y" if len(trusted) == 1 else "ies")
                ),
                detail="Trusted: %s." % ", ".join(trusted[:5])
                + (" and %d more" % (len(trusted) - 5) if len(trusted) > 5 else ""),
                mechanism=(
                    "A trusted directory gets Codex's less restrictive defaults "
                    "without the first-run question. Trusting a parent trusts "
                    "everything ever cloned beneath it."
                ),
                location=settings.path,
                remediation="Trust individual projects rather than a parent directory.",
            )
        )
    return findings


def _check_codex_app(settings) -> List[Finding]:
    """The Codex app's own permission mode, and its scheduled automations."""
    data = settings.data
    findings: List[Finding] = []
    if data.get("agent_mode") == "full-access":
        findings.append(
            Finding(
                rule="settings.approval-disabled",
                severity="high",
                title="Codex app runs local threads with full access",
                detail=(
                    "The app's permission mode for this machine is `full-access`: "
                    "no sandbox and no approval prompts."
                ),
                mechanism=_APPROVAL_OFF
                + " Without the sandbox, nothing limits what that command can "
                "read, write, or send.",
                location=settings.path,
                remediation=(
                    "Choose a sandboxed permission mode in the Codex app, and keep "
                    "full access for disposable environments."
                ),
            )
        )

    risky = [a for a in data.get("automations") or [] if a.get("full_access")]
    stopped = [a for a in risky if str(a.get("status")).upper() in _CODEX_STOPPED]
    for automation in risky:
        if automation in stopped:
            continue
        findings.append(
            Finding(
                rule="settings.approval-disabled",
                severity="high",
                title="Codex automation runs unattended with full access: %s"
                % automation["name"],
                detail=(
                    "Status `%s`. The thread it runs in has `approvalPolicy: "
                    "never` and a `dangerFullAccess` sandbox." % automation["status"]
                ),
                mechanism=(
                    "A scheduled run has nobody watching. With no sandbox and no "
                    "prompts, an instruction it picks up from a page, a file, or a "
                    "tool result executes with your full access, on a timer."
                ),
                location=automation["path"],
                remediation="Pause it, or run its thread in a sandboxed mode.",
            )
        )
    if stopped:
        findings.append(
            Finding(
                rule="settings.approval-disabled",
                severity="info",
                title="Paused Codex automations would run with full access",
                detail="%d paused automation(s) — %s — target threads with no "
                "sandbox and no approval prompts."
                % (len(stopped), ", ".join(a["name"] for a in stopped[:5])),
                mechanism=(
                    "Nothing runs while they are paused. Resuming one starts an "
                    "unattended agent with your full access."
                ),
                location=stopped[0]["path"],
                remediation="Switch their threads to a sandboxed mode before resuming.",
            )
        )
    return findings


# -- capability inventory -------------------------------------------------


def summarize_capabilities(inventory: Inventory) -> Dict[str, Any]:
    """What this configuration can do, counted.

    This is the part people actually act on. Not a list of problems — a plain
    statement of reach.
    """
    third_party_skills = [s for s in inventory.skills if s.source not in _LOCAL_SOURCES]
    skills_with_scripts = [s for s in inventory.skills if s.scripts]

    return {
        "skills_total": len(inventory.skills),
        "skills_distinct": len({s.digest for s in inventory.skills}),
        "skills_third_party": len(third_party_skills),
        "skills_with_scripts": len(skills_with_scripts),
        "skills_skipped": sum(inventory.skipped.values()),
        "skipped": dict(sorted(inventory.skipped.items())),
        "agents": sorted(getattr(inventory, "agents", ())),
        "servers_total": len(inventory.servers),
        "servers_remote": len([s for s in inventory.servers if s.url]),
        "servers_by_agent": _count_by_agent(inventory.servers),
        "servers_disabled": getattr(inventory, "servers_disabled", 0),
        "hooks_total": len(inventory.hooks),
        "hook_events": sorted({h.event for h in inventory.hooks}),
        "hooks_by_agent": _count_by_agent(inventory.hooks),
        "settings_files": len(inventory.settings),
        "unreadable": len(inventory.unreadable),
        "notes": list(inventory.notes),
    }


def _count_by_agent(items) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        agent = getattr(item, "agent", "claude-code")
        counts[agent] = counts.get(agent, 0) + 1
    return dict(sorted(counts.items()))


def merge_copies(findings: List[Finding]) -> List[Finding]:
    """Report each distinct finding once, with every location it occurs in.

    Two findings are the same when rule, severity, title, and detail match
    and so does the evidence — or, for findings without evidence, the
    fingerprint of the content they describe. Findings with neither stay
    separate: two settings files that both disable approval are two
    decisions, not two copies of one.
    """
    merged: Dict[tuple, Finding] = {}
    out: List[Finding] = []
    for finding in findings:
        identity = finding.evidence or finding.fingerprint or finding.location
        key = (finding.rule, finding.severity, finding.title, finding.detail, identity)
        first = merged.get(key)
        if first is None:
            merged[key] = finding
            out.append(finding)
        elif finding.location not in first.locations:
            first.locations.append(finding.location)
    return out


def run_all(inventory: Inventory) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_settings(inventory))
    findings.extend(check_servers(inventory))
    findings.extend(check_skills(inventory))
    findings.extend(check_hooks(inventory))
    # Sorting first makes the reported location of a merged finding stable:
    # always the first path in order, not whichever copy was walked first.
    findings.sort(key=lambda f: (f.rank, f.rule, f.location))
    return merge_copies(findings)
