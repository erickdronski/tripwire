"""Reading TOML on every supported Python, without a dependency.

Codex keeps its configuration in TOML. Python 3.11 ships ``tomllib``; 3.9 and
3.10 do not, and tripwire installs nothing. So :func:`loads` uses ``tomllib``
when it can be imported and otherwise falls back to a small parser for the
subset agent configs actually use:

- tables ``[a.b]`` and arrays of tables ``[[a.b]]``
- bare, quoted, and dotted keys (``a."b.c".d = 1``)
- basic and literal strings, single- and multi-line, with escapes
- integers (decimal, hex, octal, binary, underscores), floats, booleans
- arrays (multi-line, trailing commas, comments inside) and inline tables
- comments

Dates and times are returned as their source text rather than ``datetime``
objects; nothing tripwire reads depends on them.

The fallback is strict where it matters: input outside the subset raises
:class:`TomlError` with a line number instead of being guessed at. Callers
fail open on that error — an unparseable file becomes a visible note in the
report, never a crash and never a silent skip.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

try:  # Python 3.11+
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - exercised on 3.9 and 3.10 in CI
    _tomllib = None

__all__ = ["TomlError", "loads", "parse"]


class TomlError(ValueError):
    """The text is not TOML this module can read."""


def loads(text: str) -> Dict[str, Any]:
    """Parse ``text``, preferring the standard library when it exists."""
    if _tomllib is not None:
        try:
            return _tomllib.loads(text)
        except _tomllib.TOMLDecodeError as exc:
            raise TomlError(str(exc)) from exc
    return parse(text)


def parse(text: str) -> Dict[str, Any]:
    """Parse ``text`` with the built-in fallback, regardless of Python version.

    Public so the tests can hold the fallback to ``tomllib``'s answers on the
    Pythons that have both.
    """
    return _Parser(text).document()


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_DATE_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
    r"(?:[Zz]|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}:\d{2}(?:\.\d+)?"
)
_FLOAT = re.compile(
    r"[+-]?(?:inf|nan)"
    r"|[+-]?(?:0|[1-9](?:_?\d)*)(?:\.\d(?:_?\d)*)?(?:[eE][+-]?\d(?:_?\d)*)?"
)
_INTEGER = re.compile(
    r"0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*"
    r"|[+-]?(?:0|[1-9](?:_?\d)*)"
)
_ESCAPES = {
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    '"': '"',
    "\\": "\\",
}
#: Characters that end a value: whitespace, a comment, or a separator.
_VALUE_END = " \t\r\n#,]}"
#: A backslash at the end of a line in a multi-line string: the newline and
#: the whitespace after it are trimmed.
_LINE_CONTINUATION = re.compile(r"[ \t]*\n\s*")
_HEX = re.compile(r"[0-9A-Fa-f]+")


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text.replace("\r\n", "\n")
        self.pos = 0
        self.root: Dict[str, Any] = {}
        # Explicitly opened `[tables]`, so a second `[a]` is an error, as in
        # `tomllib`, rather than a silent merge.
        self.opened: set = set()

    # -- document structure ------------------------------------------------

    def document(self) -> Dict[str, Any]:
        current = self.root
        while True:
            self.skip_blank_lines()
            if self.pos >= len(self.text):
                return self.root
            if self.text.startswith("[[", self.pos):
                self.pos += 2
                keys = self.key()
                self.expect("]]")
                current = self.array_table(keys)
            elif self.text[self.pos] == "[":
                self.pos += 1
                keys = self.key()
                self.expect("]")
                current = self.table(keys)
            else:
                keys = self.key()
                self.expect("=")
                self.assign(current, keys, self.value())
            self.end_of_line()

    def table(self, keys: List[str]) -> Dict[str, Any]:
        path = tuple(keys)
        if path in self.opened:
            self.error("table [%s] is defined twice" % ".".join(keys))
        self.opened.add(path)
        return self.descend(self.root, keys)

    def array_table(self, keys: List[str]) -> Dict[str, Any]:
        parent = self.descend(self.root, keys[:-1])
        existing = parent.setdefault(keys[-1], [])
        if not isinstance(existing, list):
            self.error("%s is not an array of tables" % ".".join(keys))
        entry: Dict[str, Any] = {}
        existing.append(entry)
        return entry

    def descend(self, table: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
        for key in keys:
            child = table.setdefault(key, {})
            if isinstance(child, list) and child and isinstance(child[-1], dict):
                child = child[-1]
            if not isinstance(child, dict):
                self.error("%s is already a value, not a table" % key)
            table = child
        return table

    def assign(self, table: Dict[str, Any], keys: List[str], value: Any) -> None:
        target = self.descend(table, keys[:-1])
        if keys[-1] in target:
            self.error("key %s is defined twice" % ".".join(keys))
        target[keys[-1]] = value

    # -- keys ----------------------------------------------------------------

    def key(self) -> List[str]:
        parts: List[str] = []
        while True:
            self.skip_spaces()
            char = self.peek()
            if char == '"':
                parts.append(self.basic_string())
            elif char == "'":
                parts.append(self.literal_string())
            else:
                match = _BARE_KEY.match(self.text, self.pos)
                if not match:
                    self.error("expected a key")
                parts.append(match.group(0))
                self.pos = match.end()
            self.skip_spaces()
            if self.peek() != ".":
                return parts
            self.pos += 1

    # -- values --------------------------------------------------------------

    def value(self) -> Any:
        self.skip_spaces()
        text, pos = self.text, self.pos
        if text.startswith('"""', pos):
            return self.multiline_basic_string()
        if text.startswith("'''", pos):
            return self.multiline_literal_string()
        char = self.peek()
        if char == '"':
            return self.basic_string()
        if char == "'":
            return self.literal_string()
        if char == "[":
            return self.array()
        if char == "{":
            return self.inline_table()
        for word, result in (("true", True), ("false", False)):
            if text.startswith(word, pos) and self.ends_value(pos + len(word)):
                self.pos += len(word)
                return result
        return self.scalar()

    def scalar(self) -> Any:
        text, pos = self.text, self.pos
        for pattern, convert in (
            (_DATE_TIME, str),
            (_INTEGER, _to_int),
            (_FLOAT, _to_float),
        ):
            match = pattern.match(text, pos)
            if match and self.ends_value(match.end()):
                self.pos = match.end()
                return convert(match.group(0))
        self.error("unsupported value")
        return None  # unreachable; error() raises

    def ends_value(self, index: int) -> bool:
        return index >= len(self.text) or self.text[index] in _VALUE_END

    def array(self) -> List[Any]:
        self.pos += 1
        items: List[Any] = []
        while True:
            self.skip_blank_lines()
            if self.peek() == "]":
                self.pos += 1
                return items
            items.append(self.value())
            self.skip_blank_lines()
            if self.peek() == ",":
                self.pos += 1
            elif self.peek() != "]":
                self.error("expected , or ] in array")

    def inline_table(self) -> Dict[str, Any]:
        self.pos += 1
        table: Dict[str, Any] = {}
        self.skip_spaces()
        if self.peek() == "}":
            self.pos += 1
            return table
        while True:
            keys = self.key()
            self.expect("=")
            self.assign(table, keys, self.value())
            self.skip_spaces()
            if self.peek() == ",":
                self.pos += 1
                continue
            self.expect("}")
            return table

    # -- strings -------------------------------------------------------------

    def basic_string(self) -> str:
        self.pos += 1
        out: List[str] = []
        while True:
            char = self.peek()
            if char in ("", "\n"):
                self.error("unterminated string")
            self.pos += 1
            if char == '"':
                return "".join(out)
            out.append(self.escape() if char == "\\" else char)

    def multiline_basic_string(self) -> str:
        self.pos += 3
        if self.peek() == "\n":
            self.pos += 1
        out: List[str] = []
        while True:
            if self.text.startswith('"""', self.pos):
                # Up to two quotes may sit right before the closing delimiter.
                extra = 0
                while extra < 2 and self.text.startswith('"', self.pos + 3 + extra):
                    extra += 1
                out.append('"' * extra)
                self.pos += 3 + extra
                return "".join(out)
            char = self.peek()
            if char == "":
                self.error("unterminated multi-line string")
            self.pos += 1
            if char != "\\":
                out.append(char)
                continue
            continuation = _LINE_CONTINUATION.match(self.text, self.pos)
            if continuation:
                self.pos = continuation.end()
            else:
                out.append(self.escape())

    def literal_string(self) -> str:
        end = self.text.find("'", self.pos + 1)
        newline = self.text.find("\n", self.pos + 1)
        if end < 0 or (0 <= newline < end):
            self.error("unterminated literal string")
        value = self.text[self.pos + 1 : end]
        self.pos = end + 1
        return value

    def multiline_literal_string(self) -> str:
        start = self.pos + 3
        if self.text.startswith("\n", start):
            start += 1
        end = self.text.find("'''", start)
        if end < 0:
            self.error("unterminated multi-line literal string")
        extra = 0
        while extra < 2 and self.text.startswith("'", end + 3 + extra):
            extra += 1
        self.pos = end + 3 + extra
        return self.text[start:end] + "'" * extra

    def escape(self) -> str:
        char = self.peek()
        self.pos += 1
        if char in _ESCAPES:
            return _ESCAPES[char]
        width = {"u": 4, "U": 8, "x": 2}.get(char)
        digits = self.text[self.pos : self.pos + width] if width else ""
        if not width or len(digits) != width or not _HEX.fullmatch(digits):
            self.error("invalid escape \\%s" % char)
        self.pos += width
        try:
            return chr(int(digits, 16))
        except ValueError:
            self.error("escape \\%s%s is not a character" % (char, digits))
            return ""  # unreachable; error() raises

    # -- low-level scanning --------------------------------------------------

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def skip_spaces(self) -> None:
        while self.peek() in (" ", "\t"):
            self.pos += 1

    def skip_comment(self) -> None:
        if self.peek() == "#":
            end = self.text.find("\n", self.pos)
            self.pos = len(self.text) if end < 0 else end

    def skip_blank_lines(self) -> None:
        while True:
            self.skip_spaces()
            self.skip_comment()
            if self.peek() != "\n":
                return
            self.pos += 1

    def end_of_line(self) -> None:
        self.skip_spaces()
        self.skip_comment()
        if self.peek() not in ("", "\n"):
            self.error("expected the end of the line")

    def expect(self, token: str) -> None:
        self.skip_spaces()
        if not self.text.startswith(token, self.pos):
            self.error("expected %r" % token)
        self.pos += len(token)

    def error(self, message: str) -> None:
        line = self.text.count("\n", 0, self.pos) + 1
        raise TomlError("%s (line %d)" % (message, line))


def _to_int(text: str) -> int:
    cleaned = text.replace("_", "")
    for prefix, base in (("0x", 16), ("0o", 8), ("0b", 2)):
        if cleaned.startswith(prefix):
            return int(cleaned[2:], base)
    return int(cleaned)


def _to_float(text: str) -> float:
    return float(text.replace("_", ""))
