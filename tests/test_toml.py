"""Tests for the TOML fallback used on Python 3.9 and 3.10.

The fallback only runs where ``tomllib`` does not exist, which is exactly
where nobody is looking. So every test here calls it directly on every
Python, and on 3.11+ each document is also held to ``tomllib``'s answer.
"""

import unittest
from unittest import mock

from tripwire.tomlparse import TomlError, loads, parse

try:
    import tomllib
except ImportError:  # Python 3.9 / 3.10
    tomllib = None


CODEX_CONFIG = r"""
# Codex-shaped: the subset tripwire actually reads.
model = "gpt-x"
approval_policy = "never"
sandbox_mode = 'danger-full-access'
profile = "fast"
notify = ["notify-send", "--app", "codex"]

[profiles.fast]
approval_policy = "on-request"

[profiles."with.dot"]
sandbox_mode = "read-only"

[mcp_servers.docs]
command = "npx"
args = [
  "-y",          # comment inside an array
  "docs-server",
]
env = { DOCS_TOKEN = "abc", "QUOTED KEY" = 'literal \n stays' }
startup_timeout_sec = 1_000

[mcp_servers.remote]
url = "https://mcp.example.com/sse"
http_headers.Authorization = "Bearer ${TOKEN}"

[projects."/Users/someone/My Project"]
trust_level = "trusted"
"""

DOCUMENTS = {
    "codex": CODEX_CONFIG,
    "scalars": (
        "a = 1\nb = -2\nc = +3\nd = 0x1F\ne = 0o17\nf = 0b101\ng = 1_000\n"
        "h = 3.5\ni = -0.25\nj = 1e3\nk = 6.02E+23\nl = true\nm = false\n"
    ),
    "strings": (
        'basic = "tab\\tquote\\"backslash\\\\unicode\\u00e9"\n'
        "literal = 'C:\\path\\no\\escape'\n"
        'multi = """\nline one\nline two"""\n'
        'trimmed = """one \\\n    two"""\n'
        "raw = '''\nfirst\n  second\\n'''\n"
        'quotes = """She said "hi"."""\n'
    ),
    "nesting": (
        "[a.b.c]\nx = 1\n[a]\ny = 2\n[[fruit]]\nname = 'apple'\n[fruit.color]\n"
        "hex = '#f00'\n[[fruit]]\nname = 'pear'\n"
    ),
    "dotted": 'site."google.com" = true\nphysical.color = "orange"\n',
    "arrays": "nested = [[1, 2], ['a', \"b\"]]\nempty = []\ntables = [{a = 1}, {b = 2}]\n",
    "inline": "point = { x = 1, y = 2, z.deep = 3 }\nempty = {}\n",
    "comments": "# top\n\nkey = 'v' # trailing\n   # indented\n[t] # header comment\n",
}


class TestFallbackParser(unittest.TestCase):
    def test_codex_shaped_config(self):
        data = parse(CODEX_CONFIG)
        self.assertEqual(data["approval_policy"], "never")
        self.assertEqual(data["sandbox_mode"], "danger-full-access")
        self.assertEqual(data["profiles"]["fast"], {"approval_policy": "on-request"})
        self.assertEqual(data["profiles"]["with.dot"]["sandbox_mode"], "read-only")
        docs = data["mcp_servers"]["docs"]
        self.assertEqual(docs["args"], ["-y", "docs-server"])
        self.assertEqual(docs["env"]["QUOTED KEY"], "literal \\n stays")
        self.assertEqual(docs["startup_timeout_sec"], 1000)
        self.assertEqual(
            data["mcp_servers"]["remote"]["http_headers"],
            {"Authorization": "Bearer ${TOKEN}"},
        )
        self.assertEqual(
            data["projects"]["/Users/someone/My Project"], {"trust_level": "trusted"}
        )

    def test_scalars(self):
        data = parse(DOCUMENTS["scalars"])
        self.assertEqual([data[k] for k in "abcdefg"], [1, -2, 3, 31, 15, 5, 1000])
        self.assertEqual([data[k] for k in "hijk"], [3.5, -0.25, 1000.0, 6.02e23])
        self.assertIs(data["l"], True)
        self.assertIs(data["m"], False)

    def test_strings(self):
        data = parse(DOCUMENTS["strings"])
        self.assertEqual(data["basic"], 'tab\tquote"backslash\\unicode\u00e9')
        self.assertEqual(data["literal"], "C:\\path\\no\\escape")
        self.assertEqual(data["multi"], "line one\nline two")
        self.assertEqual(data["trimmed"], "one two")
        self.assertEqual(data["raw"], "first\n  second\\n")
        self.assertEqual(data["quotes"], 'She said "hi".')

    def test_tables_and_arrays_of_tables(self):
        data = parse(DOCUMENTS["nesting"])
        self.assertEqual(data["a"], {"b": {"c": {"x": 1}}, "y": 2})
        self.assertEqual(
            data["fruit"],
            [{"name": "apple", "color": {"hex": "#f00"}}, {"name": "pear"}],
        )

    def test_dates_are_returned_as_text(self):
        self.assertEqual(parse("when = 2026-10-06\n"), {"when": "2026-10-06"})

    def test_errors_carry_a_line_number(self):
        for text in (
            'a = "unterminated\n',
            "a = 1\na = 2\n",
            "[t]\n[t]\n",
            "a = what\n",
            "just a line\n",
            "a = 1 b = 2\n",
            "a = [1, 2\n",
            'a = "bad \\q escape"\n',
        ):
            with self.subTest(text=text):
                with self.assertRaises(TomlError) as caught:
                    parse(text)
                self.assertIn("line", str(caught.exception))

    def test_loads_reports_failures_as_toml_error(self):
        with self.assertRaises(TomlError):
            loads("a = = 1\n")

    def test_loads_uses_the_fallback_when_tomllib_is_missing(self):
        """The 3.9 / 3.10 path, exercised on every Python."""
        from tripwire import tomlparse

        with mock.patch.object(tomlparse, "_tomllib", None):
            self.assertEqual(loads(CODEX_CONFIG), parse(CODEX_CONFIG))
            with self.assertRaises(TomlError):
                loads("a = = 1\n")


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestFallbackAgreesWithTomllib(unittest.TestCase):
    """On the Pythons that have both, the fallback must give the same answer."""

    def test_every_document_matches(self):
        for name, text in DOCUMENTS.items():
            with self.subTest(document=name):
                self.assertEqual(parse(text), tomllib.loads(text))

    def test_loads_prefers_tomllib(self):
        self.assertEqual(loads(CODEX_CONFIG), tomllib.loads(CODEX_CONFIG))


if __name__ == "__main__":
    unittest.main()
