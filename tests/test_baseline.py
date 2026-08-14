"""Tests for suppression and baselines.

These are the features that decide whether a scanner survives contact with a
real team. Without them, every run reprints findings the reader already judged,
and the tool gets removed — taking its true findings with it.

The properties that matter most are the ones that keep suppression honest: a
suppressed finding is always counted in the output, and a baseline never hides
something new.
"""

import json
import os
import unittest

from tripwire.baseline import (
    BaselineError,
    apply_ignores,
    diff_against_baseline,
    finding_key,
    load_baseline,
    load_ignores,
    write_baseline,
)
from tripwire.rules import Finding

from .test_cli import run_cli
from .test_rules import ConfigFixture


def finding(
    rule="hook.command", severity="medium", title="T", location="/x/settings.json"
):
    return Finding(
        rule=rule, severity=severity, title=title, detail="d", location=location
    )


class TestFindingKey(unittest.TestCase):
    def test_stable_across_runs(self):
        self.assertEqual(finding_key(finding()), finding_key(finding()))

    def test_differs_by_rule(self):
        self.assertNotEqual(
            finding_key(finding(rule="a")), finding_key(finding(rule="b"))
        )

    def test_differs_by_location(self):
        self.assertNotEqual(
            finding_key(finding(location="/a")), finding_key(finding(location="/b"))
        )

    def test_home_directory_is_normalized(self):
        """A baseline written on a laptop must still match on a CI runner."""
        home = os.path.expanduser("~")
        self.assertEqual(
            finding_key(finding(location=home + "/.claude/settings.json")),
            finding_key(finding(location="~/.claude/settings.json")),
        )

    def test_evidence_is_not_part_of_the_key(self):
        """Keys must survive an unrelated edit to the file being reported on."""
        a = finding()
        b = finding()
        b.evidence = "a line that changed"
        self.assertEqual(finding_key(a), finding_key(b))


class TestIgnores(unittest.TestCase):
    def write(self, text):
        path = os.path.join(self.dir, ".tripwireignore")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def setUp(self):
        import tempfile

        self.dir = tempfile.mkdtemp(prefix="tripwire-ignore-")
        self.addCleanup(
            lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True)
        )

    def test_missing_file_is_not_an_error(self):
        self.assertEqual(load_ignores("/nonexistent/.tripwireignore"), [])

    def test_comments_and_blanks_skipped(self):
        path = self.write("# a comment\n\n   \nhook.command\n")
        self.assertEqual(len(load_ignores(path)), 1)

    def test_rule_only_suppresses_everywhere(self):
        path = self.write("hook.command\n")
        kept, suppressed = apply_ignores([finding()], load_ignores(path))
        self.assertEqual(kept, [])
        self.assertEqual(len(suppressed), 1)

    def test_path_scoped_suppression(self):
        path = self.write("hook.command  plugins/mine\n")
        ignores = load_ignores(path)
        kept, suppressed = apply_ignores(
            [finding(location="/x/plugins/mine/s"), finding(location="/x/other/s")],
            ignores,
        )
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(suppressed), 1)

    def test_reason_is_captured_for_the_report(self):
        path = self.write("hook.command  *  reviewed: this is my own hook\n")
        _kept, suppressed = apply_ignores([finding()], load_ignores(path))
        self.assertIn("my own hook", suppressed[0].suppressed_by.reason)

    def test_wildcard_rule_suppresses_all(self):
        path = self.write("*\n")
        kept, _ = apply_ignores(
            [finding(rule="a"), finding(rule="b")], load_ignores(path)
        )
        self.assertEqual(kept, [])

    def test_malformed_rule_is_rejected_loudly(self):
        path = self.write("this is not a rule id!!\n")
        with self.assertRaises(BaselineError):
            load_ignores(path)

    def test_no_ignores_leaves_findings_untouched(self):
        items = [finding()]
        kept, suppressed = apply_ignores(items, [])
        self.assertEqual(kept, items)
        self.assertEqual(suppressed, [])


class TestBaseline(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.dir = tempfile.mkdtemp(prefix="tripwire-base-")
        self.path = os.path.join(self.dir, "base.json")
        self.addCleanup(
            lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True)
        )

    def test_roundtrip(self):
        items = [finding(rule="a"), finding(rule="b")]
        self.assertEqual(write_baseline(self.path, items, "0.1.0"), 2)
        data = load_baseline(self.path)
        self.assertEqual(len(data["findings"]), 2)

    def test_unchanged_findings_are_known_not_new(self):
        items = [finding(rule="a")]
        write_baseline(self.path, items, "0.1.0")
        new, known, resolved = diff_against_baseline(items, load_baseline(self.path))
        self.assertEqual(new, [])
        self.assertEqual(len(known), 1)
        self.assertEqual(resolved, [])

    def test_an_added_finding_is_new(self):
        write_baseline(self.path, [finding(rule="a")], "0.1.0")
        new, known, _ = diff_against_baseline(
            [finding(rule="a"), finding(rule="b")], load_baseline(self.path)
        )
        self.assertEqual(len(new), 1)
        self.assertEqual(len(known), 1)

    def test_a_removed_finding_is_reported_as_resolved(self):
        write_baseline(self.path, [finding(rule="a"), finding(rule="b")], "0.1.0")
        _new, _known, resolved = diff_against_baseline(
            [finding(rule="a")], load_baseline(self.path)
        )
        self.assertEqual(len(resolved), 1)

    def test_missing_baseline_is_empty_not_an_error(self):
        self.assertEqual(load_baseline("/nonexistent/base.json"), {})

    def test_corrupt_baseline_is_rejected_loudly(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        with self.assertRaises(BaselineError):
            load_baseline(self.path)


class TestReviewWorkflowEndToEnd(unittest.TestCase):
    """The workflow a team actually runs."""

    def fixture(self):
        f = ConfigFixture()
        f.settings(
            {
                "permissions": {"allow": ["Bash(*)"]},
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "git pull"}]}
                    ]
                },
            }
        )
        self.addCleanup(f.cleanup)
        return f

    def test_suppression_is_always_visible_in_the_output(self):
        """A suppression you cannot see is a scanner that missed something."""
        f = self.fixture()
        ignore = os.path.join(f.root, ".tripwireignore")
        with open(ignore, "w", encoding="utf-8") as handle:
            handle.write("settings.wildcard-allow  *  reviewed\n")
        _code, out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--ignore-file",
            ignore,
        )
        self.assertIn("suppressed", out)

    def test_new_finding_is_marked_and_gates_ci(self):
        f = self.fixture()
        base = os.path.join(f.root, "base.json")
        run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--update-baseline",
            base,
        )

        # Nothing changed: the gate passes.
        code, _out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--baseline",
            base,
            "--fail-on",
            "high",
        )
        self.assertEqual(code, 0)

        # Approval gets disabled: a new high finding appears and gates CI.
        f.settings(
            {
                "dangerouslySkipPermissions": True,
                "permissions": {"allow": ["Bash(*)"]},
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "git pull"}]}
                    ]
                },
            }
        )
        code, out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--baseline",
            base,
            "--fail-on",
            "high",
        )
        self.assertEqual(code, 1)
        self.assertIn("NEW", out)
        self.assertIn("1 new since the baseline", out)

    def test_known_findings_alone_do_not_gate_ci(self):
        """Otherwise the build stays red until history is cleared, and the
        gate gets disabled."""
        f = self.fixture()
        base = os.path.join(f.root, "base.json")
        f.settings({"dangerouslySkipPermissions": True})
        run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--update-baseline",
            base,
        )
        code, _out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--baseline",
            base,
            "--fail-on",
            "high",
        )
        self.assertEqual(code, 0, "a known finding broke the build")

    def test_no_ignore_reports_everything(self):
        f = self.fixture()
        ignore = os.path.join(f.root, ".tripwireignore")
        with open(ignore, "w", encoding="utf-8") as handle:
            handle.write("*\n")
        _code, out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--ignore-file",
            ignore,
            "--no-ignore",
        )
        self.assertNotIn("suppressed by", out)

    def test_json_output_separates_new_and_suppressed(self):
        f = self.fixture()
        base = os.path.join(f.root, "base.json")
        run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--update-baseline",
            base,
        )
        _code, out, _err = run_cli(
            "--config-dir",
            f.root,
            "--user-json",
            "/nonexistent/x.json",
            "--baseline",
            base,
            "--format",
            "json",
        )
        payload = json.loads(out)
        self.assertIn("new_findings", payload)
        self.assertIn("suppressed", payload)


if __name__ == "__main__":
    unittest.main()
