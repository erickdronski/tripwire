"""Tests for inventory collection, reporting, and the CLI."""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tripwire.cli import main
from tripwire.inventory import collect
from tripwire.report import render_json, render_text
from tripwire.rules import run_all

from .test_rules import ConfigFixture


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class TestInventory(unittest.TestCase):
    def test_collects_skills_servers_and_hooks(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "body")
            fixture.settings(
                {
                    "mcpServers": {"s": {"command": "node", "args": ["x.js"]}},
                    "hooks": {
                        "SessionStart": [
                            {"hooks": [{"type": "command", "command": "true"}]}
                        ]
                    },
                }
            )
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
        self.assertEqual(len(inventory.skills), 1)
        self.assertEqual(len(inventory.servers), 1)
        self.assertEqual(len(inventory.hooks), 1)
        self.assertEqual(inventory.servers[0].command_line, "node x.js")

    def test_marketplace_skills_are_labelled_by_source(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "body", plugin=True)
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
        self.assertTrue(inventory.skills[0].source.startswith("marketplace:"))

    def test_user_skills_are_labelled_user(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "body")
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
        self.assertEqual(inventory.skills[0].source, "user")

    def test_scripts_are_discovered(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "body", scripts=["scripts/run.sh", "helper.py"])
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
        self.assertEqual(
            sorted(inventory.skills[0].scripts), ["helper.py", "scripts/run.sh"]
        )

    def test_project_config_is_read_when_requested(self):
        with ConfigFixture() as fixture:
            project = os.path.join(fixture.root, "proj")
            os.makedirs(os.path.join(project, ".claude"))
            with open(os.path.join(project, ".mcp.json"), "w") as handle:
                json.dump({"mcpServers": {"p": {"command": "node"}}}, handle)
            inventory = collect(
                config_dir="/nonexistent/agent",
                user_json="/nonexistent/x.json",
                project_dir=project,
            )
        self.assertEqual(len(inventory.servers), 1)
        self.assertEqual(inventory.servers[0].scope, "project")

    def test_frontmatter_is_parsed_without_pyyaml(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "body", description="Does a thing.")
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
        self.assertEqual(inventory.skills[0].description, "Does a thing.")


class TestReport(unittest.TestCase):
    def build(self):
        fixture = ConfigFixture()
        fixture.skill("a", "body", plugin=True)
        fixture.settings({"dangerouslySkipPermissions": True})
        inventory = collect(config_dir=fixture.root, user_json="/nonexistent/x.json")
        findings = run_all(inventory)
        self.addCleanup(fixture.cleanup)
        return inventory, findings

    def test_text_leads_with_the_capability_inventory(self):
        inventory, findings = self.build()
        text = render_text(inventory, findings)
        self.assertLess(text.index("skills installed"), text.index("HIGH"))

    def test_info_findings_hidden_by_default(self):
        with ConfigFixture() as fixture:
            fixture.settings(
                {
                    "hooks": {
                        "SessionStart": [
                            {"hooks": [{"type": "command", "command": "true"}]}
                        ]
                    }
                }
            )
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
            findings = run_all(inventory)
        self.assertNotIn("Automatic command", render_text(inventory, findings))
        self.assertIn(
            "Automatic command", render_text(inventory, findings, show_info=True)
        )

    def test_home_directory_is_shortened(self):
        inventory, findings = self.build()
        text = render_text(inventory, findings)
        self.assertNotIn(os.path.expanduser("~") + "/", text)

    def test_json_shape(self):
        inventory, findings = self.build()
        payload = json.loads(render_json(inventory, findings, "0.1.0"))
        self.assertEqual(payload["tool"], "tripwire")
        self.assertIn("capabilities", payload)
        self.assertIn("counts", payload)
        self.assertGreaterEqual(payload["counts"]["high"], 1)

    def test_clean_config_says_so(self):
        with ConfigFixture() as fixture:
            fixture.skill("a", "An ordinary skill that formats code.", plugin=True)
            inventory = collect(
                config_dir=fixture.root, user_json="/nonexistent/x.json"
            )
            findings = run_all(inventory)
        self.assertIn("Nothing to flag", render_text(inventory, findings))


class TestCLI(unittest.TestCase):
    def test_runs_and_reports(self):
        with ConfigFixture() as fixture:
            fixture.settings({"dangerouslySkipPermissions": True})
            code, out, _ = run_cli(
                "--config-dir", fixture.root, "--user-json", "/nonexistent/x.json"
            )
        self.assertEqual(code, 0)
        self.assertIn("Approval prompts are disabled", out)

    def test_json_output(self):
        with ConfigFixture() as fixture:
            fixture.settings({"dangerouslySkipPermissions": True})
            _code, out, _ = run_cli(
                "--config-dir",
                fixture.root,
                "--user-json",
                "/nonexistent/x.json",
                "--format",
                "json",
            )
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "tripwire")

    def test_fail_on_high_exits_one(self):
        with ConfigFixture() as fixture:
            fixture.settings({"dangerouslySkipPermissions": True})
            code, _, _ = run_cli(
                "--config-dir",
                fixture.root,
                "--user-json",
                "/nonexistent/x.json",
                "--fail-on",
                "high",
            )
        self.assertEqual(code, 1)

    def test_fail_on_high_passes_when_only_medium(self):
        with ConfigFixture() as fixture:
            fixture.settings({"permissions": {"allow": ["Bash(*)"]}})
            code, _, _ = run_cli(
                "--config-dir",
                fixture.root,
                "--user-json",
                "/nonexistent/x.json",
                "--fail-on",
                "high",
            )
        self.assertEqual(code, 0)

    def test_default_never_fails(self):
        with ConfigFixture() as fixture:
            fixture.settings({"dangerouslySkipPermissions": True})
            code, _, _ = run_cli(
                "--config-dir", fixture.root, "--user-json", "/nonexistent/x.json"
            )
        self.assertEqual(code, 0)

    def test_no_config_exits_two(self):
        code, _, err = run_cli(
            "--config-dir", "/nonexistent/agent", "--user-json", "/nonexistent/x.json"
        )
        self.assertEqual(code, 2)
        self.assertIn("No agent configuration", err)


class TestNoNetworkCode(unittest.TestCase):
    """The README promises this package makes no outbound connections."""

    def test_no_network_imports_anywhere(self):
        import tripwire

        package_dir = os.path.dirname(os.path.abspath(tripwire.__file__))
        banned = (
            "import socket",
            "import urllib",
            "import http",
            "import requests",
            "from socket",
            "from urllib",
            "from http",
            "subprocess",
        )
        for filename in os.listdir(package_dir):
            if not filename.endswith(".py"):
                continue
            with open(os.path.join(package_dir, filename), encoding="utf-8") as handle:
                source = handle.read()
            for needle in banned:
                with self.subTest(file=filename, needle=needle):
                    self.assertNotIn(
                        needle,
                        source,
                        "%s imports %s — tripwire must not make network calls "
                        "or execute processes" % (filename, needle),
                    )


if __name__ == "__main__":
    unittest.main()


class TestSecretsNeverReachOutput(unittest.TestCase):
    """An audit report is exactly what people paste into issues.

    Hook commands routinely carry credentials, and they reach the report by two
    independent paths — finding evidence and the raw inventory dump. Securing
    one and missing the other is how a security tool ships a leak, so every
    path is asserted here rather than the one that happened to be checked.
    """

    SECRET = "sk-ant-api03-LEAKEDSECRETVALUE0123456789"

    def fixture_with_secret_hook(self):
        fixture = ConfigFixture()
        fixture.settings(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'curl -H "Authorization: Bearer %s" https://x'
                                    % self.SECRET,
                                }
                            ]
                        }
                    ]
                }
            }
        )
        self.addCleanup(fixture.cleanup)
        return fixture

    def test_secret_absent_from_text_report(self):
        fixture = self.fixture_with_secret_hook()
        _code, out, _err = run_cli(
            "--config-dir", fixture.root, "--user-json", "/nonexistent/x.json", "--info"
        )
        self.assertNotIn(self.SECRET, out)

    def test_secret_absent_from_json_report(self):
        fixture = self.fixture_with_secret_hook()
        _code, out, _err = run_cli(
            "--config-dir",
            fixture.root,
            "--user-json",
            "/nonexistent/x.json",
            "--info",
            "--format",
            "json",
        )
        self.assertNotIn(self.SECRET, out)
        json.loads(out)  # still valid JSON

    def test_secret_absent_from_the_inventory_dump_specifically(self):
        """The path that was missed the first time this was fixed."""
        fixture = self.fixture_with_secret_hook()
        inventory = collect(config_dir=fixture.root, user_json="/nonexistent/x.json")
        self.assertNotIn(self.SECRET, json.dumps(inventory.to_dict()))

    def test_the_command_is_still_recognizable_after_redaction(self):
        """Redaction that destroys the evidence protects nothing useful."""
        fixture = self.fixture_with_secret_hook()
        inventory = collect(config_dir=fixture.root, user_json="/nonexistent/x.json")
        command = inventory.hooks[0].command
        self.assertIn("curl", command)
        self.assertIn("https://x", command)
        self.assertIn("redacted", command)
