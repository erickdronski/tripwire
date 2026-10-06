"""Tests for the settings that switch an agent's checks off.

Approval prompts and sandboxes are the last line between a prompt injection
and your shell, and every agent spells "off" differently: Claude Code has a
flag and a default mode, Codex has an approval policy and a sandbox mode per
profile, and the Codex app stores its permission mode outside the config file
entirely. Each spelling gets a test that it is caught, and a test that the
setting next to it is not.
"""

import json
import unittest

from .test_cli import run_cli
from .test_rules import ConfigFixture
from .test_sources import HomeFixture


def settings_findings(findings):
    return [
        (f.rule, f.severity, f.title)
        for f in findings
        if f.rule.startswith("settings.")
    ]


class TestClaudeCodeDefaultMode(unittest.TestCase):
    def mode(self, value):
        with ConfigFixture() as fixture:
            fixture.settings({"permissions": {"defaultMode": value}})
            return settings_findings(fixture.audit()[1])

    def test_bypass_permissions_default_mode_is_high(self):
        self.assertEqual(
            self.mode("bypassPermissions"),
            [
                (
                    "settings.approval-disabled",
                    "high",
                    "Approval prompts are bypassed by default",
                )
            ],
        )

    def test_accept_edits_is_low(self):
        self.assertEqual(
            [severity for _rule, severity, _title in self.mode("acceptEdits")], ["low"]
        )

    def test_default_and_plan_modes_are_not_flagged(self):
        self.assertEqual(self.mode("default"), [])
        self.assertEqual(self.mode("plan"), [])


class TestCodexConfig(unittest.TestCase):
    def audit(self, toml):
        with HomeFixture() as fixture:
            fixture.home_write(".codex/config.toml", toml)
            return settings_findings(fixture.audit()[1])

    def test_no_sandbox_and_no_approval_is_high(self):
        found = self.audit(
            'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        )
        self.assertEqual(
            found,
            [
                (
                    "settings.approval-disabled",
                    "high",
                    "Codex runs with no sandbox and no approval prompts",
                )
            ],
        )

    def test_no_sandbox_alone_is_medium(self):
        found = self.audit(
            'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n'
        )
        self.assertEqual(
            [(r, s) for r, s, _t in found], [("settings.sandbox-disabled", "medium")]
        )

    def test_never_asking_inside_a_sandbox_is_low(self):
        found = self.audit(
            'approval_policy = "never"\nsandbox_mode = "workspace-write"\n'
        )
        self.assertEqual([s for _r, s, _t in found], ["low"])

    def test_sandboxed_with_prompts_is_not_flagged(self):
        self.assertEqual(
            self.audit(
                'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
            ),
            [],
        )

    def test_active_profile_is_graded_in_full(self):
        found = self.audit(
            'profile = "yolo"\napproval_policy = "on-request"\n\n[profiles.yolo]\n'
            'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        )
        self.assertEqual([s for _r, s, _t in found], ["high"])
        self.assertIn("profile `yolo`", found[0][2])

    def test_active_profile_that_restores_the_sandbox_clears_the_top_level(self):
        found = self.audit(
            'profile = "safe"\napproval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n\n[profiles.safe]\n'
            'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
        )
        self.assertEqual(found, [])

    def test_inactive_profile_is_one_flag_away_and_capped_at_medium(self):
        found = self.audit(
            '[profiles.yolo]\napproval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n'
        )
        self.assertEqual(
            found,
            [
                (
                    "settings.approval-disabled",
                    "medium",
                    "Codex profile `yolo` runs with no sandbox and no approval prompts",
                )
            ],
        )

    def test_trusted_projects_are_listed(self):
        found = self.audit('[projects."/work/app"]\ntrust_level = "trusted"\n')
        self.assertEqual(
            found,
            [("settings.trusted-projects", "info", "Codex trusts 1 project directory")],
        )

    def test_trusting_the_filesystem_root_is_medium(self):
        found = self.audit('[projects."/"]\ntrust_level = "trusted"\n')
        self.assertEqual([s for _r, s, _t in found], ["medium"])


def codex_state(agent_mode=None, threads=None):
    atoms = {}
    if agent_mode is not None:
        atoms["permission-selection-by-host-id:local"] = {
            "kind": "agent-mode",
            "agentMode": agent_mode,
        }
    if threads is not None:
        atoms["heartbeat-thread-permissions-by-id"] = threads
    return json.dumps({"electron-persisted-atom-state": atoms, "other": [1, 2]})


FULL = {"approvalPolicy": "never", "sandboxPolicy": {"type": "dangerFullAccess"}}
SANDBOXED = {
    "approvalPolicy": "on-request",
    "sandboxPolicy": {"type": "workspaceWrite", "networkAccess": False},
}


class TestCodexApp(unittest.TestCase):
    """The Codex app keeps its permission mode outside `config.toml`."""

    def audit(self, state, automations=()):
        with HomeFixture() as fixture:
            fixture.home_write(".codex/.codex-global-state.json", state)
            for name, status, thread in automations:
                fixture.home_write(
                    ".codex/automations/%s/automation.toml" % name,
                    'name = "%s"\nkind = "heartbeat"\nstatus = "%s"\n'
                    'prompt = "private text"\ntarget_thread_id = "%s"\n'
                    % (name, status, thread),
                )
            inventory, findings = fixture.audit()
        return inventory, settings_findings(findings)

    def test_full_access_mode_is_high(self):
        _inventory, found = self.audit(codex_state("full-access"))
        self.assertEqual(
            found,
            [
                (
                    "settings.approval-disabled",
                    "high",
                    "Codex app runs local threads with full access",
                )
            ],
        )

    def test_sandboxed_mode_is_not_flagged(self):
        _inventory, found = self.audit(codex_state("auto"))
        self.assertEqual(found, [])

    def test_active_automation_with_full_access_is_high(self):
        _inventory, found = self.audit(
            codex_state(threads={"t1": FULL}), [("nightly", "ACTIVE", "t1")]
        )
        self.assertEqual(
            found,
            [
                (
                    "settings.approval-disabled",
                    "high",
                    "Codex automation runs unattended with full access: nightly",
                )
            ],
        )

    def test_paused_automation_with_full_access_is_informational(self):
        _inventory, found = self.audit(
            codex_state(threads={"t1": FULL}), [("nightly", "PAUSED", "t1")]
        )
        self.assertEqual([s for _r, s, _t in found], ["info"])

    def test_automation_in_a_sandboxed_thread_is_not_flagged(self):
        _inventory, found = self.audit(
            codex_state(threads={"t1": SANDBOXED}), [("nightly", "ACTIVE", "t1")]
        )
        self.assertEqual(found, [])

    def test_unrecognised_state_format_reports_nothing_and_does_not_crash(self):
        inventory, found = self.audit(json.dumps({"something": "else"}))
        self.assertEqual(found, [])
        self.assertIn("codex", inventory.agents)

    def test_corrupt_state_is_a_visible_note(self):
        inventory, found = self.audit("{truncated")
        self.assertEqual(found, [])
        self.assertTrue(any(".codex-global-state.json" in n for n in inventory.notes))

    def test_automation_prompts_are_not_copied_into_output(self):
        with HomeFixture() as fixture:
            fixture.home_write(
                ".codex/.codex-global-state.json", codex_state(threads={"t1": FULL})
            )
            fixture.home_write(
                ".codex/automations/a/automation.toml",
                'name = "a"\nstatus = "ACTIVE"\nprompt = "my private prompt"\n'
                'target_thread_id = "t1"\n',
            )
            _code, raw, _err = run_cli("--home", fixture.home, "--format", "json")
        self.assertNotIn("my private prompt", raw)

    def test_full_access_gates_ci(self):
        with HomeFixture() as fixture:
            fixture.home_write(
                ".codex/config.toml",
                'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
            )
            code, _out, _err = run_cli("--home", fixture.home, "--fail-on", "high")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
