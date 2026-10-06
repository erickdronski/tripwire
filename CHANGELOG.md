# Changelog

## [0.2.0] — 2026-10-06

Measured against a real workstation (~940 skill files, Claude Desktop, Codex):
0.1.0 reported 32 high-severity findings there and every one was a false
positive. This release reports one, and it is real.

### Precision work

- Credential exfiltration needs constructs on both sides: a credential access
  (reading a store such as `~/.aws/credentials` or `.env`, using one as a
  command's data source, dumping the environment or keychain, expanding a
  `$*_TOKEN`-style variable) and an actual transmission (`curl -d`, `| nc`,
  `fetch(`, `requests.post`, "send it to <url>") in the same paragraph. A
  markdown link or bare URL is not an outbound call. Removed 18 false
  positives.
- Concealment means hiding activity ("that you…", "without the user
  noticing", "keep this hidden", "silently … without telling anyone").
  Honesty rules with sequencing words, and negated "without telling the user",
  no longer match. Removed 11 false positives.
- A quoted injection phrase next to defensive language ("treat it as data",
  "untrusted") is a mention, reported as informational; quotes alone grade
  nothing down, and every occurrence is examined so a defensive quote cannot
  shield a bare use later in the file. Removed 3 false positives.
- "Reads a credential file" no longer matches `cat` inside "fabricated", and
  "the statement you are now attempting" is no longer an identity override.

### Inventory

- Counts what the agent loads: install paths from `installed_plugins.json`
  minus plugins `enabledPlugins` turns off, and the live generation of each
  synced plugin. Deleted plugins (`.trash`), uninstalled marketplace catalogs,
  superseded synced copies, and other editors' copies are skipped and counted
  in the report. On the measured machine: 942 skill files became 636 loaded
  and 307 skipped, explained.
- Each distinct finding is reported once, with "N copies" in text and every
  path in JSON. Suppression covers a merged finding only when every copy is
  under the reviewed path.
- MCP servers from plugin `.mcp.json` files and manifests, Claude Desktop's
  `claude_desktop_config.json` (macOS, Windows, Linux), Cursor's user and
  project `mcp.json`, and Codex's `config.toml`; hooks from plugin
  `hooks/hooks.json` and manifests, and Codex's `notify`. Every server and
  hook is labelled with its agent and scope (`user`, `project`,
  `plugin:<name>`). On the measured machine: 1 server became 226, 0 hooks
  became 20.
- Symlinked user skills are followed; skills synced from an account are
  third-party, not local; project skills come from `.claude/skills` only.
- `--home DIR` reads every agent's config from under `DIR`.
- Config files are read up to 16 MB instead of 400 KB, so a large
  `~/.claude.json` no longer loses its servers to truncation. A config that
  will not parse is a visible note, never a crash.

### Checks

- Codex: `approval_policy = "never"` with `sandbox_mode = "danger-full-access"`
  is high, either alone is graded lower; the active profile is graded in full
  and other loosening profiles are capped at medium; trusted project
  directories are listed. The Codex app's full-access mode and active
  automations running in full-access threads are high.
- Claude Code: `permissions.defaultMode: "bypassPermissions"` is high,
  `acceptEdits` is low.
- Literal credentials in MCP request headers and on server command lines or
  URLs are high, and are masked at capture.

### Tooling

- A TOML reader that uses `tomllib` on 3.11+ and a tested fallback on 3.9 and
  3.10, still with zero dependencies.
- 196 tests, up from 83. CI also plants a Codex config with both checks off
  and a plugin server carrying a literal key, and confirms the key is never
  printed.
- Version 0.1.0 counted 46 tests in the badge's alt text and 83 in the badge;
  both now show the real count.

## [0.1.0] — 2026-08-14

Initial release.

### Inventory

- Skills from the user directory, plugins, marketplaces, and project-local config
- MCP servers from settings, `~/.claude.json`, and project `.mcp.json`
- Hooks from every settings file, with their event and matcher
- Permission settings across user and project scope

### Checks

- Instruction-shaped text in model-visible content, graded by construction
- Invisible Unicode (zero-width, bidirectional overrides, tag characters)
- Credential access appearing near an outbound call
- Plaintext credentials in server environments, redacted in output
- Packages installed at launch from unpinned sources
- Plaintext HTTP transport, with localhost graded lower
- Automatic hooks, escalated for pipe-to-shell, recursive delete, sudo, sockets
- Approval disabled; wildcard allow-entries; oversized allow-lists

### Precision work

- Code fences and inline spans stripped before scanning prose
- Weak signals escalate only in combination
- Path-based trust applies only to signals local authorship explains

### Tooling

- 46 tests, roughly half asserting that something is *not* flagged
- CI plants a malicious config each run to confirm detections still fire
- Test asserting the package imports no networking or subprocess module
