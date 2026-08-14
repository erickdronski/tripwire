# Changelog

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
