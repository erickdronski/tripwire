<h1 align="center">tripwire</h1>

<p align="center"><strong>See what your coding agent is actually allowed to do.</strong><br>
An offline audit of the skills, MCP servers, hooks, and permissions installed on your machine.</p>

<p align="center">
  <a href="#try-it">Try it</a> ·
  <a href="#what-it-finds">What it finds</a> ·
  <a href="#precision-is-the-product">Precision</a> ·
  <a href="#what-it-does-not-do">Limits</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <img alt="MIT license" src="https://img.shields.io/badge/license-MIT-101828">
  <img alt="zero dependencies" src="https://img.shields.io/badge/dependencies-0-08775c">
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-174ea6">
  <img alt="46 tests" src="https://img.shields.io/badge/tests-46-6b21a8">
</p>

---

You installed a plugin two months ago. You added an MCP server from a README.
You wrote a hook once and forgot about it. Somewhere in there is a setting that
turned approval prompts off "just for this one task."

Nothing shows you the union of that. `tripwire` builds it, then flags the
specific ways it can be turned against you.

## Try it

```bash
pip install tripwire-agent
tripwire
```

```
────────────────────────────────────────────────────────────────────────
  tripwire — what your agent can currently do
────────────────────────────────────────────────────────────────────────

  skills installed                   28
    from outside this machine        25
    shipping executable code          5
  MCP servers configured              1
    reached over the network          1
  automatic hooks                     1
    firing on                         SessionStart
  settings files                      1

────────────────────────────────────────────────────────────────────────
  1 high · 5 medium · 0 low · 1 informational
────────────────────────────────────────────────────────────────────────

  HIGH

  !! Approval prompts are disabled
     `dangerouslySkipPermissions` is set to true.
     Why it matters: Every tool call runs without asking — including commands
     an agent was steered into by content it read from a web page, a file, or
     an installed skill. This setting removes the last check between a prompt
     injection and your shell.
     ~/.claude/settings.json
     → Remove the flag and use a scoped allow-list, or keep it only inside a
       disposable container.
```

The inventory at the top is the part most people have never seen. **25 of 28
skills came from outside this machine, and 5 of them ship executable code** —
that is the real answer to "what can my agent do," and it is useful even when
nothing is wrong.

Nothing is executed, installed, or fetched. It reads files already on disk,
which matters, because much of what it inspects exists to run commands.

## What it finds

| Surface | Checked for |
|---|---|
| **Skills** | Instructions aimed at the model rather than at you; invisible Unicode; bundled executable code |
| **MCP servers** | Credentials stored as literals; packages installed at launch from unpinned sources; plaintext HTTP transport |
| **Hooks** | Every automatic command, escalated when it pipes to a shell, deletes recursively, elevates, or opens a socket |
| **Permissions** | Approval disabled entirely; wildcard allow-entries; allow-lists that have grown past review |

Two findings are worth calling out because they are the ones that catch real
attacks rather than sloppiness.

**Invisible characters in model-visible text.** Zero-width spaces, bidirectional
overrides, and Unicode tag characters render as nothing to you and read normally
to the model. A file containing them is, by construction, saying something to
the model that it is not saying to you. There is no legitimate reason for them
in a skill.

**Credential access next to an outbound call.** Reading a `.env` file is
ordinary setup. Reading one *and* sending it somewhere is the shape of
exfiltration, and only the combination is escalated.

## Precision is the product

A scanner whose high-severity findings are mostly false positives gets muted —
and then its true findings are invisible too. So the severity model is the
design, not an afterthought.

**High severity is reserved for constructions with no legitimate documentation
use**: overriding prior instructions, hiding activity from the user, shipping
data to a fixed endpoint, invisible characters, plaintext credentials, approval
switched off. Everything else grades down.

The first version of this tool reported **four high-severity findings on a clean
machine. Three were false positives** — official skills that *documented*
writing a `.env` file, or showed `rm -rf` inside a regex example. Three fixes:

- **Code blocks are stripped before scanning.** A hook-authoring skill quoting
  `rm\s+-rf` as a pattern is doing its job, not attacking you.
- **Weak signals grade down.** Mentioning a credential file is `low`. It only
  becomes `high` when it appears near a network call.
- **Local paths are not proof of authorship.** Skills land in `~/.claude/skills`
  via install scripts, package managers, and other agents — so the trust
  discount applies only to signals that local authorship genuinely explains.
  "Ignore all previous instructions" stays high wherever the file lives, because
  there is no version of that sentence you meant to write.

Every one of those cases is now a test. Roughly half the suite asserts that
something is *not* flagged, and CI plants a malicious config on every run to
confirm the detections still fire.

## In CI

```bash
tripwire --fail-on high
```

Exits 1 when a finding at or above that severity exists, 0 when clean, 2 when it
could not run. `--format json` emits every finding with its mechanism and
evidence.

```bash
tripwire --info            # include the full capability inventory
tripwire --project .       # also audit project-local .claude/ and .mcp.json
```

## What it does not do

Being honest about this is the difference between a useful tool and security
theater.

- **It does not prove anything is safe.** It is a static read of local config
  against a finite pattern set. A clean report means nothing obviously wrong was
  found — not that nothing is wrong.
- **It does not analyze MCP server behavior.** It reads how a server is
  configured, not what its code does once running. A server with a benign
  command line can do anything.
- **It cannot see intent.** A skill that legitimately needs to read credentials
  and a skill that steals them look similar from the outside. That is why every
  finding states its mechanism and asks you to read the file, rather than
  declaring a verdict.
- **It makes no network calls at all** — no telemetry, no reputation lookup, no
  update check. There is a test asserting the package imports no networking or
  subprocess module, so the claim stays true.

If you want dependency and package scanning, use a supply-chain scanner. This
answers a different question: *what did I already install, and what can it do
right now?*

## Testing

```bash
python -m unittest discover -s tests -t .   # 46 tests
```

## Related

Part of a set of small, standalone tools for working with coding agents:

| Tool | Job |
|---|---|
| [agentsmith](https://github.com/erickdronski/agentsmith) | Derives your AGENTS.md from the repo and detects drift |
| [contexttest](https://github.com/erickdronski/contexttest) | A/B tests whether an AGENTS.md change actually helps |
| [burnrate](https://github.com/erickdronski/burnrate) | Prices what your agent sessions cost, with a hard spend cap |
| [gtm-skills](https://github.com/erickdronski/gtm-skills) | Go-to-market skills for agents, on a tested arithmetic engine |

## License

MIT.
