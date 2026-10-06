# Contributing

The most valuable contribution is a **false-positive report**. The second most
valuable is a **detection that this misses**.

## The bar

**Precision over recall, always.** A scanner whose high-severity findings are
mostly wrong gets muted, and then its true findings are invisible too. A new
rule needs a test proving it fires on the attack *and* a test proving it stays
quiet on the legitimate case that most resembles it.

**High severity is a narrow category.** Reserve it for constructions with no
legitimate documentation use: overriding prior instructions, concealment from
the user, exfiltration to a fixed endpoint, invisible characters, plaintext
credentials, approval disabled. Everything else grades down. If you can imagine
an official skill containing the pattern for a good reason, it is not high.

**Every finding states its mechanism** — what would actually have to happen for
it to hurt someone. "Potential security risk" is not a finding, it is a shrug.

**No network calls, no subprocess, ever.** There is a test asserting the package
imports neither. A PR adding a reputation lookup or an update check will be
declined regardless of usefulness — the README promises this and the promise is
load-bearing for a tool that reads your credentials directory.

**No dependencies. Python 3.9 compatible.**

## Adding a rule

Rules live in `tripwire/rules.py` and return `Finding` objects. Give each a
stable `rule` id, a base severity, a mechanism, and a remediation someone can
act on.

```bash
python -m unittest discover -s tests -t .
python -m tripwire --info        # dogfood it
```

## Reporting a false positive

Include the file that triggered it and what the tool said. If you can, note why
the content is legitimate — that reasoning usually becomes the fix. Past false
positives are pinned in `tests/test_rules.py` — `TestDoesNotCryWolf`, and a
`*Precision` class per rule that pairs each false positive with the attack it
must still catch; add yours there. Paraphrase the text that triggered it rather
than pasting someone else's skill.

## Supporting another agent

`tripwire/inventory.py` reads Claude Code, Claude Desktop, Cursor, and Codex.
To support another harness, add collection that produces the same `Skill` /
`Server` / `Hook` / `SettingsFile` objects, labelled with an `agent` and a
`scope`, and resolve its default location under the `home` argument so tests
can point it at a temporary directory. Tests must never read the real home
directory. The rules and reporting layers are harness-agnostic, except where an
agent spells "approval off" its own way — then add a check beside the others in
`check_settings`.
