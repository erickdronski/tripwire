"""Command line interface.

    tripwire                  # audit this machine's agent configuration
    tripwire --info           # include the informational inventory
    tripwire --project .      # also read project-local config
    tripwire --format json    # machine-readable
    tripwire --fail-on high   # exit non-zero for CI

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 could not run.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .baseline import (
    BASELINE_FILE,
    IGNORE_FILE,
    BaselineError,
    apply_ignores,
    diff_against_baseline,
    load_baseline,
    load_ignores,
    write_baseline,
)
from .inventory import collect
from .report import render_json, render_text
from .rules import SEVERITIES, run_all

__all__ = ["main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description=(
            "Audit the skills, MCP servers, hooks, and permissions installed "
            "for your coding agent. Offline, read-only, nothing executed."
        ),
        epilog=(
            "tripwire never runs, installs, or fetches anything. It reads "
            "config files already on disk."
        ),
    )
    parser.add_argument(
        "--config-dir", help="agent config directory (default: ~/.claude)"
    )
    parser.add_argument(
        "--user-json", help="user config file (default: ~/.claude.json)"
    )
    parser.add_argument(
        "--project",
        nargs="?",
        const=".",
        help="also audit project-local config in this directory",
    )
    parser.add_argument(
        "--info", action="store_true", help="include informational findings"
    )
    review = parser.add_argument_group("reviewing findings over time")
    review.add_argument(
        "--ignore-file",
        default=IGNORE_FILE,
        metavar="FILE",
        help="reviewed suppressions (default: %s)" % IGNORE_FILE,
    )
    review.add_argument(
        "--no-ignore",
        action="store_true",
        help="report everything, including findings you have suppressed",
    )
    review.add_argument(
        "--baseline",
        nargs="?",
        const=BASELINE_FILE,
        metavar="FILE",
        help=(
            "compare against a recorded baseline and mark which findings are "
            "new (default file: %s)" % BASELINE_FILE
        ),
    )
    review.add_argument(
        "--update-baseline",
        nargs="?",
        const=BASELINE_FILE,
        metavar="FILE",
        help="record the current findings as accepted, then exit",
    )
    review.add_argument(
        "--new-only",
        action="store_true",
        help="with --baseline, show only findings absent from it",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "never"),
        default="never",
        help="exit 1 when a finding at or above this severity exists",
    )
    parser.add_argument(
        "--version", action="version", version="tripwire %s" % __version__
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    inventory = collect(
        config_dir=args.config_dir,
        project_dir=args.project,
        user_json=args.user_json,
    )

    if inventory.is_empty:
        sys.stderr.write(
            "No agent configuration found. Looked in %s. Use --config-dir to "
            "point somewhere else.\n" % (", ".join(inventory.roots) or "~/.claude")
        )
        return 2

    findings = run_all(inventory)

    if args.update_baseline:
        stored = write_baseline(args.update_baseline, findings, __version__)
        sys.stderr.write(
            "recorded %d finding(s) as accepted in %s. The next run reports "
            "anything absent from this file as new.\n" % (stored, args.update_baseline)
        )
        return 0

    suppressed = []
    if not args.no_ignore:
        try:
            ignores = load_ignores(args.ignore_file)
        except BaselineError as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        findings, suppressed = apply_ignores(findings, ignores)

    new_findings, known, resolved = [], [], []
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 2
        if not baseline:
            sys.stderr.write(
                "note: %s does not exist yet. Create it with --update-baseline "
                "once you have reviewed the current findings.\n" % args.baseline
            )
        else:
            new_findings, known, resolved = diff_against_baseline(findings, baseline)
            if args.new_only:
                findings = new_findings

    if args.format == "json":
        sys.stdout.write(
            render_json(
                inventory,
                findings,
                __version__,
                suppressed=suppressed,
                new_keys=list(new_findings),
            )
            + "\n"
        )
    else:
        sys.stdout.write(
            render_text(
                inventory,
                findings,
                show_info=args.info,
                suppressed=suppressed,
                new_findings=new_findings if args.baseline else None,
                resolved=resolved,
            )
            + "\n"
        )

    if args.fail_on != "never":
        threshold = SEVERITIES.index(args.fail_on)
        # With a baseline, only *new* findings should break a build. Failing on
        # known ones means the build stays red until every historical finding
        # is resolved, which is how a security gate gets disabled.
        gated = new_findings if (args.baseline and known) else findings
        if any(f.rank <= threshold for f in gated):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
