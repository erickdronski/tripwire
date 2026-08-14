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
    parser.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES + ("never",),
        default="never",
        help="exit 1 when a finding at or above this severity exists",
    )
    parser.add_argument("--version", action="version", version="tripwire %s" % __version__)
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

    if args.format == "json":
        sys.stdout.write(render_json(inventory, findings, __version__) + "\n")
    else:
        sys.stdout.write(
            render_text(inventory, findings, show_info=args.info) + "\n"
        )

    if args.fail_on != "never":
        threshold = SEVERITIES.index(args.fail_on)
        if any(f.rank <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
