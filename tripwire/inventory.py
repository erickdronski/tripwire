"""Finding everything an agent on this machine is currently able to do.

The premise: you cannot reason about an agent's blast radius until you can see
it. Skills, MCP servers, hooks, and permission settings accumulate across
months from marketplaces, plugin installs, per-project config, and one-off
experiments — and no surface anywhere shows you the union of them.

This module builds that union across the agents a machine is likely to
have: Claude Code, Claude Desktop, Cursor, and Codex. It is read-only and
offline: it opens files under their config directories and nothing else. No
package is installed, no server is started, no network call is made, and
nothing is executed — which matters, because half of what it inspects is
designed to run commands.

Four kinds of thing are inventoried:

``Skill``
    A ``SKILL.md`` with frontmatter. Its body is instructions the model will
    follow; its ``scripts/`` are code an agent may run.
``Server``
    An MCP server. Its command line is a process that gets launched, and its
    environment often carries credentials.
``Hook``
    A shell command the harness runs automatically on an event. The highest-
    privilege thing in the config, and the least visible.
``Setting``
    Permission configuration — allow-lists, deny-lists, and the flags that
    switch approval off entirely.

The inventory is of what the agent *loads*, not of every file on disk. A
plugin directory holds deleted plugins (``.trash``), marketplace catalogs
that were browsed but never installed, and superseded copies of synced
plugins. Counting those inflated a real machine's skill count by roughly a
third and reported each finding once per copy — so they are skipped here,
and the number skipped is reported rather than hidden.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .redact import redact
from .tomlparse import TomlError
from .tomlparse import loads as toml_loads

__all__ = [
    "Hook",
    "Inventory",
    "InventoryError",
    "Server",
    "SettingsFile",
    "Skill",
    "collect",
]


class InventoryError(RuntimeError):
    """Raised when a config location cannot be read at all."""


#: Claude Code's default locations. Every default — these and the other
#: agents' — is resolved under the home directory, or under ``--home``.
#: Project-local files are added at scan time from the working directory.
USER_CONFIG_DIR = "~/.claude"
USER_JSON = "~/.claude.json"

PROJECT_CONFIG_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
)

#: Claude Desktop keeps its config in the platform's application-data
#: directory. All three are checked relative to the home directory, so a
#: fixture home works on any platform; the environment variables that move
#: them are honoured when auditing the real home.
DESKTOP_CONFIG_PATHS = (
    "Library/Application Support/Claude/claude_desktop_config.json",  # macOS
    ".config/Claude/claude_desktop_config.json",  # Linux
    "AppData/Roaming/Claude/claude_desktop_config.json",  # Windows
)

#: Agent identifiers, as they appear in JSON output, and as they are shown.
AGENTS = {
    "claude-code": "Claude Code",
    "claude-desktop": "Claude Desktop",
    "cursor": "Cursor",
    "codex": "Codex",
}

#: Cap for skill text. Anything longer is not a skill anyone wrote by hand.
MAX_READ_BYTES = 400_000
#: Cap for JSON and TOML config. `~/.claude.json` grows with every project
#: opened, and truncating it would make its servers silently disappear.
MAX_CONFIG_BYTES = 16_000_000


class Skill:
    __slots__ = (
        "body",
        "description",
        "frontmatter",
        "name",
        "path",
        "scripts",
        "source",
    )

    def __init__(
        self,
        name: str,
        path: str,
        source: str,
        description: str,
        body: str,
        scripts: Sequence[str],
        frontmatter: Dict[str, str],
    ) -> None:
        self.name = name
        self.path = path
        self.source = source
        self.description = description
        self.body = body
        self.scripts = list(scripts)
        self.frontmatter = frontmatter

    @property
    def text(self) -> str:
        """Everything the model will read: description plus body."""
        return (self.description or "") + "\n" + (self.body or "")

    @property
    def digest(self) -> str:
        """Content identity, so two copies of one skill are known to be one."""
        basis = "\0".join([self.name, self.text, *self.scripts])
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "source": self.source,
            "description": self.description,
            "scripts": self.scripts,
        }


class Server:
    __slots__ = (
        "agent",
        "args",
        "command",
        "command_line",
        "env",
        "headers",
        "name",
        "scope",
        "secret_on_command_line",
        "source",
        "url",
    )

    def __init__(
        self,
        name: str,
        source: str,
        command: Optional[str],
        args: Sequence[str],
        env: Dict[str, str],
        url: Optional[str],
        scope: str = "user",
        agent: str = "claude-code",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.name = name
        self.source = source
        self.scope = scope
        self.agent = agent
        # The command line and URL are redacted at capture, like hook
        # commands: they reach the report through finding evidence and the
        # inventory dump. Whether redaction changed anything is kept, because
        # a token pasted into `args` is itself a plaintext credential.
        parts = [command or "", *args]
        raw_line = url or " ".join(part for part in parts if part).strip()
        self.command_line = redact(raw_line)
        self.secret_on_command_line = self.command_line != raw_line
        self.command = redact(command) if command else command
        self.args = [redact(arg) for arg in args]
        self.url = redact(url) if url else url
        # Values are kept for the literal-credential check and never emitted:
        # `to_dict` lists names only.
        self.env = dict(env)
        self.headers = dict(headers or {})

    @property
    def label(self) -> str:
        """Which agent loads this server, and from where."""
        scope = self.scope
        if scope.startswith("plugin:"):
            scope = "plugin %s" % scope[len("plugin:") :]
        else:
            scope = "%s scope" % scope
        return "%s, %s" % (AGENTS.get(self.agent, self.agent), scope)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "agent": self.agent,
            "source": self.source,
            "scope": self.scope,
            "command_line": self.command_line,
            "env_keys": sorted(self.env),
            "header_keys": sorted(self.headers),
        }


class Hook:
    __slots__ = (
        "agent",
        "command",
        "event",
        "kind",
        "matcher",
        "scope",
        "source",
        "timeout",
    )

    def __init__(
        self,
        event: str,
        matcher: Optional[str],
        command: str,
        source: str,
        timeout: Optional[int] = None,
        kind: str = "command",
        agent: str = "claude-code",
        scope: str = "user",
    ) -> None:
        self.agent = agent
        self.scope = scope
        self.event = event
        self.matcher = matcher
        # Redact at capture, not at render. A hook command reaches the report
        # through two paths — finding evidence and the inventory dump — and
        # securing one while missing the other is how leaks ship.
        self.command = redact(command)
        self.source = source
        self.timeout = timeout
        self.kind = kind

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "scope": self.scope,
            "event": self.event,
            "matcher": self.matcher,
            "command": self.command,
            "source": self.source,
            "kind": self.kind,
        }


class SettingsFile:
    """Permission configuration.

    ``kind`` is ``settings`` for a config file the user edits, and
    ``app-state`` for permissions an app stores on the user's behalf — the
    Codex app keeps its permission mode there, not in ``config.toml``.
    """

    __slots__ = ("agent", "data", "kind", "path", "scope")

    def __init__(
        self,
        path: str,
        data: Dict[str, Any],
        scope: str,
        agent: str = "claude-code",
        kind: str = "settings",
    ) -> None:
        self.path = path
        self.data = data
        self.scope = scope
        self.agent = agent
        self.kind = kind

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "scope": self.scope,
            "agent": self.agent,
            "kind": self.kind,
        }


class Inventory:
    def __init__(self) -> None:
        self.skills: List[Skill] = []
        self.servers: List[Server] = []
        self.hooks: List[Hook] = []
        self.settings: List[SettingsFile] = []
        self.unreadable: List[str] = []
        self.roots: List[str] = []
        #: Skill files present on disk but not loaded by the agent, by reason.
        self.skipped: Dict[str, int] = {}
        #: Things the reader should know about the scan itself — a config
        #: that could not be parsed, a layout that could not be interpreted.
        self.notes: List[str] = []
        #: Agents whose configuration was found on this machine.
        self.agents: Set[str] = set()
        #: MCP servers configured but switched off (`disabled` / `enabled`).
        self.servers_disabled = 0
        self._seen_files: Set[str] = set()

    def skip(self, reason: str, count: int) -> None:
        if count:
            self.skipped[reason] = self.skipped.get(reason, 0) + count

    @property
    def is_empty(self) -> bool:
        return not (self.skills or self.servers or self.hooks or self.settings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agents": sorted(self.agents),
            "roots": self.roots,
            "skills": [s.to_dict() for s in self.skills],
            "servers": [s.to_dict() for s in self.servers],
            "hooks": [h.to_dict() for h in self.hooks],
            "settings": [s.to_dict() for s in self.settings],
            "unreadable": self.unreadable,
            "skipped": dict(sorted(self.skipped.items())),
            "notes": self.notes,
        }


# -- collection -----------------------------------------------------------


def collect(
    config_dir: Optional[str] = None,
    project_dir: Optional[str] = None,
    user_json: Optional[str] = None,
    home: Optional[str] = None,
) -> Inventory:
    """Build the inventory. Never raises for a missing location.

    With no arguments every agent's default location under the real home
    directory is read. ``home`` moves all of those defaults under another
    directory. Naming ``config_dir`` or ``user_json`` without ``home`` audits
    just that Claude Code config — the other agents are skipped, and a note
    in the report says so.
    """
    inventory = Inventory()
    targeted = home is None and (config_dir is not None or user_json is not None)
    home_dir = os.path.expanduser(home or "~")

    base = (
        os.path.expanduser(config_dir)
        if config_dir
        else os.path.join(home_dir, ".claude")
    )
    user_config = (
        os.path.expanduser(user_json)
        if user_json
        else os.path.join(home_dir, ".claude.json")
    )
    project = os.path.abspath(os.path.expanduser(project_dir)) if project_dir else None

    # Settings come first: `enabledPlugins` decides which plugins are loaded.
    if os.path.isdir(base):
        inventory.roots.append(base)
        inventory.agents.add("claude-code")
        _collect_settings(inventory, os.path.join(base, "settings.json"), "user")

    if project:
        for relative in PROJECT_CONFIG_FILES:
            path = os.path.join(project, relative)
            if not os.path.isfile(path):
                continue
            inventory.roots.append(path)
            inventory.agents.add("claude-code")
            if relative.endswith(".mcp.json"):
                _collect_mcp_file(inventory, path, scope="project")
            else:
                _collect_settings(inventory, path, "project")

    if os.path.isdir(base):
        _collect_user_skills(inventory, base)
        _collect_plugins(inventory, base, _enabled_plugins(inventory))

    if os.path.isfile(user_config):
        inventory.roots.append(user_config)
        inventory.agents.add("claude-code")
        _collect_user_json(inventory, user_config)

    if project:
        # Only `.claude/skills` is loaded. Walking all of `.claude` would also
        # read worktree checkouts and anything else a tool parked there.
        project_skills = os.path.join(project, ".claude", "skills")
        if os.path.isdir(project_skills):
            _collect_skills(inventory, project_skills, source="project")
        cursor = os.path.join(project, ".cursor", "mcp.json")
        if os.path.isfile(cursor):
            _collect_agent_mcp_file(inventory, cursor, "cursor", "project")

    if targeted:
        inventory.notes.append(
            "Only the Claude Code config named on the command line was read. "
            "Pass --home to also audit Claude Desktop, Cursor, and Codex."
        )
        return inventory

    real_home = home is None
    for path in _desktop_config_paths(home_dir, real_home):
        _collect_agent_mcp_file(inventory, path, "claude-desktop", "user")
    cursor = os.path.join(home_dir, ".cursor", "mcp.json")
    if os.path.isfile(cursor):
        _collect_agent_mcp_file(inventory, cursor, "cursor", "user")
    codex_home = os.environ.get("CODEX_HOME") if real_home else None
    _collect_codex(inventory, codex_home or os.path.join(home_dir, ".codex"))
    return inventory


def _read(
    path: str, inventory: Inventory, limit: int = MAX_READ_BYTES
) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(limit)
        return raw.decode("utf-8", errors="replace")
    except OSError:
        inventory.unreadable.append(path)
        return None


def _read_json(path: str, inventory: Inventory) -> Optional[Dict[str, Any]]:
    text = _read(path, inventory, MAX_CONFIG_BYTES)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Fail open, visibly: one malformed file degrades its own section of
        # the report and says so, rather than aborting the run.
        inventory.unreadable.append(path)
        inventory.notes.append("Could not parse %s (%s)." % (path, exc))
        return None
    return data if isinstance(data, dict) else None


def _read_toml(path: str, inventory: Inventory) -> Optional[Dict[str, Any]]:
    text = _read(path, inventory, MAX_CONFIG_BYTES)
    if text is None:
        return None
    try:
        return toml_loads(text)
    except TomlError as exc:
        inventory.unreadable.append(path)
        inventory.notes.append(
            "Could not parse %s (%s); its servers and settings are not in this "
            "report." % (path, exc)
        )
        return None


#: Never descended into while looking for skills: dependency trees, and every
#: hidden directory — `.trash` holds deleted plugins, `.staging` a sync in
#: progress, `.git` history, and `.cursor` / `.codex-plugin` other harnesses'
#: copies of the same skills.
_PRUNED_DIRS = ("node_modules", "__pycache__")


def _prune(dirnames: List[str]) -> List[str]:
    return sorted(
        d for d in dirnames if not d.startswith(".") and d not in _PRUNED_DIRS
    )


def _skill_files(inventory: Inventory, base: str) -> Iterator[str]:
    """Every loadable SKILL.md under ``base``, in a stable order.

    Skills inside pruned hidden directories are counted as skipped, so a
    plugin that also ships a `.cursor/skills` copy for another editor shows up
    as an explained difference rather than a silent one.
    """
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames:
            if name.startswith(".") and name != ".git":
                reason = "deleted" if name == ".trash" else "in hidden directories"
                inventory.skip(reason, _count_skill_files(os.path.join(dirpath, name)))
        dirnames[:] = _prune(dirnames)
        if "SKILL.md" in filenames:
            yield os.path.join(dirpath, "SKILL.md")


def _count_skill_files(base: str, exclude: Sequence[str] = ()) -> int:
    """How many skills sit under ``base`` — used only to report what was skipped."""
    excluded = tuple(_real(path) for path in exclude)
    count = 0
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _PRUNED_DIRS]
        # `str.startswith(())` is False, so an empty exclusion list excludes nothing.
        if "SKILL.md" in filenames and not _real(dirpath).startswith(excluded):
            count += 1
    return count


def _real(path: str) -> str:
    return os.path.join(os.path.realpath(path), "")


def _collect_skills(
    inventory: Inventory, base: str, source: Optional[str] = None
) -> None:
    for path in _skill_files(inventory, base):
        # One physical file reached by two routes — a symlink, or an install
        # path inside a directory that is also walked — is one skill.
        real = os.path.realpath(path)
        if real in inventory._seen_files:
            continue
        inventory._seen_files.add(real)
        text = _read(path, inventory)
        if text is None:
            continue
        dirpath = os.path.dirname(path)
        frontmatter, body = _split_frontmatter(text)
        name = frontmatter.get("name") or os.path.basename(dirpath)
        scripts = _find_scripts(dirpath)
        inventory.skills.append(
            Skill(
                name=name,
                path=path,
                source=source or _classify_skill_source(path),
                description=frontmatter.get("description", ""),
                body=body,
                scripts=scripts,
                frontmatter=frontmatter,
            )
        )


def _collect_user_skills(inventory: Inventory, base: str) -> None:
    """Skills in ``skills/``, plus scheduled-task prompts.

    Each top-level entry is walked on its own, because a skill directory is
    often a symlink to where its author keeps it — Claude Code follows that
    link, and ``os.walk`` does not.
    """
    skills = os.path.join(base, "skills")
    if os.path.isdir(skills):
        for entry in sorted(os.listdir(skills)):
            path = os.path.join(skills, entry)
            if entry == ".trash":
                inventory.skip("deleted", _count_skill_files(path))
            elif entry.startswith(".") or not os.path.isdir(path):
                continue
            elif entry == "synced":
                # Synced from an account rather than written on this machine.
                _collect_skills(inventory, path, source="synced")
            else:
                _collect_skills(inventory, path, source="user")

    # Scheduled tasks are prompts the desktop app runs on a timer — text the
    # model follows with nobody watching, so it is scanned like a skill.
    tasks = os.path.join(base, "scheduled-tasks")
    if os.path.isdir(tasks):
        _collect_skills(inventory, tasks, source="scheduled-task")


# -- plugins ---------------------------------------------------------------
#
# Claude Code's plugin directory holds far more than it loads:
#
#   plugins/installed_plugins.json      the registry: what is installed, where
#   plugins/cache/<mkt>/<plugin>/<ver>  installed copies (registry install paths)
#   plugins/marketplaces/<mkt>/         catalog checkouts — browsable, not loaded
#   plugins/synced/<session>/<plugin>   plugins synced from an account, one
#                                       directory per generation (`name~g4`)
#   plugins/.trash/                     deleted plugins awaiting cleanup
#
# Only registry install paths and the live generation of each synced plugin
# are loaded. When there is no registry at all — an older layout, or a
# hand-built directory — everything present is assumed loaded, because for an
# audit over-reporting is the safe direction.


def _enabled_plugins(inventory: Inventory) -> Dict[str, bool]:
    """`enabledPlugins` merged across settings files, later scopes winning."""
    merged: Dict[str, bool] = {}
    for settings in inventory.settings:
        enabled = settings.data.get("enabledPlugins")
        if isinstance(enabled, dict):
            for key, value in enabled.items():
                if isinstance(value, bool):
                    merged[str(key)] = value
    return merged


def _collect_plugins(inventory: Inventory, base: str, enabled: Dict[str, bool]) -> None:
    plugins = os.path.join(base, "plugins")
    if not os.path.isdir(plugins):
        return

    cache = os.path.join(plugins, "cache")
    marketplaces = os.path.join(plugins, "marketplaces")
    registered: List[str] = []
    roots = _installed_plugin_roots(inventory, plugins, enabled, registered)
    if roots is None:
        roots = []
        legacy = [d for d in (cache, marketplaces) if os.path.isdir(d)]
    else:
        legacy = []
        for directory in (cache, marketplaces):
            if os.path.isdir(directory):
                inventory.skip(
                    "not installed", _count_skill_files(directory, exclude=registered)
                )

    roots.extend(_synced_plugin_roots(inventory, os.path.join(plugins, "synced")))

    trash = os.path.join(plugins, ".trash")
    if os.path.isdir(trash):
        inventory.skip("deleted", _count_skill_files(trash))

    for directory in legacy:
        roots.extend(_find_plugin_roots(directory))
    for root, name in roots:
        _collect_plugin_root(inventory, root, name)
    # Without a registry, skills outside any recognisable plugin still count.
    for directory in legacy:
        _collect_skills(inventory, directory)


def _installed_plugin_roots(
    inventory: Inventory,
    plugins: str,
    enabled: Dict[str, bool],
    registered: List[str],
) -> Optional[List[Tuple[str, str]]]:
    """Install paths of enabled plugins, or None when there is no registry.

    Every install path the registry names, enabled or not, is appended to
    ``registered`` so a disabled plugin is counted once, as disabled.
    """
    path = os.path.join(plugins, "installed_plugins.json")
    if not os.path.isfile(path):
        return None
    data = _read_json(path, inventory)
    if data is None:
        inventory.notes.append(
            "Could not parse %s, so every plugin on disk is treated as installed."
            % path
        )
        return None

    registry = data.get("plugins", data)
    roots: List[Tuple[str, str]] = []
    for key, entries in registry.items() if isinstance(registry, dict) else []:
        # Version 1 stored one entry per plugin; version 2 stores a list.
        for entry in entries if isinstance(entries, list) else [entries]:
            install = entry.get("installPath") if isinstance(entry, dict) else None
            if not isinstance(install, str):
                continue
            install = os.path.expanduser(install)
            if not os.path.isabs(install):
                install = os.path.join(plugins, install)
            if not os.path.isdir(install):
                continue
            registered.append(install)
            if enabled.get(str(key)) is False:
                inventory.skip("disabled", _count_skill_files(install))
                continue
            roots.append((install, str(key).split("@", 1)[0]))
    return roots


_GENERATION_RE = re.compile(r"~g\d+$")


def _synced_plugin_roots(inventory: Inventory, synced: str) -> List[Tuple[str, str]]:
    """The live generation of each plugin synced from an account.

    A sync writes a new directory per generation (`canva`, then `canva~g2`)
    and moves superseded ones to `.trash` later, so for a while both exist.
    The session's `manifest.json` names the live generation; a sibling
    `<dir>.meta.json` marks it too. Without either, every directory counts.
    """
    roots: List[Tuple[str, str]] = []
    if not os.path.isdir(synced):
        return roots
    for session in sorted(os.listdir(synced)):
        directory = os.path.join(synced, session)
        if session.startswith(".") or not os.path.isdir(directory):
            continue
        live = _live_synced_dirs(inventory, directory)
        for entry in sorted(os.listdir(directory)):
            path = os.path.join(directory, entry)
            if entry.startswith(".") or not os.path.isdir(path):
                continue
            if live is not None and entry not in live:
                inventory.skip("superseded", _count_skill_files(path))
                continue
            name = (live or {}).get(entry) or _GENERATION_RE.sub("", entry)
            roots.append((path, name))
    return roots


def _live_synced_dirs(inventory: Inventory, directory: str) -> Optional[Dict[str, str]]:
    """Directory name -> plugin name for live generations, or None if unknown."""
    present = set(os.listdir(directory))
    live: Dict[str, str] = {}
    unresolved = False

    manifest = os.path.join(directory, "manifest.json")
    if os.path.isfile(manifest):
        data = _read_json(manifest, inventory) or {}
        for plugin in data.get("plugins") or []:
            if not isinstance(plugin, dict) or not isinstance(plugin.get("name"), str):
                continue
            name, generation = plugin["name"], plugin.get("generation")
            candidates = (["%s~g%s" % (name, generation)] if generation else []) + [
                name
            ]
            found = next((c for c in candidates if c in present), None)
            if found is None:
                unresolved = True
            else:
                live[found] = name
    else:
        unresolved = True

    if unresolved:
        for filename in present:
            if filename.endswith(".meta.json"):
                entry = filename[: -len(".meta.json")]
                live.setdefault(entry, _GENERATION_RE.sub("", entry))
    return live or None


def _collect_plugin_root(inventory: Inventory, root: str, name: str) -> None:
    """Everything one loaded plugin contributes: skills, MCP servers, hooks.

    Servers come from ``.mcp.json`` at the plugin root and hooks from
    ``hooks/hooks.json``; the manifest can add more of either, inline or as
    paths. Both locations are read and de-duplicated, since a manifest that
    points at the default file must not count its servers twice.
    """
    manifest_path = os.path.join(root, ".claude-plugin", "plugin.json")
    manifest: Dict[str, Any] = {}
    if os.path.isfile(manifest_path):
        manifest = _read_json(manifest_path, inventory) or {}
        if isinstance(manifest.get("name"), str) and manifest["name"]:
            name = manifest["name"]
    scope = "plugin:%s" % name
    _collect_skills(inventory, root, source=scope)

    declared = manifest.get("mcpServers")
    if isinstance(declared, dict):
        _absorb_servers(inventory, declared, manifest_path, scope)
    for path in _plugin_files(root, ".mcp.json", declared):
        _collect_mcp_file(inventory, path, scope)

    declared = manifest.get("hooks")
    if isinstance(declared, dict):
        inline = declared if "hooks" in declared else {"hooks": declared}
        _collect_hooks(inventory, inline, manifest_path, scope=scope)
    for path in _plugin_files(root, os.path.join("hooks", "hooks.json"), declared):
        data = _read_json(path, inventory)
        if data is not None:
            _collect_hooks(inventory, data, path, scope=scope)


def _plugin_files(root: str, default: str, declared: Any) -> List[str]:
    """The default file plus any the manifest names, existing and unique."""
    candidates = [default]
    if isinstance(declared, str):
        candidates.append(declared)
    elif isinstance(declared, list):
        candidates.extend(item for item in declared if isinstance(item, str))
    out: List[str] = []
    seen: Set[str] = set()
    for candidate in candidates:
        path = os.path.normpath(os.path.join(root, candidate))
        real = os.path.realpath(path)
        if real not in seen and os.path.isfile(path):
            seen.add(real)
            out.append(path)
    return out


def _find_plugin_roots(directory: str, depth: int = 4) -> List[Tuple[str, str]]:
    """Directories with a plugin manifest, for layouts without a registry."""
    roots: List[Tuple[str, str]] = []
    for dirpath, dirnames, _filenames in os.walk(directory):
        if os.path.isfile(os.path.join(dirpath, ".claude-plugin", "plugin.json")):
            roots.append((dirpath, os.path.basename(dirpath)))
            dirnames[:] = []
            continue
        if dirpath[len(directory) :].count(os.sep) >= depth:
            dirnames[:] = []
        else:
            dirnames[:] = _prune(dirnames)
    return roots


def _posix(path: str) -> str:
    """Normalize a filesystem path to forward slashes.

    Every classification and comparison below is written against forward
    slashes. On Windows `os.walk` yields backslashes, which silently broke
    source classification: `"/plugins/marketplaces/" in path` was never true,
    so third-party skills were labelled as locally authored and given the
    trust discount that downgrades their findings. A security tool quietly
    under-reporting on one platform is the worst kind of portability bug, so
    normalization happens once, here, at the boundary.
    """
    return path.replace(os.sep, "/").replace("\\", "/")


def _classify_skill_source(path: str) -> str:
    normalized = _posix(path)
    if "/plugins/marketplaces/" in normalized:
        parts = normalized.split("/plugins/marketplaces/", 1)[1].split("/")
        return "marketplace:%s" % (parts[0] if parts else "unknown")
    # cache/<marketplace>/<plugin>/...  and  synced/<session>/<plugin>/...
    for marker in ("/plugins/cache/", "/plugins/synced/"):
        if marker in normalized:
            parts = normalized.split(marker, 1)[1].split("/")
            if len(parts) > 2:
                return "plugin:%s" % _GENERATION_RE.sub("", parts[1])
    if "/plugins/" in normalized:
        return "plugin"
    if "/skills/synced/" in normalized:
        return "synced"
    if "/scheduled-tasks/" in normalized:
        return "scheduled-task"
    return "user"


#: Extensions that make a bundled file executable code regardless of platform.
_SCRIPT_EXTENSIONS = (
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".mjs",
    ".rb",
    ".pl",
    ".ps1",
)

#: Documentation and data that ship alongside a skill. These are never
#: "executable code" no matter what the filesystem claims about them.
_NEVER_A_SCRIPT = (".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv")

#: The executable bit only means something on POSIX. On Windows
#: ``os.access(path, os.X_OK)`` is true for *every* existing file, so trusting
#: it there reported each skill's own SKILL.md as bundled executable code — a
#: false positive on every skill, on one platform, in the exact tool whose
#: whole design premise is not crying wolf.
_EXECUTABLE_BIT_IS_MEANINGFUL = os.name != "nt"


def _find_scripts(directory: str) -> List[str]:
    """Executable or script-extension files bundled with a skill."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            lowered = filename.lower()
            if lowered.endswith(_NEVER_A_SCRIPT):
                continue
            if lowered.endswith(_SCRIPT_EXTENSIONS):
                out.append(_posix(os.path.relpath(full, directory)))
                continue
            if not _EXECUTABLE_BIT_IS_MEANINGFUL:
                continue
            try:
                if os.access(full, os.X_OK) and not os.path.isdir(full):
                    out.append(_posix(os.path.relpath(full, directory)))
            except OSError:
                continue
    return sorted(set(out))


def _split_frontmatter(text: str):
    """Parse flat YAML frontmatter without requiring PyYAML."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, text

    data: Dict[str, str] = {}
    key: Optional[str] = None
    for raw in lines[1:end]:
        if not raw.strip():
            continue
        if raw.startswith((" ", "\t")) and key:
            data[key] = (data[key] + " " + raw.strip()).strip()
            continue
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        data[key] = value.strip()
    return data, "\n".join(lines[end + 1 :])


def _collect_settings(inventory: Inventory, path: str, scope: str) -> None:
    if not os.path.isfile(path):
        return
    data = _read_json(path, inventory)
    if data is None:
        return
    inventory.settings.append(SettingsFile(path=path, data=data, scope=scope))
    _collect_hooks(inventory, data, path, scope=scope)

    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, scope)


def _collect_hooks(
    inventory: Inventory,
    data: Dict[str, Any],
    source: str,
    scope: str = "user",
    agent: str = "claude-code",
) -> None:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("matcher")
            inner = entry.get("hooks")
            if not isinstance(inner, list):
                continue
            for definition in inner:
                if not isinstance(definition, dict):
                    continue
                command = definition.get("command")
                if not isinstance(command, str) or not command.strip():
                    continue
                timeout = definition.get("timeout")
                inventory.hooks.append(
                    Hook(
                        event=str(event),
                        matcher=str(matcher) if matcher is not None else None,
                        command=command,
                        source=source,
                        timeout=timeout if isinstance(timeout, int) else None,
                        kind=str(definition.get("type") or "command"),
                        agent=agent,
                        scope=scope,
                    )
                )


def _collect_user_json(inventory: Inventory, path: str) -> None:
    data = _read_json(path, inventory)
    if data is None:
        return
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, "user")

    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, config in projects.items():
            if not isinstance(config, dict):
                continue
            project_servers = config.get("mcpServers")
            if isinstance(project_servers, dict):
                _absorb_servers(
                    inventory,
                    project_servers,
                    "%s (%s)" % (path, project_path),
                    "project",
                )


def _collect_mcp_file(inventory: Inventory, path: str, scope: str) -> None:
    """A Claude Code ``.mcp.json``: servers under ``mcpServers``, or at the top."""
    data = _read_json(path, inventory)
    if data is None:
        return
    servers = data.get("mcpServers", data)
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, scope)


def _collect_agent_mcp_file(
    inventory: Inventory, path: str, agent: str, scope: str
) -> None:
    """Claude Desktop and Cursor: servers only ever under ``mcpServers``.

    Strict on purpose. Claude Desktop's file also holds preferences, and
    reading the top level as servers would invent one called `preferences`.
    """
    inventory.roots.append(path)
    inventory.agents.add(agent)
    data = _read_json(path, inventory)
    servers = data.get("mcpServers") if data else None
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, scope, agent=agent)


def _desktop_config_paths(home: str, real_home: bool) -> List[str]:
    candidates = [
        os.path.join(home, *relative.split("/")) for relative in DESKTOP_CONFIG_PATHS
    ]
    if real_home:
        for variable, relative in (
            ("APPDATA", "Claude"),
            ("XDG_CONFIG_HOME", "Claude"),
        ):
            value = os.environ.get(variable)
            if value:
                candidates.append(
                    os.path.join(value, relative, "claude_desktop_config.json")
                )
    out: List[str] = []
    seen: Set[str] = set()
    for path in candidates:
        real = os.path.realpath(path)
        if real not in seen and os.path.isfile(path):
            seen.add(real)
            out.append(path)
    return out


# -- Codex -------------------------------------------------------------------


def _collect_codex(inventory: Inventory, codex_dir: str) -> None:
    """``~/.codex/config.toml``, and the Codex app's stored permissions.

    ``config.toml`` holds MCP servers, the approval and sandbox settings, and
    ``notify`` — a program Codex runs after every agent turn, a hook in all
    but name, so it is inventoried as one and gets the same checks.
    """
    _collect_codex_app_state(inventory, codex_dir)
    config = os.path.join(codex_dir, "config.toml")
    if not os.path.isfile(config):
        return
    inventory.roots.append(config)
    inventory.agents.add("codex")
    data = _read_toml(config, inventory)
    if data is None:
        return
    inventory.settings.append(
        SettingsFile(path=config, data=data, scope="user", agent="codex")
    )
    servers = data.get("mcp_servers")
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, config, "user", agent="codex")
    notify = data.get("notify")
    if isinstance(notify, list) and notify and all(isinstance(p, str) for p in notify):
        inventory.hooks.append(
            Hook(
                event="notify",
                matcher=None,
                command=" ".join(shlex.quote(part) for part in notify),
                source=config,
                agent="codex",
            )
        )


#: Where the Codex desktop app persists UI state, including the permission
#: mode chosen for this machine and the saved permissions of the threads its
#: scheduled automations run in. An internal format, so everything below is
#: defensive: anything unrecognised is simply not reported.
_CODEX_APP_STATE = ".codex-global-state.json"
_CODEX_ATOMS = "electron-persisted-atom-state"
_CODEX_LOCAL_MODE = "permission-selection-by-host-id:local"
_CODEX_THREAD_PERMISSIONS = "heartbeat-thread-permissions-by-id"


def _collect_codex_app_state(inventory: Inventory, codex_dir: str) -> None:
    path = os.path.join(codex_dir, _CODEX_APP_STATE)
    if not os.path.isfile(path):
        return
    inventory.agents.add("codex")
    data = _read_json(path, inventory)
    atoms = data.get(_CODEX_ATOMS) if data else None
    if not isinstance(atoms, dict):
        return

    state: Dict[str, Any] = {}
    selection = atoms.get(_CODEX_LOCAL_MODE)
    if isinstance(selection, dict) and isinstance(selection.get("agentMode"), str):
        state["agent_mode"] = selection["agentMode"]

    threads = atoms.get(_CODEX_THREAD_PERMISSIONS)
    full_access = set()
    if isinstance(threads, dict):
        for thread, permissions in threads.items():
            if not isinstance(permissions, dict):
                continue
            sandbox = permissions.get("sandboxPolicy")
            if isinstance(sandbox, dict):
                sandbox = sandbox.get("type")
            if permissions.get("approvalPolicy") == "never" and sandbox in (
                "dangerFullAccess",
                "danger-full-access",
            ):
                full_access.add(thread)

    automations = []
    for automation in _codex_automations(inventory, codex_dir):
        automation["full_access"] = automation.get("thread") in full_access
        automations.append(automation)
    if automations:
        state["automations"] = automations

    if state:
        inventory.settings.append(
            SettingsFile(path, state, "user", agent="codex", kind="app-state")
        )


def _codex_automations(inventory: Inventory, codex_dir: str) -> List[Dict[str, Any]]:
    """Scheduled Codex automations: name, status, and the thread they run in."""
    directory = os.path.join(codex_dir, "automations")
    if not os.path.isdir(directory):
        return []
    out = []
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry, "automation.toml")
        if not os.path.isfile(path):
            continue
        data = _read_toml(path, inventory)
        if not data or not isinstance(data.get("target_thread_id"), str):
            continue
        out.append(
            {
                "path": path,
                "name": str(data.get("name") or entry),
                "status": str(data.get("status") or "unknown"),
                "thread": data["target_thread_id"],
            }
        )
    return out


def _absorb_servers(
    inventory: Inventory,
    servers: Dict[str, Any],
    source: str,
    scope: str,
    agent: str = "claude-code",
) -> None:
    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        command, url = config.get("command"), config.get("url")
        # A flat `.mcp.json` puts servers at the top level next to anything
        # else; an entry that neither launches nor connects is not a server.
        if not isinstance(command, str) and not isinstance(url, str):
            continue
        if config.get("disabled") is True or config.get("enabled") is False:
            inventory.servers_disabled += 1
            continue
        env = config.get("env")
        # `headers` (Claude Code, Cursor) and `http_headers` (Codex) carry
        # static request headers — the usual home of a pasted API key.
        headers: Dict[str, str] = {}
        for key in ("headers", "http_headers"):
            value = config.get(key)
            if isinstance(value, dict):
                headers.update({str(k): str(v) for k, v in value.items()})
        if isinstance(config.get("bearer_token"), str):
            headers["Authorization"] = "Bearer %s" % config["bearer_token"]
        args = config.get("args")
        inventory.servers.append(
            Server(
                name=str(name),
                source=source,
                command=command if isinstance(command, str) else None,
                args=[str(a) for a in args] if isinstance(args, list) else [],
                env={
                    str(k): str(v)
                    for k, v in (env.items() if isinstance(env, dict) else [])
                },
                url=url if isinstance(url, str) else None,
                scope=scope,
                agent=agent,
                headers=headers,
            )
        )
