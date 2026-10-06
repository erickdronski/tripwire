"""Finding everything an agent on this machine is currently able to do.

The premise: you cannot reason about an agent's blast radius until you can see
it. Skills, MCP servers, hooks, and permission settings accumulate across
months from marketplaces, plugin installs, per-project config, and one-off
experiments — and no surface anywhere shows you the union of them.

This module builds that union. It is read-only and offline: it opens files
under the config directories and nothing else. No package is installed, no
server is started, no network call is made, and nothing is executed — which
matters, because half of what it inspects is designed to run commands.

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
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .redact import redact

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


#: Config locations, in the order they are searched. Project-local files are
#: added at scan time from the working directory.
USER_CONFIG_DIR = "~/.claude"
USER_JSON = "~/.claude.json"

PROJECT_CONFIG_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
)

MAX_READ_BYTES = 400_000


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
    __slots__ = ("args", "command", "env", "name", "raw", "scope", "source", "url")

    def __init__(
        self,
        name: str,
        source: str,
        command: Optional[str],
        args: Sequence[str],
        env: Dict[str, str],
        url: Optional[str],
        raw: Dict[str, Any],
        scope: str = "user",
    ) -> None:
        self.name = name
        self.source = source
        self.command = command
        self.args = list(args)
        self.env = dict(env)
        self.url = url
        self.raw = raw
        self.scope = scope

    @property
    def command_line(self) -> str:
        if self.url:
            return self.url
        parts = [self.command or "", *self.args]
        return " ".join(part for part in parts if part).strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "scope": self.scope,
            "command_line": self.command_line,
            "env_keys": sorted(self.env),
        }


class Hook:
    __slots__ = ("command", "event", "kind", "matcher", "source", "timeout")

    def __init__(
        self,
        event: str,
        matcher: Optional[str],
        command: str,
        source: str,
        timeout: Optional[int] = None,
        kind: str = "command",
    ) -> None:
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
            "event": self.event,
            "matcher": self.matcher,
            "command": self.command,
            "source": self.source,
            "kind": self.kind,
        }


class SettingsFile:
    __slots__ = ("data", "path", "scope")

    def __init__(self, path: str, data: Dict[str, Any], scope: str) -> None:
        self.path = path
        self.data = data
        self.scope = scope

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "scope": self.scope}


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
        self._seen_files: Set[str] = set()

    def skip(self, reason: str, count: int) -> None:
        if count:
            self.skipped[reason] = self.skipped.get(reason, 0) + count

    @property
    def is_empty(self) -> bool:
        return not (self.skills or self.servers or self.hooks or self.settings)

    def to_dict(self) -> Dict[str, Any]:
        return {
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
) -> Inventory:
    """Build the inventory. Never raises for a missing location."""
    inventory = Inventory()

    base = os.path.expanduser(config_dir or USER_CONFIG_DIR)
    project = os.path.abspath(os.path.expanduser(project_dir)) if project_dir else None

    # Settings come first: `enabledPlugins` decides which plugins are loaded.
    if os.path.isdir(base):
        inventory.roots.append(base)
        _collect_settings(inventory, os.path.join(base, "settings.json"), "user")

    if project:
        for relative in PROJECT_CONFIG_FILES:
            path = os.path.join(project, relative)
            if not os.path.isfile(path):
                continue
            inventory.roots.append(path)
            if relative.endswith(".mcp.json"):
                _collect_mcp_file(inventory, path, scope="project")
            else:
                _collect_settings(inventory, path, "project")

    if os.path.isdir(base):
        _collect_user_skills(inventory, base)
        _collect_plugins(inventory, base, _enabled_plugins(inventory))

    user_config = os.path.expanduser(user_json or USER_JSON)
    if os.path.isfile(user_config):
        inventory.roots.append(user_config)
        _collect_user_json(inventory, user_config)

    if project:
        # Only `.claude/skills` is loaded. Walking all of `.claude` would also
        # read worktree checkouts and anything else a tool parked there.
        project_skills = os.path.join(project, ".claude", "skills")
        if os.path.isdir(project_skills):
            _collect_skills(inventory, project_skills, source="project")

    return inventory


def _read(path: str, inventory: Inventory) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_READ_BYTES)
        return raw.decode("utf-8", errors="replace")
    except OSError:
        inventory.unreadable.append(path)
        return None


def _read_json(path: str, inventory: Inventory) -> Optional[Dict[str, Any]]:
    text = _read(path, inventory)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        inventory.unreadable.append(path)
        return None
    return data if isinstance(data, dict) else None


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

    for root, name in roots:
        _collect_plugin_root(inventory, root, name)
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
    """Everything one loaded plugin contributes."""
    manifest = os.path.join(root, ".claude-plugin", "plugin.json")
    if os.path.isfile(manifest):
        data = _read_json(manifest, inventory) or {}
        if isinstance(data.get("name"), str) and data["name"]:
            name = data["name"]
    _collect_skills(inventory, root, source="plugin:%s" % name)


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
    _collect_hooks(inventory, data, path)

    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, scope)


def _collect_hooks(inventory: Inventory, data: Dict[str, Any], source: str) -> None:
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
    data = _read_json(path, inventory)
    if data is None:
        return
    servers = data.get("mcpServers", data)
    if isinstance(servers, dict):
        _absorb_servers(inventory, servers, path, scope)


def _absorb_servers(
    inventory: Inventory, servers: Dict[str, Any], source: str, scope: str
) -> None:
    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        env = config.get("env")
        inventory.servers.append(
            Server(
                name=str(name),
                source=source,
                command=config.get("command"),
                args=[str(a) for a in (config.get("args") or [])],
                env={
                    str(k): str(v)
                    for k, v in (env.items() if isinstance(env, dict) else [])
                },
                url=config.get("url"),
                raw=config,
                scope=scope,
            )
        )
