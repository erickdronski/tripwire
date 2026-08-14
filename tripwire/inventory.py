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
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence

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
    if os.path.isdir(base):
        inventory.roots.append(base)
        _collect_skills(inventory, base)
        _collect_settings(inventory, os.path.join(base, "settings.json"), "user")
        _collect_plugin_config(inventory, base)

    user_config = os.path.expanduser(user_json or USER_JSON)
    if os.path.isfile(user_config):
        inventory.roots.append(user_config)
        _collect_user_json(inventory, user_config)

    if project_dir:
        project = os.path.abspath(os.path.expanduser(project_dir))
        for relative in PROJECT_CONFIG_FILES:
            path = os.path.join(project, relative)
            if not os.path.isfile(path):
                continue
            inventory.roots.append(path)
            if relative.endswith(".mcp.json"):
                _collect_mcp_file(inventory, path, scope="project")
            else:
                _collect_settings(inventory, path, "project")
        project_skills = os.path.join(project, ".claude")
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


def _collect_skills(
    inventory: Inventory, base: str, source: Optional[str] = None
) -> None:
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        if "SKILL.md" not in filenames:
            continue
        path = os.path.join(dirpath, "SKILL.md")
        text = _read(path, inventory)
        if text is None:
            continue
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


def _classify_skill_source(path: str) -> str:
    if "/plugins/marketplaces/" in path:
        parts = path.split("/plugins/marketplaces/", 1)[1].split("/")
        return "marketplace:%s" % (parts[0] if parts else "unknown")
    if "/plugins/" in path:
        return "plugin"
    return "user"


def _find_scripts(directory: str) -> List[str]:
    """Executable or script-extension files bundled with a skill."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            if filename.endswith(
                (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".rb", ".pl", ".ps1")
            ):
                out.append(os.path.relpath(full, directory))
                continue
            try:
                if os.access(full, os.X_OK) and not os.path.isdir(full):
                    out.append(os.path.relpath(full, directory))
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


def _collect_plugin_config(inventory: Inventory, base: str) -> None:
    """Marketplace manifests describe where installed plugins came from."""
    marketplaces = os.path.join(base, "plugins", "marketplaces")
    if not os.path.isdir(marketplaces):
        return
    for entry in sorted(os.listdir(marketplaces)):
        manifest = os.path.join(
            marketplaces, entry, ".claude-plugin", "marketplace.json"
        )
        if os.path.isfile(manifest):
            _read_json(manifest, inventory)


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
