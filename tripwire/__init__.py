"""tripwire — see what your coding agent is actually allowed to do.

An offline, read-only audit of the skills, MCP servers, hooks, and permission
settings installed on this machine. It enumerates your agent's real capability
surface, then flags the specific ways that surface can be turned against you:
approval switched off, instructions hidden in text the model reads, credentials
sitting in config files, servers that install their own code at launch.

Nothing is executed, installed, or fetched. It reads files already on disk —
which matters, because much of what it inspects exists to run commands.

    python3 -m tripwire
    python3 -m tripwire --info --project .
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
