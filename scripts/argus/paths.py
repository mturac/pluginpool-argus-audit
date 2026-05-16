"""Filesystem paths used by argus-audit.

The home root is the user's config directory; tests override it via the
``ARGUS_HOME`` environment variable so they never touch the real ``~/.argus``.
"""

from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    override = os.environ.get("ARGUS_HOME")
    if override:
        return Path(override)
    return Path.home() / ".argus"


def master_key_path() -> Path:
    return home() / "master.key"


def token_jar_path() -> Path:
    return home() / "tokens"


def challenge_jar_path() -> Path:
    return home() / "challenges"


def intel_cache_path() -> Path:
    return home() / "intel"


def trust_list_path() -> Path:
    return home() / "trust.json"


def ensure_home() -> Path:
    root = home()
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    for sub in (token_jar_path(), challenge_jar_path(), intel_cache_path()):
        sub.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(sub, 0o700)
        except OSError:
            pass
    return root
