"""Test harness for argus-audit."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


@pytest.fixture()
def argus_home(tmp_path, monkeypatch):
    home = tmp_path / "argus_home"
    home.mkdir()
    monkeypatch.setenv("ARGUS_HOME", str(home))
    return home


@pytest.fixture()
def vault(argus_home):
    from argus.authz import Vault
    return Vault()
