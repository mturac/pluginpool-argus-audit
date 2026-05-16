"""Regression tests for review #5 fixes (the last two Lows)."""

from __future__ import annotations

import textwrap

import pytest

from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. _strip_yaml_comments removes commented-out patterns before regex match
# ---------------------------------------------------------------------------

def test_strip_yaml_comments_removes_line_comments():
    src = "permissions:\n  contents: read   # this used to be write\n"
    out = supply_chain._strip_yaml_comments(src)
    assert "# this used to be write" not in out
    assert "contents: read" in out


def test_strip_yaml_comments_preserves_hashes_inside_quoted_scalars():
    src = "name: 'value # not a comment'\n"
    out = supply_chain._strip_yaml_comments(src)
    assert "value # not a comment" in out


def test_strip_yaml_comments_handles_full_line_comments():
    src = "# top-level comment\nname: x\n"
    out = supply_chain._strip_yaml_comments(src)
    assert out.splitlines()[0] == ""
    assert "name: x" in out


@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_commented_out_permission_is_not_flagged(vault, supply_scope):
    """The MiMo review #5 false-positive case: a commented-out `write` scope
    must not be reported."""
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        permissions:
          # contents: write  -- removed during hardening
          contents: read
        jobs:
          x:
            steps:
              - run: echo ok
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert not any(r.startswith("argus.supply.gha.permission_write") for r in rids)


def test_commented_out_pull_request_target_is_not_flagged(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        # on: pull_request_target  -- intentionally not used
        on: pull_request
        jobs:
          x:
            steps:
              - uses: actions/checkout@v4
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.pwn_request" not in rids


def test_real_pwn_request_still_caught(vault, supply_scope):
    """The comment-strip must not regress detection of an actual pwn-request."""
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        on: pull_request_target
        jobs:
          x:
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.pwn_request" in rids
