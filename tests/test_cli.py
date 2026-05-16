"""End-to-end CLI tests (no network)."""

from __future__ import annotations

import json

import pytest

from argus.cli import main


def test_cli_list_scopes(argus_home, capsys):
    rc = main(["list-scopes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "static:read" in out
    assert "http:active" in out


def test_cli_authorize_and_issue_local(argus_home, tmp_path, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    main(["authorize", "local_path", str(proj)])
    challenge = json.loads(capsys.readouterr().out)
    authz_dir = proj / ".argus-authz"
    authz_dir.mkdir()
    (authz_dir / f"{challenge['challenge_id']}.txt").write_text(challenge["answer"])
    challenge_file = tmp_path / "chal.json"
    challenge_file.write_text(json.dumps(challenge))
    rc = main(["issue-token", "--challenge-file", str(challenge_file),
               "--scopes", "static:read,supply_chain"])
    out = capsys.readouterr().out
    assert rc == 0
    token = out.strip()
    assert "." in token
    (proj / "a.py").write_text("import pickle\npickle.loads(b'')\n")
    rc = main(["scan-local", str(proj), "--token", token, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["worst"] == "CRITICAL"
    rids = {f["rule_id"] for f in payload["findings"]}
    assert "argus.static.python.pickle_loads" in rids


def test_cli_issue_token_rejects_bad_proof(argus_home, tmp_path, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    main(["authorize", "local_path", str(proj)])
    challenge = json.loads(capsys.readouterr().out)
    authz_dir = proj / ".argus-authz"
    authz_dir.mkdir()
    (authz_dir / f"{challenge['challenge_id']}.txt").write_text("wrong")
    challenge_file = tmp_path / "chal.json"
    challenge_file.write_text(json.dumps(challenge))
    rc = main(["issue-token", "--challenge-file", str(challenge_file),
               "--scopes", "static:read"])
    assert rc == 2  # CLI now returns 2 instead of re-raising ChallengeError
