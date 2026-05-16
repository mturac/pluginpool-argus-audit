"""Tests for ownership verifiers (offline)."""

from __future__ import annotations

import dataclasses
import time

import pytest

from argus.errors import ChallengeError
from argus.ownership import verify_dns_host, verify_http_host, verify_local_path


def test_verify_local_path_accepts_correct_answer(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("local_path", str(proj))
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").write_text(chal.answer)
    verify_local_path(vault, chal)


def test_verify_local_path_rejects_wrong_answer(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("local_path", str(proj))
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").write_text("not-the-answer")
    with pytest.raises(ChallengeError):
        verify_local_path(vault, chal)


def test_verify_local_path_refuses_missing_file(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("local_path", str(proj))
    with pytest.raises(ChallengeError):
        verify_local_path(vault, chal)


def test_verify_local_path_refuses_symlinked_challenge(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("local_path", str(proj))
    (proj / ".argus-authz").mkdir()
    real = tmp_path / "elsewhere.txt"
    real.write_text(chal.answer)
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").symlink_to(real)
    with pytest.raises(ChallengeError):
        verify_local_path(vault, chal)


def test_verify_local_path_code_repo_requires_git_dir(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("code_repo", str(proj))
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").write_text(chal.answer)
    with pytest.raises(ChallengeError):
        verify_local_path(vault, chal)


def test_verify_local_path_code_repo_with_git_succeeds(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()
    chal = vault.new_challenge("code_repo", str(proj))
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").write_text(chal.answer)
    verify_local_path(vault, chal)


def test_verify_http_host_accepts_correct_response(vault):
    chal = vault.new_challenge("http_host", "example.com")
    verify_http_host(vault, chal, response_text=chal.answer)


def test_verify_http_host_rejects_wrong_response(vault):
    chal = vault.new_challenge("http_host", "example.com")
    with pytest.raises(ChallengeError):
        verify_http_host(vault, chal, response_text="bogus")


def test_verify_dns_host_accepts_prefixed_record(vault):
    chal = vault.new_challenge("dns_host", "example.com")
    verify_dns_host(vault, chal, txt_value=f"argus-authz={chal.answer}")


def test_verify_dns_host_rejects_unprefixed_record(vault):
    chal = vault.new_challenge("dns_host", "example.com")
    with pytest.raises(ChallengeError):
        verify_dns_host(vault, chal, txt_value=chal.answer)


def test_expired_challenge_is_refused(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    chal = vault.new_challenge("local_path", str(proj))
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{chal.challenge_id}.txt").write_text(chal.answer)
    expired = dataclasses.replace(chal, expires_at=int(time.time()) - 1)
    with pytest.raises(ChallengeError):
        verify_local_path(vault, expired)
