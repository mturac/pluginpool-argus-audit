"""Tests for the authorization vault."""

from __future__ import annotations

import base64
import dataclasses
import json
import time

import pytest

from argus.authz import (
    DEFAULT_TOKEN_TTL_S,
    KNOWN_SCOPES,
    KNOWN_TARGET_KINDS,
    Vault,
    canonical_target,
    load_or_create_master_key,
    rotate_master_key,
)
from argus.errors import AuthzError, ChallengeError, ScopeViolation


def test_master_key_is_created_with_restrictive_permissions(argus_home):
    key = load_or_create_master_key()
    assert len(key) == 32
    key_file = argus_home / "master.key"
    assert key_file.exists()
    mode = key_file.stat().st_mode & 0o777
    assert mode == 0o600
    again = load_or_create_master_key()
    assert key == again


def test_master_key_rotation_invalidates_old_tokens(argus_home):
    vault = Vault()
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    vault.parse(token)
    rotate_master_key()
    fresh = Vault()
    with pytest.raises(AuthzError):
        fresh.parse(token)


def test_canonical_target_normalizes_hosts():
    assert canonical_target("http_host", "Example.COM") == "example.com"
    assert canonical_target("http_host", "https://example.com/") == "example.com"


def test_canonical_target_resolves_local_paths(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert canonical_target("local_path", str(nested)) == str(nested.resolve())


def test_canonical_target_rejects_unknown_kind():
    with pytest.raises(AuthzError):
        canonical_target("nonsense", "x")


def test_issue_refuses_unknown_scope(vault, argus_home):
    with pytest.raises(AuthzError):
        vault.issue("local_path", str(argus_home), ["wildcard:everything"])


def test_issue_refuses_empty_scope_set(vault, argus_home):
    with pytest.raises(AuthzError):
        vault.issue("local_path", str(argus_home), [])


def test_issue_then_parse_roundtrip(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read", "sca:public"])
    parsed = vault.parse(token)
    assert parsed.target == str(argus_home.resolve())
    assert parsed.scopes == frozenset({"static:read", "sca:public"})


def test_parse_rejects_malformed_token(vault):
    with pytest.raises(AuthzError):
        vault.parse("not-a-token")


def test_parse_rejects_tampered_payload(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    payload_b64, mac_b64 = token.split(".", 1)
    pad = "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(payload_b64 + pad).decode()
    obj = json.loads(raw)
    obj["scopes"] = sorted(set(obj["scopes"]) | {"http:active"})
    tampered = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    tampered_b64 = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode()
    with pytest.raises(AuthzError):
        vault.parse(f"{tampered_b64}.{mac_b64}")


def test_require_scope_grants_match(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    parsed = vault.require_scope(token, "static:read", "local_path", str(argus_home))
    assert parsed.kind == "local_path"


def test_require_scope_refuses_target_mismatch(vault, argus_home, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    with pytest.raises(ScopeViolation):
        vault.require_scope(token, "static:read", "local_path", str(other))


def test_require_scope_refuses_kind_mismatch(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    with pytest.raises(ScopeViolation):
        vault.require_scope(token, "static:read", "http_host", "example.com")


def test_require_scope_refuses_missing_scope(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    with pytest.raises(ScopeViolation):
        vault.require_scope(token, "http:active", "local_path", str(argus_home))


def test_require_scope_refuses_expired_token(vault, argus_home):
    token = vault.issue("local_path", str(argus_home), ["static:read"], ttl_s=60)
    far = int(time.time()) + DEFAULT_TOKEN_TTL_S * 10
    with pytest.raises(AuthzError):
        vault.require_scope(token, "static:read", "local_path", str(argus_home), now=far)


def test_known_scopes_cover_documented_phases():
    needed = {"recon:passive", "recon:active", "static:read",
              "http:passive", "http:active", "tls:audit", "supply_chain"}
    assert needed.issubset(KNOWN_SCOPES)
    assert KNOWN_TARGET_KINDS == frozenset({"local_path", "http_host", "dns_host", "code_repo"})


def test_challenge_roundtrip_local(vault, tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    chal = vault.new_challenge("local_path", str(target))
    answer = vault.expected_answer(chal.kind, chal.target, chal.challenge_id, chal.expires_at)
    vault.verify_challenge_answer(chal, answer)


def test_challenge_rejects_wrong_answer(vault, tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    chal = vault.new_challenge("local_path", str(target))
    with pytest.raises(ChallengeError):
        vault.verify_challenge_answer(chal, "wrong-answer")


def test_challenge_expires(vault, tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    chal = vault.new_challenge("local_path", str(target), ttl_s=60)
    expired = dataclasses.replace(chal, expires_at=int(time.time()) - 1)
    answer = vault.expected_answer(expired.kind, expired.target, expired.challenge_id, expired.expires_at)
    with pytest.raises(ChallengeError):
        vault.verify_challenge_answer(expired, answer)
