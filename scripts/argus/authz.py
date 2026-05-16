"""Argus scope-authorization vault.

Every active probe in argus-audit refuses to run unless it can verify a scope
token issued by this module. A scope token is bound to:

    - a target (hostname or canonicalized local filesystem path)
    - a target kind (``local_path``, ``http_host``, ``dns_host``, ``code_repo``)
    - a set of granted scope strings (see ``KNOWN_SCOPES``)
    - a validity window (not-before, expiry)
    - a random nonce so identical inputs produce unique tokens

Format::

    <base64url(payload_bytes)>.<base64url(mac)>

``payload_bytes`` is canonical JSON (sorted keys, no whitespace). ``mac`` is
``HMAC-SHA256(master_key, payload_bytes)``. Verification uses
``hmac.compare_digest``. The scheme is intentionally symmetric and stdlib-only
— the operator issues and consumes tokens on the same host, so no asymmetric
keys are needed. Rotating the master key invalidates every previously-issued
token.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Iterable, Mapping

from . import paths
from .errors import AuthzError, ChallengeError, ScopeViolation


TOKEN_VERSION = 1
ISSUER = "argus-audit/0.1"
DEFAULT_TOKEN_TTL_S = 3600
DEFAULT_CHALLENGE_TTL_S = 1800
NONCE_BYTES = 16
MASTER_KEY_BYTES = 32

KNOWN_TARGET_KINDS = frozenset(
    {"local_path", "http_host", "dns_host", "code_repo"}
)

KNOWN_SCOPES = frozenset(
    {
        "recon:passive",
        "recon:active",
        "static:read",
        "sca:public",
        "http:passive",
        "http:active",
        "tls:audit",
        "supply_chain",
        "container:read",
        "cloud:read",
        "server:config",
        "mcp:audit",
    }
)


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonical_json(obj: Mapping[str, object]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_target(kind: str, target: str) -> str:
    if kind not in KNOWN_TARGET_KINDS:
        raise AuthzError(f"unknown target kind: {kind!r}")
    if kind in {"local_path", "code_repo"}:
        return str(Path(target).expanduser().resolve())
    cleaned = target.strip().lower()
    for scheme in ("https://", "http://"):
        if cleaned.startswith(scheme):
            cleaned = cleaned[len(scheme):]
    cleaned = cleaned.rstrip("/")
    if not cleaned:
        raise AuthzError("empty target after normalization")
    return cleaned


def load_or_create_master_key() -> bytes:
    paths.ensure_home()
    key_path = paths.master_key_path()
    if key_path.exists():
        raw = key_path.read_bytes()
        if len(raw) >= MASTER_KEY_BYTES:
            return raw[:MASTER_KEY_BYTES]
        raise AuthzError(
            f"master key at {key_path} is shorter than {MASTER_KEY_BYTES} bytes; "
            "rotate it with `argus authz rotate-key`"
        )
    key = secrets.token_bytes(MASTER_KEY_BYTES)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def rotate_master_key() -> bytes:
    paths.ensure_home()
    key_path = paths.master_key_path()
    if key_path.exists():
        backup = key_path.with_suffix(".key.revoked")
        try:
            key_path.replace(backup)
        except OSError:
            key_path.unlink(missing_ok=True)  # type: ignore[arg-type]
    return load_or_create_master_key()


@dataclasses.dataclass(frozen=True)
class ScopeToken:
    version: int
    target: str
    kind: str
    scopes: frozenset[str]
    nbf: int
    exp: int
    nonce: str
    issuer: str

    def covers(self, scope: str) -> bool:
        return scope in self.scopes


@dataclasses.dataclass(frozen=True)
class Challenge:
    challenge_id: str
    kind: str
    target: str
    issued_at: int
    expires_at: int
    publish_at: str
    answer: str


class Vault:
    """The single source of authorization truth in argus-audit."""

    def __init__(self, master_key: bytes | None = None) -> None:
        self._key = master_key if master_key is not None else load_or_create_master_key()

    def new_challenge(self, kind: str, target: str, ttl_s: int = DEFAULT_CHALLENGE_TTL_S) -> Challenge:
        canonical = canonical_target(kind, target)
        challenge_id = _b64u_encode(secrets.token_bytes(NONCE_BYTES))
        issued = int(time.time())
        expires = issued + max(60, int(ttl_s))
        payload = f"{kind}|{canonical}|{challenge_id}|{expires}".encode("utf-8")
        mac = hmac.new(self._key, payload, hashlib.sha256).digest()
        answer = _b64u_encode(mac)
        if kind == "http_host":
            publish_at = f"https://{canonical}/.well-known/argus-authz/{challenge_id}.txt"
        elif kind == "dns_host":
            publish_at = f"_argus-authz.{canonical} IN TXT \"argus-authz={answer}\""
        elif kind in {"local_path", "code_repo"}:
            publish_at = str(Path(canonical) / ".argus-authz" / f"{challenge_id}.txt")
        else:
            raise AuthzError(f"unknown target kind: {kind!r}")
        return Challenge(
            challenge_id=challenge_id, kind=kind, target=canonical,
            issued_at=issued, expires_at=expires,
            publish_at=publish_at, answer=answer,
        )

    def expected_answer(self, kind: str, target: str, challenge_id: str, expires_at: int) -> str:
        canonical = canonical_target(kind, target)
        payload = f"{kind}|{canonical}|{challenge_id}|{int(expires_at)}".encode("utf-8")
        mac = hmac.new(self._key, payload, hashlib.sha256).digest()
        return _b64u_encode(mac)

    def verify_challenge_answer(self, challenge: Challenge, presented: str) -> None:
        if int(time.time()) > challenge.expires_at:
            raise ChallengeError("challenge expired")
        expected = self.expected_answer(
            challenge.kind, challenge.target, challenge.challenge_id, challenge.expires_at
        )
        if not hmac.compare_digest(expected.encode("ascii"), presented.strip().encode("ascii")):
            raise ChallengeError("ownership challenge answer mismatch")

    def issue(self, kind: str, target: str, scopes: Iterable[str], ttl_s: int = DEFAULT_TOKEN_TTL_S) -> str:
        canonical = canonical_target(kind, target)
        scope_set = frozenset(str(s).strip() for s in scopes if s)
        unknown = scope_set - KNOWN_SCOPES
        if unknown:
            raise AuthzError(f"unknown scopes refused: {sorted(unknown)!r}")
        if not scope_set:
            raise AuthzError("refusing to issue a token with no scopes")
        now = int(time.time())
        payload = {
            "v": TOKEN_VERSION,
            "target": canonical,
            "kind": kind,
            "scopes": sorted(scope_set),
            "nbf": now,
            "exp": now + max(60, int(ttl_s)),
            "nonce": _b64u_encode(secrets.token_bytes(NONCE_BYTES)),
            "issuer": ISSUER,
        }
        payload_bytes = _canonical_json(payload)
        mac = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        return f"{_b64u_encode(payload_bytes)}.{_b64u_encode(mac)}"

    def parse(self, token: str) -> ScopeToken:
        try:
            payload_b64, mac_b64 = token.strip().split(".", 1)
        except ValueError as exc:
            raise AuthzError("malformed scope token") from exc
        try:
            payload_bytes = _b64u_decode(payload_b64)
            presented_mac = _b64u_decode(mac_b64)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise AuthzError("scope token base64 decode failed") from exc
        expected = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, presented_mac):
            raise AuthzError("scope token signature invalid")
        try:
            data = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthzError("scope token payload not valid JSON") from exc
        if not isinstance(data, dict):
            raise AuthzError("scope token payload must be a JSON object")
        try:
            return ScopeToken(
                version=int(data["v"]),
                target=str(data["target"]),
                kind=str(data["kind"]),
                scopes=frozenset(str(s) for s in data["scopes"]),
                nbf=int(data["nbf"]),
                exp=int(data["exp"]),
                nonce=str(data["nonce"]),
                issuer=str(data.get("issuer", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthzError(f"scope token payload incomplete: {exc}") from exc

    def require_scope(self, token: str, scope: str, target_kind: str, target: str,
                      now: int | None = None) -> ScopeToken:
        parsed = self.parse(token)
        if parsed.version != TOKEN_VERSION:
            raise AuthzError(f"unsupported token version: {parsed.version}")
        current = int(time.time()) if now is None else int(now)
        if current < parsed.nbf:
            raise AuthzError("scope token is not yet valid")
        if current > parsed.exp:
            raise AuthzError("scope token has expired")
        canonical = canonical_target(target_kind, target)
        if parsed.kind != target_kind:
            raise ScopeViolation(f"token bound to kind {parsed.kind!r}, probe requested {target_kind!r}")
        if parsed.target != canonical:
            raise ScopeViolation(f"token bound to target {parsed.target!r}, probe requested {canonical!r}")
        if scope not in parsed.scopes:
            raise ScopeViolation(f"token does not grant scope {scope!r}; granted={sorted(parsed.scopes)!r}")
        return parsed
