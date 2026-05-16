"""Ownership-proof verifiers for argus-audit."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

from .authz import Challenge, Vault, canonical_target
from .errors import ChallengeError


DEFAULT_USER_AGENT = "argus-audit-ownership/0.1"
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
HTTP_TIMEOUT_S = 8.0
DNS_TIMEOUT_S = 8.0


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _http_get(url: str, *, timeout: float = HTTP_TIMEOUT_S) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ChallengeError(f"refusing non-HTTPS ownership fetch: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            if resp.status != 200:
                raise ChallengeError(f"{url} returned HTTP {resp.status}")
            return resp.read(64 * 1024)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise ChallengeError(f"{url} unreachable: {exc}") from exc


def verify_http_host(vault: Vault, challenge: Challenge, response_text: str | None = None) -> None:
    if challenge.kind != "http_host":
        raise ChallengeError(f"expected http_host challenge, got {challenge.kind}")
    if response_text is None:
        host = challenge.target
        url = f"https://{host}/.well-known/argus-authz/{challenge.challenge_id}.txt"
        raw = _http_get(url).decode("utf-8", errors="replace")
    else:
        raw = response_text
    presented = raw.strip().splitlines()[0] if raw.strip() else ""
    vault.verify_challenge_answer(challenge, presented)


def _doh_txt(name: str) -> list[str]:
    last_exc: Exception | None = None
    for endpoint in DOH_ENDPOINTS:
        url = f"{endpoint}?name={urllib.parse.quote(name)}&type=TXT"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": DEFAULT_USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=DNS_TIMEOUT_S, context=_ssl_context()) as resp:
                payload = json.loads(resp.read(64 * 1024).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last_exc = exc
            continue
        answers = payload.get("Answer") or []
        out: list[str] = []
        for entry in answers:
            if int(entry.get("type", 0)) != 16:
                continue
            data = entry.get("data", "")
            parts: list[str] = []
            for piece in data.strip().split('" "'):
                parts.append(piece.strip('"'))
            out.append("".join(parts))
        if out:
            return out
    if last_exc is not None:
        raise ChallengeError(f"all DoH endpoints failed: {last_exc}")
    return []


def verify_dns_host(vault: Vault, challenge: Challenge, txt_value: str | None = None) -> None:
    if challenge.kind != "dns_host":
        raise ChallengeError(f"expected dns_host challenge, got {challenge.kind}")
    if txt_value is None:
        records = _doh_txt(f"_argus-authz.{challenge.target}")
    else:
        records = [txt_value]
    if not records:
        raise ChallengeError("no _argus-authz TXT record found")
    matching = None
    for record in records:
        body = record.strip()
        if body.startswith("argus-authz="):
            matching = body[len("argus-authz="):]
            break
    if matching is None:
        raise ChallengeError("no TXT record carried the 'argus-authz=' prefix")
    vault.verify_challenge_answer(challenge, matching)


def verify_local_path(vault: Vault, challenge: Challenge, *, root_override: str | None = None) -> None:
    if challenge.kind not in {"local_path", "code_repo"}:
        raise ChallengeError(f"expected local_path/code_repo challenge, got {challenge.kind}")
    target_root = Path(canonical_target(challenge.kind, root_override or challenge.target))
    if str(target_root) != challenge.target:
        raise ChallengeError(f"target canonicalized to {target_root!s} but challenge bound to {challenge.target!s}")
    if not target_root.exists() or not target_root.is_dir():
        raise ChallengeError(f"{target_root} is not an existing directory")
    challenge_file = target_root / ".argus-authz" / f"{challenge.challenge_id}.txt"
    if not challenge_file.exists() or challenge_file.is_symlink():
        raise ChallengeError(f"challenge file missing or symlinked: {challenge_file}")
    resolved = challenge_file.resolve()
    try:
        resolved.relative_to(target_root)
    except ValueError as exc:
        raise ChallengeError("challenge file escapes target root via symlink") from exc
    raw = challenge_file.read_text(encoding="utf-8", errors="replace")
    presented = raw.strip().splitlines()[0] if raw.strip() else ""
    vault.verify_challenge_answer(challenge, presented)
    if challenge.kind == "code_repo":
        if not (target_root / ".git").exists():
            raise ChallengeError(f"code_repo target {target_root} has no .git directory")


def trusted_signers(trust_list_path: Path) -> Iterable[str]:
    if not trust_list_path.exists():
        return ()
    try:
        data = json.loads(trust_list_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ChallengeError(f"trust list at {trust_list_path} is not valid JSON: {exc}") from exc
    signers = data.get("signers") if isinstance(data, dict) else None
    if not isinstance(signers, list):
        return ()
    return tuple(str(s) for s in signers if isinstance(s, str) and s)


__all__ = ["verify_http_host", "verify_dns_host", "verify_local_path", "trusted_signers"]
