"""Command-line interface for argus-audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authz import (
    DEFAULT_TOKEN_TTL_S,
    KNOWN_SCOPES,
    KNOWN_TARGET_KINDS,
    Vault,
    rotate_master_key,
)
from .enrich import enrich
from .errors import ArgusError
from .findings import FindingSet
from .ownership import verify_http_host, verify_dns_host, verify_local_path
from .report import render
from .scanners import secrets as secrets_scanner
from .scanners import static_python
from .scanners import supply_chain
from .scanners import tls_audit
from .scanners import http_probe


def _authorize(args: argparse.Namespace) -> int:
    vault = Vault()
    chal = vault.new_challenge(args.kind, args.target, ttl_s=args.ttl)
    payload = {
        "challenge_id": chal.challenge_id,
        "kind": chal.kind,
        "target": chal.target,
        "issued_at": chal.issued_at,
        "expires_at": chal.expires_at,
        "publish_at": chal.publish_at,
        "answer": chal.answer,
    }
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    sys.stderr.write(
        f"\nargus: publish the answer at:\n  {chal.publish_at}\n"
        f"argus: then call: argus issue-token --challenge-file - --scopes ... < this-json\n"
    )
    return 0


def _issue_token(args: argparse.Namespace) -> int:
    """Verify a published challenge and mint a scope token.

    Wraps the verifier + issuer in a try/except so failed proofs surface as a
    single human-readable line instead of a traceback. Returns 2 on any
    authorization-related failure so calling scripts can branch on the code.
    """
    vault = Vault()
    try:
        if args.challenge_file == "-":
            data = json.loads(sys.stdin.read())
        else:
            data = json.loads(Path(args.challenge_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"argus: cannot read challenge file: {exc}\n")
        return 2

    from .authz import Challenge

    try:
        chal = Challenge(
            challenge_id=data["challenge_id"], kind=data["kind"], target=data["target"],
            issued_at=int(data["issued_at"]), expires_at=int(data["expires_at"]),
            publish_at=data["publish_at"], answer=data["answer"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        sys.stderr.write(f"argus: challenge JSON is incomplete: {exc}\n")
        return 2

    try:
        if chal.kind == "http_host":
            verify_http_host(vault, chal)
        elif chal.kind == "dns_host":
            verify_dns_host(vault, chal)
        elif chal.kind in {"local_path", "code_repo"}:
            verify_local_path(vault, chal)
        else:
            sys.stderr.write(f"argus: unknown challenge kind: {chal.kind!r}\n")
            return 2
        scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        token = vault.issue(chal.kind, chal.target, scopes, ttl_s=args.ttl)
    except ArgusError as exc:
        sys.stderr.write(f"argus: ownership verification failed: {exc}\n")
        return 2
    sys.stdout.write(token + "\n")
    return 0


def _maybe_enrich(fs: FindingSet) -> FindingSet:
    """Fold intel-cache data into findings when the cache exists.

    Catches only the specific failures that can legitimately arise on a fresh
    install (cache file missing, sqlite open / read errors). ``cache`` is
    bound to ``None`` up-front so the ``finally`` close is unconditionally
    safe regardless of which step failed (MiMo review #4 concern about
    UnboundLocalError if construction itself raises).
    """
    import sqlite3

    try:
        from . import intel
    except ImportError as exc:
        sys.stderr.write(f"argus: intel module unavailable: {exc}\n")
        return fs

    cache = None
    try:
        cache = intel.IntelCache()
        if cache.count() == 0:
            return fs
        return enrich(fs, cache)
    except (sqlite3.Error, OSError) as exc:
        sys.stderr.write(f"argus: intel cache unavailable, skipping enrichment: {exc}\n")
        return fs
    finally:
        if cache is not None:
            try:
                cache.close()
            except sqlite3.Error as close_exc:
                # Closing a corrupt DB can raise; surface it once so the
                # operator knows the filesystem state may need attention,
                # but do not let it crash the scan (enrichment is best-effort).
                sys.stderr.write(
                    f"argus: intel cache close failed (filesystem may be corrupt): {close_exc}\n"
                )


def _run_one(fs: FindingSet, label: str, fn) -> bool:
    """Run a scanner; skip with an informational line if its scope is missing.

    Returns True if the scanner ran (regardless of finding count), False if it
    was skipped due to a ScopeViolation. The two are different because a
    skipped scanner is not a soft success — the operator may want to know
    they need a broader token.
    """
    from .errors import ScopeViolation
    try:
        fs.extend(fn())
        return True
    except ScopeViolation as exc:
        sys.stderr.write(f"argus: skipping {label}: {exc}\n")
        return False


def _scan_local(args: argparse.Namespace) -> int:
    try:
        vault = Vault()
    except ArgusError as exc:
        sys.stderr.write(f"argus: vault unavailable: {exc}\n")
        return 2
    fs = FindingSet()
    root = str(Path(args.path).expanduser().resolve())
    if not args.skip_static:
        _run_one(fs, "static_python", lambda: static_python.scan(vault, args.token, root))
    if not args.skip_secrets:
        _run_one(fs, "secrets", lambda: secrets_scanner.scan(vault, args.token, root))
    if not args.skip_supply_chain:
        _run_one(fs, "supply_chain", lambda: supply_chain.scan(vault, args.token, root))
    fs = _maybe_enrich(fs)
    sys.stdout.write(render(fs, args.format, target_label=root))
    return 1 if fs.worst().name in {"CRITICAL", "HIGH"} else 0


def _scan_host(args: argparse.Namespace) -> int:
    try:
        vault = Vault()
    except ArgusError as exc:
        sys.stderr.write(f"argus: vault unavailable: {exc}\n")
        return 2
    fs = FindingSet()
    if not args.skip_tls:
        _run_one(fs, "tls_audit", lambda: tls_audit.audit(vault, args.token, args.host, port=args.port))
    if not args.skip_http_passive:
        _run_one(fs, "http_passive", lambda: http_probe.passive_probe(vault, args.token, args.host))
    if args.http_active:
        _run_one(fs, "http_active", lambda: http_probe.active_probe(vault, args.token, args.host))
    fs = _maybe_enrich(fs)
    sys.stdout.write(render(fs, args.format, target_label=args.host))
    return 1 if fs.worst().name in {"CRITICAL", "HIGH"} else 0


def _intel_update(args: argparse.Namespace) -> int:
    from . import intel

    cache = intel.IntelCache()
    kev = intel.fetch_and_apply_kev(cache)
    sys.stdout.write(f"KEV: {kev} records ingested (cache total {cache.count()})\n")
    if args.with_nvd:
        nvd = intel.fetch_and_apply_nvd_window(cache,
                                                last_mod_start=args.nvd_start,
                                                last_mod_end=args.nvd_end)
        sys.stdout.write(f"NVD: {nvd} records ingested\n")
    if args.with_epss:
        n = intel.fetch_and_apply_epss(cache, date=args.epss_date)
        sys.stdout.write(f"EPSS: {n} CVE rows updated with EPSS score\n")
    cache.close()
    return 0


def _intel_prune(args: argparse.Namespace) -> int:
    """Trim entries from the local intel cache that are older than --max-age-days."""
    from . import intel

    cache = intel.IntelCache()
    try:
        removed = cache.prune_older_than(int(args.max_age_days))
    finally:
        cache.close()
    sys.stdout.write(f"argus: pruned {removed} CVE entries older than {args.max_age_days} days\n")
    return 0


def _rotate_key(args: argparse.Namespace) -> int:
    """Rotate the master HMAC key.

    Refuses without ``--confirm`` so an accidental key rotation cannot wipe
    out every in-flight scope token. The intended workflow is for an operator
    who has either lost the prior key or is responding to a compromise.
    """
    if not getattr(args, "confirm", False):
        sys.stderr.write(
            "argus: refusing to rotate the master key without --confirm.\n"
            "       all previously-issued tokens will be revoked. re-run:\n"
            "         argus rotate-key --confirm\n"
        )
        return 2
    rotate_master_key()
    sys.stdout.write("argus: master key rotated; all previously-issued tokens are revoked.\n")
    return 0


def _list_scopes(_args: argparse.Namespace) -> int:
    for s in sorted(KNOWN_SCOPES):
        sys.stdout.write(s + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="argus", description="scope-gated white-hat security audit + pentest orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("authorize", help="Issue an ownership challenge.")
    a.add_argument("kind", choices=sorted(KNOWN_TARGET_KINDS))
    a.add_argument("target")
    a.add_argument("--ttl", type=int, default=1800)
    a.set_defaults(func=_authorize)

    i = sub.add_parser("issue-token", help="Verify a published challenge and mint a token.")
    i.add_argument("--challenge-file", required=True)
    i.add_argument("--scopes", required=True)
    i.add_argument("--ttl", type=int, default=DEFAULT_TOKEN_TTL_S)
    i.set_defaults(func=_issue_token)

    sl = sub.add_parser("scan-local", help="Run static + secret + supply-chain audit on a local path.")
    sl.add_argument("path")
    sl.add_argument("--token", required=True)
    sl.add_argument("--format", default="text", choices=("text", "json", "md", "markdown"))
    sl.add_argument("--skip-static", action="store_true")
    sl.add_argument("--skip-secrets", action="store_true")
    sl.add_argument("--skip-supply-chain", action="store_true")
    sl.set_defaults(func=_scan_local)

    sh = sub.add_parser("scan-host", help="Run TLS + HTTP audit against an authorized host.")
    sh.add_argument("host")
    sh.add_argument("--token", required=True)
    sh.add_argument("--port", type=int, default=443)
    sh.add_argument("--format", default="text", choices=("text", "json", "md", "markdown"))
    sh.add_argument("--skip-tls", action="store_true")
    sh.add_argument("--skip-http-passive", action="store_true")
    sh.add_argument("--http-active", action="store_true")
    sh.set_defaults(func=_scan_host)

    iu = sub.add_parser("intel-update", help="Refresh CVE/KEV/EPSS cache from public feeds.")
    iu.add_argument("--with-nvd", action="store_true")
    iu.add_argument("--with-epss", action="store_true")
    iu.add_argument("--nvd-start", default=None)
    iu.add_argument("--nvd-end", default=None)
    iu.add_argument("--epss-date", default=None)
    iu.set_defaults(func=_intel_update)

    ip = sub.add_parser("intel-prune", help="Trim entries from the intel cache older than the threshold.")
    ip.add_argument("--max-age-days", type=int, default=90,
                    help="Drop CVE entries whose fetched_at is older than this many days.")
    ip.set_defaults(func=_intel_prune)

    r = sub.add_parser("rotate-key", help="Rotate the master HMAC key (revokes all tokens).")
    r.add_argument("--confirm", action="store_true",
                   help="Required acknowledgement that every issued token will be revoked.")
    r.set_defaults(func=_rotate_key)

    ls = sub.add_parser("list-scopes", help="Print known scope strings.")
    ls.set_defaults(func=_list_scopes)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
