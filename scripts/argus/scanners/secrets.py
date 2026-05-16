"""Secret scanner for argus-audit."""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Iterable, Pattern

from ..authz import Vault
from ..findings import Finding, Severity


PATTERNS: tuple[tuple[str, str, Pattern[str], Severity, str], ...] = (
    ("argus.secrets.aws_access_key_id", "AWS Access Key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL, "CWE-798"),
    ("argus.secrets.aws_secret_access_key", "AWS Secret Access Key (heuristic)",
     re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{1,5}([A-Za-z0-9/+=]{40})"),
     Severity.CRITICAL, "CWE-798"),
    ("argus.secrets.github_pat", "GitHub Personal Access Token",
     re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), Severity.CRITICAL, "CWE-798"),
    ("argus.secrets.github_fine_grained", "GitHub fine-grained PAT",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), Severity.CRITICAL, "CWE-798"),
    ("argus.secrets.github_oauth", "GitHub OAuth token",
     re.compile(r"\bgho_[A-Za-z0-9]{30,}\b"), Severity.HIGH, "CWE-798"),
    ("argus.secrets.stripe_live", "Stripe live secret key",
     re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), Severity.CRITICAL, "CWE-798"),
    ("argus.secrets.slack_token", "Slack token",
     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH, "CWE-798"),
    ("argus.secrets.google_api_key", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH, "CWE-798"),
    ("argus.secrets.twilio_account_sid", "Twilio Account SID",
     re.compile(r"\bAC[a-f0-9]{32}\b"), Severity.MEDIUM, "CWE-798"),
    ("argus.secrets.pem_private_key", "PEM private key header",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
     Severity.CRITICAL, "CWE-321"),
    ("argus.secrets.jwt", "JSON Web Token (literal in source)",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     Severity.HIGH, "CWE-798"),
    ("argus.secrets.url_basic_auth", "URL with embedded basic-auth credentials",
     re.compile(r"\b[a-z]{2,8}://[^/\s:@]+:[^@/\s]+@[^/\s]+"),
     Severity.HIGH, "CWE-522"),
)

ENTROPY_RULE = "argus.secrets.high_entropy_literal"

SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__",
                       ".pytest_cache", ".tox", "dist", "build", ".mypy_cache"})
SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                          ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
                          ".woff", ".woff2", ".ttf", ".otf",
                          ".mp3", ".mp4", ".mov", ".avi"})


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest[:16]} (len={len(secret)})"


def _scan_line(file_path: str, lineno: int, line: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    seen_at: set[tuple[int, int]] = set()
    for rid, title, pattern, severity, cwe in PATTERNS:
        for m in pattern.finditer(line):
            span = m.span()
            if span in seen_at:
                continue
            seen_at.add(span)
            findings.append(Finding(
                rule_id=rid, title=title, severity=severity, surface="secrets",
                target=file_path, location=f"{file_path}:{lineno}",
                evidence=_redact(m.group(0)),
                remediation="Rotate the secret immediately; load from env or a secret manager",
                cwe=cwe,
                references=("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",),
            ))
    for m in re.finditer(r"[\"']([A-Za-z0-9+/=_\-]{20,})[\"']", line):
        s = m.group(1)
        if _shannon_entropy(s) >= 4.3 and m.span() not in seen_at:
            findings.append(Finding(
                rule_id=ENTROPY_RULE,
                title="High-entropy string literal — possible secret",
                severity=Severity.MEDIUM, surface="secrets",
                target=file_path, location=f"{file_path}:{lineno}",
                evidence=_redact(s),
                remediation="If a secret, rotate and move to env or a secret manager",
                cwe="CWE-798",
            ))
    return findings


def _walk(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield path


def scan(vault: Vault, token: str, root: str) -> list[Finding]:
    parsed = vault.require_scope(token, "static:read", "local_path", root)
    canonical = Path(parsed.target)
    if not canonical.exists():
        return []
    findings: list[Finding] = []
    for path in _walk(canonical):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    findings.extend(_scan_line(str(path), i, line))
        except OSError:
            continue
    findings.sort(key=Finding.rank, reverse=True)
    return findings
