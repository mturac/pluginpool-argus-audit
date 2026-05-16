"""TLS / certificate audit for argus-audit (stdlib only)."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Iterable

from ..authz import Vault
from ..findings import Finding, Severity


CONNECT_TIMEOUT_S = 5.0


def _parse_cert_not_after(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def _audit_host(host: str, port: int) -> Iterable[Finding]:
    target_label = f"{host}:{port}"
    findings: list[Finding] = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as wrapped:
                proto = wrapped.version() or ""
    except (OSError, socket.timeout, ssl.SSLError):
        return [Finding(
            rule_id="argus.tls.unreachable",
            title=f"TLS handshake to {target_label} failed",
            severity=Severity.LOW, surface="tls",
            target=target_label,
            remediation="Confirm the host is up and TLS-enabled before re-running",
        )]

    if proto in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        findings.append(Finding(
            rule_id="argus.tls.weak_protocol",
            title=f"Weak TLS protocol negotiated: {proto}",
            severity=Severity.HIGH, surface="tls",
            target=target_label, evidence=proto,
            remediation="Disable TLS<1.2 on the server",
            cwe="CWE-326",
            references=("https://datatracker.ietf.org/doc/html/rfc8996",),
        ))

    cert_dict: dict = {}
    try:
        verify_ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=host) as wrapped:
                cert_dict = wrapped.getpeercert() or {}
    except (OSError, ssl.SSLError) as exc:
        findings.append(Finding(
            rule_id="argus.tls.cert_verify_failed",
            title="Certificate verification against host failed",
            severity=Severity.HIGH, surface="tls",
            target=target_label, evidence=str(exc)[:120],
            remediation="Check chain trust, SNI, hostname binding, and expiry",
            cwe="CWE-295",
        ))

    not_after = cert_dict.get("notAfter") if isinstance(cert_dict, dict) else None
    if not_after:
        try:
            exp = _parse_cert_not_after(not_after)
            days_left = (exp - datetime.datetime.utcnow()).days
        except ValueError:
            days_left = None
        if days_left is not None:
            if days_left < 0:
                findings.append(Finding(
                    rule_id="argus.tls.cert_expired",
                    title=f"Certificate expired {abs(days_left)} day(s) ago",
                    severity=Severity.CRITICAL, surface="tls",
                    target=target_label, evidence=f"notAfter={not_after}",
                    remediation="Renew the certificate immediately", cwe="CWE-295",
                ))
            elif days_left < 14:
                findings.append(Finding(
                    rule_id="argus.tls.cert_expiring_soon",
                    title=f"Certificate expires in {days_left} day(s)",
                    severity=Severity.MEDIUM, surface="tls",
                    target=target_label, evidence=f"notAfter={not_after}",
                    remediation="Renew before expiry; automate with ACME",
                ))
    return findings


def audit(vault: Vault, token: str, host: str, port: int = 443) -> list[Finding]:
    vault.require_scope(token, "tls:audit", "http_host", host)
    findings = list(_audit_host(host, port))
    findings.sort(key=Finding.rank, reverse=True)
    return findings
