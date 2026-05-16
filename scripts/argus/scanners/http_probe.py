"""HTTP probes for argus-audit. Two surfaces: passive (security headers) and active (CVE detectors)."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

from ..authz import Vault
from ..findings import Finding, Severity


USER_AGENT = "argus-audit-probe/0.1"
HTTP_TIMEOUT_S = 6.0


def _https_request(method: str, url: str, *, body: bytes | None = None) -> tuple[int, dict[str, str], bytes] | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    req = urllib.request.Request(url, method=method, data=body, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=ctx) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read(64 * 1024)
    except (urllib.error.URLError, socket.timeout, OSError):
        return None


def _passive(host: str) -> Iterable[Finding]:
    url = f"https://{host}/"
    result = _https_request("GET", url)
    if result is None:
        return [Finding(
            rule_id="argus.http.passive_unreachable",
            title=f"{host} not reachable over HTTPS root",
            severity=Severity.LOW, surface="dynamic", target=host,
            remediation="Confirm the host exposes HTTPS; the probe is non-fatal",
        )]
    status, headers, _body = result
    findings: list[Finding] = []
    if "strict-transport-security" not in headers:
        findings.append(Finding(
            rule_id="argus.http.missing_hsts",
            title="Strict-Transport-Security header missing",
            severity=Severity.MEDIUM, surface="dynamic", target=host,
            evidence=f"GET / -> {status}; HSTS absent",
            remediation='Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`',
            cwe="CWE-319",
            references=("https://owasp.org/www-project-secure-headers/",),
        ))
    if "content-security-policy" not in headers:
        findings.append(Finding(
            rule_id="argus.http.missing_csp",
            title="Content-Security-Policy header missing",
            severity=Severity.MEDIUM, surface="dynamic", target=host,
            evidence=f"GET / -> {status}; CSP absent",
            remediation="Define a CSP appropriate for the app (start with report-only)",
            cwe="CWE-693",
        ))
    if "x-content-type-options" not in headers:
        findings.append(Finding(
            rule_id="argus.http.missing_xcto",
            title="X-Content-Type-Options header missing",
            severity=Severity.LOW, surface="dynamic", target=host,
            remediation='Add `X-Content-Type-Options: nosniff`',
        ))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(Finding(
            rule_id="argus.http.missing_xfo",
            title="X-Frame-Options header missing (no CSP frame-ancestors)",
            severity=Severity.LOW, surface="dynamic", target=host,
            remediation="Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'self'`",
        ))
    server = headers.get("server", "")
    if server:
        findings.append(Finding(
            rule_id="argus.http.server_banner",
            title=f"Server header reveals product: {server!r}",
            severity=Severity.INFO, surface="dynamic", target=host,
            evidence=f"Server: {server}",
            remediation="Strip server identifiers; configure server_tokens off",
        ))
        if "apache-coyote" in server.lower():
            findings.append(Finding(
                rule_id="argus.http.tomcat_coyote_banner",
                title="Apache Tomcat (Coyote) banner — check CVE-2025-24813/55752",
                severity=Severity.HIGH, surface="dynamic", target=host,
                evidence=f"Server: {server}",
                remediation="Patch Tomcat to >=9.0.109 / 10.1.45 / 11.0.11; disable rewrite valve if unused",
                references=("https://nvd.nist.gov/vuln/detail/CVE-2025-24813",),
            ))
    return findings


def _probe_git_exposure(host: str) -> Iterable[Finding]:
    url = f"https://{host}/.git/config"
    result = _https_request("GET", url)
    if not result:
        return []
    status, _headers, body = result
    if status == 200 and b"[core]" in body:
        return [Finding(
            rule_id="argus.http.dotgit_exposed",
            title="/.git/config publicly readable — source-code leak",
            severity=Severity.CRITICAL, surface="dynamic", target=host,
            location=url, evidence=body[:120].decode("utf-8", errors="replace"),
            remediation="Deny `/.git/` at the web server; ensure deploy artifacts strip it",
            references=("https://owasp.org/www-community/attacks/Forced_browsing",),
        )]
    return []


def _probe_actuator(host: str) -> Iterable[Finding]:
    url = f"https://{host}/actuator"
    result = _https_request("GET", url)
    if not result:
        return []
    status, headers, body = result
    if status == 200 and ("spring" in headers.get("content-type", "").lower()
                          + body[:200].decode("utf-8", errors="replace").lower()):
        return [Finding(
            rule_id="argus.http.spring_actuator_open",
            title="/actuator exposed — Spring Boot management endpoints",
            severity=Severity.HIGH, surface="dynamic", target=host, location=url,
            remediation='Restrict actuator endpoints; `management.endpoints.web.exposure.include=health`',
            references=("https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",),
        )]
    return []


def _probe_next_action(host: str) -> Iterable[Finding]:
    url = f"https://{host}/_next/data/probe"
    result = _https_request("POST", url, body=b"null")
    if not result:
        return []
    status, headers, _body = result
    if "text/x-component" in headers.get("content-type", "") or status in {200, 400, 405}:
        return [Finding(
            rule_id="argus.http.react2shell_fingerprint",
            title="Next.js _next handler responded — CVE-2025-55182 React2Shell candidate",
            severity=Severity.HIGH, surface="dynamic", target=host, location=url,
            evidence=f"POST /_next/data/probe -> {status}; ct={headers.get('content-type', '')}",
            remediation="Upgrade Next.js to a patched release; confirm RSC deserialization is hardened",
            references=("https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp",),
        )]
    return []


def _probe_redis_unauth(host: str) -> Iterable[Finding]:
    try:
        with socket.create_connection((host, 6379), timeout=3.0) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(64)
    except OSError:
        return []
    if data.startswith(b"+PONG"):
        return [Finding(
            rule_id="argus.http.redis_unauth",
            title="Redis on :6379 answered PING without auth (RediShell vector CVE-2025-49844)",
            severity=Severity.CRITICAL, surface="dynamic",
            target=f"{host}:6379",
            evidence=data[:32].decode("utf-8", errors="replace"),
            remediation="Bind Redis to loopback / enable `requirepass`; disable Lua if unused",
            references=("https://redis.io/blog/security-advisory-cve-2025-49844/",),
        )]
    return []


def passive_probe(vault: Vault, token: str, host: str) -> list[Finding]:
    vault.require_scope(token, "http:passive", "http_host", host)
    findings = list(_passive(host))
    findings.sort(key=Finding.rank, reverse=True)
    return findings


def active_probe(vault: Vault, token: str, host: str) -> list[Finding]:
    vault.require_scope(token, "http:active", "http_host", host)
    findings: list[Finding] = []
    findings.extend(_probe_git_exposure(host))
    findings.extend(_probe_actuator(host))
    findings.extend(_probe_next_action(host))
    findings.extend(_probe_redis_unauth(host))
    findings.sort(key=Finding.rank, reverse=True)
    return findings
