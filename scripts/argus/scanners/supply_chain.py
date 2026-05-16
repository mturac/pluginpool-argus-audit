"""Supply-chain scanner for argus-audit."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from ..authz import Vault
from ..findings import Finding, Severity


KNOWN_MALICIOUS_NPM = frozenset({
    "rxnt-authentication",
    "rxnt-disposition",
    "rxnt-healthchecks-nestjs",
    "rxnt-kue",
})

TOP_NPM = ("react", "lodash", "express", "axios", "chalk", "debug", "left-pad")
TOP_PYPI = ("requests", "urllib3", "numpy", "pandas", "pyyaml", "click", "django")


_PINNED_NPM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([-+][A-Za-z0-9.\-]+)?$")


def _is_unpinned_npm_version(ver: str) -> bool:
    """Return True for any npm version spec that isn't a strict semver literal.

    Strict means ``MAJOR.MINOR.PATCH`` (optionally with a pre-release or build
    metadata suffix). Anything else — ``^1.0``, ``~1.0``, ``>=1.0``, ``1.x``,
    ``*``, ``latest``, range ``1.0 - 2.0``, git URLs — is unpinned.
    """
    cleaned = (ver or "").strip()
    if not cleaned:
        return True
    if cleaned.lower() in {"latest", "next", "rc", "beta"}:
        return True
    return _PINNED_NPM_VERSION_RE.match(cleaned) is None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            row[j] = min(row[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = row
    return prev[-1]


def _within_squat_distance(candidate: str, canonical: str, max_distance: int = 2) -> bool:
    """Cheap pre-filter before the full Levenshtein run.

    A name whose length differs by more than ``max_distance`` cannot possibly
    fit within that edit distance, so we skip the O(n*m) cell loop entirely.
    On a typical requirements.txt this turns the typosquat check from
    quadratic into near-linear.
    """
    if candidate == canonical:
        return False
    if abs(len(candidate) - len(canonical)) > max_distance:
        return False
    return _levenshtein(candidate, canonical) <= max_distance


def _parse_requirement_line(raw: str) -> tuple[str, str] | None:
    """Return ``(name, operator)`` for a single ``requirements.txt`` line.

    Handles, in order:
        - inline ``#`` comments
        - ``-r``/``-c``/``--option`` lines (skipped)
        - direct VCS / URL installs (``git+``, ``hg+``, ``svn+``, ``http``)
        - environment markers (``;`` and everything after)
        - extras (``pkg[extra1,extra2]``)
        - version specifier (``==``, ``===``, ``~=``, ``>=`` …)

    Returns ``None`` when the line carries no scannable dependency name.
    """
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    if line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file://")):
        return None
    # PEP 508 direct reference (``pkg @ https://...``). Treat as pinned —
    # the explicit URL is the version contract — and skip the unpinned check.
    if " @ " in line or "@ " in line.split("[", 1)[0]:
        return None
    # Drop environment marker.
    if ";" in line:
        line = line.split(";", 1)[0].strip()
    # Drop extras (``pkg[a,b]==1.0`` → ``pkg==1.0``).
    line = re.sub(r"\[[^\]]*\]", "", line)
    # Require either end-of-string or a recognised operator immediately after
    # the name. Anything else (e.g. ``pkg junk``) is ambiguous syntax and we
    # refuse to guess.
    m = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(===|==|>=|<=|!=|~=|>|<)?\s*([A-Za-z0-9._\-+*!]*)\s*$",
        line,
    )
    if not m:
        return None
    return m.group(1).lower(), (m.group(2) or "")


def _scan_requirements_txt(path: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        parsed = _parse_requirement_line(raw)
        if parsed is None:
            continue
        name, op = parsed
        if op not in {"==", "==="}:
            findings.append(Finding(
                rule_id="argus.supply.python.unpinned",
                title=f"Unpinned Python dependency: {name}",
                severity=Severity.MEDIUM, surface="supply_chain",
                target=str(path), location=f"{path}:{lineno}",
                evidence=raw.strip(),
                remediation="Pin with `==X.Y.Z`; use `pip freeze` or a lockfile",
                references=("https://owasp.org/Top10/2025/",),
            ))
        for canonical in TOP_PYPI:
            if _within_squat_distance(name, canonical):
                findings.append(Finding(
                    rule_id="argus.supply.python.typosquat_candidate",
                    title=f"Potential typosquat: '{name}' is close to '{canonical}'",
                    severity=Severity.HIGH, surface="supply_chain",
                    target=str(path), location=f"{path}:{lineno}",
                    evidence=raw.strip(),
                    remediation=f"Confirm authorship; intended `{canonical}`?",
                ))
    return findings


def _scan_package_json(path: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    for section in sections:
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            lname = name.lower()
            if lname in KNOWN_MALICIOUS_NPM:
                findings.append(Finding(
                    rule_id="argus.supply.npm.known_malicious",
                    title=f"Known-malicious npm package: {name}",
                    severity=Severity.CRITICAL, surface="supply_chain",
                    target=str(path), location=f"{path}:{section}.{name}",
                    evidence=f"{name}@{ver}",
                    remediation="Remove dependency, rotate build tokens, audit logs",
                    references=("https://blog.qualys.com/vulnerabilities-threat-research/2025/09/10/when-dependencies-turn-dangerous-responding-to-the-npm-supply-chain-attack/",),
                ))
            if isinstance(ver, str) and _is_unpinned_npm_version(ver):
                findings.append(Finding(
                    rule_id="argus.supply.npm.unpinned",
                    title=f"Unpinned npm dependency: {name}",
                    severity=Severity.MEDIUM, surface="supply_chain",
                    target=str(path), location=f"{path}:{section}.{name}",
                    evidence=f"{name}: {ver}",
                    remediation="Pin to exact version + commit lockfile; use `npm ci` in CI",
                ))
            for canonical in TOP_NPM:
                if _within_squat_distance(lname, canonical):
                    findings.append(Finding(
                        rule_id="argus.supply.npm.typosquat_candidate",
                        title=f"Potential typosquat: '{name}' is close to '{canonical}'",
                        severity=Severity.HIGH, surface="supply_chain",
                        target=str(path), location=f"{path}:{section}.{name}",
                        evidence=f"{name}@{ver}",
                        remediation=f"Confirm authorship; intended `{canonical}`?",
                    ))
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for stage in ("preinstall", "install", "postinstall"):
            if stage in scripts:
                findings.append(Finding(
                    rule_id=f"argus.supply.npm.{stage}_script",
                    title=f"Install-time script defined: scripts.{stage}",
                    severity=Severity.HIGH, surface="supply_chain",
                    target=str(path), location=f"{path}:scripts.{stage}",
                    evidence=str(scripts[stage])[:120],
                    remediation="Audit script body; use `npm install --ignore-scripts` for untrusted trees",
                ))
    return findings


def _strip_yaml_comments(text: str) -> str:
    """Remove ``#`` comments from a YAML document without parsing it.

    Stdlib-only parser that handles the cases relevant to GHA workflows:

    - unquoted ``#`` to end-of-line is a comment
    - ``#`` inside single- or double-quoted scalars is preserved
    - backslash escapes (``\\'``, ``\\"``) inside double-quoted scalars are
      respected
    - block scalars (``|`` / ``>``) keep their bodies intact — lines indented
      below the block header pass through unchanged

    The function is deliberately conservative: anything ambiguous is left
    alone so a real ``permissions: write`` can never silently slip past the
    audit (false positives we tolerate; false negatives we do not).
    """
    out: list[str] = []
    block_indent: int | None = None  # indent of the block scalar body
    block_header_indent: int | None = None

    def _line_indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    block_header_re = re.compile(r":\s*[|>][+-]?\d*\s*$")

    def _is_block_header(cleaned: str) -> bool:
        """True if a comment-stripped line really opens a YAML block scalar.

        We scan from the right so that ``description: "Check for: |"`` (the
        ``|`` lives inside a quoted scalar) does not falsely arm the body
        skip. The check finds the colon-then-``|``/``>`` pattern and then
        verifies that the colon itself is not inside a string.
        """
        if not block_header_re.search(cleaned):
            return False
        # walk forward, track quote state, look for the colon-then-|/> sequence
        in_single = False
        in_double = False
        i = 0
        while i < len(cleaned):
            ch = cleaned[i]
            if in_double and ch == "\\" and i + 1 < len(cleaned):
                i += 2
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == ":" and not in_single and not in_double:
                # Is the remainder, stripped, a valid block-header tail?
                tail = cleaned[i + 1:].lstrip()
                if tail and tail[0] in "|>":
                    return True
            i += 1
        return False

    for line in text.splitlines():
        # Inside a block scalar — only end the block when we see a line at
        # or above the header's indent that isn't blank.
        if block_indent is not None:
            stripped_len = len(line.lstrip(" "))
            if stripped_len == 0:
                out.append(line)
                continue
            indent = _line_indent(line)
            if indent > (block_header_indent or 0):
                # still inside the scalar body — pass through verbatim
                out.append(line)
                continue
            # block ended; fall through to normal handling for this line.
            block_indent = None
            block_header_indent = None

        in_single = False
        in_double = False
        i = 0
        cut = len(line)
        while i < len(line):
            ch = line[i]
            if in_double and ch == "\\" and i + 1 < len(line):
                i += 2  # skip the escaped character
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                cut = i
                break
            i += 1
        cleaned = line[:cut].rstrip()
        out.append(cleaned)

        if _is_block_header(cleaned):
            block_header_indent = _line_indent(cleaned)
            block_indent = block_header_indent  # arms the body skip
    return "\n".join(out)


_GHA_EVENT_INTERPOLATION_RE = re.compile(r"\$\{\{\s*github\.event\.[^}]+\}\}")


def _run_blocks_with_event_interpolation(text: str) -> list[int]:
    """Return the line numbers of ``run:`` blocks that interpolate
    ``github.event.*`` inside the actual command body.

    A ``run: |`` opens a block scalar; lines indented strictly deeper than
    the ``run:`` key are inside the block until the indentation drops back.
    Single-line ``run: echo ...`` checks only that one line.
    """
    hits: list[int] = []
    lines = text.splitlines()
    run_re = re.compile(r"^(\s*-?\s*)run\s*:\s*(.*)$")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = run_re.match(line)
        if m:
            prefix, after = m.group(1), m.group(2).strip()
            indent = len(prefix)
            if after in {"|", ">", "|+", "|-", ">+", ">-"}:
                # Block scalar — collect indented body lines.
                body_lines: list[str] = []
                j = i + 1
                body_indent: int | None = None
                while j < len(lines):
                    if not lines[j].strip():
                        body_lines.append(lines[j])
                        j += 1
                        continue
                    cur_indent = len(lines[j]) - len(lines[j].lstrip())
                    if cur_indent <= indent:
                        break
                    if body_indent is None:
                        body_indent = cur_indent
                    body_lines.append(lines[j])
                    j += 1
                body = "\n".join(body_lines)
                if _GHA_EVENT_INTERPOLATION_RE.search(body):
                    hits.append(i + 1)
                i = j
                continue
            else:
                # Single-line run: only the same line counts.
                if _GHA_EVENT_INTERPOLATION_RE.search(after):
                    hits.append(i + 1)
        i += 1
    return hits


def _scan_github_actions(workflow_dir: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    if not workflow_dir.is_dir():
        return findings
    for path in workflow_dir.rglob("*.y*ml"):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = _strip_yaml_comments(raw)
        if "pull_request_target" in text and re.search(r"checkout@[^\s]+", text):
            findings.append(Finding(
                rule_id="argus.supply.gha.pwn_request",
                title="GHA workflow uses pull_request_target + actions/checkout (pwn-request risk)",
                severity=Severity.HIGH, surface="supply_chain",
                target=str(path), location=str(path),
                evidence="pull_request_target + checkout",
                remediation="Avoid checking out PR head under pull_request_target; gate on author",
                references=("https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",),
            ))
        for m in re.finditer(r"uses:\s*([^\s@]+)@([^\s#]+)", text):
            owner_repo, ref = m.group(1), m.group(2)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                if owner_repo.lower() in {"tj-actions/changed-files", "reviewdog/action-setup"}:
                    findings.append(Finding(
                        rule_id="argus.supply.gha.compromised_action",
                        title=f"Known-compromised GHA action without pinned SHA: {owner_repo}",
                        severity=Severity.CRITICAL, surface="supply_chain",
                        target=str(path), location=str(path),
                        evidence=f"{owner_repo}@{ref}",
                        remediation="Pin to a known-clean commit SHA; rotate CI secrets that ran",
                        references=("https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066",),
                    ))
                else:
                    findings.append(Finding(
                        rule_id="argus.supply.gha.unpinned_action",
                        title=f"Unpinned GHA action: {owner_repo}@{ref}",
                        severity=Severity.LOW, surface="supply_chain",
                        target=str(path), location=str(path),
                        evidence=f"{owner_repo}@{ref}",
                        remediation="Pin to a full 40-char commit SHA",
                    ))
        # Step-level script-injection check: only flag when the
        # ``${{ github.event.* }}`` actually appears in the body of a
        # ``run:`` block (not e.g. an ``if:`` guard or ``env:`` mapping).
        for run_line in _run_blocks_with_event_interpolation(text):
            findings.append(Finding(
                rule_id="argus.supply.gha.script_injection",
                title="GHA workflow interpolates github.event.* into a run: step",
                severity=Severity.HIGH, surface="supply_chain",
                target=str(path), location=f"{path}:{run_line}",
                evidence="run: ... ${{ github.event.* }}",
                remediation="Read event payload into an env var, then reference $VAR inside the script",
                references=("https://securitylab.github.com/resources/github-actions-untrusted-input/",),
            ))
        # Overly-permissive token scopes — `contents: write`, `actions: write`,
        # `id-token: write`, `packages: write`. The default GITHUB_TOKEN is
        # implicitly read-only when `permissions:` is unset, but write scopes
        # let an attacker who compromises a step push commits or publish
        # artifacts. The blanket `permissions: write-all` is equally bad.
        for scope in ("contents", "actions", "id-token", "packages",
                      "deployments", "pull-requests"):
            if re.search(rf"\b{re.escape(scope)}\s*:\s*write\b", text):
                findings.append(Finding(
                    rule_id=f"argus.supply.gha.permission_write_{scope.replace('-', '_')}",
                    title=f"GHA workflow grants `{scope}: write` to the job token",
                    severity=Severity.MEDIUM, surface="supply_chain",
                    target=str(path), location=str(path),
                    evidence=f"{scope}: write",
                    remediation=(
                        f"Restrict to the smallest required permission; if this"
                        f" job only reads, use `{scope}: read`."
                    ),
                    references=(
                        "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
                    ),
                ))
        if re.search(r"permissions\s*:\s*write-all\b", text):
            findings.append(Finding(
                rule_id="argus.supply.gha.permission_write_all",
                title="GHA workflow grants `write-all` to the job token",
                severity=Severity.HIGH, surface="supply_chain",
                target=str(path), location=str(path),
                evidence="permissions: write-all",
                remediation="Replace with the minimal explicit scope list",
                references=(
                    "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
                ),
            ))
    return findings


def scan(vault: Vault, token: str, root: str) -> list[Finding]:
    parsed = vault.require_scope(token, "supply_chain", "local_path", root)
    canonical = Path(parsed.target)
    findings: list[Finding] = []
    req = canonical / "requirements.txt"
    if req.exists():
        findings.extend(_scan_requirements_txt(req))
    pkg = canonical / "package.json"
    if pkg.exists():
        findings.extend(_scan_package_json(pkg))
    findings.extend(_scan_github_actions(canonical / ".github" / "workflows"))
    findings.sort(key=Finding.rank, reverse=True)
    return findings
