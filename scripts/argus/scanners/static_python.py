"""Python AST sink scanner for argus-audit."""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterable

from ..authz import Vault
from ..findings import Finding, Severity


_DANGEROUS_CALLS = {
    "eval":              ("argus.static.python.eval", "Dynamic eval() — arbitrary code execution sink", Severity.HIGH, "CWE-95", "Pass literal data or use ast.literal_eval()"),
    "exec":              ("argus.static.python.exec", "Dynamic exec() — arbitrary code execution sink", Severity.HIGH, "CWE-95", "Refactor to explicit dispatch; never exec user input"),
    "os.system":         ("argus.static.python.os_system", "os.system() invokes a shell — command injection sink", Severity.HIGH, "CWE-78", "Use subprocess.run([...], shell=False)"),
    "pickle.loads":      ("argus.static.python.pickle_loads", "pickle.loads() — deserialization RCE sink", Severity.CRITICAL, "CWE-502", "Switch to JSON or a typed format"),
    "pickle.load":       ("argus.static.python.pickle_load", "pickle.load() — deserialization RCE sink", Severity.CRITICAL, "CWE-502", "Switch to JSON or a typed format"),
    "marshal.loads":     ("argus.static.python.marshal_loads", "marshal.loads() — deserialization RCE sink", Severity.CRITICAL, "CWE-502", "Refuse marshal on untrusted input"),
    "yaml.load":         ("argus.static.python.yaml_load", "yaml.load() without SafeLoader — RCE sink", Severity.HIGH, "CWE-502", "Use yaml.safe_load() or Loader=yaml.SafeLoader"),
    "yaml.unsafe_load":  ("argus.static.python.yaml_unsafe_load", "yaml.unsafe_load() — RCE sink", Severity.CRITICAL, "CWE-502", "Use yaml.safe_load() instead"),
    "yaml.full_load":    ("argus.static.python.yaml_full_load", "yaml.full_load() — partial deserialization RCE risk", Severity.MEDIUM, "CWE-502", "Use yaml.safe_load() instead"),
    "subprocess.getoutput":       ("argus.static.python.subprocess_getoutput", "subprocess.getoutput() invokes a shell — command injection sink", Severity.HIGH, "CWE-78", "Use subprocess.run([...], shell=False, capture_output=True)"),
    "subprocess.getstatusoutput": ("argus.static.python.subprocess_getstatusoutput", "subprocess.getstatusoutput() invokes a shell — command injection sink", Severity.HIGH, "CWE-78", "Use subprocess.run([...], shell=False, capture_output=True) and inspect .returncode"),
    "os.popen":           ("argus.static.python.os_popen", "os.popen() invokes a shell — command injection sink", Severity.HIGH, "CWE-78", "Use subprocess.run([...], shell=False)"),
    "hashlib.md5":        ("argus.static.python.weak_hash_md5_direct", "hashlib.md5() — weak hash for auth/integrity", Severity.MEDIUM, "CWE-327", "Use SHA-256+; for password hashing use scrypt/argon2/bcrypt"),
    "hashlib.sha1":       ("argus.static.python.weak_hash_sha1_direct", "hashlib.sha1() — weak hash for auth/integrity", Severity.MEDIUM, "CWE-327", "Use SHA-256+; for password hashing use scrypt/argon2/bcrypt"),
}


_BUILTIN_SQL_RECEIVERS = frozenset({
    "cursor", "cur", "c", "conn", "connection", "db", "database",
    "session", "engine", "tx", "txn", "cnx", "client",
    "query", "pool", "ds", "datasource",
})


def _sql_receivers() -> frozenset[str]:
    """Built-in DB receiver names plus any names from ``ARGUS_SQL_RECEIVERS``.

    Operators with non-standard naming (e.g. ``results.execute(...)`` when
    ``results`` is in fact a SQL cursor) can set the env var to a
    comma-separated list of extra names. Configurable, no-dependency.
    """
    extra = os.environ.get("ARGUS_SQL_RECEIVERS", "")
    extras = frozenset(p.strip().lower() for p in extra.split(",") if p.strip())
    return _BUILTIN_SQL_RECEIVERS | extras


def _looks_like_db_receiver(node: ast.expr) -> bool:
    """Return True when ``node`` is an attribute chain ending in a DB-ish name.

    Accepts ``cursor``, ``conn.cursor``, ``self.db``, ``self.cursor`` etc.
    The match is on the trailing identifier of the chain — that's what
    SQLAlchemy / DB-API code looks like in the wild.
    """
    tail = ""
    if isinstance(node, ast.Name):
        tail = node.id
    elif isinstance(node, ast.Attribute):
        tail = node.attr
    elif isinstance(node, ast.Call):
        # ``conn.cursor().execute(...)`` — recurse into the call's func chain
        return _looks_like_db_receiver(node.func)
    return tail.lower() in _sql_receivers()


# Each rule's short-name (e.g. ``loads``) MUST belong to the listed module's
# namespace to count as a true hit. Plain identifiers (``eval``, ``exec``) have
# no module prefix — they're Python builtins, so we trust the bare match.
_DANGEROUS_CALLS_HEAD: dict[str, str | None] = {
    "eval": None,
    "exec": None,
    "system": "os",
    "popen": "os",
    "loads": "pickle",
    "load": "pickle",
    "unsafe_load": "yaml",
    "full_load": "yaml",
    "getoutput": "subprocess",
    "getstatusoutput": "subprocess",
    "md5": "hashlib",
    "sha1": "hashlib",
}


def qualified_head(node: ast.expr) -> str:
    """Return the leftmost identifier of a call's func expression."""
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _yaml_load_has_safe_loader(node: ast.Call) -> bool:
    """``yaml.load(stream, Loader=yaml.SafeLoader)`` is safe — don't flag it."""
    for kw in node.keywords:
        if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
            if kw.value.attr in {"SafeLoader", "CSafeLoader"}:
                return True
    # Positional Loader argument (yaml.load(stream, SafeLoader))
    if len(node.args) >= 2 and isinstance(node.args[1], (ast.Attribute, ast.Name)):
        a = node.args[1]
        name = a.attr if isinstance(a, ast.Attribute) else a.id
        if name in {"SafeLoader", "CSafeLoader"}:
            return True
    return False


def _is_sql_string_built_dynamically(node: ast.expr) -> bool:
    """True when ``node`` is the kind of expression that breeds SQL injection.

    Catches:
      - ``f"...{x}..."``                              (ast.JoinedStr)
      - ``"a" + x`` / ``"a" % x``                     (ast.BinOp)
      - ``"...{}".format(x)``                         (ast.Call -> Attribute -> Constant str)
      - ``"%s" % x``                                  (Mod BinOp, covered above)
    """
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)):
        return True
    return False


def _qualified_name(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _collect_imports(tree: ast.AST) -> dict[str, str]:
    """Map each local binding to its fully-qualified module path.

    ``import X``               → ``X`` → ``X``
    ``import X as Z``          → ``Z`` → ``X``
    ``import X.Y``             → ``X`` → ``X``  (preserves top-level binding only)
    ``import X.Y as Z``        → ``Z`` → ``X.Y``
    ``from X import Y``        → ``Y`` → ``X.Y``
    ``from X import Y as Z``   → ``Z`` → ``X.Y``

    The top-level-only rule for unaliased dotted imports prevents the
    pathological case ``import os.path; os.path.join(...)`` from resolving
    to ``os.path.path.join`` (MiMo review #2 finding).
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                qualified = f"{module}.{alias.name}" if module else alias.name
                aliases[local] = qualified
    return aliases


def _resolve_call_name(node: ast.expr, aliases: dict[str, str]) -> str:
    """Return the fully-qualified callable name resolved through ``aliases``.

    Substitutes the leading identifier (and only the leading identifier) with
    its mapped fully-qualified form, then re-joins the tail. The earlier
    implementation appended the full alias *and* the full tail, which doubled
    any overlap (e.g. ``os.path`` → ``os.path.path``) — MiMo review #2.
    """
    qualified = _qualified_name(node)
    if not qualified:
        return ""
    head, _, tail = qualified.partition(".")
    if head in aliases:
        base = aliases[head]
        return f"{base}.{tail}" if tail else base
    return qualified


def _scan_source(source: str, file_path: str) -> Iterable[Finding]:
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return ()
    aliases = _collect_imports(tree)
    findings: list[Finding] = []

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            name = _resolve_call_name(node.func, aliases)
            short = name.rsplit(".", 1)[-1] if "." in name else name
            # Only match dangerous calls if either:
            #   (a) the fully-qualified name exactly matches a rule, OR
            #   (b) the short name matches AND the alias map confirms the head
            #       binding maps to the expected module (no false positives for
            #       unrelated ``my_obj.eval()`` / ``logger.system()``).
            rule = _DANGEROUS_CALLS.get(name)
            if not rule and short in _DANGEROUS_CALLS:
                head = qualified_head(node.func)
                expected_prefix = _DANGEROUS_CALLS_HEAD.get(short)
                if expected_prefix is None or (head and aliases.get(head, head).split(".", 1)[0] == expected_prefix):
                    rule = _DANGEROUS_CALLS[short]
            if rule:
                rid, title, sev, cwe, fix = rule
                # yaml.load(...) with an explicit non-default Loader= is safe.
                if rid == "argus.static.python.yaml_load" and _yaml_load_has_safe_loader(node):
                    rule = None
            if rule:
                rid, title, sev, cwe, fix = rule
                findings.append(Finding(
                    rule_id=rid, title=title, severity=sev, surface="static",
                    target=file_path, location=f"{file_path}:{node.lineno}",
                    evidence=name + "(...)", remediation=fix, cwe=cwe,
                ))
            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                        "subprocess.check_call", "subprocess.check_output"}:
                for kw in node.keywords:
                    if kw.arg != "shell":
                        continue
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            findings.append(Finding(
                                rule_id="argus.static.python.subprocess_shell_true",
                                title=f"{name}(shell=True) — command-injection sink",
                                severity=Severity.HIGH, surface="static",
                                target=file_path, location=f"{file_path}:{node.lineno}",
                                evidence=f"{name}(shell=True)",
                                remediation="Pass args as a list and drop shell=True",
                                cwe="CWE-78",
                            ))
                        # ``shell=False`` literal is fine — no finding.
                    else:
                        # Non-literal: cannot prove the runtime value is False.
                        # Lower-severity warning so the operator can audit it.
                        findings.append(Finding(
                            rule_id="argus.static.python.subprocess_shell_dynamic",
                            title=f"{name}(shell=<expression>) — value not statically False",
                            severity=Severity.MEDIUM, surface="static",
                            target=file_path, location=f"{file_path}:{node.lineno}",
                            evidence=f"{name}(shell=<expr>)",
                            remediation="Pin shell=False statically, or assert the expression's value",
                            cwe="CWE-78",
                        ))
            # `.execute(f"...{x}")` is only flagged when the receiver name
            # matches a known SQL idiom — keeps the false-positive rate down
            # on unrelated `Executor.execute(...)` calls (MiMo review #6).
            # SQLAlchemy / Databases / Peewee expose `query(...)` as a SQL
            # entry point too; treat it identically to `execute(...)`. We
            # check both positional args[0] AND keyword args named
            # ``sql``/``query``/``statement`` (some libraries take the SQL by
            # keyword) and we recognise both f-string concat and the
            # ``"...{}".format(x)`` pattern.
            if (short in {"execute", "executemany", "query"}
                    and isinstance(node.func, ast.Attribute)
                    and _looks_like_db_receiver(node.func.value)):
                # Build the list of candidate SQL-carrying arguments.
                candidates: list[ast.expr] = []
                if node.args:
                    candidates.append(node.args[0])
                for kw in node.keywords:
                    if kw.arg in {"sql", "query", "statement", "stmt"}:
                        candidates.append(kw.value)
                arg = next((c for c in candidates if _is_sql_string_built_dynamically(c)), None)
                if arg is not None:
                    if isinstance(arg, ast.JoinedStr):
                        evidence = "cursor.execute(f\"...{x}\")"
                    elif isinstance(arg, ast.Call):
                        evidence = "cursor.execute(\"...{}\".format(x))"
                    else:
                        evidence = "cursor.execute(\"...\" + x)"
                    findings.append(Finding(
                        rule_id="argus.static.python.sql_string_concat",
                        title="SQL string built dynamically in execute()/query()",
                        severity=Severity.HIGH, surface="static",
                        target=file_path, location=f"{file_path}:{node.lineno}",
                        evidence=evidence,
                        remediation="Use parameterized queries (?, %s, :name) with execute(sql, params)",
                        cwe="CWE-89",
                    ))
            if short == "new" and isinstance(node.func, ast.Attribute):
                base = _qualified_name(node.func.value)
                if base == "hashlib" and node.args:
                    a = node.args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower() in {"md5", "sha1"}:
                        findings.append(Finding(
                            rule_id=f"argus.static.python.weak_hash_{a.value.lower()}",
                            title=f"hashlib.new({a.value!r}) — weak hash for auth/integrity",
                            severity=Severity.MEDIUM, surface="static",
                            target=file_path, location=f"{file_path}:{node.lineno}",
                            evidence=f"hashlib.new({a.value!r})",
                            remediation="Use SHA-256+; for password hashing use scrypt/argon2/bcrypt",
                            cwe="CWE-327",
                        ))
                    elif not isinstance(a, ast.Constant):
                        # Dynamic algorithm — cannot prove it's a safe one.
                        findings.append(Finding(
                            rule_id="argus.static.python.weak_hash_dynamic",
                            title="hashlib.new(<expression>) — algorithm not statically known",
                            severity=Severity.MEDIUM, surface="static",
                            target=file_path, location=f"{file_path}:{node.lineno}",
                            evidence="hashlib.new(<expr>)",
                            remediation="Pin a strong algorithm literal, or validate the input against an allowlist",
                            cwe="CWE-327",
                        ))
            self.generic_visit(node)

    _Visitor().visit(tree)
    return findings


def _walk_python_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            ".pytest_cache", ".tox", "dist", "build", ".mypy_cache",
        }]
        for name in filenames:
            if name.endswith(".py"):
                yield Path(dirpath) / name


def scan(vault: Vault, token: str, root: str) -> list[Finding]:
    parsed = vault.require_scope(token, "static:read", "local_path", root)
    canonical = Path(parsed.target)
    if not canonical.exists():
        return []
    findings: list[Finding] = []
    for file_path in _walk_python_files(canonical):
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_source(source, str(file_path)))
    findings.sort(key=Finding.rank, reverse=True)
    return findings
