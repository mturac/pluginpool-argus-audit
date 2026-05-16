"""Enrich findings with intel-cache data.

Scanners emit ``Finding`` records that often reference public CVE pages in
``references``. The cache populated by ``argus intel-update`` holds CVSS, EPSS
and KEV flags for those CVEs. This module joins the two: it walks a
``FindingSet`` and, for every CVE-ID referenced (in ``references`` or
``title``), looks up the cache and produces a new ``Finding`` with ``cvss``,
``epss`` and ``kev`` populated.

The function is intentionally pure — it returns a new ``FindingSet``; the
caller decides whether to replace the original. The cache lookup is
best-effort: a CVE missing from the cache leaves the finding untouched.
"""

from __future__ import annotations

import dataclasses
import re

from .findings import Finding, FindingSet, Severity


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _extract_cves(finding: Finding) -> list[str]:
    """Return every distinct CVE-ID mentioned by the finding."""
    seen: list[str] = []
    haystacks = (finding.title, finding.rule_id, finding.evidence) + tuple(finding.references)
    for text in haystacks:
        for match in _CVE_RE.findall(text or ""):
            cve = match.upper()
            if cve not in seen:
                seen.append(cve)
    return seen


def enrich(fs: FindingSet, cache) -> FindingSet:
    """Return a copy of ``fs`` with intel data populated where available."""
    out = FindingSet()
    for finding in fs.findings:
        cves = _extract_cves(finding)
        if not cves:
            out.add(finding)
            continue
        # When a finding references multiple CVEs (e.g. a chained advisory),
        # take the worst across all of them — the operator should see the
        # ceiling, not whichever ID happens to be first in the references
        # tuple. (MiMo review #8.)
        cvss = finding.cvss
        epss = finding.epss
        kev = finding.kev
        for cve in cves:
            rec = cache.lookup(cve)
            if rec is None:
                continue
            if rec.cvss is not None:
                cvss = rec.cvss if cvss is None else max(cvss, float(rec.cvss))
            if rec.epss is not None:
                epss = rec.epss if epss is None else max(epss, float(rec.epss))
            if rec.kev:
                kev = True
        # If the cache delivered a CVSS that is strictly higher severity than
        # the scanner's static guess, promote the severity. We never demote —
        # static evidence is still ground truth.
        severity = finding.severity
        if cvss is not None:
            promoted = Severity.from_cvss(cvss)
            if promoted > severity:
                severity = promoted
        out.add(dataclasses.replace(
            finding,
            cvss=cvss, epss=epss, kev=kev, severity=severity,
        ))
    return out


__all__ = ["enrich"]
