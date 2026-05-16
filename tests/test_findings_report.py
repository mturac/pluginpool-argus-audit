"""Tests for the Finding model and report renderers."""

from __future__ import annotations

import json

import pytest

from argus.findings import Finding, FindingSet, Severity
from argus.report import render, render_json, render_markdown, render_text


def _fixture_set() -> FindingSet:
    fs = FindingSet()
    fs.add(Finding(rule_id="argus.x.low", title="minor", severity=Severity.LOW,
                   surface="static", target="/p"))
    fs.add(Finding(rule_id="argus.x.critical", title="big one", severity=Severity.CRITICAL,
                   surface="dynamic", target="example.com",
                   cvss=9.8, epss=0.95, kev=True, cwe="CWE-79",
                   remediation="patch X",
                   references=("https://nvd.nist.gov/vuln/detail/CVE-2025-55182",)))
    fs.add(Finding(rule_id="argus.x.medium", title="meh", severity=Severity.MEDIUM,
                   surface="supply_chain", target="/p", epss=0.1))
    return fs


def test_severity_from_cvss_bands():
    assert Severity.from_cvss(9.5) is Severity.CRITICAL
    assert Severity.from_cvss(7.5) is Severity.HIGH
    assert Severity.from_cvss(5.0) is Severity.MEDIUM
    assert Severity.from_cvss(1.0) is Severity.LOW
    assert Severity.from_cvss(None) is Severity.INFO


def test_findingset_sort_puts_critical_first():
    ordered = _fixture_set().sorted()
    assert ordered[0].rule_id == "argus.x.critical"
    assert ordered[-1].rule_id == "argus.x.low"


def test_findingset_summary_counts():
    summary = _fixture_set().summary()
    assert summary["CRITICAL"] == 1
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1


def test_render_text_contains_worst_line():
    out = render_text(_fixture_set(), target_label="demo")
    assert "Worst severity: CRITICAL" in out
    assert "argus.x.critical" in out
    assert "KEV" in out


def test_render_json_is_valid_and_sorted():
    out = json.loads(render_json(_fixture_set(), target_label="demo"))
    assert out["worst"] == "CRITICAL"
    assert out["findings"][0]["rule_id"] == "argus.x.critical"


def test_render_markdown_has_section_headers():
    out = render_markdown(_fixture_set(), target_label="demo")
    assert "# argus-audit report" in out
    assert "| CRITICAL | 1 |" in out


def test_render_dispatcher_handles_aliases():
    fs = _fixture_set()
    assert render(fs, "text") == render_text(fs)
    assert render(fs, "json") == render_json(fs)
    assert render(fs, "md") == render_markdown(fs)


def test_render_dispatcher_refuses_unknown():
    with pytest.raises(ValueError):
        render(_fixture_set(), "yaml")


def test_empty_findingset_renders_cleanly():
    fs = FindingSet()
    assert "No findings" in render_text(fs)
    js = json.loads(render_json(fs))
    assert js["findings"] == []
    assert js["worst"] == "INFO"
