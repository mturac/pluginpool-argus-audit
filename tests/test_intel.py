"""Tests for intel cache + feed parsers (offline)."""

from __future__ import annotations

import gzip
import json

import pytest

from argus import intel


def test_parse_kev_minimal():
    payload = json.dumps({
        "vulnerabilities": [
            {"cveID": "CVE-2024-3094", "vulnerabilityName": "XZ backdoor",
             "knownRansomwareCampaignUse": "Unknown", "dateAdded": "2024-04-01"},
            {"cveID": "CVE-2025-49844", "vulnerabilityName": "RediShell",
             "knownRansomwareCampaignUse": "Known", "dateAdded": "2025-10-03"},
        ]
    }).encode("utf-8")
    records = intel.parse_kev(payload)
    by_id = {r.cve_id: r for r in records}
    assert by_id["CVE-2024-3094"].kev is True
    assert by_id["CVE-2025-49844"].kev is True
    # KEV intentionally does not carry severity — CVSS comes from NVD.
    assert by_id["CVE-2024-3094"].severity == ""
    assert by_id["CVE-2025-49844"].severity == ""


def test_parse_kev_malformed_raises():
    with pytest.raises(intel.IntelError):
        intel.parse_kev(b"<not json>")


def test_parse_nvd_2_0_minimal():
    payload = json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2025-55182",
                "published": "2025-12-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "React2Shell"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"},
                                       "baseSeverity": "CRITICAL"}]
                },
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-55182"}],
            }
        }]
    }).encode("utf-8")
    records = intel.parse_nvd_2_0(payload)
    assert records[0].cvss == 10.0
    assert records[0].severity == "CRITICAL"


def test_parse_epss_csv_gz():
    csv_text = "cve,epss,percentile\nCVE-2024-3094,0.97,0.99\nCVE-2025-55182,0.85,0.95\n"
    payload = gzip.compress(csv_text.encode("utf-8"))
    scores = intel.parse_epss_csv_gz(payload)
    assert scores["CVE-2024-3094"] == 0.97
    assert scores["CVE-2025-55182"] == 0.85


def test_intel_cache_roundtrip(argus_home):
    cache = intel.IntelCache()
    records = intel.parse_kev(json.dumps({
        "vulnerabilities": [{"cveID": "CVE-2024-3094", "vulnerabilityName": "XZ",
                              "dateAdded": "2024-04-01"}]
    }).encode("utf-8"))
    assert cache.upsert_cves(records) == 1
    rec = cache.lookup("CVE-2024-3094")
    assert rec is not None and rec.kev is True
    assert cache.kev_count() == 1
    cache.close()


def test_feed_state_records(argus_home):
    cache = intel.IntelCache()
    cache.record_feed_state("kev", intel.KEV_URL, "deadbeef")
    rows = list(cache._conn.execute("SELECT feed_id,last_url,last_sha256 FROM feed_state"))
    assert rows == [("kev", intel.KEV_URL, "deadbeef")]
    cache.close()
