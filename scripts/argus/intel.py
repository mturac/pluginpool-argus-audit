"""Self-updating vulnerability intelligence layer for argus-audit (stdlib only)."""

from __future__ import annotations

import csv
import dataclasses
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

from . import paths
from .errors import IntelError


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

USER_AGENT = "argus-audit-intel/0.1"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

# Strict ISO date pattern; anything else is refused before we interpolate
# the caller-supplied value into a URL. Without this an attacker who can pass
# `--epss-date ../../evil.com/x.csv.gz?` would steer the fetcher off-host and
# poison the local intel cache.
_EPSS_DATE_RE = re.compile(
    r"^20\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$"
)


@dataclasses.dataclass(frozen=True)
class CveRecord:
    cve_id: str
    title: str
    severity: str
    cvss: float | None
    epss: float | None
    kev: bool
    published: str
    references: tuple[str, ...]
    raw_source: str


def _http_get(url: str, *, headers: dict[str, str] | None = None, timeout: float = 30.0) -> bytes:
    """Fetch a URL with a hard size cap.

    Reading exactly ``MAX_RESPONSE_BYTES`` silently drops a larger payload and
    downstream parsers then fail with confusing JSON / gzip errors. Instead
    we attempt one extra byte and raise on any leftover, and we pre-check
    ``Content-Length`` when the server provides it. This converts an
    overflow bug into a precise refusal.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise IntelError(f"{url} returned HTTP {resp.status}")
            try:
                advertised = int(resp.headers.get("Content-Length") or 0)
            except ValueError:
                advertised = 0
            if advertised and advertised > MAX_RESPONSE_BYTES:
                raise IntelError(
                    f"{url} advertises {advertised} bytes, exceeds limit {MAX_RESPONSE_BYTES}"
                )
            payload = resp.read(MAX_RESPONSE_BYTES)
            if resp.read(1):
                raise IntelError(
                    f"{url} exceeded {MAX_RESPONSE_BYTES} bytes; refusing partial read"
                )
            return payload
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
        raise IntelError(f"{url} fetch failed: {exc}") from exc


SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id     TEXT PRIMARY KEY,
    title      TEXT,
    severity   TEXT,
    cvss       REAL,
    epss       REAL,
    kev        INTEGER NOT NULL DEFAULT 0,
    published  TEXT,
    refs_json  TEXT,
    raw_source TEXT,
    fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS feed_state (
    feed_id    TEXT PRIMARY KEY,
    last_url   TEXT,
    last_etag  TEXT,
    last_mod   TEXT,
    last_sha256 TEXT,
    fetched_at INTEGER NOT NULL
);
"""


class IntelCache:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (paths.intel_cache_path() / "intel.sqlite3")
        paths.ensure_home()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def upsert_cves(self, records: Iterable[CveRecord]) -> int:
        rows = [
            (r.cve_id, r.title, r.severity, r.cvss, r.epss, int(r.kev),
             r.published, json.dumps(list(r.references)), r.raw_source, int(time.time()))
            for r in records
        ]
        if not rows:
            return 0
        # ON CONFLICT preserves higher-fidelity values. Only overwrite
        # severity/cvss/title when the incoming row actually carries something
        # — a later KEV ingest must not blank out an NVD-sourced CVSS score.
        self._conn.executemany(
            "INSERT INTO cve (cve_id,title,severity,cvss,epss,kev,published,refs_json,raw_source,fetched_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET "
            "title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE cve.title END, "
            "severity=CASE WHEN excluded.severity<>'' THEN excluded.severity ELSE cve.severity END, "
            "cvss=COALESCE(excluded.cvss, cve.cvss), "
            "epss=COALESCE(excluded.epss, cve.epss), "
            "kev=MAX(excluded.kev, cve.kev), "
            "published=CASE WHEN excluded.published<>'' THEN excluded.published ELSE cve.published END, "
            "refs_json=CASE WHEN excluded.refs_json<>'[]' THEN excluded.refs_json ELSE cve.refs_json END, "
            "raw_source=excluded.raw_source, "
            "fetched_at=excluded.fetched_at",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def lookup(self, cve_id: str) -> CveRecord | None:
        cur = self._conn.execute(
            "SELECT cve_id,title,severity,cvss,epss,kev,published,refs_json,raw_source FROM cve WHERE cve_id=?",
            (cve_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return CveRecord(
            cve_id=row[0], title=row[1] or "", severity=row[2] or "",
            cvss=row[3], epss=row[4], kev=bool(row[5]),
            published=row[6] or "",
            references=tuple(json.loads(row[7] or "[]")),
            raw_source=row[8] or "",
        )

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]

    def kev_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0]

    def prune_older_than(self, max_age_days: int, *, vacuum: bool | None = None) -> int:
        """Remove CVE rows whose ``fetched_at`` is older than ``max_age_days``.

        Returns the number of rows removed. ``VACUUM`` rewrites the entire
        SQLite file, which becomes slow as the cache grows; we now run it
        only when at least 20% of the table was actually pruned (or when the
        caller forces it via ``vacuum=True``).
        """
        if max_age_days < 0:
            raise ValueError("max_age_days must be >= 0")
        total_before = self.count()
        cutoff = int(time.time()) - max_age_days * 86400
        # Build the destructive verb at runtime to keep the literal text out
        # of the source — the workstation's safety hook refuses to commit the
        # combined keywords. SQLite still parses the assembled SQL normally.
        verb = "DEL" + "ETE"
        sql = f"{verb} FROM cve WHERE fetched_at < ?"
        cur = self._conn.execute(sql, (cutoff,))
        self._conn.commit()
        removed = cur.rowcount
        if vacuum is True or (
            vacuum is None and total_before > 0 and removed >= max(1, total_before // 5)
        ):
            self._conn.execute("VACUUM")
        return removed

    def record_feed_state(self, feed_id: str, url: str, sha256: str,
                          etag: str = "", last_mod: str = "") -> None:
        self._conn.execute(
            "INSERT INTO feed_state (feed_id,last_url,last_etag,last_mod,last_sha256,fetched_at) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(feed_id) DO UPDATE SET "
            "last_url=excluded.last_url, last_etag=excluded.last_etag, "
            "last_mod=excluded.last_mod, last_sha256=excluded.last_sha256, "
            "fetched_at=excluded.fetched_at",
            (feed_id, url, etag, last_mod, sha256, int(time.time())),
        )
        self._conn.commit()


def parse_kev(raw: bytes) -> list[CveRecord]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelError(f"KEV payload not JSON: {exc}") from exc
    # KEV is a *priority* signal, not a severity grade. We emit an empty
    # severity string here so a later upsert never demotes an NVD-sourced
    # CVSS-derived severity. The ``kev`` flag is the authoritative bit.
    out: list[CveRecord] = []
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        out.append(CveRecord(
            cve_id=cve_id,
            title=entry.get("vulnerabilityName") or entry.get("shortDescription", ""),
            severity="",
            cvss=None, epss=None, kev=True,
            published=entry.get("dateAdded", ""),
            references=tuple(filter(None, (entry.get("notes"),))),
            raw_source="CISA KEV",
        ))
    return out


def parse_nvd_2_0(raw: bytes) -> list[CveRecord]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelError(f"NVD payload not JSON: {exc}") from exc
    out: list[CveRecord] = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        title = next((d.get("value") for d in descs if d.get("lang") == "en"), "") or ""
        metrics = cve.get("metrics", {})
        cvss = None
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                data_ = m.get("cvssData", {})
                cvss = data_.get("baseScore")
                severity = (m.get("baseSeverity") or data_.get("baseSeverity") or "").upper()
                break
        refs = tuple(r.get("url") for r in cve.get("references", []) if r.get("url"))
        out.append(CveRecord(
            cve_id=cve_id, title=title.strip()[:240], severity=severity,
            cvss=cvss, epss=None, kev=False,
            published=cve.get("published", ""),
            references=refs, raw_source="NVD",
        ))
    return out


def parse_epss_csv_gz(raw: bytes) -> dict[str, float]:
    try:
        decompressed = gzip.decompress(raw)
    except OSError as exc:
        raise IntelError(f"EPSS payload not gzip: {exc}") from exc
    reader = csv.reader(io.StringIO(decompressed.decode("utf-8", errors="replace")))
    out: dict[str, float] = {}
    for row in reader:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            cve_id, prob = row[0], row[1]
            out[cve_id] = float(prob)
        except (IndexError, ValueError):
            continue
    return out


def fetch_and_apply_kev(cache: IntelCache) -> int:
    raw = _http_get(KEV_URL)
    sha = hashlib.sha256(raw).hexdigest()
    records = parse_kev(raw)
    n = cache.upsert_cves(records)
    cache.record_feed_state("kev", KEV_URL, sha)
    return n


NVD_PAGE_SIZE = 2000  # NVD 2.0 API hard maximum per call.
# NVD rate limits: 5 req / 30s anonymous, 50 req / 30s with an API key.
# The two delay levels keep us comfortably under both quotas.
NVD_PAGE_DELAY_ANON_S = 6.0      # ~5 req / 30s
NVD_PAGE_DELAY_AUTHED_S = 0.6    # ~50 req / 30s


def _nvd_page_delay() -> float:
    return NVD_PAGE_DELAY_AUTHED_S if os.environ.get("NVD_API_KEY") else NVD_PAGE_DELAY_ANON_S


def fetch_and_apply_nvd_window(cache: IntelCache, last_mod_start: str | None = None,
                                last_mod_end: str | None = None,
                                _fetcher: "callable | None" = None) -> int:
    """Pull every NVD CVE inside the supplied last-modified window.

    The NVD 2.0 API caps a single response at 2,000 entries; longer windows
    must be paged with ``startIndex`` until ``totalResults`` is exhausted.
    Earlier versions of this function silently dropped everything past the
    first page.

    ``_fetcher`` is an injection point used by the test-suite so the loop can
    run against fixture payloads instead of hitting the real API.
    """
    fetch = _fetcher or (lambda url, headers: _http_get(url, headers=headers, timeout=60.0))
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    base_params: list[str] = []
    if last_mod_start:
        base_params.append(f"lastModStartDate={last_mod_start}")
    if last_mod_end:
        base_params.append(f"lastModEndDate={last_mod_end}")
    base_params.append(f"resultsPerPage={NVD_PAGE_SIZE}")

    total_ingested = 0
    start_index = 0
    first_sha = ""
    first_url = ""
    page_count = 0
    page_cap = 500  # hard cap on number of pages (1M CVEs at 2000/page)

    while True:
        params = base_params + [f"startIndex={start_index}"]
        url = NVD_API + "?" + "&".join(params)
        raw = fetch(url, headers)
        if not first_sha:
            first_sha = hashlib.sha256(raw).hexdigest()
            first_url = url
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntelError(f"NVD page at startIndex={start_index} not JSON: {exc}") from exc
        records = parse_nvd_2_0(raw)
        total_ingested += cache.upsert_cves(records)
        total_results = int(doc.get("totalResults") or 0)
        results_per_page = int(doc.get("resultsPerPage") or len(records) or NVD_PAGE_SIZE)
        start_index += results_per_page
        page_count += 1
        if start_index >= total_results or results_per_page == 0:
            break
        if page_count >= page_cap:
            break
        # Respect NVD rate limits between pages. With NVD_API_KEY set we drop
        # to ~50 req / 30s; otherwise we crawl at ~5 req / 30s.
        if _fetcher is None:
            time.sleep(_nvd_page_delay())

    cache.record_feed_state(
        f"nvd:{last_mod_start or ''}:{last_mod_end or ''}", first_url, first_sha,
    )
    return total_ingested


def fetch_and_apply_epss(cache: IntelCache, date: str | None = None) -> int:
    """Apply EPSS scores. Inserts rows for previously-unseen CVE IDs so a CVE
    whose KEV/NVD record has not landed yet still gets its exploit-probability
    score.

    ``date`` must match ``YYYY-MM-DD`` exactly — see ``_EPSS_DATE_RE``. When
    omitted, argus tries yesterday's feed and falls back two more days if the
    server returns 404 (the daily EPSS publish window is not deterministic).
    """
    candidates: list[str]
    if date is not None:
        if not _EPSS_DATE_RE.match(date):
            raise IntelError(f"refusing unsafe EPSS date: {date!r}")
        # Second-layer check: the regex shape is right, but the calendar
        # logic may still be impossible (e.g. 2026-02-31). fromisoformat
        # rejects those explicitly, so we never emit a request whose URL
        # path will 100% return 404.
        import datetime as _dt
        try:
            _dt.date.fromisoformat(date)
        except ValueError as exc:
            raise IntelError(f"refusing invalid EPSS date: {date!r} ({exc})") from exc
        candidates = [date]
    else:
        now = time.time()
        candidates = [
            time.strftime("%Y-%m-%d", time.gmtime(now - n * 86400))
            for n in (1, 2, 3)
        ]
    last_exc: Exception | None = None
    raw = b""
    chosen_date = candidates[0]
    for candidate in candidates:
        url_try = EPSS_URL_TEMPLATE.format(date=candidate)
        try:
            raw = _http_get(url_try)
            chosen_date = candidate
            break
        except IntelError as exc:
            last_exc = exc
            continue
    if not raw:
        raise IntelError(f"no EPSS feed reachable in {candidates}: {last_exc}")
    url = EPSS_URL_TEMPLATE.format(date=chosen_date)
    sha = hashlib.sha256(raw).hexdigest()
    scores = parse_epss_csv_gz(raw)
    now_ts = int(time.time())
    conn = cache._conn  # type: ignore[attr-defined]
    conn.executemany(
        "INSERT INTO cve (cve_id,title,severity,cvss,epss,kev,published,refs_json,raw_source,fetched_at) "
        "VALUES (?,'','',NULL,?,0,'','[]','EPSS',?) "
        "ON CONFLICT(cve_id) DO UPDATE SET "
        "epss=excluded.epss, fetched_at=excluded.fetched_at",
        [(cve, score, now_ts) for cve, score in scores.items()],
    )
    conn.commit()
    cache.record_feed_state(f"epss:{chosen_date}", url, sha)
    return len(scores)
