import datetime as dt
import gzip
import io
import json
import os
import re
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ENV_FILES = [
    os.environ.get("SECURITY_CORE_ENV_FILE", "/etc/security-core/security-core.env"),
    "/opt/security-core/.env",
]


def load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return values
    try:
        for raw in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                values[key] = value
    except Exception:
        pass
    return values


FILE_ENV: dict[str, str] = {}
for env_file in ENV_FILES:
    FILE_ENV.update(load_env_file(env_file))


def getenv_any(names: list[str], default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value is not None and str(value).strip() != "":
            return str(value).strip().strip('"').strip("'")
    for name in names:
        value = FILE_ENV.get(name)
        if value is not None and str(value).strip() != "":
            return str(value).strip().strip('"').strip("'")
    return default


DATABASE_URL = getenv_any(["DATABASE_URL"])
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

NVD_CVE_FEED_BASE = getenv_any(["NVD_CVE_FEED_BASE"], "https://nvd.nist.gov/feeds/json/cve/2.0")
NVD_CVE_MODIFIED_FEED = getenv_any(["NVD_CVE_MODIFIED_FEED"], f"{NVD_CVE_FEED_BASE}/nvdcve-2.0-modified.json.gz")
NVD_CPE_DICT_FEED = getenv_any(["NVD_CPE_DICT_FEED"], "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz")
NVD_CPE_MATCH_FEED = getenv_any(["NVD_CPE_MATCH_FEED"], "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz")
CISA_KEV_FEED_URL = getenv_any(["CISA_KEV_FEED_URL"], "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
VULN_MIRROR_DIR = Path(getenv_any(["VULN_MIRROR_DIR"], "/opt/security-core/data/vuln-mirror"))
VULN_IMPORT_BATCH_SIZE = int(getenv_any(["VULN_IMPORT_BATCH_SIZE"], "500"))
VULN_MAX_DEVICES_PER_RUN = int(getenv_any(["VULN_SYNC_MAX_DEVICES_PER_RUN"], "500"))
VULN_SYNC_ONLY_CONFIRMED = getenv_any(["VULN_SYNC_ONLY_CONFIRMED"], "false").lower() in {"1", "true", "yes", "on"}
VULN_MATCHERS_FILE = Path(getenv_any(["VULN_MATCHERS_FILE"], "/opt/security-core/config/vulnerability_matchers.json"))
HTTP_TIMEOUT = int(getenv_any(["VULN_HTTP_TIMEOUT"], "1800"))
HTTP_RETRIES = int(getenv_any(["VULN_HTTP_RETRIES"], "3"))
HTTP_BACKOFF_SECONDS = float(getenv_any(["VULN_HTTP_BACKOFF_SECONDS"], "5"))

DEFAULT_MATCHERS = {"rules": []}


def load_matchers() -> dict[str, Any]:
    paths = [
        VULN_MATCHERS_FILE,
        Path("/opt/security-core/vulnerability_matchers.json"),
        Path("/opt/security-core/app/worker/vulnerability_matchers.json"),
    ]
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return DEFAULT_MATCHERS


MATCHERS = load_matchers()


def log(message: str):
    print(message, flush=True)


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return str(value).strip()
    return str(value).strip()


def normalize_text(value: Any) -> str:
    return to_text(value).lower()


def normalize_uuid_text(value: Any) -> str:
    if value is None:
        raise ValueError("UUID value is required")
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 16:
            return str(uuid.UUID(bytes=raw))
        decoded = raw.decode("ascii", errors="ignore").strip()
        if decoded:
            return str(uuid.UUID(decoded))
        raise ValueError(f"Unsupported UUID bytes value: {raw!r}")
    text = to_text(value)
    if text.startswith("\\x") and len(text) == 34:
        return str(uuid.UUID(bytes=bytes.fromhex(text[2:])))
    return str(uuid.UUID(text))


UNICODE_REPLACEMENTS = str.maketrans(
    {
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "–": "-",
        "—": "-",
        "\u00a0": " ",
    }
)


def ascii_text(value: Any) -> str:
    return to_text(value).translate(UNICODE_REPLACEMENTS).encode("ascii", "ignore").decode("ascii")


def ascii_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {ascii_text(k): ascii_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [ascii_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [ascii_json_safe(v) for v in value]
    if isinstance(value, str):
        return ascii_text(value)
    return value


def j(value: Any) -> Jsonb:
    return Jsonb(ascii_json_safe(value))


def json_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def chunked(seq: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


_VERSION_TOKEN_RE = re.compile(r"[0-9]+|[A-Za-z]+")


def normalize_version(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    text = text.strip().lstrip("vV")
    return text or None


def tokenize_version(value: Any) -> list[Any]:
    text = normalize_version(value)
    if not text:
        return []
    out: list[Any] = []
    for token in _VERSION_TOKEN_RE.findall(text):
        out.append(int(token) if token.isdigit() else token.lower())
    return out


def compare_versions(left: Any, right: Any) -> int | None:
    a = tokenize_version(left)
    b = tokenize_version(right)
    if not a or not b:
        return None
    max_len = max(len(a), len(b))
    for idx in range(max_len):
        av = a[idx] if idx < len(a) else 0
        bv = b[idx] if idx < len(b) else 0
        if type(av) != type(bv):
            av = str(av)
            bv = str(bv)
        if av < bv:
            return -1
        if av > bv:
            return 1
    return 0


def extract_cpe_parts(cpe: Any) -> dict[str, str] | None:
    text = to_text(cpe)
    if not text or not text.startswith("cpe:2.3:"):
        return None
    parts = text.split(":")
    if len(parts) < 13:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
        "update": parts[6],
        "edition": parts[7],
        "language": parts[8],
        "sw_edition": parts[9],
        "target_sw": parts[10],
        "target_hw": parts[11],
        "other": parts[12],
    }


def extract_version_from_cpe(cpe: Any) -> str | None:
    parts = extract_cpe_parts(cpe)
    if not parts:
        return None
    version = to_text(parts.get("version"))
    return version if version not in {"", "*", "-"} else None


def iter_cpe_matches(configurations: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for config in configurations or []:
        nodes = config.get("nodes") if isinstance(config, dict) else None
        for node in nodes or []:
            for item in node.get("cpeMatch") or []:
                if isinstance(item, dict):
                    yield item
            for child in node.get("children") or []:
                for item in child.get("cpeMatch") or []:
                    if isinstance(item, dict):
                        yield item


def english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions") or []:
        if normalize_text(desc.get("lang")) == "en":
            return to_text(desc.get("value"))
    first = (cve.get("descriptions") or [{}])[0]
    return to_text(first.get("value"))


def cve_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        out.append(
            {
                "url": to_text(ref.get("url")),
                "source": to_text(ref.get("source")),
                "tags": [to_text(tag) for tag in ref.get("tags") or [] if to_text(tag)],
            }
        )
    return out


def best_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for key in order:
        for item in metrics.get(key) or []:
            cvss_data = item.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or item.get("baseSeverity")
            try:
                return float(score), to_text(severity) or None
            except Exception:
                continue
    return None, None


def severity_rank(severity: Any) -> int:
    value = normalize_text(severity)
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1, "unknown": 0}.get(value, 0)


def version_in_range(device_version: str | None, criteria: dict[str, Any]) -> bool | None:
    device_version = normalize_version(device_version)
    if not device_version:
        return None
    start = criteria.get("versionStartIncluding") or criteria.get("versionStartExcluding")
    end = criteria.get("versionEndIncluding") or criteria.get("versionEndExcluding")
    if not start and not end:
        criteria_version = extract_version_from_cpe(criteria.get("criteria") or criteria.get("cpe23Uri"))
        if criteria_version and criteria_version != "*":
            cmp = compare_versions(device_version, criteria_version)
            return cmp == 0 if cmp is not None else None
        return None
    if start:
        cmp = compare_versions(device_version, start)
        if cmp is None:
            return None
        if criteria.get("versionStartIncluding") and cmp < 0:
            return False
        if criteria.get("versionStartExcluding") and cmp <= 0:
            return False
    if end:
        cmp = compare_versions(device_version, end)
        if cmp is None:
            return None
        if criteria.get("versionEndIncluding") and cmp > 0:
            return False
        if criteria.get("versionEndExcluding") and cmp >= 0:
            return False
    return True


def recommendation_for(score: float | None, is_kev: bool, match_count: int) -> str:
    if is_kev:
        return "Nedelsiant atnaujinti arba izoliuoti; spraga yra aktyviai išnaudojama"
    if score is not None and score >= 9.0:
        return "Kritinis prioritetas: nedelsiant atnaujinti arba izoliuoti"
    if score is not None and score >= 7.0:
        return "Aukštas prioritetas: suplanuoti atnaujinimą artimiausiu metu"
    if match_count >= 5:
        return "Daug atitikimų: rekomenduojama patikrinti tikslų modelį ir firmware versiją"
    return "Stebėti, patikslinti įrenginio identitetą ir planuoti atnaujinimą"


def risk_score_from_summary(vuln_count: int, kev_count: int, highest_cvss: float | None) -> int:
    score = 0
    score += min(vuln_count * 5, 40)
    score += min(kev_count * 20, 40)
    if highest_cvss is not None:
        score += min(int(round(highest_cvss * 2)), 20)
    return max(0, min(score, 100))


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def requests_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "security-core-phase3-fullmirror/1.0"})
    return session


def http_get_bytes(url: str) -> bytes:
    last_error: Exception | None = None
    session = requests_session()
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            resp = session.get(url, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                time.sleep(HTTP_BACKOFF_SECONDS * attempt)
    raise RuntimeError(f"Failed to download {url}: {last_error}")


def http_get_json(url: str) -> dict[str, Any]:
    content = http_get_bytes(url)
    return json.loads(content.decode("utf-8", errors="ignore"))


def read_gzip_json_from_bytes(content: bytes) -> dict[str, Any]:
    with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
        return json.loads(gz.read().decode("utf-8", errors="ignore"))


def read_tar_json_from_bytes(content: bytes) -> dict[str, Any]:
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(".json"):
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                return json.loads(extracted.read().decode("utf-8", errors="ignore"))
    raise RuntimeError("No JSON file found inside tar.gz feed")


def ensure_data_dir():
    VULN_MIRROR_DIR.mkdir(parents=True, exist_ok=True)


def cache_file(name: str) -> Path:
    ensure_data_dir()
    return VULN_MIRROR_DIR / name


def download_to_cache(url: str, filename: str) -> Path:
    path = cache_file(filename)
    content = http_get_bytes(url)
    path.write_bytes(content)
    return path


def load_json_from_cached_gz(url: str, filename: str) -> dict[str, Any]:
    path = download_to_cache(url, filename)
    return read_gzip_json_from_bytes(path.read_bytes())


def load_json_from_cached_tar(url: str, filename: str) -> dict[str, Any]:
    path = download_to_cache(url, filename)
    return read_tar_json_from_bytes(path.read_bytes())


def feed_meta_url(feed_url: str) -> str:
    if feed_url.endswith(".json.gz"):
        return feed_url[:-8] + ".meta"
    if feed_url.endswith(".tar.gz"):
        return feed_url[:-7] + ".meta"
    raise ValueError(f"Unsupported feed URL: {feed_url}")


def fetch_feed_meta(feed_url: str) -> dict[str, str]:
    meta_url = feed_meta_url(feed_url)
    content = http_get_bytes(meta_url).decode("utf-8", errors="ignore")
    out: dict[str, str] = {}
    for token in content.split():
        if ":" not in token:
            continue
        key, value = token.split(":", 1)
        out[key.strip()] = value.strip()
    return out


def record_source_state(cur, source_name: str, last_cursor: str | None = None, etag: str | None = None, details: dict[str, Any] | None = None):
    cur.execute(
        """
        INSERT INTO vulnerability_source_state (source_name, last_success_at, last_cursor, etag, details_json, updated_at)
        VALUES (%s, now(), %s, %s, %s, now())
        ON CONFLICT (source_name) DO UPDATE
        SET last_success_at = EXCLUDED.last_success_at,
            last_cursor = EXCLUDED.last_cursor,
            etag = EXCLUDED.etag,
            details_json = EXCLUDED.details_json,
            updated_at = now()
        """,
        (source_name, last_cursor, etag, j(details or {})),
    )


def get_source_state(cur, source_name: str) -> dict[str, Any] | None:
    cur.execute("SELECT source_name, last_success_at, last_cursor, etag, details_json FROM vulnerability_source_state WHERE source_name = %s", (source_name,))
    row = cur.fetchone()
    return dict(row) if row else None


def iter_feed_cves(feed_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for item in feed_json.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, dict) and to_text(cve.get("id")):
            yield cve


def cve_to_catalog_row(cve: dict[str, Any], kev_map: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    kev_map = kev_map or {}
    cve_id = to_text(cve.get("id"))
    kev_row = kev_map.get(cve_id) or {}
    score, severity = best_cvss(cve)
    cpe_candidates: list[str] = []
    vendor_project = None
    product_name = None
    for match in iter_cpe_matches(cve.get("configurations") or []):
        criteria = to_text(match.get("criteria") or match.get("cpe23Uri"))
        if not criteria:
            continue
        cpe_candidates.append(criteria)
        parts = extract_cpe_parts(criteria)
        if parts:
            vendor_project = vendor_project or parts.get("vendor")
            product_name = product_name or parts.get("product")
    published = to_text(cve.get("published")) or None
    year = None
    try:
        year = int(to_text(cve_id).split("-")[1])
    except Exception:
        pass
    return {
        "cve_id": cve_id,
        "source_system": "nvd",
        "cve_year": year,
        "vendor_project": to_text(kev_row.get("vendor_project")) or vendor_project or None,
        "product_name": to_text(kev_row.get("product_name")) or product_name or None,
        "cpe_candidates": sorted(set(cpe_candidates)),
        "cvss_base_score": score,
        "cvss_severity": severity,
        "published_at": published,
        "last_modified_at": to_text(cve.get("lastModified")) or None,
        "description": english_description(cve) or to_text(kev_row.get("description")) or None,
        "references_json": cve_references(cve),
        "raw_json": cve,
        "is_kev": bool(kev_row.get("is_kev")),
        "kev_date_added": kev_row.get("kev_date_added"),
        "kev_due_date": kev_row.get("kev_due_date"),
        "kev_known_ransomware": bool(kev_row.get("kev_known_ransomware")),
        "kev_notes": kev_row.get("kev_notes"),
    }


def upsert_cve_catalog(cur, row: dict[str, Any]):
    cur.execute(
        """
        INSERT INTO cve_catalog (
            cve_id, source_system, cve_year, vendor_project, product_name, cpe_candidates,
            cvss_base_score, cvss_severity, published_at, last_modified_at, description,
            references_json, raw_json, is_kev, kev_date_added, kev_due_date,
            kev_known_ransomware, kev_notes, created_at, updated_at
        ) VALUES (
            %(cve_id)s, %(source_system)s, %(cve_year)s, %(vendor_project)s, %(product_name)s, %(cpe_candidates)s,
            %(cvss_base_score)s, %(cvss_severity)s, %(published_at)s, %(last_modified_at)s, %(description)s,
            %(references_json)s, %(raw_json)s, %(is_kev)s, %(kev_date_added)s, %(kev_due_date)s,
            %(kev_known_ransomware)s, %(kev_notes)s, now(), now()
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            source_system = EXCLUDED.source_system,
            cve_year = EXCLUDED.cve_year,
            vendor_project = EXCLUDED.vendor_project,
            product_name = EXCLUDED.product_name,
            cpe_candidates = EXCLUDED.cpe_candidates,
            cvss_base_score = EXCLUDED.cvss_base_score,
            cvss_severity = EXCLUDED.cvss_severity,
            published_at = EXCLUDED.published_at,
            last_modified_at = EXCLUDED.last_modified_at,
            description = EXCLUDED.description,
            references_json = EXCLUDED.references_json,
            raw_json = EXCLUDED.raw_json,
            is_kev = EXCLUDED.is_kev,
            kev_date_added = EXCLUDED.kev_date_added,
            kev_due_date = EXCLUDED.kev_due_date,
            kev_known_ransomware = EXCLUDED.kev_known_ransomware,
            kev_notes = EXCLUDED.kev_notes,
            updated_at = now()
        """,
        {
            **row,
            "cpe_candidates": j(row.get("cpe_candidates") or []),
            "references_json": j(row.get("references_json") or []),
            "raw_json": j(row.get("raw_json") or {}),
        },
    )


def parse_kev_feed() -> dict[str, dict[str, Any]]:
    data = http_get_json(CISA_KEV_FEED_URL)
    catalog: dict[str, dict[str, Any]] = {}
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = to_text(item.get("cveID"))
        if not cve_id:
            continue
        catalog[cve_id] = {
            "cve_id": cve_id,
            "vendor_project": to_text(item.get("vendorProject")) or None,
            "product_name": to_text(item.get("product")) or None,
            "description": to_text(item.get("shortDescription")) or None,
            "is_kev": True,
            "kev_date_added": to_text(item.get("dateAdded")) or None,
            "kev_due_date": to_text(item.get("dueDate")) or None,
            "kev_known_ransomware": normalize_text(item.get("knownRansomwareCampaignUse")) == "known",
            "kev_notes": to_text(item.get("notes")) or None,
        }
    return catalog


def refresh_kev_flags(cur, kev_map: dict[str, dict[str, Any]]):
    log(f"Refreshing KEV flags for {len(kev_map)} CVE entries")
    cur.execute("UPDATE cve_catalog SET is_kev = false, kev_date_added = null, kev_due_date = null, kev_known_ransomware = false, kev_notes = null WHERE is_kev = true")
    rows = list(kev_map.values())
    for batch in chunked(rows, VULN_IMPORT_BATCH_SIZE):
        for row in batch:
            cur.execute(
                """
                UPDATE cve_catalog
                SET is_kev = true,
                    kev_date_added = %s,
                    kev_due_date = %s,
                    kev_known_ransomware = %s,
                    kev_notes = %s,
                    vendor_project = COALESCE(%s, vendor_project),
                    product_name = COALESCE(%s, product_name),
                    description = COALESCE(description, %s),
                    updated_at = now()
                WHERE cve_id = %s
                """,
                (
                    row.get("kev_date_added"),
                    row.get("kev_due_date"),
                    bool(row.get("kev_known_ransomware")),
                    row.get("kev_notes"),
                    row.get("vendor_project"),
                    row.get("product_name"),
                    row.get("description"),
                    row.get("cve_id"),
                ),
            )


def parse_cpe_dict_products(feed_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for item in feed_json.get("products") or []:
        entry = item.get("cpe") if isinstance(item, dict) else None
        if not isinstance(entry, dict):
            continue
        cpe_name = to_text(entry.get("cpeName") or entry.get("cpeNameId"))
        if not cpe_name:
            continue
        title = None
        for title_item in entry.get("titles") or []:
            if normalize_text(title_item.get("lang")) == "en":
                title = to_text(title_item.get("title"))
                break
        parts = extract_cpe_parts(cpe_name) or {}
        yield {
            "cpe_name": cpe_name,
            "cpe_title": title,
            "deprecated": bool(entry.get("deprecated")),
            "vendor": parts.get("vendor"),
            "product": parts.get("product"),
            "part": parts.get("part"),
            "version": parts.get("version"),
            "update_value": parts.get("update"),
            "edition": parts.get("edition"),
            "language": parts.get("language"),
            "sw_edition": parts.get("sw_edition"),
            "target_sw": parts.get("target_sw"),
            "target_hw": parts.get("target_hw"),
            "other_value": parts.get("other"),
            "last_modified_at": to_text(entry.get("lastModified")) or None,
            "raw_json": entry,
        }


def parse_cpe_match_entries(feed_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for item in feed_json.get("matchStrings") or []:
        entry = item.get("matchString") if isinstance(item, dict) and isinstance(item.get("matchString"), dict) else item
        if not isinstance(entry, dict):
            continue
        match_id = to_text(entry.get("matchCriteriaId") or entry.get("matchStringId") or entry.get("uuid"))
        criteria = to_text(entry.get("criteria") or entry.get("cpe23Uri"))
        if not match_id or not criteria:
            continue
        parts = extract_cpe_parts(criteria) or {}
        matches_json = entry.get("matches") or []
        yield {
            "match_criteria_id": match_id,
            "criteria": criteria,
            "status": to_text(entry.get("status")) or None,
            "version_start_including": to_text(entry.get("versionStartIncluding")) or None,
            "version_start_excluding": to_text(entry.get("versionStartExcluding")) or None,
            "version_end_including": to_text(entry.get("versionEndIncluding")) or None,
            "version_end_excluding": to_text(entry.get("versionEndExcluding")) or None,
            "vendor": parts.get("vendor"),
            "product": parts.get("product"),
            "part": parts.get("part"),
            "last_modified_at": to_text(entry.get("lastModified")) or None,
            "cpe_last_modified_at": to_text(entry.get("cpeLastModified")) or None,
            "created_at": to_text(entry.get("created")) or None,
            "matches_json": matches_json,
            "raw_json": entry,
        }


def fetch_devices_with_overrides() -> list[dict[str, Any]]:
    sql = """
        SELECT
            d.id::text AS id,
            host(d.current_ip) AS current_ip,
            d.hostname,
            d.vendor,
            d.model,
            d.category,
            d.firmware_version,
            d.hardware_version,
            d.serial_number,
            d.manual_vendor,
            d.manual_model,
            d.manual_category,
            d.manual_firmware_version,
            d.manual_hardware_version,
            d.manual_serial_number,
            d.identity_confirmed,
            d.status,
            d.is_online,
            d.risk_score,
            d.risk_level,
            d.notes,
            o.manual_cpe_23,
            o.search_terms,
            o.notes AS override_notes
        FROM devices d
        LEFT JOIN device_vulnerability_overrides o ON o.device_id = d.id
        WHERE d.current_ip IS NOT NULL
    """
    if VULN_SYNC_ONLY_CONFIRMED:
        sql += " AND COALESCE(d.identity_confirmed, false) = true"
    sql += " ORDER BY d.updated_at DESC LIMIT %s"
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (VULN_MAX_DEVICES_PER_RUN,))
            return cur.fetchall()


def fetch_existing_open_cves(cur, device_id: str) -> set[str]:
    cur.execute(
        "SELECT cve_id FROM device_vulnerability_matches WHERE device_id = %s::uuid AND match_status = 'open'",
        (normalize_uuid_text(device_id),),
    )
    return {to_text((row.get('cve_id') if hasattr(row, 'get') else row[0])) for row in cur.fetchall()}


def upsert_device_match(cur, device: dict[str, Any], row: dict[str, Any]):
    cur.execute(
        """
        INSERT INTO device_vulnerability_matches (
            device_id, cve_id, match_source, match_confidence, matched_vendor, matched_model,
            matched_version, manual_cpe_override, recommended_action, is_kev,
            cvss_base_score, cvss_severity, match_status, evidence_json,
            first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (
            %s::uuid, %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, 'open', %s,
            now(), now(), now(), now()
        )
        ON CONFLICT (device_id, cve_id, match_source) DO UPDATE SET
            match_confidence = EXCLUDED.match_confidence,
            matched_vendor = EXCLUDED.matched_vendor,
            matched_model = EXCLUDED.matched_model,
            matched_version = EXCLUDED.matched_version,
            manual_cpe_override = EXCLUDED.manual_cpe_override,
            recommended_action = EXCLUDED.recommended_action,
            is_kev = EXCLUDED.is_kev,
            cvss_base_score = EXCLUDED.cvss_base_score,
            cvss_severity = EXCLUDED.cvss_severity,
            match_status = 'open',
            evidence_json = EXCLUDED.evidence_json,
            last_seen_at = now(),
            updated_at = now()
        """,
        (
            normalize_uuid_text(device.get("id")),
            row.get("cve_id"),
            row.get("match_source"),
            int(row.get("match_confidence") or 0),
            row.get("matched_vendor"),
            row.get("matched_model"),
            row.get("matched_version"),
            row.get("manual_cpe_override"),
            row.get("recommended_action"),
            bool(row.get("is_kev")),
            row.get("cvss_base_score"),
            row.get("cvss_severity"),
            j(row.get("evidence_json") or {}),
        ),
    )


def close_missing_matches(cur, device_id: str, seen_pairs: set[tuple[str, str]]):
    device_uuid = normalize_uuid_text(device_id)
    cur.execute(
        "SELECT cve_id, match_source FROM device_vulnerability_matches WHERE device_id = %s::uuid AND match_status = 'open'",
        (device_uuid,),
    )
    for row in cur.fetchall():
        pair = (
            to_text((row.get('cve_id') if hasattr(row, 'get') else row[0])),
            to_text((row.get('match_source') if hasattr(row, 'get') else row[1])),
        )
        if pair in seen_pairs:
            continue
        cur.execute(
            """
            UPDATE device_vulnerability_matches
            SET match_status = 'closed', updated_at = now()
            WHERE device_id = %s::uuid AND cve_id = %s AND match_source = %s AND match_status = 'open'
            """,
            (device_uuid, pair[0], pair[1]),
        )


def ensure_incident(cur, device_id: str, cve_id: str, title: str, severity: str, description: str, evidence: dict[str, Any]):
    cur.execute(
        """
        SELECT id
        FROM incidents
        WHERE device_id = %s::uuid
          AND incident_type = 'vulnerability_match'
          AND status IN ('open', 'acknowledged', 'in_progress')
          AND (evidence_json ->> 'cve_id') = %s
        LIMIT 1
        """,
        (normalize_uuid_text(device_id), cve_id),
    )
    if cur.fetchone():
        return
    cur.execute(
        """
        INSERT INTO incidents (
            device_id, incident_type, severity, source_system, title, description, evidence_json, status, created_at, updated_at
        ) VALUES (
            %s::uuid, 'vulnerability_match', %s, 'security-vulnerability-sync', %s, %s, %s, 'open', now(), now()
        )
        """,
        (normalize_uuid_text(device_id), severity, title, description, j(evidence)),
    )


def aggregate_device(cur, device_id: str) -> dict[str, Any]:
    cur.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE match_status = 'open')::int AS vulnerability_count,
            COUNT(*) FILTER (WHERE match_status = 'open' AND is_kev IS TRUE)::int AS kev_count,
            MAX(cvss_base_score) FILTER (WHERE match_status = 'open') AS highest_cvss,
            COALESCE(
                MAX(cvss_severity) FILTER (WHERE match_status = 'open' AND cvss_severity IS NOT NULL),
                'unknown'
            ) AS raw_severity
        FROM device_vulnerability_matches
        WHERE device_id = %s::uuid
        """,
        (normalize_uuid_text(device_id),),
    )
    row = cur.fetchone() or {}
    vuln_count = int(row.get("vulnerability_count") or 0)
    kev_count = int(row.get("kev_count") or 0)
    highest_cvss = row.get("highest_cvss")
    highest_cvss_f = float(highest_cvss) if highest_cvss is not None else None
    highest_severity = "critical" if kev_count > 0 or (highest_cvss_f is not None and highest_cvss_f >= 9.0) else (
        "high" if highest_cvss_f is not None and highest_cvss_f >= 7.0 else (
            "medium" if highest_cvss_f is not None and highest_cvss_f >= 4.0 else (
                normalize_text(row.get("raw_severity")) or "unknown"
            )
        )
    )
    recommendation = recommendation_for(highest_cvss_f, kev_count > 0, vuln_count) if vuln_count else None
    summary = {
        "vulnerability_count": vuln_count,
        "kev_count": kev_count,
        "highest_cvss": highest_cvss_f,
        "highest_severity": highest_severity,
        "recommendation": recommendation,
        "last_checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    risk_score = risk_score_from_summary(vuln_count, kev_count, highest_cvss_f)
    risk_level = risk_level_from_score(risk_score)
    cur.execute(
        """
        UPDATE devices
        SET vulnerability_count = %s,
            kev_count = %s,
            highest_cvss = %s,
            highest_severity = %s,
            vulnerability_recommendation = %s,
            vulnerability_last_checked_at = now(),
            vulnerability_summary_json = %s,
            risk_score = GREATEST(risk_score, %s),
            risk_level = CASE
                WHEN %s = 'critical' THEN 'critical'
                WHEN %s = 'high' AND risk_level NOT IN ('critical') THEN 'high'
                WHEN %s = 'medium' AND risk_level NOT IN ('critical', 'high') THEN 'medium'
                WHEN %s = 'low' AND risk_level NOT IN ('critical', 'high', 'medium') THEN 'low'
                ELSE risk_level
            END,
            updated_at = now()
        WHERE id = %s::uuid
        """,
        (
            vuln_count,
            kev_count,
            highest_cvss_f,
            highest_severity,
            recommendation,
            j(summary),
            risk_score,
            risk_level,
            risk_level,
            risk_level,
            risk_level,
            normalize_uuid_text(device_id),
        ),
    )
    return summary


def update_health(component_name: str, details: dict[str, Any], status: str = "healthy"):
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO system_health (component_name, component_type, status, version, details_json, last_check_at, updated_at)
                VALUES (%s, 'worker', %s, 'phase3-fullmirror', %s, now(), now())
                ON CONFLICT (component_name) DO UPDATE SET
                    status = EXCLUDED.status,
                    version = EXCLUDED.version,
                    details_json = EXCLUDED.details_json,
                    last_check_at = now(),
                    updated_at = now()
                """,
                (component_name, status, j(details)),
            )
        conn.commit()
