import argparse
from typing import Any

import psycopg
from psycopg.rows import dict_row

from vuln_mirror_common import (
    CISA_KEV_FEED_URL,
    DATABASE_URL,
    MATCHERS,
    NVD_CPE_DICT_FEED,
    NVD_CPE_MATCH_FEED,
    NVD_CVE_MODIFIED_FEED,
    VULN_IMPORT_BATCH_SIZE,
    compare_versions,
    cve_to_catalog_row,
    english_description,
    extract_cpe_parts,
    fetch_devices_with_overrides,
    fetch_existing_open_cves,
    get_source_state,
    iter_cpe_matches,
    j,
    load_json_from_cached_gz,
    load_json_from_cached_tar,
    log,
    normalize_text,
    normalize_uuid_text,
    normalize_version,
    parse_cpe_dict_products,
    parse_cpe_match_entries,
    parse_kev_feed,
    recommendation_for,
    record_source_state,
    refresh_kev_flags,
    update_health,
    upsert_cve_catalog,
    upsert_device_match,
    close_missing_matches,
    aggregate_device,
    best_cvss,
    version_in_range,
    to_text,
    fetch_feed_meta,
)


def matchers_for_device(device: dict[str, Any]) -> list[dict[str, Any]]:
    vendor = normalize_text(device.get("manual_vendor") or device.get("vendor"))
    model = normalize_text(device.get("manual_model") or device.get("model"))
    category = normalize_text(device.get("manual_category") or device.get("category"))
    identity = " ".join(
        value
        for value in [
            normalize_text(device.get("hostname")),
            vendor,
            model,
            normalize_text(device.get("current_ip")),
        ]
        if value
    )
    matches: list[dict[str, Any]] = []
    for rule in MATCHERS.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        if rule.get("category_any") and category not in [normalize_text(v) for v in rule.get("category_any") or []]:
            continue
        hostname_any = [normalize_text(v) for v in rule.get("hostname_any") or []]
        if hostname_any and not any(token in identity for token in hostname_any):
            continue
        vendor_any = [normalize_text(v) for v in rule.get("vendor_any") or []]
        if vendor_any and not any(token in vendor for token in vendor_any):
            continue
        model_any = [normalize_text(v) for v in rule.get("model_any") or []]
        if model_any and not any(token in model for token in model_any):
            continue
        matches.append(rule)
    return matches


def fetch_local_candidates(cur, device: dict[str, Any]) -> list[dict[str, Any]]:
    vendor = normalize_text(device.get("manual_vendor") or device.get("vendor"))
    model = normalize_text(device.get("manual_model") or device.get("model"))
    manual_cpe = to_text(device.get("manual_cpe_23"))
    search_terms = [to_text(x) for x in (device.get("search_terms") or []) if to_text(x)]
    rows: dict[str, dict[str, Any]] = {}

    def add_query(sql: str, params: tuple[Any, ...]):
        cur.execute(sql, params)
        for row in cur.fetchall():
            rows[to_text(row["cve_id"])] = dict(row)

    if manual_cpe:
        parts = extract_cpe_parts(manual_cpe) or {}
        cpe_vendor = normalize_text(parts.get("vendor"))
        cpe_product = normalize_text(parts.get("product"))
        if cpe_vendor and cpe_product:
            add_query(
                """
                SELECT cve_id, raw_json, is_kev, cvss_base_score, cvss_severity
                FROM cve_catalog
                WHERE lower(vendor_project) = %s AND lower(product_name) = %s
                ORDER BY is_kev DESC, cvss_base_score DESC NULLS LAST
                LIMIT 5000
                """,
                (cpe_vendor, cpe_product),
            )

    if vendor and model:
        add_query(
            """
            SELECT cve_id, raw_json, is_kev, cvss_base_score, cvss_severity
            FROM cve_catalog
            WHERE lower(vendor_project) = %s AND lower(product_name) = %s
            ORDER BY is_kev DESC, cvss_base_score DESC NULLS LAST
            LIMIT 5000
            """,
            (vendor, model),
        )
        add_query(
            """
            SELECT cve_id, raw_json, is_kev, cvss_base_score, cvss_severity
            FROM cve_catalog
            WHERE lower(description) LIKE %s AND lower(description) LIKE %s
            ORDER BY is_kev DESC, cvss_base_score DESC NULLS LAST
            LIMIT 2000
            """,
            (f"%{vendor}%", f"%{model}%"),
        )

    for rule in matchers_for_device(device):
        cpe_match_string = to_text(rule.get("cpe_match_string"))
        parts = extract_cpe_parts(cpe_match_string) or {}
        cpe_vendor = normalize_text(parts.get("vendor"))
        cpe_product = normalize_text(parts.get("product"))
        if cpe_vendor and cpe_product:
            add_query(
                """
                SELECT cve_id, raw_json, is_kev, cvss_base_score, cvss_severity
                FROM cve_catalog
                WHERE lower(vendor_project) = %s AND lower(product_name) = %s
                ORDER BY is_kev DESC, cvss_base_score DESC NULLS LAST
                LIMIT 5000
                """,
                (cpe_vendor, cpe_product),
            )

    for term in search_terms:
        term_l = normalize_text(term)
        if not term_l:
            continue
        add_query(
            """
            SELECT cve_id, raw_json, is_kev, cvss_base_score, cvss_severity
            FROM cve_catalog
            WHERE lower(description) LIKE %s
            ORDER BY is_kev DESC, cvss_base_score DESC NULLS LAST
            LIMIT 1000
            """,
            (f"%{term_l}%",),
        )

    return list(rows.values())


def cve_matches_device(cve: dict[str, Any], device: dict[str, Any]) -> tuple[bool, int, str, dict[str, Any]]:
    vendor = normalize_text(device.get("manual_vendor") or device.get("vendor"))
    model = normalize_text(device.get("manual_model") or device.get("model"))
    device_version = normalize_version(device.get("manual_firmware_version") or device.get("firmware_version"))
    manual_cpe = to_text(device.get("manual_cpe_23"))
    description = normalize_text(english_description(cve))
    cve_id = to_text(cve.get("id"))

    best_confidence = 0
    best_source = "keyword"
    best_evidence: dict[str, Any] = {"cve_id": cve_id, "manual_cpe_override": manual_cpe or None}

    if manual_cpe:
        for match in iter_cpe_matches(cve.get("configurations") or []):
            criteria = to_text(match.get("criteria") or match.get("cpe23Uri"))
            if manual_cpe in criteria or criteria in manual_cpe:
                best_confidence = 100
                best_source = "manual_cpe"
                best_evidence.update({"matched_criteria": criteria})
                return True, best_confidence, best_source, best_evidence

    matched_by_cpe = False
    for match in iter_cpe_matches(cve.get("configurations") or []):
        criteria = to_text(match.get("criteria") or match.get("cpe23Uri"))
        parts = extract_cpe_parts(criteria)
        if not parts:
            continue
        cpe_vendor = normalize_text(parts.get("vendor"))
        cpe_product = normalize_text(parts.get("product"))
        vendor_ok = not vendor or vendor in cpe_vendor or cpe_vendor in vendor or vendor in description
        model_ok = not model or model in cpe_product or cpe_product in model or model in description
        if not (vendor_ok and model_ok):
            continue
        range_ok = version_in_range(device_version, match)
        if range_ok is False:
            continue
        confidence = 95 if range_ok is True else 80
        if confidence > best_confidence:
            matched_by_cpe = True
            best_confidence = confidence
            best_source = "local_cpe"
            best_evidence = {
                "cve_id": cve_id,
                "matched_criteria": criteria,
                "version_range": {
                    "start_including": match.get("versionStartIncluding"),
                    "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"),
                    "end_excluding": match.get("versionEndExcluding"),
                },
            }

    if matched_by_cpe:
        return True, best_confidence, best_source, best_evidence

    vendor_ok = bool(vendor and vendor in description)
    model_ok = bool(model and model in description)
    if vendor_ok and model_ok:
        confidence = 55
        if device_version and device_version in description:
            confidence = 70
        best_evidence = {"cve_id": cve_id, "keyword_vendor": vendor, "keyword_model": model, "description_match": True}
        return True, confidence, "keyword", best_evidence

    return False, 0, "keyword", {"cve_id": cve_id}


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


def process_device(cur, device: dict[str, Any]) -> dict[str, Any]:
    device_id = normalize_uuid_text(device.get("id"))
    seen_pairs: set[tuple[str, str]] = set()
    open_before = fetch_existing_open_cves(cur, device_id)
    candidates = fetch_local_candidates(cur, device)
    matches_added = 0
    high_risk_added = 0

    for candidate in candidates:
        cve = candidate.get("raw_json") if isinstance(candidate.get("raw_json"), dict) else candidate
        if not isinstance(cve, dict):
            continue
        matched, confidence, match_source, evidence = cve_matches_device(cve, device)
        if not matched:
            continue
        cve_id = to_text(cve.get("id"))
        score, severity = best_cvss(cve)
        is_kev = bool(candidate.get("is_kev"))
        recommendation = recommendation_for(score, is_kev, 1)
        match_row = {
            "cve_id": cve_id,
            "match_source": match_source,
            "match_confidence": confidence,
            "matched_vendor": to_text(device.get("manual_vendor") or device.get("vendor")) or None,
            "matched_model": to_text(device.get("manual_model") or device.get("model")) or None,
            "matched_version": normalize_version(device.get("manual_firmware_version") or device.get("firmware_version")),
            "manual_cpe_override": to_text(device.get("manual_cpe_23")) or None,
            "recommended_action": recommendation,
            "is_kev": is_kev,
            "cvss_base_score": score,
            "cvss_severity": severity,
            "evidence_json": evidence,
        }
        upsert_device_match(cur, device, match_row)
        seen_pairs.add((cve_id, match_source))
        if cve_id not in open_before:
            matches_added += 1
            sev = "critical" if is_kev or (score is not None and score >= 9.0) else "high" if score is not None and score >= 7.0 else "medium"
            if sev in {"critical", "high"}:
                high_risk_added += 1
                ensure_incident(
                    cur,
                    device_id,
                    cve_id,
                    title=f"Pažeidžiamumo atitikimas: {cve_id}",
                    severity=sev,
                    description=(english_description(cve) or recommendation or f"Aptiktas CVE atitikimas įrenginiui {to_text(device.get('hostname') or device.get('current_ip'))}")[:5000],
                    evidence={
                        **evidence,
                        "cve_id": cve_id,
                        "match_source": match_source,
                        "cvss_base_score": score,
                        "cvss_severity": severity,
                        "is_kev": is_kev,
                    },
                )

    close_missing_matches(cur, device_id, seen_pairs)
    summary = aggregate_device(cur, device_id)
    return {
        "device_id": device_id,
        "candidates_seen": len(candidates),
        "matches_added": matches_added,
        "high_risk_added": high_risk_added,
        "summary": summary,
    }


def refresh_modified_cves(cur, kev_map: dict[str, dict[str, Any]]) -> int:
    state = get_source_state(cur, "nvd-cve-modified")
    previous_cursor = to_text((state or {}).get("last_cursor"))
    meta = fetch_feed_meta(NVD_CVE_MODIFIED_FEED)
    current_cursor = to_text(meta.get("lastModifiedDate"))
    if current_cursor and current_cursor == previous_cursor:
        log(f"[sync] modified feed unchanged: {current_cursor}")
        return 0
    feed = load_json_from_cached_gz(NVD_CVE_MODIFIED_FEED, "nvdcve-2.0-modified.json.gz")
    count = 0
    batch_count = 0
    newest_modified = current_cursor or previous_cursor
    for item in feed.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        modified = to_text(cve.get("lastModified"))
        if modified and (not newest_modified or modified > newest_modified):
            newest_modified = modified
        upsert_cve_catalog(cur, cve_to_catalog_row(cve, kev_map))
        count += 1
        batch_count += 1
        if batch_count >= VULN_IMPORT_BATCH_SIZE:
            cur.connection.commit()
            batch_count = 0
            log(f"[sync] modified CVEs imported: {count}")
    cur.connection.commit()
    record_source_state(cur, "nvd-cve-modified", last_cursor=newest_modified or None, etag=to_text(meta.get("sha256")) or None, details={"entries": count, "feed": NVD_CVE_MODIFIED_FEED, "meta": meta})
    cur.connection.commit()
    return count


def maybe_refresh_cpe_dictionary(cur) -> int:
    old = get_source_state(cur, "nvd-cpe-dictionary") or {}
    previous_cursor = to_text(old.get("last_cursor"))
    meta = fetch_feed_meta(NVD_CPE_DICT_FEED)
    current_marker = to_text(meta.get("lastModifiedDate"))
    if previous_cursor and previous_cursor == current_marker:
        log(f"[sync] CPE dictionary unchanged: {current_marker}")
        return 0
    feed = load_json_from_cached_tar(NVD_CPE_DICT_FEED, "nvdcpe-2.0.tar.gz")
    rows = list(parse_cpe_dict_products(feed))
    cur.execute("TRUNCATE TABLE cpe_dictionary")
    cur.connection.commit()
    inserted = 0
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) >= VULN_IMPORT_BATCH_SIZE:
            insert_cpe_dictionary_batch(cur, batch)
            inserted += len(batch)
            batch = []
    if batch:
        insert_cpe_dictionary_batch(cur, batch)
        inserted += len(batch)
    record_source_state(cur, "nvd-cpe-dictionary", last_cursor=current_marker, etag=to_text(meta.get("sha256")) or None, details={"entries": inserted, "feed": NVD_CPE_DICT_FEED, "meta": meta})
    cur.connection.commit()
    return inserted


def insert_cpe_dictionary_batch(cur, batch: list[dict[str, Any]]):
    for row in batch:
        cur.execute(
            """
            INSERT INTO cpe_dictionary (
                cpe_name, cpe_title, deprecated, vendor, product, part, version,
                update_value, edition, language, sw_edition, target_sw, target_hw, other_value,
                last_modified_at, raw_json, created_at, updated_at
            ) VALUES (
                %(cpe_name)s, %(cpe_title)s, %(deprecated)s, %(vendor)s, %(product)s, %(part)s, %(version)s,
                %(update_value)s, %(edition)s, %(language)s, %(sw_edition)s, %(target_sw)s, %(target_hw)s, %(other_value)s,
                %(last_modified_at)s, %(raw_json)s, now(), now()
            )
            """,
            {**row, "raw_json": j(row.get("raw_json") or {})},
        )
    cur.connection.commit()


def maybe_refresh_cpe_match(cur) -> int:
    old = get_source_state(cur, "nvd-cpe-match") or {}
    previous_cursor = to_text(old.get("last_cursor"))
    meta = fetch_feed_meta(NVD_CPE_MATCH_FEED)
    current_marker = to_text(meta.get("lastModifiedDate"))
    if previous_cursor and previous_cursor == current_marker:
        log(f"[sync] CPE match feed unchanged: {current_marker}")
        return 0
    feed = load_json_from_cached_tar(NVD_CPE_MATCH_FEED, "nvdcpematch-2.0.tar.gz")
    rows = list(parse_cpe_match_entries(feed))
    cur.execute("TRUNCATE TABLE cpe_match_feed")
    cur.connection.commit()
    inserted = 0
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) >= VULN_IMPORT_BATCH_SIZE:
            insert_cpe_match_batch(cur, batch)
            inserted += len(batch)
            batch = []
    if batch:
        insert_cpe_match_batch(cur, batch)
        inserted += len(batch)
    record_source_state(cur, "nvd-cpe-match", last_cursor=current_marker, etag=to_text(meta.get("sha256")) or None, details={"entries": inserted, "feed": NVD_CPE_MATCH_FEED, "meta": meta})
    cur.connection.commit()
    return inserted


def insert_cpe_match_batch(cur, batch: list[dict[str, Any]]):
    for row in batch:
        cur.execute(
            """
            INSERT INTO cpe_match_feed (
                match_criteria_id, criteria, status,
                version_start_including, version_start_excluding, version_end_including, version_end_excluding,
                vendor, product, part,
                last_modified_at, cpe_last_modified_at, created_at_remote,
                matches_json, raw_json, updated_at
            ) VALUES (
                %(match_criteria_id)s, %(criteria)s, %(status)s,
                %(version_start_including)s, %(version_start_excluding)s, %(version_end_including)s, %(version_end_excluding)s,
                %(vendor)s, %(product)s, %(part)s,
                %(last_modified_at)s, %(cpe_last_modified_at)s, %(created_at)s,
                %(matches_json)s, %(raw_json)s, now()
            )
            """,
            {**row, "matches_json": j(row.get("matches_json") or []), "raw_json": j(row.get("raw_json") or {})},
        )
    cur.connection.commit()


def run_incremental(rebuild_products: bool = False, rebuild_matches: bool = True):
    stats = {
        "mode": "incremental",
        "modified_cves_imported": 0,
        "cpe_dictionary_refreshed": 0,
        "cpe_match_refreshed": 0,
        "kev_entries": 0,
        "devices_seen": 0,
        "devices_processed": 0,
        "matches_added": 0,
        "high_risk_matches_added": 0,
        "at_risk_devices": 0,
        "critical_devices": 0,
        "matcher_rule_count": len(MATCHERS.get("rules") or []),
        "rebuild_products": rebuild_products,
        "rebuild_matches": rebuild_matches,
    }

    kev_map = parse_kev_feed()
    stats["kev_entries"] = len(kev_map)

    with psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False) as conn:
        with conn.cursor() as cur:
            stats["modified_cves_imported"] = refresh_modified_cves(cur, kev_map)
            refresh_kev_flags(cur, kev_map)
            record_source_state(cur, "cisa-kev", details={"entries": len(kev_map), "feed": CISA_KEV_FEED_URL})
            conn.commit()
            if rebuild_products:
                stats["cpe_dictionary_refreshed"] = maybe_refresh_cpe_dictionary(cur)
                stats["cpe_match_refreshed"] = maybe_refresh_cpe_match(cur)
                conn.commit()
            if rebuild_matches:
                devices = fetch_devices_with_overrides()
                stats["devices_seen"] = len(devices)
                for idx, device in enumerate(devices, start=1):
                    result = process_device(cur, device)
                    stats["devices_processed"] += 1
                    stats["matches_added"] += int(result.get("matches_added") or 0)
                    stats["high_risk_matches_added"] += int(result.get("high_risk_added") or 0)
                    summary = result.get("summary") or {}
                    if int(summary.get("vulnerability_count") or 0) > 0:
                        stats["at_risk_devices"] += 1
                    if normalize_text(summary.get("highest_severity")) == "critical" or int(summary.get("kev_count") or 0) > 0:
                        stats["critical_devices"] += 1
                    conn.commit()
                    log(f"[sync] device {idx}/{len(devices)} processed: {device.get('hostname') or device.get('current_ip')} | candidates={result.get('candidates_seen')} | added={result.get('matches_added')}")

    update_health("security-vulnerability-sync", stats)


def main():
    parser = argparse.ArgumentParser(description="Incremental vulnerability sync using local full mirror")
    parser.add_argument("--rebuild-products", action="store_true", help="Refresh full CPE dictionary and CPE match feeds")
    parser.add_argument("--skip-matches", action="store_true", help="Do not rebuild device vulnerability matches")
    args = parser.parse_args()
    run_incremental(rebuild_products=args.rebuild_products, rebuild_matches=not args.skip_matches)


if __name__ == "__main__":
    main()
