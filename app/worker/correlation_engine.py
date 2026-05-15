import datetime as dt
import json
from typing import Any

from detection_common import (
    connect,
    create_security_event,
    getenv_any,
    normalize_ip,
    to_text,
    update_health,
)

COMPONENT = "security-detection-correlator"
WINDOW_MINUTES = int(getenv_any(["CORRELATION_WINDOW_MINUTES"], "30"))
MIN_DNS_BLOCKS = int(getenv_any(["CORRELATION_MIN_DNS_BLOCKS"], "1"))
MIN_IDS_ALERTS = int(getenv_any(["CORRELATION_MIN_IDS_ALERTS"], "1"))
INCLUDE_DNS_QUERIES = getenv_any(["CORRELATION_INCLUDE_DNS_QUERIES"], "false").lower() in {"1", "true", "yes", "on"}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def bucket_key(now: dt.datetime, window_minutes: int) -> str:
    minute = (now.minute // window_minutes) * window_minutes
    return now.replace(minute=minute, second=0, microsecond=0).isoformat()


def already_emitted(cur, dedupe_key: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM security_events
        WHERE dedupe_key = %s
          AND event_time >= now() - interval '24 hours'
        LIMIT 1
        """,
        (dedupe_key,),
    )
    return cur.fetchone() is not None


def severity_from_rank(rank: int) -> str:
    if rank >= 5:
        return "critical"
    if rank >= 4:
        return "high"
    if rank >= 3:
        return "medium"
    if rank >= 2:
        return "low"
    return "info"


def process() -> dict[str, Any]:
    now = utc_now()
    bucket = bucket_key(now, WINDOW_MINUTES)
    emitted = 0
    dns_types = ["dns_block", "malicious_dns_block", "policy_dns_block"]
    if INCLUDE_DNS_QUERIES:
        dns_types.append("dns_query")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH ids AS (
                    SELECT
                        se.device_id,
                        COUNT(*)::int AS ids_count,
                        MAX(CASE se.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)::int AS ids_max_rank,
                        array_agg(DISTINCT se.event_type ORDER BY se.event_type) AS ids_types,
                        array_agg(DISTINCT COALESCE(se.signature_name, se.title) ORDER BY COALESCE(se.signature_name, se.title)) FILTER (WHERE COALESCE(se.signature_name, se.title) IS NOT NULL) AS signatures,
                        MAX(se.event_time) AS last_ids_time
                    FROM security_events se
                    WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
                      AND se.source_system ILIKE 'suricata%%'
                      AND se.device_id IS NOT NULL
                    GROUP BY se.device_id
                    HAVING COUNT(*) >= %s
                ), dns AS (
                    SELECT
                        se.device_id,
                        COUNT(*)::int AS dns_count,
                        MAX(CASE se.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)::int AS dns_max_rank,
                        array_agg(DISTINCT se.event_type ORDER BY se.event_type) AS dns_types,
                        array_agg(DISTINCT se.domain ORDER BY se.domain) FILTER (WHERE se.domain IS NOT NULL) AS domains,
                        MAX(se.event_time) AS last_dns_time
                    FROM security_events se
                    WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
                      AND se.source_system ILIKE 'adguard%%'
                      AND se.event_type = ANY(%s)
                      AND se.device_id IS NOT NULL
                    GROUP BY se.device_id
                    HAVING COUNT(*) >= %s
                )
                SELECT
                    ids.device_id::text AS device_id,
                    d.hostname,
                    host(d.current_ip) AS ip,
                    ids.ids_count,
                    ids.ids_max_rank,
                    ids.ids_types,
                    ids.signatures,
                    ids.last_ids_time,
                    dns.dns_count,
                    dns.dns_max_rank,
                    dns.dns_types,
                    dns.domains,
                    dns.last_dns_time
                FROM ids
                JOIN dns ON dns.device_id = ids.device_id
                LEFT JOIN devices d ON d.id = ids.device_id
                ORDER BY GREATEST(ids.last_ids_time, dns.last_dns_time) DESC
                """,
                (WINDOW_MINUTES, MIN_IDS_ALERTS, WINDOW_MINUTES, dns_types, MIN_DNS_BLOCKS),
            )
            rows = cur.fetchall()
            for row in rows:
                device_id = to_text(row.get("device_id"))
                dedupe = f"correlation|ids_dns|{device_id}|{bucket}"
                if already_emitted(cur, dedupe):
                    continue
                ids_count = int(row.get("ids_count") or 0)
                dns_count = int(row.get("dns_count") or 0)
                rank = max(int(row.get("ids_max_rank") or 0), int(row.get("dns_max_rank") or 0), 4)
                severity = severity_from_rank(rank)
                name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
                title = f"Correlated IDS and DNS activity: {name}"
                description = f"{ids_count} Suricata alert(s) and {dns_count} AdGuard DNS block/query event(s) occurred in the same {WINDOW_MINUTES}-minute window."
                create_security_event(
                    cur,
                    source_system="correlation-engine",
                    event_type="ids_dns_correlation",
                    severity=severity,
                    title=title,
                    description=description,
                    device_id=device_id,
                    src_ip=normalize_ip(row.get("ip")),
                    raw_json={
                        "window_minutes": WINDOW_MINUTES,
                        "ids_count": ids_count,
                        "dns_count": dns_count,
                        "ids_types": row.get("ids_types"),
                        "dns_types": row.get("dns_types"),
                        "signatures": row.get("signatures"),
                        "domains": row.get("domains"),
                        "last_ids_time": row.get("last_ids_time"),
                        "last_dns_time": row.get("last_dns_time"),
                    },
                    dedupe_key=dedupe,
                    create_incident=True,
                )
                emitted += 1
        conn.commit()

    details = {"window_minutes": WINDOW_MINUTES, "correlations_created": emitted, "include_dns_queries": INCLUDE_DNS_QUERIES}
    update_health(COMPONENT, "detection-worker", "healthy", details, version="phase5-complete-5a5b-keep5c")
    return {"status": "healthy", **details}


def main():
    try:
        result = process()
    except Exception as exc:
        details = {"error": str(exc), "window_minutes": WINDOW_MINUTES}
        update_health(COMPONENT, "detection-worker", "degraded", details, version="phase5-complete-5a5b-keep5c")
        result = {"status": "degraded", **details}
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
