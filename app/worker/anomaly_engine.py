import datetime as dt
import json
from typing import Any

from detection_common import (
    connect,
    create_security_event,
    getenv_any,
    load_state,
    normalize_ip,
    save_state,
    to_text,
    update_health,
    j,
)

COMPONENT = "security-anomaly-engine"
WINDOW_MINUTES = int(getenv_any(["ANOMALY_WINDOW_MINUTES"], "15"))
DNS_BLOCK_THRESHOLD = int(getenv_any(["ANOMALY_DNS_BLOCK_THRESHOLD"], "20"))
UNIQUE_DOMAIN_THRESHOLD = int(getenv_any(["ANOMALY_UNIQUE_DOMAIN_THRESHOLD"], "40"))
IDS_ALERT_THRESHOLD = int(getenv_any(["ANOMALY_IDS_ALERT_THRESHOLD"], "10"))
DNS_REQUEST_THRESHOLD = int(getenv_any(["ANOMALY_DNS_REQUEST_THRESHOLD"], "120"))
TRAFFIC_BYTES_THRESHOLD = int(getenv_any(["ANOMALY_TRAFFIC_BYTES_THRESHOLD"], str(50 * 1024 * 1024)))
OUTBOUND_CONNECTION_THRESHOLD = int(getenv_any(["ANOMALY_OUTBOUND_CONNECTION_THRESHOLD"], "80"))
BASELINE_MIN_SAMPLES = int(getenv_any(["ANOMALY_BASELINE_MIN_SAMPLES"], "6"))
BASELINE_MULTIPLIER = float(getenv_any(["ANOMALY_BASELINE_MULTIPLIER"], "3.0"))
BASELINE_ALPHA = float(getenv_any(["ANOMALY_BASELINE_ALPHA"], "0.25"))
LEARN_OPEN_PORTS_ON_FIRST_RUN = getenv_any(["ANOMALY_LEARN_OPEN_PORTS_ON_FIRST_RUN"], "true").lower() in {"1", "true", "yes", "on"}
LEARN_COUNTRIES_ON_FIRST_RUN = getenv_any(["ANOMALY_LEARN_COUNTRIES_ON_FIRST_RUN"], "true").lower() in {"1", "true", "yes", "on"}
SUSPICIOUS_COUNTRIES = {x.strip().upper() for x in getenv_any(["ANOMALY_SUSPICIOUS_COUNTRIES"], "RU,CN,IR,KP").split(",") if x.strip()}
NEW_COUNTRY_CREATE_GENERAL_INCIDENTS = getenv_any(["ANOMALY_NEW_COUNTRY_CREATE_GENERAL_INCIDENTS"], "false").lower() in {"1", "true", "yes", "on"}
NEW_COUNTRY_EVENT_SEVERITY = getenv_any(["ANOMALY_NEW_COUNTRY_EVENT_SEVERITY"], "info").lower()
SUSPICIOUS_COUNTRY_SEVERITY = getenv_any(["ANOMALY_SUSPICIOUS_COUNTRY_SEVERITY"], "high").lower()
SUSPICIOUS_COUNTRY_REPEAT_COOLDOWN_MINUTES = int(getenv_any(["ANOMALY_SUSPICIOUS_COUNTRY_REPEAT_COOLDOWN_MINUTES"], "60"))
NEW_COUNTRY_REPEAT_COOLDOWN_MINUTES = int(getenv_any(["ANOMALY_NEW_COUNTRY_REPEAT_COOLDOWN_MINUTES"], str(24 * 60)))

# Phase 5 noise-control settings.
# Stable dedupe means one open incident per device/anomaly type, while event_count/last_seen_at
# are updated on a controlled cadence instead of creating a new incident every window.
ANOMALY_REPEAT_COOLDOWN_MINUTES = int(getenv_any(["ANOMALY_REPEAT_COOLDOWN_MINUTES"], "60"))
STABLE_ANOMALY_DEDUPE_TYPES = {
    x.strip()
    for x in getenv_any(
        ["ANOMALY_STABLE_DEDUPE_TYPES"],
        "dns_block_burst,dns_domain_spike,ids_alert_spike,dns_request_rate_spike,traffic_volume_spike,outbound_connection_burst",
    ).split(",")
    if x.strip()
}
DNS_ANOMALY_IGNORE_IPS = {
    x.strip()
    for x in getenv_any(["ANOMALY_DNS_ANOMALY_IGNORE_IPS"], "").split(",")
    if x.strip()
}
DNS_ANOMALY_IGNORE_HOSTNAMES = {
    x.strip().lower()
    for x in getenv_any(["ANOMALY_DNS_ANOMALY_IGNORE_HOSTNAMES"], "").split(",")
    if x.strip()
}
DNS_ANOMALY_IGNORE_DEVICE_IDS = {
    x.strip().lower()
    for x in getenv_any(["ANOMALY_DNS_ANOMALY_IGNORE_DEVICE_IDS"], "").split(",")
    if x.strip()
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def bucket_key(now: dt.datetime, window_minutes: int) -> str:
    minute = (now.minute // window_minutes) * window_minutes
    return now.replace(minute=minute, second=0, microsecond=0).isoformat()


def list_ints(value: Any) -> list[int]:
    if isinstance(value, list):
        out: list[int] = []
        for item in value:
            try:
                out.append(int(item))
            except Exception:
                pass
        return sorted(set(out))
    return []


def recently_emitted(cur, dedupe_key: str, cooldown_minutes: int | None = None) -> bool:
    cooldown = int(cooldown_minutes if cooldown_minutes is not None else ANOMALY_REPEAT_COOLDOWN_MINUTES)
    if cooldown <= 0:
        return False
    cur.execute(
        """
        SELECT 1
        FROM security_events
        WHERE dedupe_key = %s
          AND event_time >= now() - (%s::text || ' minutes')::interval
        LIMIT 1
        """,
        (dedupe_key, cooldown),
    )
    return cur.fetchone() is not None


def anomaly_dedupe_key(event_type: str, device_id: str, bucket: str | None = None, *parts: object) -> str:
    clean_parts = [to_text(x) for x in parts if to_text(x)]
    if event_type in STABLE_ANOMALY_DEDUPE_TYPES:
        base = ["anomaly", event_type, device_id]
    else:
        base = ["anomaly", event_type, device_id]
        if bucket:
            base.append(bucket)
    return "|".join(base + clean_parts)


def dns_anomaly_ignored(row: dict[str, Any] | Any, device_id: str | None = None) -> bool:
    row_get = row.get if hasattr(row, "get") else lambda _k, _default=None: _default
    did = (to_text(device_id) or to_text(row_get("device_id"))).lower()
    ip = normalize_ip(row_get("ip"))
    hostname = to_text(row_get("hostname")).lower()
    return (
        (did and did in DNS_ANOMALY_IGNORE_DEVICE_IDS)
        or (ip and ip in DNS_ANOMALY_IGNORE_IPS)
        or (hostname and hostname in DNS_ANOMALY_IGNORE_HOSTNAMES)
    )

def baseline_row(cur, device_id: str, metric_name: str) -> dict[str, Any] | None:
    cur.execute(
        """
        SELECT device_id::text AS device_id, metric_name, baseline_value, last_value, sample_count, details_json
        FROM device_detection_baselines
        WHERE device_id = %s::uuid AND metric_name = %s
        """,
        (device_id, metric_name),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def update_baseline(cur, device_id: str, metric_name: str, value: float, details: dict[str, Any] | None = None):
    existing = baseline_row(cur, device_id, metric_name)
    details = details or {}
    if existing:
        old_avg = float(existing.get("baseline_value") or 0)
        samples = int(existing.get("sample_count") or 0)
        new_avg = value if samples <= 0 else (old_avg * (1.0 - BASELINE_ALPHA) + value * BASELINE_ALPHA)
        cur.execute(
            """
            UPDATE device_detection_baselines
            SET baseline_value = %s,
                last_value = %s,
                sample_count = sample_count + 1,
                last_seen_at = now(),
                details_json = COALESCE(details_json, '{}'::jsonb) || %s::jsonb
            WHERE device_id = %s::uuid AND metric_name = %s
            """,
            (new_avg, value, j(details), device_id, metric_name),
        )
    else:
        cur.execute(
            """
            INSERT INTO device_detection_baselines (
                device_id, metric_name, baseline_value, last_value, sample_count, first_seen_at, last_seen_at, details_json
            ) VALUES (%s::uuid, %s, %s, %s, 1, now(), now(), %s::jsonb)
            ON CONFLICT (device_id, metric_name) DO NOTHING
            """,
            (device_id, metric_name, value, value, j(details)),
        )


def should_trigger_baseline(cur, device_id: str, metric_name: str, value: float, min_threshold: float) -> tuple[bool, dict[str, Any]]:
    row = baseline_row(cur, device_id, metric_name)
    if not row:
        return False, {"reason": "no_baseline"}
    baseline = float(row.get("baseline_value") or 0)
    samples = int(row.get("sample_count") or 0)
    if samples < BASELINE_MIN_SAMPLES:
        return False, {"reason": "not_enough_samples", "samples": samples, "baseline": baseline}
    if value < min_threshold:
        return False, {"reason": "below_min_threshold", "value": value, "threshold": min_threshold, "baseline": baseline, "samples": samples}
    if baseline <= 0:
        return value >= min_threshold, {"baseline": baseline, "samples": samples, "value": value, "threshold": min_threshold}
    triggered = value >= baseline * BASELINE_MULTIPLIER
    return triggered, {"baseline": baseline, "samples": samples, "value": value, "multiplier": BASELINE_MULTIPLIER, "threshold": min_threshold}


def detect_dns_block_burst(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT se.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COUNT(*)::int AS blocked_count
        FROM security_events se
        LEFT JOIN devices d ON d.id = se.device_id
        WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
          AND se.source_system ILIKE 'adguard%%'
          AND se.event_type IN ('dns_block', 'malicious_dns_block', 'policy_dns_block')
          AND se.device_id IS NOT NULL
        GROUP BY se.device_id, d.hostname, d.current_ip
        HAVING COUNT(*) >= %s
        """,
        (WINDOW_MINUTES, DNS_BLOCK_THRESHOLD),
    )
    count = 0
    for row in cur.fetchall():
        device_id = to_text(row.get("device_id"))
        if dns_anomaly_ignored(row, device_id):
            continue
        dedupe = anomaly_dedupe_key("dns_block_burst", device_id, bucket)
        if recently_emitted(cur, dedupe):
            continue
        blocked_count = int(row.get("blocked_count") or 0)
        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type="dns_block_burst",
            severity="high" if blocked_count >= DNS_BLOCK_THRESHOLD * 2 else "medium",
            title=f"DNS block burst detected: {name}",
            description=f"{blocked_count} blocked DNS requests in the last {WINDOW_MINUTES} minutes.",
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            protocol="DNS",
            raw_json={"blocked_count": blocked_count, "window_minutes": WINDOW_MINUTES, "threshold": DNS_BLOCK_THRESHOLD},
            dedupe_key=dedupe,
            create_incident=True,
        )
        count += 1
    return count


def detect_unique_domain_spike(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT se.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COUNT(DISTINCT se.domain)::int AS unique_domains
        FROM security_events se
        LEFT JOIN devices d ON d.id = se.device_id
        WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
          AND se.source_system ILIKE 'adguard%%'
          AND se.domain IS NOT NULL
          AND se.device_id IS NOT NULL
        GROUP BY se.device_id, d.hostname, d.current_ip
        HAVING COUNT(DISTINCT se.domain) >= %s
        """,
        (WINDOW_MINUTES, UNIQUE_DOMAIN_THRESHOLD),
    )
    count = 0
    for row in cur.fetchall():
        device_id = to_text(row.get("device_id"))
        if dns_anomaly_ignored(row, device_id):
            continue
        dedupe = anomaly_dedupe_key("dns_domain_spike", device_id, bucket)
        if recently_emitted(cur, dedupe):
            continue
        unique_domains = int(row.get("unique_domains") or 0)
        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type="dns_domain_spike",
            severity="medium",
            title=f"Unusual DNS domain volume: {name}",
            description=f"{unique_domains} unique domains in the last {WINDOW_MINUTES} minutes.",
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            protocol="DNS",
            raw_json={"unique_domains": unique_domains, "window_minutes": WINDOW_MINUTES, "threshold": UNIQUE_DOMAIN_THRESHOLD},
            dedupe_key=dedupe,
            create_incident=True,
        )
        count += 1
    return count


def detect_ids_alert_spike(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT se.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COUNT(*)::int AS alert_count,
               MAX(CASE se.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)::int AS max_rank
        FROM security_events se
        LEFT JOIN devices d ON d.id = se.device_id
        WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
          AND se.source_system ILIKE 'suricata%%'
          AND se.device_id IS NOT NULL
        GROUP BY se.device_id, d.hostname, d.current_ip
        HAVING COUNT(*) >= %s
        """,
        (WINDOW_MINUTES, IDS_ALERT_THRESHOLD),
    )
    count = 0
    for row in cur.fetchall():
        device_id = to_text(row.get("device_id"))
        dedupe = anomaly_dedupe_key("ids_alert_spike", device_id, bucket)
        if recently_emitted(cur, dedupe):
            continue
        alert_count = int(row.get("alert_count") or 0)
        severity = "critical" if int(row.get("max_rank") or 0) >= 5 else "high"
        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type="ids_alert_spike",
            severity=severity,
            title=f"IDS alert spike detected: {name}",
            description=f"{alert_count} Suricata alerts in the last {WINDOW_MINUTES} minutes.",
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            raw_json={"alert_count": alert_count, "window_minutes": WINDOW_MINUTES, "threshold": IDS_ALERT_THRESHOLD},
            dedupe_key=dedupe,
            create_incident=True,
        )
        count += 1
    return count


def detect_new_open_ports(cur, state: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    known_ports: dict[str, dict[str, list[int]]] = state.get("known_ports") if isinstance(state.get("known_ports"), dict) else {}
    first_run = not bool(known_ports)
    cur.execute(
        """
        SELECT id::text AS device_id, host(current_ip) AS ip, hostname, open_tcp_ports, open_udp_ports
        FROM devices
        WHERE current_ip IS NOT NULL
        ORDER BY current_ip
        """
    )
    rows = cur.fetchall()
    current: dict[str, dict[str, list[int]]] = {}
    emitted = 0
    for row in rows:
        device_id = to_text(row.get("device_id"))
        tcp = list_ints(row.get("open_tcp_ports"))
        udp = list_ints(row.get("open_udp_ports"))
        current[device_id] = {"tcp": tcp, "udp": udp}
        old = known_ports.get(device_id) or {"tcp": [], "udp": []}
        new_tcp = sorted(set(tcp) - set(old.get("tcp") or []))
        new_udp = sorted(set(udp) - set(old.get("udp") or []))
        if first_run and LEARN_OPEN_PORTS_ON_FIRST_RUN:
            continue
        if not new_tcp and not new_udp:
            continue
        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        dedupe = anomaly_dedupe_key("new_open_service", device_id, None, f"tcp:{','.join(map(str, new_tcp))}", f"udp:{','.join(map(str, new_udp))}")
        if recently_emitted(cur, dedupe, 24 * 60):
            continue
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type="new_open_service",
            severity="medium",
            title=f"New open service detected: {name}",
            description=f"New open ports detected. TCP: {new_tcp or '-'}, UDP: {new_udp or '-'}",
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            raw_json={"new_tcp_ports": new_tcp, "new_udp_ports": new_udp, "known_before": old, "current": current[device_id]},
            dedupe_key=dedupe,
            create_incident=True,
        )
        emitted += 1
    state["known_ports"] = current
    return emitted, state


def detect_baseline_metric(cur, bucket: str, metric_name: str, event_type: str, title_prefix: str, min_threshold: int, rows: list[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        device_id = to_text(row.get("device_id"))
        if not device_id:
            continue
        value = float(row.get("metric_value") or 0)
        triggered, info = should_trigger_baseline(cur, device_id, metric_name, value, min_threshold)
        update_baseline(cur, device_id, metric_name, value, {"window_minutes": WINDOW_MINUTES, **info})
        if not triggered:
            continue
        if event_type in {"dns_request_rate_spike"} and dns_anomaly_ignored(row, device_id):
            continue
        dedupe = anomaly_dedupe_key(event_type, device_id, bucket)
        if recently_emitted(cur, dedupe):
            continue
        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type=event_type,
            severity="high" if event_type in {"traffic_volume_spike", "outbound_connection_burst"} else "medium",
            title=f"{title_prefix}: {name}",
            description=f"{metric_name} value {int(value)} exceeded learned baseline in the last {WINDOW_MINUTES} minutes.",
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            raw_json={"metric_name": metric_name, "value": value, "window_minutes": WINDOW_MINUTES, **info},
            dedupe_key=dedupe,
            create_incident=True,
        )
        count += 1
    return count


def detect_dns_request_rate(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT se.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COUNT(*)::int AS metric_value
        FROM security_events se
        LEFT JOIN devices d ON d.id = se.device_id
        WHERE se.event_time >= now() - (%s::text || ' minutes')::interval
          AND se.source_system ILIKE 'adguard%%'
          AND se.event_type IN ('dns_query','dns_block','malicious_dns_block','policy_dns_block')
          AND se.device_id IS NOT NULL
        GROUP BY se.device_id, d.hostname, d.current_ip
        """,
        (WINDOW_MINUTES,),
    )
    return detect_baseline_metric(cur, bucket, "dns_requests_per_window", "dns_request_rate_spike", "DNS request rate spike", DNS_REQUEST_THRESHOLD, [dict(r) for r in cur.fetchall()])


def detect_traffic_volume_spike(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT dts.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COALESCE(SUM(dts.bytes_delta),0)::bigint AS metric_value
        FROM device_traffic_samples dts
        LEFT JOIN devices d ON d.id = dts.device_id
        WHERE dts.sample_time >= now() - (%s::text || ' minutes')::interval
          AND dts.direction = 'outbound'
          AND dts.device_id IS NOT NULL
        GROUP BY dts.device_id, d.hostname, d.current_ip
        """,
        (WINDOW_MINUTES,),
    )
    return detect_baseline_metric(cur, bucket, "outbound_bytes_per_window", "traffic_volume_spike", "Unusual outbound traffic volume", TRAFFIC_BYTES_THRESHOLD, [dict(r) for r in cur.fetchall()])


def detect_outbound_connection_burst(cur, bucket: str) -> int:
    cur.execute(
        """
        SELECT dts.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, COUNT(DISTINCT dts.state_key)::int AS metric_value
        FROM device_traffic_samples dts
        LEFT JOIN devices d ON d.id = dts.device_id
        WHERE dts.sample_time >= now() - (%s::text || ' minutes')::interval
          AND dts.direction = 'outbound'
          AND dts.device_id IS NOT NULL
        GROUP BY dts.device_id, d.hostname, d.current_ip
        """,
        (WINDOW_MINUTES,),
    )
    return detect_baseline_metric(cur, bucket, "outbound_connections_per_window", "outbound_connection_burst", "Outbound connection burst", OUTBOUND_CONNECTION_THRESHOLD, [dict(r) for r in cur.fetchall()])


def detect_new_destination_countries(cur, state: dict[str, Any], bucket: str) -> tuple[int, dict[str, Any]]:
    """Record new destination-country observations and alert only on suspicious countries.

    Normal countries are useful telemetry for the HA "Naujos paskirties šalys" tile, but
    creating a separate incident for every newly observed country is too noisy in a home
    network. Therefore, non-suspicious countries are stored as info security_events only.

    Countries listed in ANOMALY_SUSPICIOUS_COUNTRIES remain incident-worthy. They are
    emitted with a stable dedupe key per device+country, so one active incident is updated
    instead of creating repeated duplicates. Suspicious-country checks do not require the
    country to be new; if the device keeps talking to RU/CN/IR/KP, the active incident can
    be refreshed after the cooldown.
    """
    seen = state.get("seen_countries") if isinstance(state.get("seen_countries"), dict) else {}
    first_run = not bool(seen)
    cur.execute(
        """
        SELECT DISTINCT dts.device_id::text AS device_id, d.hostname, host(d.current_ip) AS ip, dts.country_code
        FROM device_traffic_samples dts
        LEFT JOIN devices d ON d.id = dts.device_id
        WHERE dts.sample_time >= now() - (%s::text || ' minutes')::interval
          AND dts.direction = 'outbound'
          AND dts.country_code IS NOT NULL
          AND dts.device_id IS NOT NULL
        """,
        (WINDOW_MINUTES,),
    )
    emitted = 0
    for row in cur.fetchall():
        device_id = to_text(row.get("device_id"))
        cc = to_text(row.get("country_code")).upper()
        if not device_id or not cc:
            continue

        countries = set(seen.get(device_id) or [])
        is_new = cc not in countries
        is_suspicious = cc in SUSPICIOUS_COUNTRIES
        countries.add(cc)
        seen[device_id] = sorted(countries)

        # Non-suspicious countries are only interesting when newly observed.
        # Suspicious countries are interesting whenever observed, but deduped below.
        if not is_new and not is_suspicious:
            continue

        # On first run, learn the current normal baseline silently. Do not hide suspicious
        # countries during the first run.
        if first_run and LEARN_COUNTRIES_ON_FIRST_RUN and not is_suspicious:
            continue

        dedupe = anomaly_dedupe_key("new_destination_country", device_id, None, cc)
        cooldown = SUSPICIOUS_COUNTRY_REPEAT_COOLDOWN_MINUTES if is_suspicious else NEW_COUNTRY_REPEAT_COOLDOWN_MINUTES
        if recently_emitted(cur, dedupe, cooldown):
            continue

        name = to_text(row.get("hostname")) or to_text(row.get("ip")) or device_id
        severity = SUSPICIOUS_COUNTRY_SEVERITY if is_suspicious else NEW_COUNTRY_EVENT_SEVERITY
        title = (
            f"Suspicious destination country observed: {name} -> {cc}"
            if is_suspicious
            else f"New destination country observed: {name} -> {cc}"
        )
        description = (
            f"Device contacted suspicious destination country {cc}. Country is listed in ANOMALY_SUSPICIOUS_COUNTRIES."
            if is_suspicious
            else f"Device contacted destination country {cc} for the first time in the learned baseline. Informational event only."
        )
        create_security_event(
            cur,
            source_system="anomaly-engine",
            event_type="new_destination_country",
            severity=severity,
            title=title,
            description=description,
            device_id=device_id,
            src_ip=normalize_ip(row.get("ip")),
            country_code=cc,
            raw_json={
                "country_code": cc,
                "suspicious_country": is_suspicious,
                "suspicious_countries": sorted(SUSPICIOUS_COUNTRIES),
                "first_run": first_run,
                "informational_only": not is_suspicious and not NEW_COUNTRY_CREATE_GENERAL_INCIDENTS,
            },
            dedupe_key=dedupe,
            create_incident=is_suspicious or NEW_COUNTRY_CREATE_GENERAL_INCIDENTS,
        )
        emitted += 1
    state["seen_countries"] = seen
    return emitted, state


def process() -> dict[str, Any]:
    now = utc_now()
    bucket = bucket_key(now, WINDOW_MINUTES)
    state = load_state("anomaly_engine")
    counts = {
        "dns_block_burst": 0,
        "dns_domain_spike": 0,
        "ids_alert_spike": 0,
        "new_open_service": 0,
        "dns_request_rate_spike": 0,
        "traffic_volume_spike": 0,
        "outbound_connection_burst": 0,
        "new_destination_country": 0,
    }
    with connect() as conn:
        with conn.cursor() as cur:
            counts["dns_block_burst"] = detect_dns_block_burst(cur, bucket)
            counts["dns_domain_spike"] = detect_unique_domain_spike(cur, bucket)
            counts["ids_alert_spike"] = detect_ids_alert_spike(cur, bucket)
            counts["dns_request_rate_spike"] = detect_dns_request_rate(cur, bucket)
            counts["traffic_volume_spike"] = detect_traffic_volume_spike(cur, bucket)
            counts["outbound_connection_burst"] = detect_outbound_connection_burst(cur, bucket)
            new_ports, state = detect_new_open_ports(cur, state)
            counts["new_open_service"] = new_ports
            new_countries, state = detect_new_destination_countries(cur, state, bucket)
            counts["new_destination_country"] = new_countries
        conn.commit()

    state["last_run_at"] = now.isoformat()
    save_state("anomaly_engine", state)
    details = {"window_minutes": WINDOW_MINUTES, "baseline_min_samples": BASELINE_MIN_SAMPLES, "baseline_multiplier": BASELINE_MULTIPLIER, **counts}
    update_health(COMPONENT, "detection-worker", "healthy", details, version="phase5-complete-5a5b-keep5c")
    return {"status": "healthy", **details}


def main():
    try:
        result = process()
    except Exception as exc:
        details = {"error": str(exc)}
        update_health(COMPONENT, "detection-worker", "degraded", details, version="phase5-complete-5a5b-keep5c")
        result = {"status": "degraded", **details}
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
