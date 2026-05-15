import base64
import datetime as dt
import json
from collections import deque
from typing import Any

import requests

from detection_common import (
    clean_optional_text,
    connect,
    create_security_event,
    getenv_any,
    load_state,
    normalize_ip,
    save_state,
    to_text,
    update_health,
)


COMPONENT = "security-adguard-ingest"

# Default mode is direct AdGuard Home API because Phase 5 uses a standalone AdGuard Home instance on REDACTED.
# Optional fallback mode: home_assistant, but that only sees aggregate HA integration counters.
ADGUARD_SOURCE = getenv_any(["ADGUARD_SOURCE", "SECURITY_CORE_ADGUARD_SOURCE"], "adguard_api").lower()

HOME_ASSISTANT_URL = getenv_any(["HOME_ASSISTANT_URL", "HA_URL"], "http://REDACTED").rstrip("/")
HOME_ASSISTANT_TOKEN = getenv_any(["HOME_ASSISTANT_TOKEN", "HA_TOKEN"], "")
HA_VERIFY_SSL = getenv_any(["HOME_ASSISTANT_VERIFY_SSL", "HA_VERIFY_SSL"], "false").lower() == "true"
HA_DNS_QUERIES_ENTITY = getenv_any(["HA_ADGUARD_DNS_QUERIES_ENTITY"], "sensor.adguard_home_dns_queries")
HA_DNS_BLOCKED_ENTITY = getenv_any(["HA_ADGUARD_DNS_BLOCKED_ENTITY"], "sensor.adguard_home_dns_queries_blocked")
HA_SAFE_BROWSING_ENTITY = getenv_any(["HA_ADGUARD_SAFE_BROWSING_BLOCKED_ENTITY"], "sensor.adguard_home_safe_browsing_blocked")
HA_PARENTAL_BLOCKED_ENTITY = getenv_any(["HA_ADGUARD_PARENTAL_BLOCKED_ENTITY"], "sensor.adguard_home_parental_control_blocked")
HA_BLOCK_BURST_THRESHOLD = int(getenv_any(["ADGUARD_HA_BLOCK_BURST_THRESHOLD"], "20"))
HA_CREATE_GENERAL_BLOCK_EVENTS = getenv_any(["ADGUARD_HA_CREATE_GENERAL_BLOCK_EVENTS"], "true").lower() in {"1", "true", "yes", "on"}
HA_CREATE_GENERAL_BLOCK_INCIDENTS = getenv_any(["ADGUARD_HA_CREATE_GENERAL_BLOCK_INCIDENTS"], "false").lower() in {"1", "true", "yes", "on"}

# Direct AdGuard API mode. Default matches the new standalone AdGuard Home instance.
ADGUARD_URL = getenv_any(["ADGUARD_URL", "SECURITY_CORE_ADGUARD_URL"], "http://REDACTED").rstrip("/")
ADGUARD_AUTH_B64 = getenv_any(["ADGUARD_AUTH_B64", "SECURITY_CORE_ADGUARD_AUTH_B64"], "")
ADGUARD_USERNAME = getenv_any(["ADGUARD_USERNAME", "SECURITY_CORE_ADGUARD_USERNAME"], "")
ADGUARD_PASSWORD = getenv_any(["ADGUARD_PASSWORD", "SECURITY_CORE_ADGUARD_PASSWORD"], "")
ADGUARD_VERIFY_SSL = getenv_any(["ADGUARD_VERIFY_SSL"], "false").lower() == "true"
QUERY_LIMIT = int(getenv_any(["ADGUARD_QUERY_LOG_LIMIT"], "500"))
ONLY_BLOCKED = getenv_any(["ADGUARD_ONLY_BLOCKED_EVENTS"], "false").lower() in {"1", "true", "yes", "on"}
SEEN_CACHE_SIZE = int(getenv_any(["ADGUARD_SEEN_CACHE_SIZE"], "3000"))
CREATE_INCIDENTS = getenv_any(["ADGUARD_CREATE_INCIDENTS"], "true").lower() in {"1", "true", "yes", "on"}
# Incident creation is intentionally conservative. Generic ad/tracker blocks are useful evidence/events,
# but should not flood the incident list. Anomaly engine creates burst incidents separately.
CREATE_MALICIOUS_INCIDENTS = getenv_any(["ADGUARD_CREATE_MALICIOUS_INCIDENTS"], "true").lower() in {"1", "true", "yes", "on"}
CREATE_GENERAL_BLOCK_INCIDENTS = getenv_any(["ADGUARD_CREATE_GENERAL_BLOCK_INCIDENTS"], "false").lower() in {"1", "true", "yes", "on"}
CREATE_POLICY_BLOCK_INCIDENTS = getenv_any(["ADGUARD_CREATE_POLICY_BLOCK_INCIDENTS"], "false").lower() in {"1", "true", "yes", "on"}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: Any) -> dt.datetime | None:
    text = to_text(value)
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except Exception:
        return None


def numeric_state(value: Any) -> int | None:
    text = to_text(value)
    if text.lower() in {"", "unknown", "unavailable", "none", "nan"}:
        return None
    try:
        return int(float(text.replace(",", ".")))
    except Exception:
        return None


def ha_headers() -> dict[str, str]:
    if not HOME_ASSISTANT_TOKEN:
        raise RuntimeError("HOME_ASSISTANT_TOKEN is not set; create a Home Assistant long-lived access token")
    return {"Authorization": f"Bearer {HOME_ASSISTANT_TOKEN}", "Accept": "application/json"}


def fetch_ha_state(entity_id: str) -> dict[str, Any]:
    url = f"{HOME_ASSISTANT_URL}/api/states/{entity_id}"
    response = requests.get(url, headers=ha_headers(), timeout=20, verify=HA_VERIFY_SSL)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected Home Assistant state response for {entity_id}")
    return data


def fetch_ha_adguard_snapshot() -> dict[str, Any]:
    entities = {
        "dns_queries": HA_DNS_QUERIES_ENTITY,
        "dns_blocked": HA_DNS_BLOCKED_ENTITY,
        "safe_browsing_blocked": HA_SAFE_BROWSING_ENTITY,
        "parental_blocked": HA_PARENTAL_BLOCKED_ENTITY,
    }
    snapshot: dict[str, Any] = {"entities": {}, "values": {}}
    for key, entity_id in entities.items():
        state = fetch_ha_state(entity_id)
        snapshot["entities"][key] = entity_id
        snapshot["values"][key] = numeric_state(state.get("state"))
        snapshot.setdefault("raw", {})[key] = state
    snapshot["fetched_at"] = utc_now().isoformat()
    return snapshot


def process_home_assistant_entities() -> dict[str, Any]:
    snapshot = fetch_ha_adguard_snapshot()
    values = snapshot.get("values") or {}
    previous = load_state("adguard_ha_entities")
    previous_values = previous.get("values") if isinstance(previous.get("values"), dict) else {}

    deltas: dict[str, int] = {}
    first_run = not previous_values
    for key, current in values.items():
        previous_value = previous_values.get(key)
        if current is None or previous_value is None:
            continue
        try:
            delta = int(current) - int(previous_value)
        except Exception:
            continue
        if delta >= 0:
            deltas[key] = delta

    save_state("adguard_ha_entities", {"values": values, "updated_at": snapshot.get("fetched_at")})

    processed = 0
    incident_events = 0
    skipped = 0

    if first_run:
        details = {"mode": "home_assistant", "first_run": True, "values": values, "entities": snapshot.get("entities")}
        update_health(COMPONENT, "detection-worker", "healthy", details)
        return {"status": "healthy", **details}

    with connect() as conn:
        with conn.cursor() as cur:
            # Safe browsing increase is the closest HA integration signal to a malicious DNS block.
            safe_delta = deltas.get("safe_browsing_blocked", 0)
            if safe_delta > 0:
                result = create_security_event(
                    cur,
                    source_system="adguard",
                    event_type="malicious_dns_block",
                    severity="high",
                    title="AdGuard safe browsing blocked DNS requests",
                    description=f"Home Assistant AdGuard integration reports {safe_delta} new safe-browsing blocks since the previous poll.",
                    protocol="DNS",
                    event_time=utc_now(),
                    raw_json={"mode": "home_assistant_entities", "delta": safe_delta, "snapshot": snapshot},
                    dedupe_key=f"adguard_ha|safe_browsing|{values.get('safe_browsing_blocked')}",
                    create_incident=CREATE_INCIDENTS,
                )
                processed += 1
                if result.get("incident_id"):
                    incident_events += 1

            parental_delta = deltas.get("parental_blocked", 0)
            if parental_delta > 0:
                result = create_security_event(
                    cur,
                    source_system="adguard",
                    event_type="policy_dns_block",
                    severity="low",
                    title="AdGuard parental-control DNS blocks increased",
                    description=f"Home Assistant AdGuard integration reports {parental_delta} new parental-control blocks since the previous poll.",
                    protocol="DNS",
                    event_time=utc_now(),
                    raw_json={"mode": "home_assistant_entities", "delta": parental_delta, "snapshot": snapshot},
                    dedupe_key=f"adguard_ha|parental|{values.get('parental_blocked')}",
                    create_incident=False,
                )
                processed += 1
                if result.get("incident_id"):
                    incident_events += 1

            blocked_delta = deltas.get("dns_blocked", 0)
            if blocked_delta > 0 and HA_CREATE_GENERAL_BLOCK_EVENTS:
                burst = blocked_delta >= HA_BLOCK_BURST_THRESHOLD
                event_type = "dns_block_burst" if burst else "dns_block"
                severity = "medium" if burst else "low"
                result = create_security_event(
                    cur,
                    source_system="adguard",
                    event_type=event_type,
                    severity=severity,
                    title="AdGuard DNS blocked request counter increased",
                    description=f"Home Assistant AdGuard integration reports {blocked_delta} new blocked DNS requests since the previous poll.",
                    protocol="DNS",
                    event_time=utc_now(),
                    raw_json={"mode": "home_assistant_entities", "delta": blocked_delta, "threshold": HA_BLOCK_BURST_THRESHOLD, "snapshot": snapshot},
                    dedupe_key=f"adguard_ha|dns_blocked|{values.get('dns_blocked')}",
                    create_incident=CREATE_INCIDENTS and (burst or HA_CREATE_GENERAL_BLOCK_INCIDENTS),
                )
                processed += 1
                if result.get("incident_id"):
                    incident_events += 1
            elif blocked_delta <= 0:
                skipped += 1
        conn.commit()

    details = {
        "mode": "home_assistant",
        "home_assistant_url": HOME_ASSISTANT_URL,
        "entities": snapshot.get("entities"),
        "values": values,
        "deltas": deltas,
        "processed": processed,
        "skipped": skipped,
        "events_with_incident": incident_events,
        "limitation": "HA integration mode provides aggregate counters only; no per-device domain query log is available unless direct AdGuard API/log access is exposed.",
    }
    update_health(COMPONENT, "detection-worker", "healthy", details)
    return {"status": "healthy", **details}


def adguard_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if ADGUARD_AUTH_B64:
        headers["Authorization"] = f"Basic {ADGUARD_AUTH_B64}"
    elif ADGUARD_USERNAME or ADGUARD_PASSWORD:
        token = base64.b64encode(f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def fetch_querylog() -> list[dict[str, Any]]:
    if not ADGUARD_URL:
        raise RuntimeError("ADGUARD_URL is not set. Expected standalone AdGuard Home Web/API URL, for example http://REDACTED.")
    url = f"{ADGUARD_URL}/control/querylog"
    response = requests.get(
        url,
        params={"limit": QUERY_LIMIT, "response_status": "all"},
        headers=adguard_headers(),
        timeout=30,
        verify=ADGUARD_VERIFY_SSL,
    )
    response.raise_for_status()
    data = response.json()
    if isinstance(data, dict):
        rows = data.get("data") or data.get("items") or data.get("queries") or []
        return rows if isinstance(rows, list) else []
    if isinstance(data, list):
        return data
    return []


def query_value(item: dict[str, Any], key: str) -> Any:
    if key in item:
        return item.get(key)
    question = item.get("question") if isinstance(item.get("question"), dict) else {}
    if key in question:
        return question.get(key)
    return None


def client_ip(item: dict[str, Any]) -> str | None:
    for key in ("client", "client_ip", "clientIP", "client_id"):
        ip = normalize_ip(item.get(key))
        if ip:
            return ip
    client_info = item.get("client_info") if isinstance(item.get("client_info"), dict) else {}
    for key in ("ip", "client", "name"):
        ip = normalize_ip(client_info.get(key))
        if ip:
            return ip
    return None


def domain_name(item: dict[str, Any]) -> str | None:
    for value in [item.get("domain"), query_value(item, "name"), query_value(item, "host"), query_value(item, "qname")]:
        text = to_text(value).rstrip(".").lower()
        if text:
            return text
    return None


BLOCKED_REASONS = {
    "filteredblacklist",
    "filteredsafebrowsing",
    "filteredparental",
    "filteredsafesearch",
    "filteredblockedservice",
    "filteredinvalid",
}

NOT_BLOCKED_REASONS = {
    "notfilterednotfound",
    "notfilteredwhitelist",
    "notfilteredallowlist",
    "notfilterederror",
    "notfilteredunknown",
    "notfilteredunmatched",
    "notfilteredcache",
    "notfiltered",
}


def normalized_reason(item: dict[str, Any]) -> str:
    return to_text(item.get("reason") or item.get("filtering_reason") or "").replace("_", "").replace("-", "").lower()


def response_status(item: dict[str, Any]) -> str:
    return to_text(item.get("status") or item.get("response_status") or "").lower()


def is_blocked(item: dict[str, Any]) -> bool:
    """Return True only for real AdGuard filtering/blocking decisions.

    AdGuard reasons such as NotFilteredWhiteList and NotFilteredNotFound contain
    the word "Filter", but they are explicitly not blocked. Keep this strict to
    avoid false-positive incident floods.
    """
    reason = normalized_reason(item)
    status = response_status(item)

    if reason in NOT_BLOCKED_REASONS or reason.startswith("notfiltered"):
        return False
    if reason in BLOCKED_REASONS or reason.startswith("filtered"):
        return True
    if status in {"filtered", "blocked"}:
        return True

    answers = item.get("answer") if isinstance(item.get("answer"), list) else []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        if to_text(answer.get("value")) in {"0.0.0.0", "::", "::0"}:
            return True
    return False


def classify_dns_event(item: dict[str, Any]) -> tuple[str, str, str, bool]:
    """Return event_type, severity, title, incident_eligible."""
    reason = normalized_reason(item)
    rules_text = json.dumps(item.get("rules") or item.get("filters") or [], ensure_ascii=False).lower()
    combined = f"{reason} {rules_text}"

    if not is_blocked(item):
        return "dns_query", "info", "DNS query observed", False

    if "safebrowsing" in combined or "malware" in combined or "phishing" in combined or "threat" in combined:
        return "malicious_dns_block", "high", "Malicious DNS request blocked", CREATE_MALICIOUS_INCIDENTS
    if "parental" in combined or "safesearch" in combined or "safe search" in combined:
        return "policy_dns_block", "low", "Policy DNS request blocked", CREATE_POLICY_BLOCK_INCIDENTS
    if reason == "filteredblockedservice":
        return "policy_dns_block", "low", "Blocked-service DNS request blocked", CREATE_POLICY_BLOCK_INCIDENTS
    return "dns_block", "low", "DNS request blocked", CREATE_GENERAL_BLOCK_INCIDENTS


def event_identity(item: dict[str, Any]) -> str:
    return "|".join([
        to_text(item.get("time") or item.get("timestamp")),
        to_text(client_ip(item)),
        to_text(domain_name(item)),
        to_text(item.get("reason") or item.get("status")),
        to_text(item.get("elapsedMs") or item.get("elapsed_ms")),
    ])


def process_direct_api() -> dict[str, Any]:
    state = load_state("adguard_querylog")
    seen = deque(state.get("seen") or [], maxlen=SEEN_CACHE_SIZE)
    seen_set = set(seen)
    rows = fetch_querylog()
    processed = 0
    skipped = 0
    incident_events = 0

    rows = list(reversed([row for row in rows if isinstance(row, dict)]))

    with connect() as conn:
        with conn.cursor() as cur:
            for item in rows:
                identity = event_identity(item)
                if not identity or identity in seen_set:
                    skipped += 1
                    continue
                seen.append(identity)
                seen_set.add(identity)

                blocked = is_blocked(item)
                if ONLY_BLOCKED and not blocked:
                    skipped += 1
                    continue

                event_type, severity, default_title, incident_eligible = classify_dns_event(item)
                domain = domain_name(item)
                src_ip = client_ip(item)
                qtype = clean_optional_text(query_value(item, "type"))
                reason = clean_optional_text(item.get("reason") or item.get("filtering_reason") or item.get("status"))
                title = f"{default_title}: {domain}" if domain else default_title
                description = f"AdGuard {reason or 'query'} for {domain or 'unknown domain'}"
                if qtype:
                    description += f" ({qtype})"

                result = create_security_event(
                    cur,
                    source_system="adguard",
                    event_type=event_type,
                    severity=severity,
                    title=title,
                    description=description,
                    src_ip=src_ip,
                    protocol="DNS",
                    domain=domain,
                    event_time=parse_time(item.get("time") or item.get("timestamp")),
                    raw_json=item,
                    dedupe_key=f"adguard|{event_type}|{src_ip or '-'}|{domain or '-'}|{reason or '-'}",
                    create_incident=CREATE_INCIDENTS and incident_eligible,
                )
                processed += 1
                if result.get("incident_id"):
                    incident_events += 1
        conn.commit()

    save_state("adguard_querylog", {"seen": list(seen)})
    details = {"mode": "direct_api", "url": ADGUARD_URL, "auth_mode": ("basic" if (ADGUARD_AUTH_B64 or ADGUARD_USERNAME or ADGUARD_PASSWORD) else "none"), "rows_read": len(rows), "processed": processed, "skipped": skipped, "events_with_incident": incident_events, "only_blocked": ONLY_BLOCKED, "create_general_block_incidents": CREATE_GENERAL_BLOCK_INCIDENTS, "create_policy_block_incidents": CREATE_POLICY_BLOCK_INCIDENTS, "create_malicious_incidents": CREATE_MALICIOUS_INCIDENTS}
    update_health(COMPONENT, "detection-worker", "healthy", details)
    return {"status": "healthy", **details}


def process() -> dict[str, Any]:
    if ADGUARD_SOURCE in {"home_assistant", "ha", "ha_entities", "entities"}:
        return process_home_assistant_entities()
    if ADGUARD_SOURCE in {"direct_api", "adguard_api", "querylog"}:
        return process_direct_api()
    raise RuntimeError(f"Unsupported ADGUARD_SOURCE={ADGUARD_SOURCE}. Use home_assistant or direct_api.")


def main():
    try:
        result = process()
    except Exception as exc:
        details = {"source": ADGUARD_SOURCE, "home_assistant_url": HOME_ASSISTANT_URL, "adguard_url": ADGUARD_URL, "error": str(exc)}
        update_health(COMPONENT, "detection-worker", "degraded", details)
        result = {"status": "degraded", **details}
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
