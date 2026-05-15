#!/usr/bin/env python3
"""Phase 7 notification worker for security-core.

Hotfix v4:
- sends notification through enabled channels from env: HA persistent, SMTP email, and Home Assistant mobile app;
- can auto-discover notify.mobile_app_* services when PHASE7_HA_MOBILE_NOTIFY_SERVICE=auto or empty;
- adds test-smtp, test-mobile and test-all commands.

Earlier fixes:
- records/claims notification delivery before calling Home Assistant, so a DB error cannot create endless HA notification spam;
- normalizes UUID/text values returned as bytes/memoryview;
- sends each incident/response notification once per channel by stable dedupe key;
- skips noisy GeoIP country notifications by default;
- optionally skips device incidents when the device is currently offline;
- uses Home Assistant notification_id so repeated calls update instead of stacking.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import smtplib
import socket
import uuid
from email.message import EmailMessage
from typing import Any

import requests

from detection_common import connect, getenv_any, j, to_text, update_health

COMPONENT = "security-notification-worker"
VERSION = "phase7-notifications-v5-smtp-helo-retry"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OPEN_STATUSES = {"open", "acknowledged", "in_progress"}

HOME_ASSISTANT_URL = getenv_any(["HOME_ASSISTANT_URL", "HA_URL"], "http://REDACTED").rstrip("/")
HOME_ASSISTANT_TOKEN = getenv_any(["HOME_ASSISTANT_TOKEN", "HA_TOKEN"], "")
HA_VERIFY_SSL = getenv_any(["HA_VERIFY_SSL", "HOME_ASSISTANT_VERIFY_SSL"], "false").lower() in {"1", "true", "yes", "on"}
PHASE7_HA_MOBILE_NOTIFY_SERVICE = getenv_any(["PHASE7_HA_MOBILE_NOTIFY_SERVICE"], "")
PHASE7_ENABLE_HA_PERSISTENT = getenv_any(["PHASE7_ENABLE_HA_PERSISTENT"], "true").lower() in {"1", "true", "yes", "on"}
PHASE7_ENABLE_HA_MOBILE = getenv_any(["PHASE7_ENABLE_HA_MOBILE"], "false").lower() in {"1", "true", "yes", "on"}
PHASE7_ENABLE_SMTP = getenv_any(["PHASE7_ENABLE_SMTP"], "false").lower() in {"1", "true", "yes", "on"}
SMTP_HOST = getenv_any(["PHASE7_SMTP_HOST", "SMTP_HOST"], "")
SMTP_PORT = int(getenv_any(["PHASE7_SMTP_PORT", "SMTP_PORT"], "587") or "587")
SMTP_USERNAME = getenv_any(["PHASE7_SMTP_USERNAME", "SMTP_USERNAME"], "")
SMTP_PASSWORD = getenv_any(["PHASE7_SMTP_PASSWORD", "SMTP_PASSWORD"], "")
SMTP_FROM = getenv_any(["PHASE7_SMTP_FROM", "SMTP_FROM"], SMTP_USERNAME)
SMTP_TO = [x.strip() for x in getenv_any(["PHASE7_SMTP_TO", "SMTP_TO"], "").split(",") if x.strip()]
SMTP_STARTTLS = getenv_any(["PHASE7_SMTP_STARTTLS", "SMTP_STARTTLS"], "true").lower() in {"1", "true", "yes", "on"}
SMTP_HELO_HOSTNAME_RAW = getenv_any(["PHASE7_SMTP_HELO_HOSTNAME", "PHASE7_SMTP_LOCAL_HOSTNAME", "SMTP_HELO_HOSTNAME"], "")
DEFAULT_COOLDOWN_MINUTES = int(getenv_any(["PHASE7_NOTIFICATION_DEFAULT_COOLDOWN_MINUTES"], "1440") or "1440")
LOOKBACK_HOURS = int(getenv_any(["PHASE7_NOTIFICATION_LOOKBACK_HOURS"], "6") or "6")
REQUIRE_ONLINE = getenv_any(["PHASE7_NOTIFY_REQUIRE_ONLINE_FOR_DEVICE_INCIDENTS"], "true").lower() in {"1", "true", "yes", "on"}
EXCLUDED_INCIDENT_TYPES = {
    x.strip()
    for x in getenv_any(["PHASE7_NOTIFICATION_EXCLUDED_INCIDENT_TYPES"], "new_destination_country").split(",")
    if x.strip()
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def safe_smtp_helo_hostname() -> str:
    """Return a valid SMTP EHLO/HELO hostname.

    Some MTAs reject short or malformed hostnames. On this system Python picked
    a bad value like ``security-core..`` which caused:
    501 5.5.2 <security-core..>: Helo command rejected: Invalid name.
    """
    raw = SMTP_HELO_HOSTNAME_RAW.strip()
    if not raw:
        # Prefer a hostname under the sender domain, e.g. REDACTED.
        domain = ""
        if "@" in SMTP_FROM:
            domain = SMTP_FROM.split("@", 1)[1].strip().strip(".").lower()
        host = socket.gethostname().strip().strip(".").lower() or "security-core"
        host = re.sub(r"[^a-z0-9-]+", "-", host).strip("-") or "security-core"
        raw = f"{host}.{domain}" if domain and "." not in host else host
    raw = raw.strip().strip(".").lower()
    raw = re.sub(r"[^a-z0-9.-]+", "-", raw)
    raw = re.sub(r"\.+", ".", raw).strip(".")
    parts = [part.strip("-") for part in raw.split(".") if part.strip("-")]
    if not parts:
        parts = ["security-core"]
    # Ensure this looks like an FQDN because many mail servers reject bare hostnames.
    if len(parts) == 1:
        domain = SMTP_FROM.split("@", 1)[1].strip().strip(".").lower() if "@" in SMTP_FROM else "localdomain"
        parts.append(domain)
    return ".".join(parts)


def db_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 16:
            try:
                return str(uuid.UUID(bytes=raw))
            except Exception:
                pass
        return raw.decode("utf-8", errors="ignore").strip()
    return str(value).strip()




def maybe_decode_hex_text(value: Any) -> str:
    """Decode legacy hex-encoded text fields used by early Phase 7 rows.

    Some rows may contain UTF-8 text represented as hex with UUID-style dashes,
    e.g. 68696768-5f69-6e63-6964-656e745f6861 -> high_incident_ha.
    This is only for display/text fields; UUID normalization remains separate.
    """
    text = db_text(value)
    if not text:
        return ""
    candidates = []
    if text.startswith("\\x") and len(text) > 2:
        candidates.append(text[2:])
    candidates.append(text.replace("-", ""))
    for candidate in candidates:
        if len(candidate) < 8 or len(candidate) % 2 != 0:
            continue
        if any(ch not in "0123456789abcdefABCDEF" for ch in candidate):
            continue
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="strict").strip()
        except Exception:
            continue
        if not decoded:
            continue
        if all((ch.isprintable() or ch in "\r\n\t") for ch in decoded) and any(ch.isalpha() for ch in decoded):
            return decoded
    return text


def decode_embedded_hex_text(value: Any) -> str:
    text = db_text(value)
    if not text:
        return ""

    def repl(match):
        original = match.group(0)
        decoded = maybe_decode_hex_text(original)
        return decoded if decoded != original else original

    # UUID-shaped hex tokens and raw long hex tokens. Actual UUID values normally
    # decode to non-printable bytes and therefore remain unchanged.
    pattern = re.compile(
        r"(?<![0-9A-Fa-f])(?:"
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        r"|\\x[0-9A-Fa-f]{8,}"
        r"|[0-9A-Fa-f]{12,}"
        r")(?![0-9A-Fa-f])"
    )
    return pattern.sub(repl, text)


def uuid_text_or_none(value: Any) -> str | None:
    text = db_text(value)
    if not text or text.lower() in {"none", "null"}:
        return None
    if text.startswith("\\x") and len(text) == 34:
        try:
            return str(uuid.UUID(bytes=bytes.fromhex(text[2:])))
        except Exception:
            return None
    try:
        return str(uuid.UUID(text))
    except Exception:
        return None


def table_exists(cur, table: str) -> bool:
    cur.execute("SELECT to_regclass(%s) IS NOT NULL AS exists", (f"public.{table}",))
    return bool((cur.fetchone() or {}).get("exists"))


def severity_allowed(value: Any, minimum: Any) -> bool:
    return SEVERITY_RANK.get(db_text(value).lower(), 0) >= SEVERITY_RANK.get(db_text(minimum).lower(), 3)


def json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [db_text(x) for x in value if db_text(x)]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [db_text(x) for x in parsed if db_text(x)]
        except Exception:
            pass
    return []


def ha_headers() -> dict[str, str]:
    if not HOME_ASSISTANT_TOKEN:
        raise RuntimeError("HOME_ASSISTANT_TOKEN is not set")
    return {"Authorization": f"Bearer {HOME_ASSISTANT_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}


def normalize_notify_service(value: Any) -> str:
    text = db_text(value).strip()
    if not text:
        return ""
    text = text.replace("/", ".")
    if text.startswith("notify."):
        return text
    return f"notify.{text}"


def explicit_mobile_services() -> list[str]:
    raw = PHASE7_HA_MOBILE_NOTIFY_SERVICE.strip()
    if not raw or raw.lower() in {"auto", "all", "auto_all"}:
        return []
    result: list[str] = []
    for item in re.split(r"[,;\s]+", raw):
        service = normalize_notify_service(item)
        if service and service not in result:
            result.append(service)
    return result


def discover_mobile_services() -> list[str]:
    if not PHASE7_ENABLE_HA_MOBILE:
        return []
    explicit = explicit_mobile_services()
    if explicit:
        return explicit
    url = f"{HOME_ASSISTANT_URL}/api/services"
    response = requests.get(url, headers=ha_headers(), timeout=20, verify=HA_VERIFY_SSL)
    response.raise_for_status()
    data = response.json()
    result: list[str] = []
    for domain_item in data if isinstance(data, list) else []:
        if not isinstance(domain_item, dict) or domain_item.get("domain") != "notify":
            continue
        services = domain_item.get("services") or {}
        if not isinstance(services, dict):
            continue
        for service_name in services.keys():
            service = normalize_notify_service(service_name)
            if "mobile_app" in service and service not in result:
                result.append(service)
    return sorted(result)


def resolve_rule_channels(channels: list[str]) -> list[str]:
    # DB rules may contain only ha_persistent from early Phase 7. Add enabled env channels
    # here so SMTP/mobile can be enabled from /etc/security-core/security-core.env without
    # requiring another DB migration for every channel change.
    requested: list[str] = []
    for ch in channels or []:
        ch = db_text(ch).strip()
        if ch and ch not in requested:
            requested.append(ch)
    if PHASE7_ENABLE_HA_PERSISTENT and "ha_persistent" not in requested:
        requested.append("ha_persistent")
    if PHASE7_ENABLE_SMTP and "email" not in requested:
        requested.append("email")
    if PHASE7_ENABLE_HA_MOBILE and "ha_mobile" not in requested:
        requested.append("ha_mobile")

    resolved: list[str] = []
    for ch in requested:
        base = ch.split(":", 1)[0]
        if base == "ha_persistent":
            if PHASE7_ENABLE_HA_PERSISTENT and "ha_persistent" not in resolved:
                resolved.append("ha_persistent")
        elif base == "email":
            if PHASE7_ENABLE_SMTP and "email" not in resolved:
                resolved.append("email")
        elif base == "ha_mobile":
            if not PHASE7_ENABLE_HA_MOBILE:
                continue
            if ":" in ch:
                service = normalize_notify_service(ch.split(":", 1)[1])
                token = f"ha_mobile:{service}"
                if service and token not in resolved:
                    resolved.append(token)
            else:
                services = discover_mobile_services()
                if services:
                    for service in services:
                        token = f"ha_mobile:{service}"
                        if token not in resolved:
                            resolved.append(token)
                elif "ha_mobile" not in resolved:
                    # Keep one explicit failure so misconfiguration is visible in notification_deliveries/system_health.
                    resolved.append("ha_mobile")
    return resolved


def notification_id_for(dedupe_key: str) -> str:
    digest = hashlib.sha1(dedupe_key.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return f"security_core_{digest}"


def deliver_ha_persistent(title: str, body: str, dedupe_key: str) -> dict[str, Any]:
    if not PHASE7_ENABLE_HA_PERSISTENT:
        return {"skipped": "ha_persistent_disabled"}
    url = f"{HOME_ASSISTANT_URL}/api/services/persistent_notification/create"
    payload = {"title": title, "message": body, "notification_id": notification_id_for(dedupe_key)}
    response = requests.post(url, headers=ha_headers(), json=payload, timeout=20, verify=HA_VERIFY_SSL)
    response.raise_for_status()
    return {"http_status": response.status_code, "response": response.text[:500], "notification_id": payload["notification_id"]}


def deliver_ha_mobile(title: str, body: str, dedupe_key: str, service: str | None = None) -> dict[str, Any]:
    if not PHASE7_ENABLE_HA_MOBILE:
        return {"skipped": "ha_mobile_disabled"}
    services = [normalize_notify_service(service)] if service else discover_mobile_services()
    services = [x for x in services if x]
    if not services:
        raise RuntimeError("HA mobile notifications are enabled, but no mobile notify service was configured or discovered. Set PHASE7_HA_MOBILE_NOTIFY_SERVICE=notify.mobile_app_<phone> or auto.")
    sent: list[dict[str, Any]] = []
    for svc in services:
        short_service = svc.replace("notify.", "", 1)
        url = f"{HOME_ASSISTANT_URL}/api/services/notify/{short_service}"
        payload = {
            "title": title,
            "message": body,
            "data": {
                "tag": notification_id_for(f"{dedupe_key}|{svc}"),
                "group": "security_core",
                "channel": "Security Core",
                "importance": "high",
                "ttl": 0,
                "priority": "high",
            },
        }
        response = requests.post(url, headers=ha_headers(), json=payload, timeout=20, verify=HA_VERIFY_SSL)
        response.raise_for_status()
        sent.append({"service": svc, "http_status": response.status_code, "response": response.text[:500]})
    return {"sent_to": [x["service"] for x in sent], "responses": sent}


def deliver_email(title: str, body: str, dedupe_key: str) -> dict[str, Any]:
    if not PHASE7_ENABLE_SMTP:
        return {"skipped": "smtp_disabled"}
    if not SMTP_HOST or not SMTP_FROM or not SMTP_TO:
        raise RuntimeError("SMTP is enabled but PHASE7_SMTP_HOST/FROM/TO are not configured")
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(SMTP_TO)
    msg.set_content(body)
    helo_hostname = safe_smtp_helo_hostname()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, local_hostname=helo_hostname, timeout=30) as smtp:
        # Explicit EHLO makes the configured hostname visible before STARTTLS.
        smtp.ehlo(helo_hostname)
        if SMTP_STARTTLS:
            smtp.starttls()
            smtp.ehlo(helo_hostname)
        if SMTP_USERNAME:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(msg)
    return {"sent_to": SMTP_TO, "smtp_host": SMTP_HOST, "smtp_port": SMTP_PORT, "helo_hostname": helo_hostname}


def deliver(channel: str, title: str, body: str, dedupe_key: str) -> dict[str, Any]:
    if channel == "ha_persistent":
        return deliver_ha_persistent(title, body, dedupe_key)
    if channel == "ha_mobile":
        return deliver_ha_mobile(title, body, dedupe_key)
    if channel.startswith("ha_mobile:"):
        return deliver_ha_mobile(title, body, dedupe_key, service=channel.split(":", 1)[1])
    if channel == "email":
        return deliver_email(title, body, dedupe_key)
    return {"skipped": f"unsupported_channel:{channel}"}


def fetch_rules(cur) -> list[dict[str, Any]]:
    if not table_exists(cur, "notification_rules"):
        return []
    cur.execute(
        """
        SELECT rule_name, is_enabled, min_severity, event_types, channels, cooldown_minutes
        FROM notification_rules
        WHERE COALESCE(is_enabled, true) = true
        ORDER BY rule_name
        """
    )
    return [dict(row) for row in cur.fetchall()]


def fetch_incident_candidates(cur, rule: dict[str, Any]) -> list[dict[str, Any]]:
    min_severity = db_text(rule.get("min_severity") or "high").lower()
    event_types = set(json_list(rule.get("event_types")))
    if event_types and "incident" not in event_types:
        return []
    cur.execute(
        """
        SELECT i.id::text AS incident_id,
               i.device_id::text AS device_id,
               i.incident_type,
               i.severity,
               i.source_system,
               i.title,
               i.description,
               i.status,
               i.event_count,
               i.created_at,
               i.last_seen_at,
               d.hostname AS device_hostname,
               host(d.current_ip) AS device_ip,
               d.category AS device_category,
               COALESCE(d.is_online, false) AS device_is_online
        FROM incidents i
        LEFT JOIN devices d ON d.id = i.device_id
        WHERE i.status = ANY(%s)
          AND (i.created_at >= now() - (%s::text || ' hours')::interval
               OR i.last_seen_at >= now() - (%s::text || ' hours')::interval)
        ORDER BY COALESCE(i.last_seen_at, i.created_at) DESC
        LIMIT 200
        """,
        (list(OPEN_STATUSES), LOOKBACK_HOURS, LOOKBACK_HOURS),
    )
    rows: list[dict[str, Any]] = []
    for row in cur.fetchall():
        item = dict(row)
        item["incident_id"] = uuid_text_or_none(item.get("incident_id"))
        item["device_id"] = uuid_text_or_none(item.get("device_id"))
        if not item.get("incident_id"):
            continue
        if db_text(item.get("incident_type")) in EXCLUDED_INCIDENT_TYPES:
            continue
        if REQUIRE_ONLINE and item.get("device_id") and not bool(item.get("device_is_online")):
            continue
        if severity_allowed(item.get("severity"), min_severity):
            rows.append(item)
    return rows


def fetch_response_candidates(cur, rule: dict[str, Any]) -> list[dict[str, Any]]:
    event_types = set(json_list(rule.get("event_types")))
    if event_types and "response_action" not in event_types:
        return []
    if not table_exists(cur, "response_actions"):
        return []
    cur.execute(
        """
        SELECT ra.id::text AS response_action_id,
               ra.incident_id::text AS incident_id,
               ra.device_id::text AS device_id,
               ra.action_type,
               ra.status,
               COALESCE(ra.severity, i.severity, 'low') AS severity,
               ra.reason,
               ra.updated_at,
               i.title AS incident_title,
               d.hostname AS device_hostname,
               host(d.current_ip) AS device_ip
        FROM response_actions ra
        LEFT JOIN incidents i ON i.id = ra.incident_id
        LEFT JOIN devices d ON d.id = ra.device_id
        WHERE ra.updated_at >= now() - (%s::text || ' hours')::interval
          AND ra.status IN ('applied_degraded', 'failed', 'rollback_failed')
        ORDER BY ra.updated_at DESC
        LIMIT 100
        """,
        (LOOKBACK_HOURS,),
    )
    min_severity = db_text(rule.get("min_severity") or "high").lower()
    rows: list[dict[str, Any]] = []
    for row in cur.fetchall():
        item = dict(row)
        item["response_action_id"] = uuid_text_or_none(item.get("response_action_id"))
        item["incident_id"] = uuid_text_or_none(item.get("incident_id"))
        item["device_id"] = uuid_text_or_none(item.get("device_id"))
        if item.get("response_action_id") and severity_allowed(item.get("severity"), min_severity):
            rows.append(item)
    return rows


def claim_delivery(cur, *, rule_name: str, channel: str, dedupe_key: str, title: str, body: str, incident_id: str | None, device_id: str | None) -> str | None:
    cur.execute(
        """
        INSERT INTO notification_deliveries(
            rule_name, channel, status, dedupe_key, incident_id, device_id,
            message_title, message_body, response_json, created_at
        ) VALUES (%s, %s, 'pending', %s, NULLIF(%s::text, '')::uuid, NULLIF(%s::text, '')::uuid, %s, %s, '{}'::jsonb, now())
        ON CONFLICT (dedupe_key) DO UPDATE
        SET status='pending',
            error_message=NULL,
            response_json='{}'::jsonb,
            message_title=EXCLUDED.message_title,
            message_body=EXCLUDED.message_body,
            created_at=now()
        WHERE notification_deliveries.status = 'failed'
        RETURNING id::text AS id
        """,
        (rule_name, channel, dedupe_key, incident_id or "", device_id or "", title, body),
    )
    row = cur.fetchone()
    return db_text(row.get("id")) if row else None


def update_delivery(cur, delivery_id: str, status: str, response: dict[str, Any] | None = None, error: str | None = None) -> None:
    cur.execute(
        """
        UPDATE notification_deliveries
        SET status=%s,
            response_json=%s,
            error_message=%s,
            sent_at=CASE WHEN %s='sent' THEN now() ELSE sent_at END
        WHERE id=NULLIF(%s::text, '')::uuid
        """,
        (status, j(response or {}), error, status, delivery_id),
    )


def body_for_incident(item: dict[str, Any]) -> tuple[str, str]:
    title = f"Security Core {maybe_decode_hex_text(item.get('severity')).upper()}: {decode_embedded_hex_text(item.get('title'))}"
    device = item.get("device_hostname") or item.get("device_ip") or item.get("device_id") or "unknown device"
    body = "\n".join(
        [
            f"Incidentas: {decode_embedded_hex_text(item.get('title'))}",
            f"Severity: {maybe_decode_hex_text(item.get('severity'))}",
            f"Tipas: {maybe_decode_hex_text(item.get('incident_type'))}",
            f"Šaltinis: {maybe_decode_hex_text(item.get('source_system'))}",
            f"Įrenginys: {decode_embedded_hex_text(device)}",
            f"IP: {maybe_decode_hex_text(item.get('device_ip')) or '-'}",
            f"Būsena: {maybe_decode_hex_text(item.get('status'))}",
            f"Įvykių kiekis: {maybe_decode_hex_text(item.get('event_count'))}",
            f"Aprašymas: {decode_embedded_hex_text(item.get('description')) or '-'}",
        ]
    )
    return title, body


def body_for_response(item: dict[str, Any]) -> tuple[str, str]:
    title = f"Security Core response {maybe_decode_hex_text(item.get('status'))}: {maybe_decode_hex_text(item.get('action_type'))}"
    device = item.get("device_hostname") or item.get("device_ip") or item.get("device_id") or "unknown device"
    body = "\n".join(
        [
            f"Response veiksmas: {maybe_decode_hex_text(item.get('action_type'))}",
            f"Būsena: {maybe_decode_hex_text(item.get('status'))}",
            f"Severity: {maybe_decode_hex_text(item.get('severity'))}",
            f"Incidentas: {decode_embedded_hex_text(item.get('incident_title')) or maybe_decode_hex_text(item.get('incident_id')) or '-'}",
            f"Įrenginys: {decode_embedded_hex_text(device)}",
            f"IP: {maybe_decode_hex_text(item.get('device_ip')) or '-'}",
            f"Priežastis: {decode_embedded_hex_text(item.get('reason')) or '-'}",
        ]
    )
    return title, body


def send_one(rule_name: str, channel: str, dedupe: str, title: str, body: str, incident_id: str | None, device_id: str | None) -> str:
    with connect() as conn:
        with conn.cursor() as cur:
            delivery_id = claim_delivery(cur, rule_name=rule_name, channel=channel, dedupe_key=dedupe, title=title, body=body, incident_id=incident_id, device_id=device_id)
        conn.commit()
    if not delivery_id:
        return "skipped"
    try:
        response = deliver(channel, title, body, dedupe)
        with connect() as conn:
            with conn.cursor() as cur:
                update_delivery(cur, delivery_id, "sent", response=response)
            conn.commit()
        return "sent"
    except Exception as exc:
        with connect() as conn:
            with conn.cursor() as cur:
                update_delivery(cur, delivery_id, "failed", error=str(exc))
            conn.commit()
        return "failed"


def process() -> dict[str, Any]:
    delivered = 0
    skipped = 0
    failed = 0
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "notification_deliveries") or not table_exists(cur, "notification_rules"):
                raise RuntimeError("Phase 7 schema is not installed")
            rules = fetch_rules(cur)
            incident_jobs: list[tuple[str, str, str, str, str, str | None, str | None]] = []
            response_jobs: list[tuple[str, str, str, str, str, str | None, str | None]] = []
            for rule in rules:
                rule_name = maybe_decode_hex_text(rule.get("rule_name"))
                channels = resolve_rule_channels(json_list(rule.get("channels")) or ["ha_persistent"])
                for item in fetch_incident_candidates(cur, rule):
                    title, body = body_for_incident(item)
                    for channel in channels:
                        dedupe = f"notification|incident|{item.get('incident_id')}|{channel}"
                        incident_jobs.append((rule_name, channel, dedupe, title, body, item.get("incident_id"), item.get("device_id")))
                for item in fetch_response_candidates(cur, rule):
                    title, body = body_for_response(item)
                    for channel in channels:
                        dedupe = f"notification|response|{item.get('response_action_id')}|{channel}"
                        response_jobs.append((rule_name, channel, dedupe, title, body, item.get("incident_id"), item.get("device_id")))
        conn.commit()

    for job in incident_jobs + response_jobs:
        result = send_one(*job)
        if result == "sent":
            delivered += 1
        elif result == "failed":
            failed += 1
        else:
            skipped += 1

    update_health(
        COMPONENT,
        "notification-worker",
        "healthy",
        {
            "delivered": delivered,
            "skipped": skipped,
            "failed": failed,
            "lookback_hours": LOOKBACK_HOURS,
            "require_online": REQUIRE_ONLINE,
            "excluded_incident_types": sorted(EXCLUDED_INCIDENT_TYPES),
        },
        VERSION,
    )
    return {"status": "ok", "delivered": delivered, "skipped": skipped, "failed": failed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run", "test-decode", "test-smtp", "test-mobile", "test-all"])
    args = parser.parse_args()
    try:
        if args.command == "run":
            print(json.dumps(process(), default=str), flush=True)
        elif args.command == "test-decode":
            samples = {
                "rule_name": maybe_decode_hex_text("68696768-5f69-6e63-6964-656e745f6861"),
                "hostname": decode_embedded_hex_text("Įrenginys: 6e616d61-692e-6974-6e61-6d61732e6c74"),
            }
            print(json.dumps({"status": "ok", "samples": samples}, ensure_ascii=False), flush=True)
        elif args.command == "test-smtp":
            title = "Security Core SMTP test"
            body = "Tai yra Security Core Phase 7 SMTP pranešimų testas."
            print(json.dumps({"status": "ok", "result": deliver_email(title, body, "manual-test-smtp")}, ensure_ascii=False, default=str), flush=True)
        elif args.command == "test-mobile":
            services = discover_mobile_services() if PHASE7_ENABLE_HA_MOBILE else []
            title = "Security Core mobile test"
            body = "Tai yra Security Core Phase 7 Home Assistant mobile push testas."
            result = deliver_ha_mobile(title, body, "manual-test-mobile")
            print(json.dumps({"status": "ok", "services": services, "result": result}, ensure_ascii=False, default=str), flush=True)
        elif args.command == "test-all":
            title = "Security Core notification test"
            body = "Tai yra Security Core Phase 7 bendras pranešimų testas: HA persistent, SMTP ir HA mobile, jei jie įjungti."
            results = {}
            for channel in resolve_rule_channels(["ha_persistent"]):
                results[channel] = deliver(channel, title, body, f"manual-test-all|{channel}")
            print(json.dumps({"status": "ok", "results": results}, ensure_ascii=False, default=str), flush=True)
        return 0
    except Exception as exc:
        update_health(COMPONENT, "notification-worker", "error", {"error": str(exc)}, VERSION)
        print(json.dumps({"status": "error", "error": str(exc)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
