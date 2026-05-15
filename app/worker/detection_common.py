import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import decimal
import uuid
from pathlib import Path
from typing import Any

import psycopg
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

STATE_DIR = Path(getenv_any(["SECURITY_CORE_STATE_DIR"], "/opt/security-core/state"))
LAN_CIDRS = [
    item.strip()
    for item in getenv_any(["SECURITY_CORE_LAN_CIDRS"], "REDACTED").split(",")
    if item.strip()
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OPEN_STATUSES = {"open", "acknowledged", "in_progress", "ignored"}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    return str(value).strip()


def decode_hex_text(value: Any) -> str:
    text = to_text(value)
    if text.startswith("\\x") and len(text) > 2 and len(text[2:]) % 2 == 0:
        try:
            decoded = bytes.fromhex(text[2:]).decode("utf-8", errors="strict").strip()
            return decoded or text
        except Exception:
            return text
    return text


def normalize_uuid_text(value: Any) -> str | None:
    """Normalize UUID-like values returned by psycopg/PostgreSQL.

    Some UUID columns may be returned as uuid.UUID, text, memoryview, or raw
    16-byte values. Always convert them to a plain UUID string before passing
    them back into SQL. Otherwise psycopg adapts Python bytes as bytea and
    PostgreSQL rejects expressions such as %s::uuid.
    """
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 16:
            try:
                return str(uuid.UUID(bytes=raw))
            except Exception:
                pass
        try:
            text = raw.decode("utf-8", errors="ignore").strip()
        except Exception:
            text = ""
        if text.startswith("\\x") and len(text) == 34:
            try:
                return str(uuid.UUID(bytes=bytes.fromhex(text[2:])))
            except Exception:
                pass
        if text:
            try:
                return str(uuid.UUID(text))
            except Exception:
                return None
        return None
    text = to_text(value)
    if not text:
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


def clean_optional_text(value: Any) -> str | None:
    text = to_text(value)
    return text or None


def response_suppression_for_event(cur, device_id: str | None, incident_type: str, source_system: str) -> dict[str, Any] | None:
    """Return active device/type/source suppression, if Phase 6 response schema exists.

    This intentionally avoids SQL-side device_id comparisons because early Phase 6
    test databases may have response_suppressions.device_id as bytea instead of uuid.
    Security events are still recorded; only incident/response creation is skipped.
    """
    device_id = normalize_uuid_text(device_id)
    incident_type = decode_hex_text(incident_type)
    source_system = decode_hex_text(source_system)
    if not device_id or not incident_type:
        return None

    # Preferred Phase 6 fix37 path: ignores are stored in a dedicated table to avoid
    # legacy response_suppressions schema drift.
    try:
        cur.execute("SELECT to_regclass('public.response_ignores') IS NOT NULL AS exists")
        if (cur.fetchone() or {}).get("exists"):
            cur.execute(
                """
                SELECT id::text AS id,
                       device_id::text AS device_id,
                       incident_type,
                       source_system,
                       reason,
                       expires_at,
                       created_at
                FROM response_ignores
                WHERE COALESCE(is_enabled, true)=true
                  AND (expires_at IS NULL OR expires_at > now())
                  AND device_id=%s::uuid
                  AND incident_type IS NOT DISTINCT FROM %s
                  AND source_system IS NOT DISTINCT FROM %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (device_id, incident_type, source_system),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
    except Exception:
        pass

    cur.execute("SELECT to_regclass('public.response_suppressions') IS NOT NULL AS exists")
    if not (cur.fetchone() or {}).get("exists"):
        return None

    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'response_suppressions'
        """
    )
    cols = {to_text(row.get("column_name")) for row in (cur.fetchall() or [])}
    if not {"device_id", "incident_type"}.issubset(cols):
        return None

    clauses = []
    if "is_enabled" in cols:
        clauses.append("COALESCE(is_enabled, true) = true")
    if "expires_at" in cols:
        clauses.append("(expires_at IS NULL OR expires_at > now())")
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    select_cols = ["id::text AS id", "device_id", "incident_type"]
    for col in ("source_system", "reason", "expires_at"):
        if col in cols:
            select_cols.append(col)

    try:
        cur.execute(
            f"""
            SELECT {', '.join(select_cols)}
            FROM response_suppressions
            {where_sql}
            ORDER BY created_at DESC NULLS LAST
            LIMIT 500
            """
        )
    except Exception:
        return None

    for row in (cur.fetchall() or []):
        data = dict(row)
        rid = normalize_uuid_text(data.get("device_id"))
        if rid and rid != device_id:
            continue
        rtype = decode_hex_text(data.get("incident_type"))
        if rtype and rtype != incident_type:
            continue
        rsource = decode_hex_text(data.get("source_system")) if "source_system" in cols else ""
        if rsource and source_system and rsource != source_system:
            continue
        return data
    return None



UNICODE_REPLACEMENTS = str.maketrans({
    "’": "'",
    "‘": "'",
    "“": '"',
    "”": '"',
    "–": "-",
    "—": "-",
    "\u00a0": " ",
})


def ascii_text(value: Any) -> str:
    return to_text(value).translate(UNICODE_REPLACEMENTS).encode("ascii", "ignore").decode("ascii")


def ascii_json_safe(value: Any) -> Any:
    """Return a value that is safe to pass into PostgreSQL JSONB.

    OPNsense/psycopg rows can occasionally contain bytes, memoryview, date/time,
    Decimal, UUID, sets, or other non-standard JSON values. Jsonb() uses
    json.dumps() under the hood, so every nested value must be converted first.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="ignore")
    if isinstance(value, dict):
        return {ascii_text(k): ascii_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [ascii_json_safe(v) for v in value]
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        try:
            return int(value) if value == value.to_integral_value() else float(value)
        except Exception:
            return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    if isinstance(value, str):
        return ascii_text(value)
    try:
        json.dumps(value)
        return value
    except TypeError:
        return ascii_text(value)


def j(value: Any) -> Jsonb:
    return Jsonb(ascii_json_safe(value))


def normalize_ip(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return None


def parse_lan_networks() -> list[ipaddress._BaseNetwork]:
    networks = []
    for cidr in LAN_CIDRS:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    return networks


LAN_NETWORKS = parse_lan_networks()


def ip_in_lan(ip_value: Any) -> bool:
    ip = normalize_ip(ip_value)
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(ip_obj in network for network in LAN_NETWORKS)


def normalize_severity(value: Any) -> str:
    text = to_text(value).lower()
    if text in SEVERITY_ORDER:
        return text
    if text in {"notice", "debug"}:
        return "info"
    if text in {"warning", "warn"}:
        return "medium"
    if text in {"error", "major"}:
        return "high"
    if text in {"fatal", "emergency"}:
        return "critical"
    return "low"


def max_severity(left: Any, right: Any) -> str:
    a = normalize_severity(left)
    b = normalize_severity(right)
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def normalize_event_type(value: Any) -> str:
    text = to_text(value).lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "security_event"


def normalize_country_code(value: Any) -> str | None:
    text = to_text(value).upper()
    if re.fullmatch(r"[A-Z]{2}", text):
        return text
    return None


def stable_hash(parts: list[Any]) -> str:
    raw = "|".join(to_text(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def default_dedupe_key(
    source_system: Any,
    event_type: Any,
    device_id: Any,
    src_ip: Any,
    dest_ip: Any,
    domain: Any = None,
    signature_id: Any = None,
    dest_port: Any = None,
    title: Any = None,
) -> str:
    return "|".join(
        [
            to_text(source_system).lower(),
            normalize_event_type(event_type),
            to_text(device_id) or "-",
            normalize_ip(src_ip) or "-",
            normalize_ip(dest_ip) or "-",
            to_text(domain).lower() or "-",
            to_text(signature_id) or "-",
            to_text(dest_port) or "-",
            stable_hash([title or ""]),
        ]
    )


def connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def update_health(component_name: str, component_type: str, status: str, details: dict[str, Any] | None = None, version: str = "phase5"):
    details = details or {}
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO system_health (component_name, component_type, status, last_check_at, version, details_json, updated_at)
                    VALUES (%s, %s, %s, now(), %s, %s, now())
                    ON CONFLICT (component_name)
                    DO UPDATE SET
                        component_type = EXCLUDED.component_type,
                        status = EXCLUDED.status,
                        last_check_at = now(),
                        version = EXCLUDED.version,
                        details_json = EXCLUDED.details_json,
                        updated_at = now()
                    """,
                    (component_name, component_type, status, version, j(details)),
                )
            conn.commit()
    except Exception as exc:
        print(f"[health] failed to update {component_name}: {exc}", flush=True)


def load_state(name: str) -> dict[str, Any]:
    path = STATE_DIR / f"{name}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        return {}


def save_state(name: str, state: dict[str, Any]):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / f"{name}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ascii_json_safe(state), indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def find_device_by_ip(cur, ip_value: Any) -> dict[str, Any] | None:
    ip = normalize_ip(ip_value)
    if not ip:
        return None
    cur.execute(
        """
        SELECT
            id::text AS id,
            host(current_ip) AS ip,
            mac_address,
            hostname,
            vendor,
            model,
            category,
            policy_effective_mode,
            policy_effective_json,
            open_tcp_ports,
            open_udp_ports
        FROM devices
        WHERE current_ip = %s::inet
        ORDER BY last_seen_at DESC NULLS LAST
        LIMIT 1
        """,
        (ip,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def find_event_device(cur, src_ip: Any = None, dest_ip: Any = None, preferred: str = "src") -> dict[str, Any] | None:
    src = normalize_ip(src_ip)
    dst = normalize_ip(dest_ip)
    ordered = [src, dst] if preferred == "src" else [dst, src]
    for ip in ordered:
        if ip and ip_in_lan(ip):
            row = find_device_by_ip(cur, ip)
            if row:
                return row
    for ip in ordered:
        if ip:
            row = find_device_by_ip(cur, ip)
            if row:
                return row
    return None


def create_security_event(
    cur,
    *,
    source_system: str,
    event_type: str,
    severity: str,
    title: str,
    description: str | None = None,
    device_id: str | None = None,
    src_ip: str | None = None,
    src_port: int | None = None,
    dest_ip: str | None = None,
    dest_port: int | None = None,
    protocol: str | None = None,
    domain: str | None = None,
    country_code: str | None = None,
    signature_id: str | None = None,
    signature_name: str | None = None,
    event_time: dt.datetime | str | None = None,
    raw_json: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
    create_incident: bool = True,
) -> dict[str, Any]:
    """Insert one normalized security event and optionally create/update an incident.

    This function intentionally keeps SQL expressions simple and casts all nullable
    text/IP/time parameters explicitly. Earlier Phase 5 builds used untyped NULL
    parameters inside jsonb_build_object(), which PostgreSQL could reject with
    "could not determine data type of parameter". The incident evidence JSON is
    now assembled in Python and inserted as Jsonb to avoid that ambiguity.
    """
    source_system = clean_optional_text(source_system) or "security-core"
    event_type = normalize_event_type(event_type)
    severity = normalize_severity(severity)
    title = clean_optional_text(title) or event_type.replace("_", " ").title()
    description = clean_optional_text(description)
    src_ip = normalize_ip(src_ip)
    dest_ip = normalize_ip(dest_ip)
    country_code = normalize_country_code(country_code)
    raw_json = raw_json or {}

    if not device_id:
        device = find_event_device(cur, src_ip, dest_ip)
        device_id = normalize_uuid_text(device.get("id")) if device else None
    else:
        device_id = normalize_uuid_text(device_id)

    dedupe_key = clean_optional_text(dedupe_key) or default_dedupe_key(
        source_system, event_type, device_id, src_ip, dest_ip, domain, signature_id, dest_port, title
    )

    if isinstance(event_time, dt.datetime):
        event_time_text = event_time.isoformat()
    else:
        event_time_text = clean_optional_text(event_time) or ""

    cur.execute(
        """
        INSERT INTO security_events (
            device_id,
            source_system,
            event_type,
            severity,
            title,
            description,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            protocol,
            domain,
            country_code,
            signature_id,
            signature_name,
            dedupe_key,
            event_time,
            raw_json,
            created_at
        ) VALUES (
            NULLIF(%s::text, '')::uuid,
            %s::text,
            %s::text,
            %s::text,
            %s::text,
            NULLIF(%s::text, ''),
            NULLIF(%s::text, '')::inet,
            %s::integer,
            NULLIF(%s::text, '')::inet,
            %s::integer,
            NULLIF(%s::text, ''),
            NULLIF(%s::text, ''),
            NULLIF(%s::text, ''),
            NULLIF(%s::text, ''),
            NULLIF(%s::text, ''),
            %s::text,
            COALESCE(NULLIF(%s::text, '')::timestamptz, now()),
            %s::jsonb,
            now()
        )
        RETURNING id::text AS id, event_time
        """,
        (
            device_id or "",
            source_system,
            event_type,
            severity,
            title,
            description or "",
            src_ip or "",
            src_port,
            dest_ip or "",
            dest_port,
            clean_optional_text(protocol) or "",
            clean_optional_text(domain) or "",
            country_code or "",
            clean_optional_text(signature_id) or "",
            clean_optional_text(signature_name) or "",
            dedupe_key,
            event_time_text,
            j(raw_json),
        ),
    )
    event_row = cur.fetchone()
    event_id = normalize_uuid_text(event_row.get("id")) if event_row else None
    if not event_id:
        raise RuntimeError(f"Inserted security event returned invalid id: {event_row!r}")
    event_time_db = event_row.get("event_time")
    incident_id = None

    if create_incident:
        suppression = response_suppression_for_event(cur, device_id, event_type, source_system)
        if suppression:
            return {
                "event_id": event_id,
                "incident_id": None,
                "dedupe_key": dedupe_key,
                "suppressed": True,
                "suppression_id": normalize_uuid_text(suppression.get("id")),
            }

        incident_description = description or f"{source_system} event: {title}"
        cur.execute(
            """
            SELECT id::text AS id, severity
            FROM incidents
            WHERE dedupe_key = %s::text
              AND status IN ('open', 'acknowledged', 'in_progress', 'ignored')
            LIMIT 1
            """,
            (dedupe_key,),
        )
        existing = cur.fetchone()
        if existing:
            incident_id = normalize_uuid_text(existing.get("id"))
            if not incident_id:
                raise RuntimeError(f"Existing incident returned invalid id: {existing!r}")
            severity = max_severity(existing.get("severity"), severity)
            evidence_update = {
                "last_event_id": event_id,
                "last_event_time": event_time_db,
                "last_source_system": source_system,
            }
            cur.execute(
                """
                UPDATE incidents
                SET
                    severity = %s::text,
                    title = %s::text,
                    description = COALESCE(NULLIF(%s::text, ''), description),
                    evidence_json = COALESCE(evidence_json, '{}'::jsonb) || %s::jsonb,
                    event_count = COALESCE(event_count, 0) + 1,
                    last_seen_at = %s::timestamptz,
                    updated_at = now()
                WHERE id = %s::uuid
                """,
                (
                    severity,
                    title,
                    incident_description,
                    j(evidence_update),
                    event_time_db,
                    incident_id,
                ),
            )
        else:
            evidence = {
                "first_event_id": event_id,
                "last_event_id": event_id,
                "source_system": source_system,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "domain": clean_optional_text(domain),
                "signature_id": clean_optional_text(signature_id),
                "signature_name": clean_optional_text(signature_name),
                "raw": raw_json,
            }
            cur.execute(
                """
                INSERT INTO incidents (
                    device_id,
                    incident_type,
                    severity,
                    source_system,
                    title,
                    description,
                    evidence_json,
                    status,
                    dedupe_key,
                    event_count,
                    first_seen_at,
                    last_seen_at,
                    created_at,
                    updated_at
                ) VALUES (
                    NULLIF(%s::text, '')::uuid,
                    %s::text,
                    %s::text,
                    %s::text,
                    %s::text,
                    NULLIF(%s::text, ''),
                    %s::jsonb,
                    'open',
                    %s::text,
                    1,
                    %s::timestamptz,
                    %s::timestamptz,
                    now(),
                    now()
                )
                RETURNING id::text AS id
                """,
                (
                    device_id or "",
                    event_type,
                    severity,
                    source_system,
                    title,
                    incident_description,
                    j(evidence),
                    dedupe_key,
                    event_time_db,
                    event_time_db,
                ),
            )
            incident_row = cur.fetchone()
            incident_id = normalize_uuid_text(incident_row.get("id")) if incident_row else None
            if not incident_id:
                raise RuntimeError(f"Inserted incident returned invalid id: {incident_row!r}")

        cur.execute(
            """
            UPDATE security_events
            SET incident_id = NULLIF(%s::text, '')::uuid
            WHERE id = NULLIF(%s::text, '')::uuid
            """,
            (incident_id or "", event_id),
        )

    return {"event_id": event_id, "incident_id": incident_id, "dedupe_key": dedupe_key}
