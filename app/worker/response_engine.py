#!/usr/bin/env python3
"""
security-core Phase 6 response engine.

Purpose:
- Create safe response suggestions for open incidents.
- Apply approved/manual temporary containment actions.
- Roll back expired or requested actions.
- Keep UUID values as plain strings before sending them back to PostgreSQL.

This file is intentionally self-contained so it can replace a broken
/opt/security-core/app/worker/response_engine.py without changing Phase 5 code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import ipaddress
import json
import os
import re
import subprocess
import sys
import uuid
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

COMPONENT = "security-response-engine"
COMPONENT_TYPE = "response-worker"
VERSION = "phase6-fix25-sync-close-ttl0-opnsense-idempotent"

ENV_FILES = [
    os.environ.get("SECURITY_CORE_ENV_FILE", "/etc/security-core/security-core.env"),
    "/opt/security-core/.env",
]


def load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return values
    try:
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
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

OPNSENSE_URL = getenv_any(["OPNSENSE_URL"], "https://REDACTED").rstrip("/")
HOME_ASSISTANT_URL = getenv_any(["HOME_ASSISTANT_URL", "HA_URL"], "http://REDACTED").rstrip("/")
SECURITY_CORE_BIND = getenv_any(["SECURITY_CORE_BIND"], "REDACTED")
OPNSENSE_AUTH_B64 = getenv_any(["OPNSENSE_AUTH_B64"])
OPNSENSE_VERIFY_SSL = getenv_any(["OPNSENSE_VERIFY_SSL"], "false").lower() in {"1", "true", "yes", "on"}
LAN_CIDRS = [x.strip() for x in getenv_any(["SECURITY_CORE_LAN_CIDRS"], "REDACTED").split(",") if x.strip()]

POLICY_ENFORCER_SCRIPT = getenv_any(["POLICY_ENFORCER_SCRIPT"], "/opt/security-core/app/worker/policy_enforcer.py")
SECURITY_CORE_PYTHON = getenv_any(["SECURITY_CORE_PYTHON"], "/opt/security-core/venv/bin/python")
RESPONSE_RULE_PREFIX = getenv_any(["RESPONSE_RULE_PREFIX"], "SECURITY_CORE_RESPONSE")
RESPONSE_QUARANTINE_ALIAS = getenv_any(["RESPONSE_QUARANTINE_ALIAS"], "RESPONSE_QUARANTINE_HOSTS")
RESPONSE_INTERNET_BLOCK_ALIAS = getenv_any(["RESPONSE_INTERNET_BLOCK_ALIAS"], "RESPONSE_INTERNET_BLOCK_HOSTS")
RESPONSE_DNS_ONLY_ALIAS = getenv_any(["RESPONSE_DNS_ONLY_ALIAS"], "RESPONSE_DNS_ONLY_HOSTS")
RESPONSE_IP_ONLY_ALIAS = getenv_any(["RESPONSE_IP_ONLY_ALIAS"], "RESPONSE_IP_ONLY_HOSTS")
RESPONSE_RATE_LIMIT_ALIAS = getenv_any(["RESPONSE_RATE_LIMIT_ALIAS"], "RESPONSE_RATE_LIMIT_HOSTS")
RESPONSE_DYNAMIC_SRC_PREFIX = getenv_any(["RESPONSE_DYNAMIC_SRC_PREFIX"], "SCR_SRC_")
RESPONSE_DYNAMIC_DST_PREFIX = getenv_any(["RESPONSE_DYNAMIC_DST_PREFIX"], "SCR_DST_")
RESPONSE_DNS_SERVER_ALIAS = getenv_any(["RESPONSE_DNS_SERVER_ALIAS"], "RESPONSE_DNS_SERVERS")
RESPONSE_LAN_NETS_ALIAS = getenv_any(["RESPONSE_LAN_NETS_ALIAS"], "RESPONSE_LAN_NETS")
RESPONSE_DNS_SERVERS = [x.strip() for x in getenv_any(["RESPONSE_DNS_SERVERS"], "REDACTED").split(",") if x.strip()]
RESPONSE_RATE_LIMIT_KBIT = int(getenv_any(["RESPONSE_RATE_LIMIT_KBIT"], "1024") or "1024")
RESPONSE_RATE_LIMIT_ENABLE_SHAPER = getenv_any(["RESPONSE_RATE_LIMIT_ENABLE_SHAPER"], "true").lower() in {"1", "true", "yes", "on"}
RESPONSE_RATE_LIMIT_FALLBACK_TO_DNS_ONLY = getenv_any(["RESPONSE_RATE_LIMIT_FALLBACK_TO_DNS_ONLY"], "false").lower() in {"1", "true", "yes", "on"}
RESPONSE_INTERFACE = getenv_any(["RESPONSE_INTERFACE", "POLICY_ENFORCE_INTERFACE"], "lan")
RESPONSE_IPPROTOCOL = getenv_any(["RESPONSE_IPPROTOCOL", "POLICY_ENFORCE_IPPROTOCOL"], "inet")
RESPONSE_PROTECTED_IPS_RAW = getenv_any(["RESPONSE_PROTECTED_IPS", "RESPONSE_INFRA_PROTECTED_IPS"], "")
RESPONSE_PROTECTED_HOSTNAMES_RAW = getenv_any(["RESPONSE_PROTECTED_HOSTNAMES", "RESPONSE_INFRA_PROTECTED_HOSTNAMES"], "")
RESPONSE_ALLOW_PROTECTED_FORCE = getenv_any(["RESPONSE_ALLOW_PROTECTED_FORCE"], "false").lower() in {"1", "true", "yes", "on"}
RESPONSE_ENFORCEMENT_STRICT = getenv_any(["RESPONSE_ENFORCEMENT_STRICT"], "true").lower() in {"1", "true", "yes", "on"}
RESPONSE_CREATE_FILTER_RULES = getenv_any(["RESPONSE_CREATE_FILTER_RULES"], "true").lower() in {"1", "true", "yes", "on"}
# Default places response rules after policy whitelist/allow rules (policy engine starts around 500).
# If a whitelist rule is detected in OPNsense, the engine dynamically places response rules right after it.
RESPONSE_RULE_SEQUENCE_START = int(getenv_any(["RESPONSE_RULE_SEQUENCE_START"], "650") or "650")
RESPONSE_TRIGGER_POLICY_ENFORCER = getenv_any(["RESPONSE_TRIGGER_POLICY_ENFORCER"], "false").lower() in {"1", "true", "yes", "on"}
RESPONSE_CREATE_SHAPER = getenv_any(["RESPONSE_CREATE_SHAPER", "RESPONSE_RATE_LIMIT_ENABLE_SHAPER"], "true").lower() in {"1", "true", "yes", "on"}
RESPONSE_SHAPER_PIPE_DESC = getenv_any(["RESPONSE_SHAPER_PIPE_DESC"], f"{RESPONSE_RULE_PREFIX}_RATE_LIMIT_PIPE")
RESPONSE_SHAPER_RULE_DESC = getenv_any(["RESPONSE_SHAPER_RULE_DESC"], f"{RESPONSE_RULE_PREFIX}_RATE_LIMIT_RULE")
RESPONSE_SHAPER_PIPE_NUMBER_START = int(getenv_any(["RESPONSE_SHAPER_PIPE_NUMBER", "RESPONSE_RATE_LIMIT_PIPE_NUMBER"], "10000") or "10000")
RESPONSE_SHAPER_RULE_SEQUENCE_START = int(getenv_any(["RESPONSE_SHAPER_RULE_SEQUENCE_START", "RESPONSE_RATE_LIMIT_RULE_SEQUENCE_START"], "10000") or "10000")
# Download limiting must match post-NAT traffic going out of the LAN interface to the client.
# Do NOT default to RESPONSE_WAN_INTERFACE here: WAN inbound packets usually target the WAN address,
# so a rule with destination=<LAN device IP> will not match and only upload gets limited.
RESPONSE_SHAPER_DOWNLOAD_INTERFACE = getenv_any(["RESPONSE_SHAPER_DOWNLOAD_INTERFACE"], RESPONSE_INTERFACE)

SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
OPEN_INCIDENT_STATUSES = {"open", "acknowledged", "in_progress"}
ACTIVE_ACTION_STATUSES = {"approved", "pending", "applying", "applied", "applied_degraded"}
APPLYABLE_ACTIONS = {"notify_only", "dns_only", "ip_only", "internet_block", "quarantine", "rate_limit", "dynamic_firewall_block"}


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
            decoded = bytes.fromhex(text[2:]).decode("utf-8", errors="strict")
            return decoded or text
        except Exception:
            return text
    return text


def uuid_text(value: Any, required: bool = True) -> str | None:
    """Return a plain UUID string or None.

    This avoids psycopg adapting raw bytes as bytea and PostgreSQL errors like:
    "cannot cast type bytea to uuid".
    """
    if value is None:
        if required:
            raise ValueError("UUID value is required")
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
        text = raw.decode("utf-8", errors="ignore").strip()
    else:
        text = to_text(value)
    if not text:
        if required:
            raise ValueError("UUID value is required")
        return None
    if text.startswith("\\x") and len(text) == 34:
        try:
            return str(uuid.UUID(bytes=bytes.fromhex(text[2:])))
        except Exception:
            pass
    try:
        return str(uuid.UUID(text))
    except Exception as exc:
        if required:
            raise ValueError(f"Invalid UUID: {text!r}") from exc
        return None


def clean_optional_text(value: Any) -> str | None:
    text = to_text(value)
    return text or None


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


def normalize_severity(value: Any) -> str:
    text = to_text(value).lower()
    if text in SEVERITY_RANK:
        return text
    if text in {"warn", "warning"}:
        return "medium"
    if text in {"error", "major"}:
        return "high"
    if text in {"fatal", "emergency"}:
        return "critical"
    return "low"


def normalize_action(value: Any) -> str:
    text = to_text(value).lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "", text)
    if text in APPLYABLE_ACTIONS:
        return text
    return "notify_only"


def bool_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return to_text(value).lower() in {"1", "true", "yes", "on"}


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


def normalize_country(value: Any) -> str | None:
    text = to_text(value).upper()
    if re.fullmatch(r"[A-Z]{2}", text):
        return text
    return None


def parse_networks() -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for item in LAN_CIDRS:
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except Exception:
            pass
    return result


LAN_NETWORKS = parse_networks()


def ip_in_lan(ip_value: Any) -> bool:
    ip = normalize_ip(ip_value)
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(obj in net for net in LAN_NETWORKS)


def host_from_url(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    try:
        parsed = urlparse(text if "://" in text else f"//{text}")
        host = parsed.hostname or ""
        return host.strip().lower().rstrip(".") or None
    except Exception:
        return None


def split_csv_words(value: Any) -> list[str]:
    text = to_text(value)
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,;\s]+", text) if part.strip()]


def build_protected_infra_ips() -> set[str]:
    candidates: list[Any] = [
        SECURITY_CORE_BIND,
        host_from_url(HOME_ASSISTANT_URL),
        host_from_url(OPNSENSE_URL),
        *RESPONSE_DNS_SERVERS,
        "REDACTED",
        "REDACTED",
        "REDACTED",
        *split_csv_words(RESPONSE_PROTECTED_IPS_RAW),
    ]
    result: set[str] = set()
    for item in candidates:
        ip = normalize_ip(item)
        if ip:
            result.add(ip)
    return result


def build_protected_infra_hostnames() -> set[str]:
    candidates = {
        "security-core",
        "homeassistant",
        "home-assistant",
        "REDACTED",
        "opnsense",
        "REDACTED",
        *(x.lower().rstrip(".") for x in split_csv_words(RESPONSE_PROTECTED_HOSTNAMES_RAW)),
    }
    for url in (HOME_ASSISTANT_URL, OPNSENSE_URL):
        host = host_from_url(url)
        if host and not normalize_ip(host):
            candidates.add(host)
    return {x for x in candidates if x}


PROTECTED_INFRA_IPS = build_protected_infra_ips()
PROTECTED_INFRA_HOSTNAMES = build_protected_infra_hostnames()


def protected_infra_reason(incident: dict[str, Any] | None = None, params: dict[str, Any] | None = None, action: dict[str, Any] | None = None) -> str | None:
    incident = incident or {}
    params = params or {}
    action = action or {}
    sim = action.get("simulation_json") if isinstance(action.get("simulation_json"), dict) else {}
    sim_incident = sim.get("incident") if isinstance(sim.get("incident"), dict) else {}
    sim_params = sim.get("params") if isinstance(sim.get("params"), dict) else {}

    ip_candidates = [
        incident.get("device_ip"),
        params.get("device_ip"),
        params.get("src_ip"),
        params.get("dest_ip"),
        action.get("device_ip"),
        sim_incident.get("device_ip"),
        sim_params.get("device_ip"),
        sim_params.get("src_ip"),
        sim_params.get("dest_ip"),
    ]
    for item in ip_candidates:
        ip = normalize_ip(item)
        if ip and ip in PROTECTED_INFRA_IPS:
            return f"protected_infrastructure_ip={ip}"

    host_candidates = [
        incident.get("device_hostname"),
        incident.get("title"),
        action.get("device_hostname"),
        sim_incident.get("device_hostname"),
        sim_incident.get("title"),
    ]
    for item in host_candidates:
        text = to_text(item).lower().rstrip(".")
        if not text:
            continue
        for name in PROTECTED_INFRA_HOSTNAMES:
            if text == name or name in text:
                return f"protected_infrastructure_host={name}"
    return None


def protected_notify_playbook(reason: str | None = None) -> dict[str, Any]:
    return {
        "playbook_name": "builtin_protected_infrastructure_notify",
        "action_type": "notify_only",
        "ttl_minutes": 30,
        "auto_allowed": True,
        "priority": 1,
        "conditions_json": {"safety_reason": reason or "protected_infrastructure"},
        "require_device": False,
        "require_lan_device": False,
        "require_dest_ip": False,
    }


def child_process_env() -> dict[str, str]:
    env = os.environ.copy()
    for key, value in FILE_ENV.items():
        if key and value is not None:
            env[key] = value
    env.setdefault("DATABASE_URL", DATABASE_URL)
    env.setdefault("OPNSENSE_URL", OPNSENSE_URL)
    env.setdefault("OPNSENSE_AUTH_B64", OPNSENSE_AUTH_B64)
    env.setdefault("OPNSENSE_VERIFY_SSL", "true" if OPNSENSE_VERIFY_SSL else "false")
    existing_pythonpath = env.get("PYTHONPATH", "")
    needed_pythonpath = "/opt/security-core/app/worker:/opt/security-core/app"
    env["PYTHONPATH"] = f"{needed_pythonpath}:{existing_pythonpath}" if existing_pythonpath else needed_pythonpath
    return env


def connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


_COLUMN_CACHE: dict[str, set[str]] = {}


def table_columns(cur, table_name: str) -> set[str]:
    if table_name in _COLUMN_CACHE:
        return _COLUMN_CACHE[table_name]
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (table_name,),
    )
    cols = {to_text(row.get("column_name")) for row in (cur.fetchall() or []) if to_text(row.get("column_name"))}
    _COLUMN_CACHE[table_name] = cols
    return cols



def ensure_response_ignores(cur) -> None:
    """Runtime check only; DDL is applied by SQL migration.

    Running CREATE TABLE/INDEX from the worker DB user caused "must be owner of
    table response_ignores" after the migration had created the table as postgres.
    """
    cur.execute("SELECT to_regclass('public.response_ignores') IS NOT NULL AS exists")
    row = cur.fetchone() or {}
    if not bool(row.get("exists")):
        raise RuntimeError("response_ignores table missing; run phase6_response_ignores_schema_fix38.sql")

def response_ignore_match(cur, incident: dict[str, Any]) -> dict[str, Any] | None:
    if not table_columns(cur, "response_ignores"):
        return None
    device_id = uuid_text(incident.get("device_id"), required=False)
    incident_type = decode_hex_text(incident.get("incident_type"))
    source_system = decode_hex_text(incident.get("source_system"))
    if not device_id or not incident_type:
        return None
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
    return dict(row) if row else None


def disable_response_ignores_for_incident(cur, incident: dict[str, Any], reason: str) -> list[str]:
    if not table_columns(cur, "response_ignores"):
        return []
    device_id = uuid_text(incident.get("device_id"), required=False)
    incident_type = decode_hex_text(incident.get("incident_type"))
    source_system = decode_hex_text(incident.get("source_system"))
    if not device_id or not incident_type:
        return []
    cur.execute(
        """
        UPDATE response_ignores
        SET is_enabled=false,
            updated_at=now(),
            reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN %s ELSE ' | ' || %s END
        WHERE COALESCE(is_enabled, true)=true
          AND (expires_at IS NULL OR expires_at > now())
          AND device_id=%s::uuid
          AND incident_type IS NOT DISTINCT FROM %s
          AND source_system IS NOT DISTINCT FROM %s
        RETURNING id::text AS id
        """,
        (reason, reason, device_id, incident_type, source_system),
    )
    return [to_text(r.get("id")) for r in (cur.fetchall() or []) if to_text(r.get("id"))]


_COLUMN_TYPE_CACHE: dict[tuple[str, str], str | None] = {}


def table_column_udt(cur, table_name: str, column_name: str) -> str | None:
    key = (table_name, column_name)
    if key in _COLUMN_TYPE_CACHE:
        return _COLUMN_TYPE_CACHE[key]
    cur.execute(
        """
        SELECT udt_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    )
    row = cur.fetchone() or {}
    value = to_text(row.get("udt_name")) or None
    _COLUMN_TYPE_CACHE[key] = value
    return value


def bytea_uuid_text_expr(column_sql: str) -> str:
    encoded = f"encode({column_sql}, 'hex')"
    return (
        f"CASE WHEN {column_sql} IS NULL THEN NULL::text "
        f"WHEN octet_length({column_sql}) = 16 THEN "
        f"lower(substr({encoded},1,8)||'-'||substr({encoded},9,4)||'-'||substr({encoded},13,4)||'-'||substr({encoded},17,4)||'-'||substr({encoded},21,12)) "
        f"ELSE NULLIF(convert_from({column_sql}, 'UTF8'), '') END"
    )


def response_suppression_device_id_condition(cur, column_sql: str = "device_id", placeholder: str = "%s") -> str:
    kind = table_column_udt(cur, "response_suppressions", "device_id")
    if kind == "bytea":
        return f"{bytea_uuid_text_expr(column_sql)} IS NOT DISTINCT FROM {placeholder}"
    if kind == "uuid":
        return f"{column_sql} IS NOT DISTINCT FROM {placeholder}::uuid"
    return f"NULLIF({column_sql}::text, '') IS NOT DISTINCT FROM {placeholder}"


def response_suppression_device_id_insert_expr(cur, placeholder: str = "%s") -> str:
    kind = table_column_udt(cur, "response_suppressions", "device_id")
    if kind == "bytea":
        return f"convert_to({placeholder}, 'UTF8')"
    if kind == "uuid":
        return f"NULLIF({placeholder}::text, '')::uuid"
    return placeholder


def insert_row(cur, table: str, values: dict[str, Any], returning: str = "id") -> dict[str, Any]:
    cols = table_columns(cur, table)
    data = {k: v for k, v in values.items() if k in cols}
    if not data:
        raise RuntimeError(f"No compatible columns for insert into {table}")
    names = list(data.keys())
    placeholders = []
    params: list[Any] = []
    for name in names:
        value = data[name]
        if name.endswith("_json") or name in {"simulation_json", "params_json", "result_json", "details_json"}:
            placeholders.append("%s::jsonb")
            params.append(j(value if value is not None else {}))
        elif table == "response_suppressions" and name == "device_id" and table_column_udt(cur, table, name) == "bytea":
            placeholders.append("convert_to(%s, 'UTF8')")
            params.append(uuid_text(value, required=False) or "")
        elif name.endswith("_id") or name == "id":
            placeholders.append("NULLIF(%s::text, '')::uuid")
            params.append(uuid_text(value, required=False) or "")
        else:
            placeholders.append("%s")
            params.append(value)
    sql = f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join(placeholders)})"
    if returning and returning in cols:
        sql += f" RETURNING {returning}::text AS {returning}"
    cur.execute(sql, params)
    row = cur.fetchone() if returning and returning in cols else None
    return dict(row) if row else {}


def update_row(cur, table: str, key_col: str, key_value: Any, values: dict[str, Any]) -> None:
    cols = table_columns(cur, table)
    data = {k: v for k, v in values.items() if k in cols and k != key_col}
    if not data:
        return
    assignments = []
    params: list[Any] = []
    for name, value in data.items():
        if name.endswith("_json") or name in {"simulation_json", "params_json", "result_json", "details_json"}:
            assignments.append(f"{name} = %s::jsonb")
            params.append(j(value if value is not None else {}))
        elif name.endswith("_id"):
            assignments.append(f"{name} = NULLIF(%s::text, '')::uuid")
            params.append(uuid_text(value, required=False) or "")
        else:
            assignments.append(f"{name} = %s")
            params.append(value)
    params.append(uuid_text(key_value) if key_col.endswith("_id") or key_col == "id" else key_value)
    key_expr = f"{key_col} = %s::uuid" if key_col.endswith("_id") or key_col == "id" else f"{key_col} = %s"
    cur.execute(f"UPDATE {table} SET {', '.join(assignments)} WHERE {key_expr}", params)


def update_health(status: str, details: dict[str, Any] | None = None) -> None:
    details = details or {}
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO system_health (component_name, component_type, status, last_check_at, version, details_json, updated_at)
                    VALUES (%s, %s, %s, now(), %s, %s::jsonb, now())
                    ON CONFLICT (component_name)
                    DO UPDATE SET
                        component_type = EXCLUDED.component_type,
                        status = EXCLUDED.status,
                        last_check_at = now(),
                        version = EXCLUDED.version,
                        details_json = EXCLUDED.details_json,
                        updated_at = now()
                    """,
                    (COMPONENT, COMPONENT_TYPE, status, VERSION, j(details)),
                )
            conn.commit()
    except Exception:
        pass


def setting_value(cur, key: str, default: Any = None) -> Any:
    try:
        cur.execute("SELECT setting_value FROM response_settings WHERE setting_key = %s", (key,))
        row = cur.fetchone()
        if not row:
            return default
        return row.get("setting_value")
    except Exception:
        return default


def all_settings(cur) -> dict[str, Any]:
    try:
        cur.execute("SELECT setting_key, setting_value FROM response_settings")
        return {to_text(row.get("setting_key")): row.get("setting_value") for row in (cur.fetchall() or [])}
    except Exception:
        return {}


def int_or_default(value: Any, default: int) -> int:
    try:
        if value is None:
            return int(default)
        text = to_text(value)
        if text == "":
            return int(default)
        return int(float(text))
    except Exception:
        return int(default)


def response_default_ttl_minutes(cur) -> int:
    # 0 is meaningful and means unlimited. Do not use `or 60`.
    return int_or_default(setting_value(cur, "default_ttl_minutes", 60), 60)


def ttl_expires_at(ttl_minutes: Any, action_type: str, now: dt.datetime | None = None) -> tuple[int, dt.datetime | None]:
    now = now or utc_now()
    ttl_int = int_or_default(ttl_minutes, response_default_ttl_minutes if False else 60)
    # notify_only never changes network state; ttl <= 0 means no expiration.
    expires_at = None if normalize_action(action_type) == "notify_only" or ttl_int <= 0 else now + dt.timedelta(minutes=ttl_int)
    return ttl_int, expires_at


def fetch_incident(cur, incident_id: Any) -> dict[str, Any] | None:
    incident_id = uuid_text(incident_id)
    cur.execute(
        """
        SELECT
            i.id::text AS id,
            i.device_id::text AS device_id,
            i.incident_type,
            i.severity,
            i.source_system,
            i.title,
            i.description,
            i.status,
            i.dedupe_key,
            i.event_count,
            i.evidence_json,
            i.first_seen_at,
            i.last_seen_at,
            i.created_at,
            i.updated_at,
            d.hostname AS device_hostname,
            d.category AS device_category,
            d.vendor AS device_vendor,
            d.model AS device_model,
            host(d.current_ip) AS device_ip,
            d.mac_address AS device_mac
        FROM incidents i
        LEFT JOIN devices d ON d.id = i.device_id
        WHERE i.id = %s::uuid
        """,
        (incident_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def fetch_latest_event(cur, incident_id: Any) -> dict[str, Any] | None:
    incident_id = uuid_text(incident_id)
    cur.execute(
        """
        SELECT
            se.id::text AS id,
            se.incident_id::text AS incident_id,
            se.device_id::text AS device_id,
            se.source_system,
            se.event_type,
            se.severity,
            se.title,
            se.description,
            host(se.src_ip) AS src_ip,
            se.src_port,
            host(se.dest_ip) AS dest_ip,
            se.dest_port,
            se.protocol,
            se.domain,
            se.country_code,
            se.signature_id,
            se.signature_name,
            se.event_time,
            se.raw_json
        FROM security_events se
        WHERE se.incident_id = %s::uuid
        ORDER BY se.event_time DESC, se.created_at DESC
        LIMIT 1
        """,
        (incident_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def open_incidents(cur, limit: int = 100) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT
            i.id::text AS id,
            i.device_id::text AS device_id,
            i.incident_type,
            i.severity,
            i.source_system,
            i.title,
            i.description,
            i.status,
            i.dedupe_key,
            i.event_count,
            i.evidence_json,
            i.first_seen_at,
            i.last_seen_at,
            i.created_at,
            i.updated_at,
            d.hostname AS device_hostname,
            d.category AS device_category,
            d.vendor AS device_vendor,
            d.model AS device_model,
            host(d.current_ip) AS device_ip,
            d.mac_address AS device_mac
        FROM incidents i
        LEFT JOIN devices d ON d.id = i.device_id
        WHERE i.status IN ('open','acknowledged','in_progress')
        ORDER BY
            CASE i.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
            COALESCE(i.last_seen_at, i.created_at) DESC
        LIMIT %s
        """,
        (limit,),
    )
    return [dict(row) for row in (cur.fetchall() or [])]


def active_action_for_incident(cur, incident_id: Any) -> dict[str, Any] | None:
    incident_id = uuid_text(incident_id)
    cur.execute(
        """
        SELECT id::text AS id, status, action_type
        FROM response_actions
        WHERE incident_id = %s::uuid
          AND status IN ('suggested','approved','pending','applying','applied','applied_degraded')
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (incident_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def device_override(cur, device_id: Any) -> dict[str, Any]:
    """Return per-device response override without aborting the transaction.

    The Phase 6 schema uses device_response_overrides.auto_response_enabled,
    not is_enabled. Referencing a missing is_enabled column aborts the current
    PostgreSQL transaction even if the exception is caught. Build the WHERE
    clause from the actual columns to keep the worker safe across schema
    revisions.
    """
    device_id = uuid_text(device_id, required=False)
    if not device_id:
        return {}
    cols = table_columns(cur, "device_response_overrides")
    if not cols:
        return {}

    clauses = ["device_id = %s::uuid"]
    params: list[Any] = [device_id]

    if "is_enabled" in cols:
        clauses.append("COALESCE(is_enabled, true) = true")
    elif "auto_response_enabled" in cols:
        clauses.append("COALESCE(auto_response_enabled, true) = true")

    if "suppress_until" in cols:
        clauses.append("(suppress_until IS NULL OR suppress_until <= now())")

    cur.execute(
        f"""
        SELECT *
        FROM device_response_overrides
        WHERE {' AND '.join(clauses)}
        LIMIT 1
        """,
        params,
    )
    row = cur.fetchone()
    return dict(row) if row else {}


def suppression_match(cur, incident: dict[str, Any]) -> dict[str, Any] | None:
    ignore = response_ignore_match(cur, incident)
    if ignore:
        return ignore
    cols = table_columns(cur, "response_suppressions")
    if not cols:
        return None
    device_id = uuid_text(incident.get("device_id"), required=False)
    incident_type = decode_hex_text(incident.get("incident_type"))
    source_system = decode_hex_text(incident.get("source_system"))
    severity = normalize_severity(incident.get("severity"))
    title = to_text(incident.get("title"))
    device_ip = normalize_ip(incident.get("device_ip"))
    evidence = incident.get("evidence_json") if isinstance(incident.get("evidence_json"), dict) else {}
    raw = evidence.get("raw") if isinstance(evidence.get("raw"), dict) else {}
    domain = to_text(evidence.get("domain") or raw.get("domain"))
    country = normalize_country(evidence.get("country_code") or raw.get("country_code"))

    select_cols = "*"
    clauses = ["COALESCE(is_enabled, true) = true"] if "is_enabled" in cols else ["TRUE"]
    if "expires_at" in cols:
        clauses.append("(expires_at IS NULL OR expires_at > now())")
    try:
        cur.execute(f"SELECT {select_cols} FROM response_suppressions WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 500")
        rows = [dict(row) for row in (cur.fetchall() or [])]
    except Exception:
        return None

    def row_matches(row: dict[str, Any]) -> bool:
        specific = False
        rid = uuid_text(row.get("device_id"), required=False) if "device_id" in cols else None
        if rid:
            specific = True
            if not device_id or rid != device_id:
                return False
        rtype = decode_hex_text(row.get("incident_type")) if "incident_type" in cols else ""
        if rtype:
            specific = True
            if rtype != incident_type:
                return False
        rsource = decode_hex_text(row.get("source_system")) if "source_system" in cols else ""
        if rsource:
            specific = True
            if rsource != source_system:
                return False
        rsev = decode_hex_text(row.get("severity")) if "severity" in cols else ""
        if rsev:
            specific = True
            if normalize_severity(rsev) != severity:
                return False
        rip = normalize_ip(row.get("device_ip")) if "device_ip" in cols else None
        if rip:
            specific = True
            if rip != device_ip:
                return False
        rdomain = decode_hex_text(row.get("domain")) if "domain" in cols else ""
        if rdomain:
            specific = True
            if rdomain != domain:
                return False
        rcountry = normalize_country(row.get("country_code")) if "country_code" in cols else None
        if rcountry:
            specific = True
            if rcountry != country:
                return False
        rsig = decode_hex_text(row.get("signature_id")) if "signature_id" in cols else ""
        isig = to_text((incident.get("evidence_json") or {}).get("signature_id"))
        if rsig:
            specific = True
            if rsig != isig:
                return False
        pattern = decode_hex_text(row.get("title_pattern")) if "title_pattern" in cols else ""
        if pattern:
            specific = True
            if pattern.lower() not in title.lower():
                return False
        return specific

    for row in rows:
        if row_matches(row):
            return row
    return None


def json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def condition_text_list(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        items = [x.strip() for x in re.split(r"[,;\s]+", value) if x.strip()]
    elif isinstance(value, (list, tuple, set)):
        items = [to_text(x) for x in value]
    else:
        items = [to_text(value)]
    return {x for x in items if x}


def playbook_conditions_match(playbook: dict[str, Any], incident: dict[str, Any], params: dict[str, Any]) -> bool:
    """Evaluate response_playbooks.conditions_json.

    The default notify_info_and_low playbook has {"max_severity":"low"}.
    Without this check it catches medium/high incidents first because its
    priority is intentionally low and incident_type/source are NULL.
    """
    cond = json_object(playbook.get("conditions_json"))
    if not cond:
        return True

    sev = normalize_severity(incident.get("severity"))
    sev_rank = SEVERITY_RANK.get(sev, 0)

    min_sev = cond.get("min_severity")
    if min_sev and sev_rank < SEVERITY_RANK.get(normalize_severity(min_sev), 0):
        return False

    max_sev = cond.get("max_severity")
    if max_sev and sev_rank > SEVERITY_RANK.get(normalize_severity(max_sev), 0):
        return False

    allowed_categories = condition_text_list(cond.get("device_categories") or cond.get("allowed_device_categories"))
    if allowed_categories and to_text(incident.get("device_category")) not in allowed_categories:
        return False

    excluded_categories = condition_text_list(cond.get("exclude_device_categories") or cond.get("excluded_device_categories"))
    if excluded_categories and to_text(incident.get("device_category")) in excluded_categories:
        return False

    allowed_countries = {x.upper() for x in condition_text_list(cond.get("country_codes") or cond.get("allowed_country_codes"))}
    if allowed_countries and to_text(params.get("country_code")).upper() not in allowed_countries:
        return False

    excluded_countries = {x.upper() for x in condition_text_list(cond.get("exclude_country_codes") or cond.get("excluded_country_codes"))}
    if excluded_countries and to_text(params.get("country_code")).upper() in excluded_countries:
        return False

    allowed_actions = {normalize_action(x) for x in condition_text_list(cond.get("action_types") or cond.get("allowed_action_types"))}
    if allowed_actions and normalize_action(playbook.get("action_type")) not in allowed_actions:
        return False

    return True


def playbook_requirements_match(playbook: dict[str, Any], incident: dict[str, Any], params: dict[str, Any]) -> bool:
    device_id = uuid_text(incident.get("device_id"), required=False)
    device_ip = normalize_ip(params.get("device_ip") or incident.get("device_ip"))
    dest_ip = normalize_ip(params.get("dest_ip"))
    remote_ip = normalize_ip(params.get("remote_ip"))

    if bool_flag(playbook.get("require_device")) and not (device_id or device_ip):
        return False
    if bool_flag(playbook.get("require_lan_device")) and not (device_ip and ip_in_lan(device_ip)):
        return False
    if bool_flag(playbook.get("require_dest_ip")) and not (dest_ip or remote_ip):
        return False
    return True


def matching_playbooks(cur, incident: dict[str, Any], event: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    sev = normalize_severity(incident.get("severity"))
    sev_rank = SEVERITY_RANK.get(sev, 0)
    incident_type = to_text(incident.get("incident_type"))
    source_system = to_text(incident.get("source_system"))
    params = event_params(incident, event)
    try:
        cur.execute(
            """
            SELECT *
            FROM response_playbooks
            WHERE COALESCE(is_enabled, true) = true
            ORDER BY COALESCE(priority, 1000), created_at
            """
        )
        rows = [dict(row) for row in (cur.fetchall() or [])]
    except Exception:
        return []
    result: list[dict[str, Any]] = []
    for row in rows:
        min_sev = normalize_severity(row.get("min_severity") or "info")
        if sev_rank < SEVERITY_RANK.get(min_sev, 0):
            continue
        pb_type = to_text(row.get("incident_type"))
        pb_source = to_text(row.get("source_system"))
        if pb_type and pb_type != incident_type:
            continue
        if pb_source and pb_source != source_system:
            continue
        if not playbook_conditions_match(row, incident, params):
            continue
        if not playbook_requirements_match(row, incident, params):
            continue
        result.append(row)
    return result


def choose_playbook(cur, incident: dict[str, Any], force_action: str | None = None, event: dict[str, Any] | None = None) -> dict[str, Any]:
    if force_action:
        return {
            "playbook_name": "manual_force_action",
            "action_type": normalize_action(force_action),
            "ttl_minutes": response_default_ttl_minutes(cur),
            "auto_allowed": False,
            "priority": 0,
        }
    matches = matching_playbooks(cur, incident, event)
    if matches:
        return matches[0]

    # Safe fallback: if no explicit playbook matched, do not invent containment.
    # This prevents medium/high unknown incident types from becoming DNS-only or
    # internet-block suggestions for infrastructure devices or WAN-only IDS alerts.
    return {
        "playbook_name": "builtin_safe_notify_fallback",
        "action_type": "notify_only",
        "ttl_minutes": response_default_ttl_minutes(cur),
        "auto_allowed": True,
        "priority": 9999,
    }


def event_params(incident: dict[str, Any], event: dict[str, Any] | None) -> dict[str, Any]:
    evidence = incident.get("evidence_json") if isinstance(incident.get("evidence_json"), dict) else {}
    raw = evidence.get("raw") if isinstance(evidence.get("raw"), dict) else {}
    src_ip = normalize_ip((event or {}).get("src_ip") or evidence.get("src_ip") or raw.get("src_ip"))
    dest_ip = normalize_ip((event or {}).get("dest_ip") or evidence.get("dest_ip") or raw.get("dest_ip"))
    country_code = normalize_country((event or {}).get("country_code") or evidence.get("country_code") or raw.get("country_code"))

    incident_device_ip = normalize_ip(incident.get("device_ip"))
    device_ip = incident_device_ip if incident_device_ip and ip_in_lan(incident_device_ip) else None
    if not device_ip and src_ip and ip_in_lan(src_ip):
        device_ip = src_ip
    if not device_ip and dest_ip and ip_in_lan(dest_ip):
        device_ip = dest_ip

    remote_ip = None
    if device_ip:
        if src_ip == device_ip and dest_ip and not ip_in_lan(dest_ip):
            remote_ip = dest_ip
        elif dest_ip == device_ip and src_ip and not ip_in_lan(src_ip):
            remote_ip = src_ip
        elif dest_ip and not ip_in_lan(dest_ip):
            remote_ip = dest_ip
        elif src_ip and not ip_in_lan(src_ip):
            remote_ip = src_ip

    return {
        "device_id": uuid_text(incident.get("device_id"), required=False),
        "device_ip": device_ip,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "remote_ip": remote_ip,
        "country_code": country_code,
        "domain": clean_optional_text((event or {}).get("domain") or evidence.get("domain") or raw.get("domain")),
        "signature_id": clean_optional_text((event or {}).get("signature_id") or evidence.get("signature_id") or raw.get("signature_id")),
        "signature_name": clean_optional_text((event or {}).get("signature_name") or evidence.get("signature_name") or raw.get("signature_name")),
    }

def should_auto_apply(cur, incident: dict[str, Any], playbook: dict[str, Any], action_type: str) -> tuple[bool, list[str]]:
    settings = all_settings(cur)
    mode = to_text(settings.get("auto_response_mode") or "suggest_only")
    simulate_only = bool_flag(settings.get("simulate_only"))
    reasons = [f"auto_response_mode={mode}"]
    if simulate_only:
        return False, reasons + ["simulate_only=true"]
    if mode in {"off", "suggest_only", ""}:
        return False, reasons
    if action_type == "quarantine" and bool_flag(settings.get("require_manual_quarantine", True)):
        return False, reasons + ["require_manual_quarantine=true"]
    if not bool_flag(playbook.get("auto_allowed")):
        return False, reasons + ["playbook_auto_allowed=false"]
    severity = normalize_severity(incident.get("severity"))
    sev_rank = SEVERITY_RANK.get(severity, 0)
    if mode == "auto_low_risk":
        return action_type == "notify_only" or sev_rank <= SEVERITY_RANK["low"], reasons
    if mode == "auto_high_risk":
        return sev_rank >= SEVERITY_RANK["high"], reasons
    if mode == "full_auto":
        return True, reasons
    return False, reasons


def simulate_incident(cur, incident_id: Any, force_action: str | None = None) -> dict[str, Any]:
    incident = fetch_incident(cur, incident_id)
    if not incident:
        raise RuntimeError("Incident not found")
    event = fetch_latest_event(cur, incident["id"])
    suppression = suppression_match(cur, incident)
    playbook = choose_playbook(cur, incident, force_action, event)
    action_type = normalize_action(playbook.get("action_type"))
    override = device_override(cur, incident.get("device_id"))
    if override:
        max_action = to_text(override.get("max_auto_action") or override.get("max_action") or "")
        automation_enabled = True
        if "automation_enabled" in override:
            automation_enabled = bool_flag(override.get("automation_enabled"))
        elif "auto_response_enabled" in override:
            automation_enabled = bool_flag(override.get("auto_response_enabled"))
        if not automation_enabled:
            action_type = "notify_only"
        elif max_action:
            order = ["notify_only", "dns_only", "rate_limit", "internet_block", "dynamic_firewall_block", "quarantine"]
            if action_type in order and max_action in order and order.index(action_type) > order.index(max_action):
                action_type = max_action
    params = event_params(incident, event)
    protected_reason = protected_infra_reason(incident, params)
    if protected_reason and not (force_action and RESPONSE_ALLOW_PROTECTED_FORCE):
        playbook = protected_notify_playbook(protected_reason)
        action_type = "notify_only"

    ttl_minutes = int_or_default(playbook.get("ttl_minutes"), response_default_ttl_minutes(cur))
    auto_apply, auto_reasons = should_auto_apply(cur, incident, playbook, action_type)
    if protected_reason:
        auto_reasons.append(protected_reason)
    if suppression:
        auto_apply = False
    if action_type != "notify_only" and not params.get("device_ip"):
        action_type = "notify_only"
        auto_apply = False
        auto_reasons.append("no_device_ip_for_enforcement")
    simulation = {
        "incident_id": uuid_text(incident.get("id")),
        "device_id": uuid_text(incident.get("device_id"), required=False),
        "recommended_action": action_type,
        "action_type": action_type,
        "ttl_minutes": ttl_minutes,
        "auto_apply": auto_apply,
        "suppressed": bool(suppression),
        "suppression_id": uuid_text(suppression.get("id"), required=False) if suppression else None,
        "playbook": {k: ascii_json_safe(v) for k, v in playbook.items()},
        "override": ascii_json_safe(override),
        "incident": ascii_json_safe(incident),
        "latest_event": ascii_json_safe(event),
        "params": params,
        "reasons": auto_reasons,
    }
    return simulation


def action_event(cur, action_id: Any, incident_id: Any, device_id: Any, event_type: str, actor: str, message: str, details: dict[str, Any] | None = None) -> None:
    if not table_columns(cur, "response_action_events"):
        return
    try:
        insert_row(
            cur,
            "response_action_events",
            {
                "response_action_id": uuid_text(action_id, required=False),
                "incident_id": uuid_text(incident_id, required=False),
                "device_id": uuid_text(device_id, required=False),
                "event_type": event_type,
                "actor": actor,
                "message": message,
                "details_json": details or {},
                "created_at": utc_now(),
            },
            returning="id",
        )
    except Exception:
        pass


def insert_response_action(cur, incident_id: Any, action_type: str, status: str, actor: str, reason: str | None, ttl_minutes: int, simulation: dict[str, Any], mode: str = "manual", params: dict[str, Any] | None = None) -> dict[str, Any]:
    incident_id = uuid_text(incident_id)
    incident = simulation.get("incident") if isinstance(simulation.get("incident"), dict) else fetch_incident(cur, incident_id)
    if not incident:
        raise RuntimeError("Incident not found")
    device_id = uuid_text(incident.get("device_id"), required=False)
    now = utc_now()
    ttl_int = int_or_default(ttl_minutes, response_default_ttl_minutes(cur))
    expires_at = None if action_type == "notify_only" or ttl_int <= 0 else now + dt.timedelta(minutes=ttl_int)
    row = insert_row(
        cur,
        "response_actions",
        {
            "incident_id": incident_id,
            "device_id": device_id,
            "action_type": normalize_action(action_type),
            "action_mode": mode,
            "mode": mode,
            "status": status,
            "severity": incident.get("severity"),
            "source_system": incident.get("source_system"),
            "incident_type": incident.get("incident_type"),
            "requested_by": actor,
            "approved_by": actor if status in {"approved", "applying", "applied", "applied_degraded"} else None,
            "actor": actor,
            "created_by": actor,
            "reason": reason,
            "ttl_minutes": ttl_int,
            "expires_at": expires_at,
            "suggested_at": now,
            "approved_at": now if status in {"approved", "applying", "applied", "applied_degraded"} else None,
            "simulation_json": simulation,
            "params_json": params or simulation.get("params") or {},
            "result_json": {},
            "created_at": now,
            "updated_at": now,
        },
    )
    action_id = uuid_text(row.get("id")) if row.get("id") else None
    if action_id:
        action_event(cur, action_id, incident_id, device_id, "response_action_created", actor, f"{status}: {action_type}", {"reason": reason})
    return {"id": action_id, "incident_id": incident_id, "device_id": device_id, "action_type": action_type, "status": status}


def create_or_update_suggestion(cur, incident: dict[str, Any]) -> dict[str, Any] | None:
    existing = active_action_for_incident(cur, incident.get("id"))
    if existing and to_text(existing.get("status")) != "suggested":
        return {"status": "exists", "action_id": existing.get("id")}

    simulation = simulate_incident(cur, incident.get("id"))
    if simulation.get("suppressed"):
        action_event(cur, None, incident.get("id"), incident.get("device_id"), "response_suppressed", "response-engine", "Incident matched response suppression", simulation)
        return {"status": "suppressed"}

    action_type = normalize_action(simulation.get("action_type") or simulation.get("recommended_action") or "notify_only")
    ttl_minutes = int_or_default(simulation.get("ttl_minutes"), response_default_ttl_minutes(cur))
    status = "approved" if simulation.get("auto_apply") else "suggested"
    mode = "auto" if simulation.get("auto_apply") else "suggest_only"

    if existing and to_text(existing.get("status")) == "suggested":
        action_id = uuid_text(existing.get("id"))
        now = utc_now()
        expires_at = None if action_type == "notify_only" or ttl_minutes <= 0 else now + dt.timedelta(minutes=ttl_minutes)
        update_row(
            cur,
            "response_actions",
            "id",
            action_id,
            {
                "action_type": action_type,
                "action_mode": mode,
                "mode": mode,
                "status": status,
                "ttl_minutes": ttl_minutes,
                "expires_at": expires_at,
                "simulation_json": simulation,
                "params_json": simulation.get("params") or {},
                "reason": "refreshed by response playbook",
                "updated_at": now,
            },
        )
        action_event(cur, action_id, incident.get("id"), incident.get("device_id"), "response_suggestion_refreshed", "response-engine", f"refreshed suggestion: {action_type}", simulation)
        return {"status": "refreshed", "action_id": action_id}

    row = insert_response_action(
        cur,
        incident.get("id"),
        action_type,
        status,
        "response-engine",
        "created by response playbook",
        ttl_minutes,
        simulation,
        mode=mode,
    )
    return {"status": status, "action_id": row.get("id")}

def opnsense_headers(method: str = "GET", has_payload: bool = False) -> dict[str, str]:
    if not OPNSENSE_AUTH_B64:
        raise RuntimeError("OPNSENSE_AUTH_B64 is not set")
    headers = {"Authorization": f"Basic {OPNSENSE_AUTH_B64}", "Accept": "application/json"}
    if has_payload or method.upper() not in {"GET", "HEAD"}:
        headers["Content-Type"] = "application/json"
    return headers


def opnsense_request(session: requests.Session, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"{OPNSENSE_URL}{endpoint}"
    response = session.request(method, url, headers=opnsense_headers(method, payload is not None), json=payload if payload is not None else None, timeout=25, verify=OPNSENSE_VERIFY_SSL)
    if response.status_code == 404:
        raise FileNotFoundError(endpoint)
    response.raise_for_status()
    text = (response.text or "").strip()
    if not text:
        return {}
    try:
        data = response.json()
        return data if isinstance(data, dict) else {"items": data}
    except Exception:
        return {"raw": text}


def get_alias_uuid(session: requests.Session, alias_name: str) -> str | None:
    for endpoint in (
        f"/api/firewall/alias/get_alias_u_u_i_d/{quote(alias_name, safe='')}",
        f"/api/firewall/alias/getAliasUUID/{quote(alias_name, safe='')}",
    ):
        try:
            data = opnsense_request(session, "GET", endpoint)
            for key in ("uuid", "result", "alias_uuid"):
                value = to_text(data.get(key))
                if value and value.lower() not in {"not found", "failed", "false"}:
                    return value
        except Exception:
            continue
    return None


def search_alias_items(session: requests.Session, search_phrase: str = "", row_count: int = 1000) -> list[dict[str, Any]]:
    for endpoint in (
        f"/api/firewall/alias/search_item?current=1&rowCount={row_count}&searchPhrase={quote(search_phrase, safe='')}",
        f"/api/firewall/alias/searchItem?current=1&rowCount={row_count}&searchPhrase={quote(search_phrase, safe='')}",
    ):
        try:
            data = opnsense_request(session, "GET", endpoint)
            rows = data.get("rows") if isinstance(data, dict) else []
            if isinstance(rows, list):
                return [r for r in rows if isinstance(r, dict)]
        except Exception:
            continue
    return []


def ensure_alias_definition(session: requests.Session, alias_name: str, alias_type: str, content: str, description: str, issues: list[dict[str, Any]]) -> bool:
    payload = {
        "alias": {
            "enabled": "1",
            "name": alias_name,
            "type": alias_type,
            "proto": "",
            "categories": "",
            "updatefreq": "",
            "content": content,
            "interface": "",
            "counters": "0",
            "description": description,
        },
        "network_content": content.replace("\n", ",") if content else "",
        "authgroup_content": "",
    }
    try:
        alias_uuid = get_alias_uuid(session, alias_name)
        if alias_uuid:
            opnsense_request(session, "POST", f"/api/firewall/alias/set_item/{alias_uuid}", payload)
        else:
            opnsense_request(session, "POST", "/api/firewall/alias/add_item", payload)
        return True
    except Exception as exc:
        issues.append({"alias": alias_name, "error": "alias_definition_failed", "message": str(exc)})
        return False


def read_alias_runtime_set(session: requests.Session, alias_name: str) -> tuple[set[str], str | None, dict[str, Any] | None]:
    try:
        data = opnsense_request(session, "GET", f"/api/firewall/alias_util/list/{quote(alias_name, safe='')}")
        rows = data.get("rows") if isinstance(data, dict) else []
        values: set[str] = set()
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    for key in ("address", "ip", "value", "host"):
                        ip = normalize_ip(row.get(key))
                        if ip:
                            values.add(ip)
                else:
                    ip = normalize_ip(row)
                    if ip:
                        values.add(ip)
            return values, "alias_util", None
    except FileNotFoundError:
        return set(), None, {"alias": alias_name, "warning": "alias_util_not_available"}
    except Exception as exc:
        return set(), None, {"alias": alias_name, "warning": "alias_util_list_failed", "message": str(exc)}
    return set(), None, None


def alias_util_change(session: requests.Session, alias_name: str, action: str, address: str, issues: list[dict[str, Any]]) -> bool:
    try:
        opnsense_request(session, "POST", f"/api/firewall/alias_util/{action}/{quote(alias_name, safe='')}", {"address": address})
        return True
    except Exception as exc:
        issues.append({"alias": alias_name, "address": address, "action": action, "error": "alias_util_change_failed", "message": str(exc)})
        return False


def reconcile_alias_exact(session: requests.Session, alias_name: str, alias_type: str, desired: set[str], description: str, issues: list[dict[str, Any]]) -> None:
    """Make an OPNsense alias definition exactly match desired values.

    Do not call alias_util/add after set_item: some OPNsense versions report stale
    runtime content before alias/reconfigure and this creates duplicate IP entries.
    """
    normalized: set[str] = set()
    for value in desired:
        if alias_type == "host":
            ip = normalize_ip(value)
            if ip:
                normalized.add(ip)
        else:
            item = to_text(value)
            if item:
                normalized.add(item)
    content = "\n".join(sorted(normalized))
    ensure_alias_definition(session, alias_name, alias_type, content, description, issues)


def alias_reconfigure(session: requests.Session, issues: list[dict[str, Any]]) -> None:
    try:
        opnsense_request(session, "POST", "/api/firewall/alias/reconfigure", {})
    except Exception as exc:
        issues.append({"endpoint": "/api/firewall/alias/reconfigure", "warning": "alias_reconfigure_failed", "message": str(exc)})


def _extract_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        rows = data.get("rows") or data.get("items") or data.get("data") or []
        if isinstance(rows, dict):
            rows = rows.get("rows") or rows.get("items") or []
        return [row for row in rows if isinstance(row, dict)]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def search_rule_rows(session: requests.Session, phrase: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    payload = {"current": 1, "rowCount": 2000, "searchPhrase": phrase, "sort": {}}
    endpoints = (
        ("POST", "/api/firewall/filter/searchRule", payload),
        ("POST", "/api/firewall/filter/search_rule", payload),
        ("GET", f"/api/firewall/filter/searchRule?current=1&rowCount=2000&searchPhrase={quote(phrase, safe='')}", None),
        ("GET", f"/api/firewall/filter/search_rule?current=1&rowCount=2000&searchPhrase={quote(phrase, safe='')}", None),
    )
    for method, endpoint, body in endpoints:
        try:
            data = opnsense_request(session, method, endpoint, body)
            for row in _extract_rows(data):
                key = to_text(row.get("uuid") or row.get("id") or row.get("description") or json.dumps(ascii_json_safe(row), sort_keys=True))
                if key and key not in seen:
                    seen.add(key)
                    rows.append(row)
        except Exception:
            continue
    return rows


def search_rule_by_description(session: requests.Session, description: str) -> dict[str, Any] | None:
    for row in search_rule_rows(session, description):
        if to_text(row.get("description")) == description:
            return row
    return None


def search_rules_by_description(session: requests.Session, description: str) -> list[dict[str, Any]]:
    return [row for row in search_rule_rows(session, description) if to_text(row.get("description")) == description]


def search_rules_by_prefix(session: requests.Session, prefix: str) -> set[str]:
    result: set[str] = set()
    for row in search_rule_rows(session, prefix):
        desc = to_text(row.get("description"))
        if desc.startswith(prefix):
            result.add(desc)
    return result


def response_rule_sequence_start(session: requests.Session, issues: list[dict[str, Any]]) -> int:
    """Start response rules immediately after a detected whitelist rule, otherwise use default."""
    try:
        candidates: list[dict[str, Any]] = []
        for phrase in ("WHITELIST", "WHITELIST_HOSTS", "SECURITY_CORE_POLICY"):
            candidates.extend(search_rule_rows(session, phrase))
        whitelist_sequences: list[int] = []
        seen: set[str] = set()
        for row in candidates:
            key = to_text(row.get("uuid") or row.get("id") or row.get("description") or json.dumps(ascii_json_safe(row), sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            blob = json.dumps(ascii_json_safe(row), sort_keys=True).upper()
            if "WHITELIST" not in blob and "WHITELIST_HOSTS" not in blob:
                continue
            seq_raw = row.get("sequence") or row.get("seq") or row.get("sort_order") or row.get("sortorder")
            try:
                whitelist_sequences.append(int(str(seq_raw).strip()))
            except Exception:
                pass
        if whitelist_sequences:
            return max(whitelist_sequences) + 1
    except Exception as exc:
        issues.append({"warning": "response_sequence_detect_failed", "message": str(exc)})
    return RESPONSE_RULE_SEQUENCE_START


def build_filter_rule(description: str, action: str, source_alias: str, destination_alias: str = "any", sequence: int = 0, protocol: str = "any", destination_port: str = "", log_enabled: bool = True, source_not: str = "0", destination_not: str = "0") -> dict[str, Any]:
    return {
        "enabled": "1",
        "action": action,
        "quick": "1",
        "interface": RESPONSE_INTERFACE,
        "direction": "in",
        "ipprotocol": RESPONSE_IPPROTOCOL,
        "protocol": protocol,
        "source_net": source_alias or "any",
        "source_not": source_not,
        "destination_net": destination_alias or "any",
        "destination_not": destination_not,
        "destination_port": destination_port,
        "log": "1" if log_enabled else "0",
        "sequence": str(sequence),
        "description": description,
    }


def ensure_filter_rule(session: requests.Session, rule: dict[str, Any], issues: list[dict[str, Any]]) -> bool:
    description = to_text(rule.get("description"))
    try:
        matches = search_rules_by_description(session, description)
        payload = {"rule": rule}
        keep_uuid = to_text(matches[0].get("uuid")) if matches else ""
        if keep_uuid:
            opnsense_request(session, "POST", f"/api/firewall/filter/set_rule/{keep_uuid}", payload)
            # Remove duplicates with the same description so repeated apply never creates rule spam.
            for dup in matches[1:]:
                dup_uuid = to_text(dup.get("uuid"))
                if dup_uuid:
                    try:
                        opnsense_request(session, "POST", f"/api/firewall/filter/del_rule/{dup_uuid}", {})
                    except Exception as exc:
                        issues.append({"rule": description, "warning": "duplicate_filter_rule_delete_failed", "uuid": dup_uuid, "message": str(exc)})
        else:
            opnsense_request(session, "POST", "/api/firewall/filter/add_rule", payload)
        return True
    except Exception as exc:
        issues.append({"rule": description, "error": "filter_rule_failed", "message": str(exc)})
        return False


def delete_filter_rule(session: requests.Session, description: str, issues: list[dict[str, Any]]) -> bool:
    deleted = False
    try:
        for existing in search_rules_by_description(session, description):
            rule_uuid = to_text(existing.get("uuid"))
            if not rule_uuid:
                continue
            opnsense_request(session, "POST", f"/api/firewall/filter/del_rule/{rule_uuid}", {})
            deleted = True
        return deleted
    except Exception as exc:
        issues.append({"rule": description, "warning": "filter_rule_delete_failed", "message": str(exc)})
        return deleted


def filter_apply(session: requests.Session, issues: list[dict[str, Any]]) -> None:
    try:
        opnsense_request(session, "POST", "/api/firewall/filter/apply", {})
    except Exception as exc:
        issues.append({"endpoint": "/api/firewall/filter/apply", "warning": "filter_apply_failed", "message": str(exc)})


def ensure_response_filter_rules(session: requests.Session, dns_only: set[str], ip_only: set[str], internet_block: set[str], quarantine: set[str], rate_limit: set[str], dynamic_sources: dict[str, str], dynamic_dests: dict[str, str], issues: list[dict[str, Any]]) -> None:
    if not RESPONSE_CREATE_FILTER_RULES:
        return
    desired: dict[str, dict[str, Any]] = {}
    seq = response_rule_sequence_start(session, issues)
    if dns_only:
        # DNS-only web containment: allow DNS to the trusted resolver and allow normal web ports only.
        # Firewall rules cannot prove that tcp/80 or tcp/443 was opened from a domain instead of a raw IP,
        # so this is the practical port-based version: 53 + 80 + 443, then block all else.
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_DNS_UDP"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_DNS_UDP", "pass", RESPONSE_DNS_ONLY_ALIAS, RESPONSE_DNS_SERVER_ALIAS, seq, "udp", "53")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_DNS_TCP"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_DNS_TCP", "pass", RESPONSE_DNS_ONLY_ALIAS, RESPONSE_DNS_SERVER_ALIAS, seq, "tcp", "53")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_TCP_80"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_TCP_80", "pass", RESPONSE_DNS_ONLY_ALIAS, "any", seq, "tcp", "80")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_TCP_443"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_TCP_443", "pass", RESPONSE_DNS_ONLY_ALIAS, "any", seq, "tcp", "443")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_UDP_443"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_ALLOW_WEB_UDP_443", "pass", RESPONSE_DNS_ONLY_ALIAS, "any", seq, "udp", "443")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_BLOCK_OTHER"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_DNS_ONLY_BLOCK_OTHER", "block", RESPONSE_DNS_ONLY_ALIAS, "any", seq)
        seq += 1
    if ip_only:
        # IP-only containment: block name-resolution and common web ports. A firewall cannot
        # reliably know whether tcp/80 or tcp/443 was opened by a domain or a raw IP after DNS
        # resolution, so this mode intentionally blocks normal web ports and leaves other
        # direct-IP protocols to lower rules.
        for proto in ("udp", "tcp"):
            desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DNS_{proto.upper()}_53"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DNS_{proto.upper()}_53", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, proto, "53")
            seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DOT_TCP_853"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DOT_TCP_853", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "tcp", "853")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DOT_UDP_853"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_DOT_UDP_853", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "udp", "853")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_80"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_80", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "tcp", "80")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_443"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_443", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "tcp", "443")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_QUIC_UDP_443"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_QUIC_UDP_443", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "udp", "443")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_8080"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_8080", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "tcp", "8080")
        seq += 1
        desired[f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_8443"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_IP_ONLY_BLOCK_WEB_TCP_8443", "block", RESPONSE_IP_ONLY_ALIAS, "any", seq, "tcp", "8443")
        seq += 1
    if internet_block:
        # Internet block: block non-LAN destinations but leave LAN access intact.
        desired[f"{RESPONSE_RULE_PREFIX}_INTERNET_BLOCK"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_INTERNET_BLOCK", "block", RESPONSE_INTERNET_BLOCK_ALIAS, RESPONSE_LAN_NETS_ALIAS, seq, destination_not="1")
        seq += 1
    if quarantine:
        # Quarantine: strict block to both LAN and Internet.
        desired[f"{RESPONSE_RULE_PREFIX}_QUARANTINE_BLOCK"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_QUARANTINE_BLOCK", "block", RESPONSE_QUARANTINE_ALIAS, "any", seq)
        seq += 1
    if rate_limit:
        desired[f"{RESPONSE_RULE_PREFIX}_RATE_LIMIT_MATCH"] = build_filter_rule(f"{RESPONSE_RULE_PREFIX}_RATE_LIMIT_MATCH", "pass", RESPONSE_RATE_LIMIT_ALIAS, "any", seq)
        seq += 1
    for src_alias in sorted(dynamic_sources):
        short = src_alias.replace(RESPONSE_DYNAMIC_SRC_PREFIX, "")
        dst_alias = f"{RESPONSE_DYNAMIC_DST_PREFIX}{short}"
        if dst_alias in dynamic_dests:
            desc = f"{RESPONSE_RULE_PREFIX}_DYNAMIC_BLOCK_{short}"
            destination = "any" if dynamic_dests.get(dst_alias) == "any" else dst_alias
            desired[desc] = build_filter_rule(desc, "block", src_alias, destination, seq)
            seq += 1
    existing = search_rules_by_prefix(session, RESPONSE_RULE_PREFIX)
    for desc, rule in desired.items():
        ensure_filter_rule(session, rule, issues)
    for stale in sorted(existing - set(desired)):
        delete_filter_rule(session, stale, issues)
    if desired or existing:
        filter_apply(session, issues)



def shaper_api_variants(command: str, *parts: str, query: str = "") -> list[str]:
    """Return official OPNsense trafficshaper endpoints first, then legacy fallbacks."""
    suffix = "/" + "/".join(quote(str(part), safe="") for part in parts if part is not None and str(part) != "") if parts else ""
    q = query or ""
    return [
        f"/api/trafficshaper/settings/{command}{suffix}{q}",
        f"/api/firewall/shaper/{command}{suffix}{q}",
    ]


def shaper_request_variants(session: requests.Session, method: str, variants: list[str], payload: dict[str, Any] | None = None) -> dict[str, Any]:
    last_exc: Exception | None = None
    for endpoint in variants:
        try:
            return opnsense_request(session, method, endpoint, payload)
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    raise RuntimeError("No shaper endpoint variants provided")


def search_shaper_items(session: requests.Session, kind: str, phrase: str = "") -> list[dict[str, Any]]:
    search_command = {"pipe": "search_pipes", "queue": "search_queues", "rule": "search_rules"}.get(kind, f"search_{kind}s")
    legacy_command = {"pipe": "search_pipes", "queue": "search_queues", "rule": "search_rules"}.get(kind, f"search_{kind}s")
    payload = {"current": 1, "rowCount": 500, "searchPhrase": phrase, "sort": {}}
    endpoints = [
        ("POST", f"/api/trafficshaper/settings/{search_command}", payload),
        ("GET", f"/api/trafficshaper/settings/{search_command}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
        ("POST", f"/api/firewall/shaper/{legacy_command}", payload),
        ("GET", f"/api/firewall/shaper/{legacy_command}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
    ]
    # Some older code paths used singular/camelCase command names. Keep them as safe fallbacks.
    plural = "pipes" if kind == "pipe" else "queues" if kind == "queue" else "rules"
    singular = "pipe" if kind == "pipe" else "queue" if kind == "queue" else "rule"
    camel_plural = "Pipes" if kind == "pipe" else "Queues" if kind == "queue" else "Rules"
    camel_singular = "Pipe" if kind == "pipe" else "Queue" if kind == "queue" else "Rule"
    endpoints.extend([
        ("GET", f"/api/firewall/shaper/search_{plural}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
        ("GET", f"/api/firewall/shaper/search_{singular}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
        ("GET", f"/api/firewall/shaper/search{camel_plural}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
        ("GET", f"/api/firewall/shaper/search{camel_singular}?current=1&rowCount=500&searchPhrase={quote(phrase, safe='')}", None),
    ])
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for method, endpoint, body in endpoints:
        try:
            data = opnsense_request(session, method, endpoint, body)
            for row in _extract_rows(data):
                key = to_text(row.get("uuid") or row.get("id") or row.get("description") or row.get("descr") or json.dumps(ascii_json_safe(row), sort_keys=True))
                if key and key not in seen:
                    seen.add(key)
                    rows.append(row)
        except Exception:
            continue
    return rows


def shaper_row_description(row: dict[str, Any]) -> str:
    return to_text(row.get("description") or row.get("descr") or row.get("name"))


def search_shaper_item(session: requests.Session, kind: str, description: str) -> dict[str, Any] | None:
    for row in search_shaper_items(session, kind, description):
        if shaper_row_description(row) == description:
            return row
    return None


def search_shaper_items_by_prefix(session: requests.Session, kind: str, prefix: str) -> list[dict[str, Any]]:
    return [row for row in search_shaper_items(session, kind, prefix) if shaper_row_description(row).startswith(prefix)]


def shaper_uuid(row: dict[str, Any] | None) -> str | None:
    if not row:
        return None
    value = to_text(row.get("uuid") or row.get("id"))
    return value or None


def delete_shaper_item_by_uuid(session: requests.Session, kind: str, uuid: str, description: str, issues: list[dict[str, Any]]) -> bool:
    delete_command = {"pipe": "del_pipe", "queue": "del_queue", "rule": "del_rule"}.get(kind, f"del_{kind}")
    legacy_delete = {"pipe": "delPipe", "queue": "delQueue", "rule": "delRule"}.get(kind, f"del{kind.capitalize()}")
    try:
        shaper_request_variants(session, "POST", [
            f"/api/trafficshaper/settings/{delete_command}/{quote(uuid, safe='')}",
            f"/api/firewall/shaper/{delete_command}/{quote(uuid, safe='')}",
            f"/api/firewall/shaper/{legacy_delete}/{quote(uuid, safe='')}",
        ], {})
        return True
    except Exception as exc:
        issues.append({"shaper": description, "warning": f"shaper_{kind}_delete_failed", "message": str(exc)})
        return False


def delete_shaper_item(session: requests.Session, kind: str, description: str, issues: list[dict[str, Any]]) -> bool:
    item = search_shaper_item(session, kind, description)
    uuid = shaper_uuid(item)
    if not uuid:
        return False
    return delete_shaper_item_by_uuid(session, kind, uuid, description, issues)


def shaper_post_variants(session: requests.Session, variants: list[str], payload: dict[str, Any]) -> dict[str, Any]:
    return shaper_request_variants(session, "POST", variants, payload)


def shaper_apply(session: requests.Session, issues: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply Traffic Shaper changes using all known apply endpoints."""
    attempts: list[dict[str, Any]] = []
    endpoints = [
        "/api/trafficshaper/service/reconfigure",
        "/api/trafficshaper/service/flushreload",
        "/api/firewall/shaper/reconfigure",
        "/api/firewall/shaper/reconfigureAct",
    ]
    for endpoint in endpoints:
        try:
            data = opnsense_request(session, "POST", endpoint, {})
            attempts.append({"endpoint": endpoint, "ok": True, "result": ascii_json_safe(data)})
        except Exception as exc:
            attempts.append({"endpoint": endpoint, "ok": False, "message": str(exc)})
    if not any(a.get("ok") for a in attempts):
        issues.append({"endpoint": "/api/trafficshaper/service/reconfigure", "warning": "shaper_apply_failed", "attempts": attempts})
    return {"attempts": attempts, "ok": any(a.get("ok") for a in attempts)}


def shaper_get_default(session: requests.Session, kind: str) -> dict[str, Any]:
    get_cmd = {"pipe": "get_pipe", "queue": "get_queue", "rule": "get_rule"}.get(kind, f"get_{kind}")
    for endpoint in (
        f"/api/trafficshaper/settings/{get_cmd}",
        f"/api/firewall/shaper/{get_cmd}",
        f"/api/firewall/shaper/get{kind.capitalize()}",
    ):
        try:
            data = opnsense_request(session, "GET", endpoint)
            obj = data.get(kind) if isinstance(data, dict) else None
            if isinstance(obj, dict):
                return obj.copy()
        except Exception:
            continue
    return {}


def shaper_row_number(row: dict[str, Any] | None) -> int | None:
    if not row:
        return None
    raw = row.get("number") or row.get("pipe") or row.get("queue")
    if isinstance(raw, dict):
        raw = raw.get("number")
    try:
        text = to_text(raw)
        return int(text) if text else None
    except Exception:
        return None


def find_available_shaper_number(session: requests.Session, kind: str, start_number: int) -> int:
    used: set[int] = set()
    try:
        for row in search_shaper_items(session, kind, ""):
            n = shaper_row_number(row)
            if n is not None:
                used.add(n)
    except Exception:
        pass
    n = max(1, int(start_number))
    while n in used:
        n += 1
    return n


def compact_payload(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if v is not None}


def shaper_response_ok(data: dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    result = to_text(data.get("result") or data.get("status")).lower()
    if result in {"saved", "ok", "success", "done"}:
        return True
    if data.get("uuid") or data.get("id"):
        return True
    return result not in {"failed", "error"}


def ensure_rate_limit_pipe(session: requests.Session, issues: list[dict[str, Any]]) -> str | None:
    existing = search_shaper_item(session, "pipe", RESPONSE_SHAPER_PIPE_DESC)
    existing_uuid = shaper_uuid(existing)
    pipe_number = shaper_row_number(existing) or find_available_shaper_number(session, "pipe", RESPONSE_SHAPER_PIPE_NUMBER_START)
    pipe = shaper_get_default(session, "pipe")
    pipe.update({
        "number": str(pipe_number),
        "enabled": "1",
        "bandwidth": str(max(1, RESPONSE_RATE_LIMIT_KBIT)),
        "bandwidthMetric": "Kbit",
        "queue": "",
        "mask": "none",
        "buckets": "",
        "scheduler": "",
        "codel_enable": "0",
        "codel_target": "",
        "codel_interval": "",
        "codel_ecn_enable": "0",
        "pie_enable": "0",
        "fqcodel_quantum": "",
        "fqcodel_limit": "",
        "fqcodel_flows": "",
        "origin": "securitycore",
        "delay": "",
        "description": RESPONSE_SHAPER_PIPE_DESC,
    })
    payload = {"pipe": compact_payload(pipe)}
    responses: list[dict[str, Any]] = []
    try:
        if existing_uuid:
            data = shaper_request_variants(session, "POST", [
                f"/api/trafficshaper/settings/set_pipe/{quote(existing_uuid, safe='')}",
                f"/api/firewall/shaper/set_pipe/{quote(existing_uuid, safe='')}",
                f"/api/firewall/shaper/setPipe/{quote(existing_uuid, safe='')}",
            ], payload)
            responses.append(ascii_json_safe(data))
            if not shaper_response_ok(data):
                raise RuntimeError(f"set_pipe returned {data}")
            return existing_uuid
        data = shaper_request_variants(session, "POST", [
            "/api/trafficshaper/settings/add_pipe",
            "/api/firewall/shaper/add_pipe",
            "/api/firewall/shaper/addPipe",
        ], payload)
        responses.append(ascii_json_safe(data))
        if not shaper_response_ok(data):
            raise RuntimeError(f"add_pipe returned {data}")
        new_uuid = to_text(data.get("uuid") or data.get("id"))
        found = search_shaper_item(session, "pipe", RESPONSE_SHAPER_PIPE_DESC)
        return new_uuid or shaper_uuid(found) or "created_or_updated"
    except Exception as exc:
        issues.append({"shaper": RESPONSE_SHAPER_PIPE_DESC, "warning": "rate_limit_pipe_failed", "message": str(exc), "payload": ascii_json_safe(payload), "responses": responses})
        return None


def ensure_rate_limit_shaper_rule(session: requests.Session, description: str, ip: str, direction: str, interface: str, source: str, destination: str, target: str, sequence: int, issues: list[dict[str, Any]]) -> str | None:
    rule = shaper_get_default(session, "rule")
    rule.update({
        "enabled": "1",
        "sequence": str(sequence),
        "interface": interface,
        "interface2": "",
        "proto": "ip",
        "iplen": "",
        "source": source,
        "source_not": "0",
        "src_port": "any",
        "destination": destination,
        "destination_not": "0",
        "dst_port": "any",
        "dscp": "",
        "direction": direction,
        "target": target,
        "description": description,
        "origin": "securitycore",
    })
    payload = {"rule": compact_payload(rule)}
    existing = search_shaper_item(session, "rule", description)
    existing_uuid = shaper_uuid(existing)
    responses: list[dict[str, Any]] = []
    try:
        if existing_uuid:
            data = shaper_request_variants(session, "POST", [
                f"/api/trafficshaper/settings/set_rule/{quote(existing_uuid, safe='')}",
                f"/api/firewall/shaper/set_rule/{quote(existing_uuid, safe='')}",
                f"/api/firewall/shaper/setRule/{quote(existing_uuid, safe='')}",
            ], payload)
            responses.append(ascii_json_safe(data))
            if not shaper_response_ok(data):
                raise RuntimeError(f"set_rule returned {data}")
            return existing_uuid
        data = shaper_request_variants(session, "POST", [
            "/api/trafficshaper/settings/add_rule",
            "/api/firewall/shaper/add_rule",
            "/api/firewall/shaper/addRule",
        ], payload)
        responses.append(ascii_json_safe(data))
        if not shaper_response_ok(data):
            raise RuntimeError(f"add_rule returned {data}")
        new_uuid = to_text(data.get("uuid") or data.get("id"))
        found = search_shaper_item(session, "rule", description)
        return new_uuid or shaper_uuid(found) or "created_or_updated"
    except Exception as exc:
        issues.append({"shaper": description, "ip": ip, "warning": "rate_limit_rule_failed", "message": str(exc), "payload": ascii_json_safe(payload), "responses": responses})
        return None


def ensure_rate_limit_shaper(session: requests.Session, rate_limit: set[str], issues: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": RESPONSE_CREATE_SHAPER, "requested_hosts": len(rate_limit), "pipe": None, "rules": [], "apply": None}
    if not RESPONSE_CREATE_SHAPER:
        return result

    rule_prefix = f"{RESPONSE_SHAPER_RULE_DESC}_"
    existing_rules = search_shaper_items_by_prefix(session, "rule", rule_prefix)
    desired_descriptions: set[str] = set()

    if not rate_limit:
        for row in existing_rules:
            uuid = shaper_uuid(row)
            if uuid:
                delete_shaper_item_by_uuid(session, "rule", uuid, shaper_row_description(row), issues)
        delete_shaper_item(session, "rule", RESPONSE_SHAPER_RULE_DESC, issues)
        delete_shaper_item(session, "pipe", RESPONSE_SHAPER_PIPE_DESC, issues)
        result["apply"] = shaper_apply(session, issues)
        return result

    pipe_uuid = ensure_rate_limit_pipe(session, issues)
    result["pipe"] = pipe_uuid
    if not pipe_uuid:
        return result

    seq = RESPONSE_SHAPER_RULE_SEQUENCE_START
    for ip in sorted(rate_limit):
        safe_ip = ip.replace(".", "_").replace(":", "_")
        upload_desc = f"{rule_prefix}{safe_ip}_UPLOAD_LAN_IN"
        download_desc = f"{rule_prefix}{safe_ip}_DOWNLOAD_LAN_OUT"
        desired_descriptions.update({upload_desc, download_desc})
        # Upload: packet enters firewall from the LAN client.
        upload_uuid = ensure_rate_limit_shaper_rule(session, upload_desc, ip, "in", RESPONSE_INTERFACE, ip, "any", pipe_uuid, seq, issues)
        seq += 1
        # Download: after NAT/routing, packet leaves firewall toward the LAN client.
        download_interface = RESPONSE_SHAPER_DOWNLOAD_INTERFACE or RESPONSE_INTERFACE
        download_uuid = ensure_rate_limit_shaper_rule(session, download_desc, ip, "out", download_interface, "any", ip, pipe_uuid, seq, issues)
        seq += 1
        result["rules"].append({"ip": ip, "upload_lan_in": upload_uuid, "download_lan_out": download_uuid, "download_interface": download_interface})

    for row in existing_rules:
        desc = shaper_row_description(row)
        if desc not in desired_descriptions:
            uuid = shaper_uuid(row)
            if uuid:
                delete_shaper_item_by_uuid(session, "rule", uuid, desc, issues)

    delete_shaper_item(session, "rule", RESPONSE_SHAPER_RULE_DESC, issues)
    result["apply"] = shaper_apply(session, issues)
    return result


def desired_active_actions(cur) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT
            ra.id::text AS id,
            ra.incident_id::text AS incident_id,
            ra.device_id::text AS device_id,
            ra.action_type,
            ra.status,
            ra.params_json,
            ra.simulation_json,
            d.hostname AS device_hostname,
            host(d.current_ip) AS device_ip
        FROM response_actions ra
        LEFT JOIN devices d ON d.id = ra.device_id
        WHERE ra.status IN ('approved','pending','applying','applied','applied_degraded')
          AND ra.action_type IN ('dns_only','ip_only','internet_block','quarantine','rate_limit','dynamic_firewall_block')
          AND (ra.expires_at IS NULL OR ra.expires_at > now())
        ORDER BY ra.created_at
        """
    )
    return [dict(row) for row in (cur.fetchall() or [])]


def sync_aliases_and_rules(cur) -> dict[str, Any]:
    actions = desired_active_actions(cur)
    issues: list[dict[str, Any]] = []
    dns_only: set[str] = set()
    ip_only: set[str] = set()
    internet_block: set[str] = set()
    quarantine: set[str] = set()
    rate_limit: set[str] = set()
    dynamic_sources: dict[str, str] = {}
    dynamic_dests: dict[str, str] = {}
    for action in actions:
        action_id = uuid_text(action.get("id"), required=False) or ""
        short = action_id.replace("-", "")[:12].upper()
        action_type = normalize_action(action.get("action_type"))
        params = action.get("params_json") if isinstance(action.get("params_json"), dict) else {}
        sim = action.get("simulation_json") if isinstance(action.get("simulation_json"), dict) else {}
        sim_params = sim.get("params") if isinstance(sim.get("params"), dict) else {}
        device_ip = normalize_ip(action.get("device_ip") or params.get("device_ip") or sim_params.get("device_ip"))
        remote_ip = normalize_ip(params.get("remote_ip") or params.get("dest_ip") or sim_params.get("remote_ip") or sim_params.get("dest_ip"))
        protected_reason = protected_infra_reason(action=action)
        if protected_reason:
            issues.append({"action_id": action_id, "warning": "protected_infrastructure_skipped", "reason": protected_reason})
            continue
        if action_type == "dynamic_firewall_block":
            if not device_ip:
                issues.append({"action_id": action_id, "warning": "dynamic_block_without_lan_device_skipped", "remote_ip": remote_ip})
                continue
            dynamic_sources[f"{RESPONSE_DYNAMIC_SRC_PREFIX}{short}"] = device_ip
            # If an incident has no external peer (for example traffic_volume_spike), manual dynamic block
            # still creates a visible temporary OPNsense rule for this device source.
            dynamic_dests[f"{RESPONSE_DYNAMIC_DST_PREFIX}{short}"] = remote_ip or "any"
            if not remote_ip:
                issues.append({"action_id": action_id, "warning": "dynamic_block_without_remote_ip_using_any_destination", "device_ip": device_ip})
            continue
        if not device_ip:
            issues.append({"action_id": action_id, "warning": "missing_device_ip", "action_type": action_type})
            continue
        if action_type == "dns_only":
            dns_only.add(device_ip)
        elif action_type == "ip_only":
            ip_only.add(device_ip)
        elif action_type == "internet_block":
            internet_block.add(device_ip)
        elif action_type == "quarantine":
            quarantine.add(device_ip)
        elif action_type == "rate_limit":
            rate_limit.add(device_ip)
    if not OPNSENSE_AUTH_B64:
        return {"ok": False, "mode": "db_only", "issues": issues + [{"error": "OPNSENSE_AUTH_B64 missing"}]}
    shaper_result: dict[str, Any] = {}
    try:
        with requests.Session() as session:
            session.headers.update({"Authorization": f"Basic {OPNSENSE_AUTH_B64}", "Accept": "application/json"})
            reconcile_alias_exact(session, RESPONSE_QUARANTINE_ALIAS, "host", quarantine, "security-core temporary quarantine hosts", issues)
            reconcile_alias_exact(session, RESPONSE_INTERNET_BLOCK_ALIAS, "host", internet_block, "security-core temporary internet-block hosts", issues)
            reconcile_alias_exact(session, RESPONSE_DNS_ONLY_ALIAS, "host", dns_only, "security-core temporary DNS-controlled hosts", issues)
            reconcile_alias_exact(session, RESPONSE_IP_ONLY_ALIAS, "host", ip_only, "security-core temporary IP-only hosts", issues)
            reconcile_alias_exact(session, RESPONSE_RATE_LIMIT_ALIAS, "host", rate_limit, "security-core temporary rate-limited hosts", issues)
            reconcile_alias_exact(session, RESPONSE_DNS_SERVER_ALIAS, "host", set(RESPONSE_DNS_SERVERS), "security-core DNS servers for temporary response", issues)
            reconcile_alias_exact(session, RESPONSE_LAN_NETS_ALIAS, "network", set(LAN_CIDRS), "security-core LAN networks for temporary response", issues)
            desired_dynamic_aliases = set(dynamic_sources) | {name for name, value in dynamic_dests.items() if value != "any"}
            for alias_name, value in sorted(dynamic_sources.items()):
                reconcile_alias_exact(session, alias_name, "host", {value}, "security-core dynamic response source", issues)
            for alias_name, value in sorted(dynamic_dests.items()):
                if value != "any":
                    reconcile_alias_exact(session, alias_name, "host", {value}, "security-core dynamic response destination", issues)
            for row in search_alias_items(session, "SCR_"):
                name = to_text(row.get("name"))
                if (name.startswith(RESPONSE_DYNAMIC_SRC_PREFIX) or name.startswith(RESPONSE_DYNAMIC_DST_PREFIX)) and name not in desired_dynamic_aliases:
                    alias_uuid = to_text(row.get("uuid"))
                    if alias_uuid:
                        try:
                            opnsense_request(session, "POST", f"/api/firewall/alias/del_item/{alias_uuid}", {})
                        except Exception as exc:
                            issues.append({"alias": name, "warning": "stale_dynamic_alias_delete_failed", "message": str(exc)})
            alias_reconfigure(session, issues)
            ensure_response_filter_rules(session, dns_only, ip_only, internet_block, quarantine, rate_limit, dynamic_sources, dynamic_dests, issues)
            shaper_result = ensure_rate_limit_shaper(session, rate_limit, issues)
    except Exception as exc:
        issues.append({"error": "opnsense_sync_failed", "message": str(exc)})
    errors = [i for i in issues if "error" in i]
    ok = not errors if RESPONSE_ENFORCEMENT_STRICT else not any(i.get("error") == "opnsense_sync_failed" for i in issues)
    return {"ok": ok, "issues": issues, "shaper": shaper_result, "rules_enabled": RESPONSE_CREATE_FILTER_RULES, "counts": {"dns_only": len(dns_only), "ip_only": len(ip_only), "internet_block": len(internet_block), "quarantine": len(quarantine), "rate_limit": len(rate_limit), "dynamic_blocks": len(dynamic_dests)}}

def trigger_policy_enforcer() -> dict[str, Any]:
    if not RESPONSE_TRIGGER_POLICY_ENFORCER:
        return {"ok": True, "skipped": True, "reason": "RESPONSE_TRIGGER_POLICY_ENFORCER=false"}
    if not Path(POLICY_ENFORCER_SCRIPT).exists():
        return {"ok": False, "skipped": True, "reason": "policy_enforcer.py not found"}
    try:
        proc = subprocess.run([SECURITY_CORE_PYTHON, POLICY_ENFORCER_SCRIPT], capture_output=True, text=True, timeout=60, check=False, env=child_process_env())
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": (proc.stdout or "")[-1000:], "stderr": (proc.stderr or "")[-1000:]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def mark_action_status(cur, action_id: Any, status: str, result: dict[str, Any] | None = None, actor: str = "response-engine") -> None:
    action_id = uuid_text(action_id)
    now = utc_now()
    values = {"status": status, "updated_at": now}
    if status in {"applied", "applied_degraded"}:
        values["applied_at"] = now
    if result is not None:
        values["result_json"] = result
    update_row(cur, "response_actions", "id", action_id, values)
    try:
        cur.execute("SELECT incident_id::text AS incident_id, device_id::text AS device_id, action_type FROM response_actions WHERE id = %s::uuid", (action_id,))
        row = cur.fetchone()
        if row:
            action_event(cur, action_id, row.get("incident_id"), row.get("device_id"), "response_action_status", actor, f"status={status}", result or {})
    except Exception:
        pass


def apply_action(cur, action: dict[str, Any], actor: str = "response-engine") -> dict[str, Any]:
    action_id = uuid_text(action.get("id"))
    action_type = normalize_action(action.get("action_type"))
    protected_reason = protected_infra_reason(action=action)
    if action_type != "notify_only" and protected_reason:
        result = {"ok": False, "blocked_by_safety": True, "reason": protected_reason}
        mark_action_status(cur, action_id, "rolled_back", result, actor)
        return result
    if action_type == "notify_only":
        result = {"ok": True, "message": "notify_only action recorded"}
        mark_action_status(cur, action_id, "applied", result, actor)
        return result
    mark_action_status(cur, action_id, "applying", {"started_at": utc_now().isoformat()}, actor)
    sync_result = sync_aliases_and_rules(cur)
    enforcer = trigger_policy_enforcer()
    result = {"sync": sync_result, "policy_enforcer": enforcer}
    status = "applied" if sync_result.get("ok", False) else "applied_degraded"
    if action_type == "rate_limit" and RESPONSE_RATE_LIMIT_ENABLE_SHAPER:
        result["rate_limit"] = {"mode": "best_effort_alias", "kbit": RESPONSE_RATE_LIMIT_KBIT, "note": "Traffic shaper API is version-dependent; RESPONSE_RATE_LIMIT_HOSTS alias is maintained for limiter rules."}
        if not sync_result.get("ok") and RESPONSE_RATE_LIMIT_FALLBACK_TO_DNS_ONLY:
            result["fallback"] = "dns_only_requested"
    mark_action_status(cur, action_id, status, result, actor)
    return result


def approved_actions(cur, limit: int = 50) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id, action_type, status, params_json, simulation_json
        FROM response_actions
        WHERE status IN ('approved','pending')
        ORDER BY created_at
        LIMIT %s
        """,
        (limit,),
    )
    return [dict(row) for row in (cur.fetchall() or [])]


def expire_actions(cur) -> int:
    try:
        cur.execute(
            """
            UPDATE response_actions
            SET status = 'expired', updated_at = now(), result_json = COALESCE(result_json, '{}'::jsonb) || jsonb_build_object('expired_at', now())
            WHERE status IN ('applied','applied_degraded')
              AND expires_at IS NOT NULL
              AND expires_at <= now()
            RETURNING id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id
            """
        )
        rows = [dict(row) for row in (cur.fetchall() or [])]
        for row in rows:
            action_event(cur, row.get("id"), row.get("incident_id"), row.get("device_id"), "response_action_expired", "response-engine", "Temporary response expired", {})
        if rows:
            sync_aliases_and_rules(cur)
            trigger_policy_enforcer()
        return len(rows)
    except Exception:
        return 0


def rollback_action_id(cur, action_id: Any, actor: str = "api", reason: str | None = None) -> dict[str, Any]:
    action_id = uuid_text(action_id)
    cur.execute("SELECT id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id, action_type, status FROM response_actions WHERE id = %s::uuid", (action_id,))
    row = cur.fetchone()
    if not row:
        raise RuntimeError("Response action not found")
    now = utc_now()
    update_row(cur, "response_actions", "id", action_id, {"status": "rolled_back", "rollback_by": actor, "rollback_reason": reason, "rolled_back_at": now, "updated_at": now})
    action_event(cur, action_id, row.get("incident_id"), row.get("device_id"), "response_action_rolled_back", actor, "Response action rolled back", {"reason": reason})
    sync_result = sync_aliases_and_rules(cur)
    enforcer = trigger_policy_enforcer()
    return {"status": "ok", "action_id": action_id, "sync": sync_result, "policy_enforcer": enforcer}


def rollback_active_actions_for_incident(cur, incident_id: Any, actor: str = "api", reason: str | None = None) -> list[str]:
    incident_id = uuid_text(incident_id)
    now = utc_now()
    cur.execute(
        """
        UPDATE response_actions
        SET status = 'rolled_back',
            rollback_by = %s,
            rollback_reason = %s,
            rolled_back_at = COALESCE(rolled_back_at, %s),
            updated_at = %s
        WHERE incident_id = %s::uuid
          AND status IN ('suggested','approved','pending','applying','applied','applied_degraded')
        RETURNING id::text AS id, device_id::text AS device_id, action_type
        """,
        (actor, reason, now, now, incident_id),
    )
    rows = [dict(row) for row in (cur.fetchall() or [])]
    for row in rows:
        action_event(cur, row.get("id"), incident_id, row.get("device_id"), "response_action_rolled_back", actor, "Incident-level rollback", {"reason": reason, "action_type": row.get("action_type")})
    return [to_text(row.get("id")) for row in rows if to_text(row.get("id"))]


def run_worker() -> dict[str, Any]:
    summary = {
        "suggestions_created": 0,
        "suggestions_refreshed": 0,
        "already_existing": 0,
        "suppressed": 0,
        "approved_to_apply": 0,
        "applied": 0,
        "expired": 0,
        "suggestion_failures": 0,
        "apply_failures": 0,
        "failure_samples": [],
    }
    with connect() as conn:
        with conn.cursor() as cur:
            if not bool_flag(setting_value(cur, "response_engine_enabled", True)):
                result = {"status": "disabled", **summary}
                update_health("healthy", result)
                print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
                return result
            for incident in open_incidents(cur, limit=150):
                savepoint_name = "sp_response_incident"
                try:
                    cur.execute(f"SAVEPOINT {savepoint_name}")
                    result = create_or_update_suggestion(cur, incident)
                    cur.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                    if not result:
                        continue
                    if result.get("status") in {"suggested", "approved"}:
                        summary["suggestions_created"] += 1
                        if result.get("status") == "approved":
                            summary["approved_to_apply"] += 1
                    elif result.get("status") == "refreshed":
                        summary["suggestions_refreshed"] += 1
                    elif result.get("status") == "exists":
                        summary["already_existing"] += 1
                    elif result.get("status") == "suppressed":
                        summary["suppressed"] += 1
                except Exception as exc:
                    try:
                        cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                        cur.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                    except Exception:
                        conn.rollback()
                    summary["suggestion_failures"] += 1
                    if len(summary["failure_samples"]) < 5:
                        summary["failure_samples"].append({"incident_id": incident.get("id"), "error": str(exc)})
                    try:
                        action_event(cur, None, incident.get("id"), incident.get("device_id"), "response_suggestion_failed", "response-engine", str(exc), {"incident_id": incident.get("id")})
                    except Exception:
                        pass
            for action in approved_actions(cur):
                savepoint_name = "sp_response_apply"
                try:
                    cur.execute(f"SAVEPOINT {savepoint_name}")
                    apply_action(cur, action)
                    cur.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                    summary["applied"] += 1
                except Exception as exc:
                    try:
                        cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                        cur.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                    except Exception:
                        conn.rollback()
                    summary["apply_failures"] += 1
                    try:
                        mark_action_status(cur, action.get("id"), "applied_degraded", {"error": str(exc)}, "response-engine")
                    except Exception:
                        pass
            try:
                summary["expired"] = expire_actions(cur)
            except Exception as exc:
                summary["failure_samples"].append({"stage": "expire_actions", "error": str(exc)})
        conn.commit()
    status = "healthy" if summary["suggestion_failures"] == 0 and summary["apply_failures"] == 0 else "degraded"
    result = {"status": status, **summary}
    update_health(status, result)
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result

def run_simulate(incident_id: Any, action: str | None = None) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            result = simulate_incident(cur, uuid_text(incident_id), force_action=action)
        conn.commit()
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_suggest(incident_id: Any, action: str | None, actor: str, reason: str | None) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            sim = simulate_incident(cur, uuid_text(incident_id), force_action=action)
            row = insert_response_action(cur, incident_id, sim.get("action_type") or "notify_only", "suggested", actor, reason, int_or_default(sim.get("ttl_minutes"), response_default_ttl_minutes(cur)), sim, mode="manual")
        conn.commit()
    result = {"status": "ok", "action": row}
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_apply_incident(incident_id: Any, action: str | None, actor: str, reason: str | None, ttl_minutes: int | None = None) -> dict[str, Any]:
    incident_id = uuid_text(incident_id)
    with connect() as conn:
        with conn.cursor() as cur:
            # Applying a new action for the same incident must replace any old active/suggested action.
            rolled_back_old = rollback_active_actions_for_incident(cur, incident_id, actor, "superseded_by_new_action")
            sim = simulate_incident(cur, incident_id, force_action=action)
            effective_ttl = int_or_default(ttl_minutes if ttl_minutes is not None else sim.get("ttl_minutes"), response_default_ttl_minutes(cur))
            row = insert_response_action(cur, incident_id, sim.get("action_type") or "notify_only", "approved", actor, reason, effective_ttl, sim, mode="manual")
            cur.execute("SELECT id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id, action_type, status, params_json, simulation_json FROM response_actions WHERE id = %s::uuid", (row.get("id"),))
            action_row = dict(cur.fetchone())
            apply_result = apply_action(cur, action_row, actor=actor)
            cur.execute("""
                UPDATE incidents
                SET status = CASE WHEN status IN ('open','in_progress') THEN 'acknowledged' ELSE status END,
                    updated_at = now(),
                    evidence_json = COALESCE(evidence_json, '{}'::jsonb) || %s::jsonb
                WHERE id = %s::uuid
            """, (j({"last_action": "acknowledged", "acknowledged_by": actor, "acknowledged_reason": reason or f"response action applied: {action or sim.get('action_type')}"}), incident_id))
        conn.commit()
    result = {"status": "ok", "action_id": row.get("id"), "rolled_back_old_action_ids": rolled_back_old, "apply_result": apply_result}
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_apply_action(action_id: Any, actor: str, reason: str | None = None) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            action_id = uuid_text(action_id)
            update_row(cur, "response_actions", "id", action_id, {"status": "approved", "actor": actor, "reason": reason, "updated_at": utc_now()})
            cur.execute("SELECT id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id, action_type, status, params_json, simulation_json FROM response_actions WHERE id = %s::uuid", (action_id,))
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Response action not found")
            apply_result = apply_action(cur, dict(row), actor=actor)
        conn.commit()
    result = {"status": "ok", "action_id": action_id, "apply_result": apply_result}
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_rollback(action_id: Any, actor: str, reason: str | None) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            result = rollback_action_id(cur, action_id, actor, reason)
        conn.commit()
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_rollback_incident(incident_id: Any, actor: str, reason: str | None) -> dict[str, Any]:
    incident_id = uuid_text(incident_id)
    with connect() as conn:
        with conn.cursor() as cur:
            ensure_response_ignores(cur)
            incident = fetch_incident(cur, incident_id)
            rolled_back = rollback_active_actions_for_incident(cur, incident_id, actor, reason or "incident rollback")
            disabled_suppressions = disable_response_ignores_for_incident(cur, incident or {}, "ignore removed by rollback") if incident else []
            cur.execute("""
                UPDATE incidents
                SET status='acknowledged',
                    updated_at=now(),
                    evidence_json = (COALESCE(evidence_json, '{}'::jsonb)
                        - 'ignore_suppression_id' - 'ignore_id' - 'ignored_by' - 'ignored_reason'
                        - 'ignore_scope' - 'ignore_device_id' - 'ignore_incident_type' - 'ignore_source_system') || %s::jsonb
                WHERE id=%s::uuid
                  AND status IN ('ignored','open','acknowledged','in_progress')
            """, (j({"ignore_removed_by": actor, "ignore_removed_reason": reason or "rollback", "disabled_ignore_ids": disabled_suppressions}), incident_id))
            sync_result = sync_aliases_and_rules(cur)
            enforcer = trigger_policy_enforcer()
        conn.commit()
    result = {"status": "ok", "incident_id": incident_id, "rolled_back_action_ids": rolled_back, "disabled_suppression_ids": disabled_suppressions, "disabled_ignore_ids": disabled_suppressions, "sync": sync_result, "policy_enforcer": enforcer}
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result

def run_false_positive(incident_id: Any, actor: str, reason: str | None, ttl_hours: int | None = None) -> dict[str, Any]:
    incident_id = uuid_text(incident_id)
    with connect() as conn:
        with conn.cursor() as cur:
            incident = fetch_incident(cur, incident_id)
            if not incident:
                raise RuntimeError("Incident not found")
            expires_at = None
            if ttl_hours is not None and int_or_default(ttl_hours, 0) > 0:
                expires_at = utc_now() + dt.timedelta(hours=int_or_default(ttl_hours, 0))
            # False-positive is a final disposition, so remove any active ignore/suppression for this exact device/type/source first.
            if table_columns(cur, "response_suppressions"):
                cur.execute(f"""
                    UPDATE response_suppressions
                    SET is_enabled = false,
                        updated_at = now(),
                        reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN 'cleared by false positive' ELSE ' | cleared by false positive' END
                    WHERE COALESCE(is_enabled, true) = true
                      AND (expires_at IS NULL OR expires_at > now())
                      AND {response_suppression_device_id_condition(cur, "device_id", "%s")}
                      AND incident_type IS NOT DISTINCT FROM %s
                      AND source_system IS NOT DISTINCT FROM %s
                """, (uuid_text(incident.get("device_id"), required=False), decode_hex_text(incident.get("incident_type")), decode_hex_text(incident.get("source_system"))))

            suppression_id = None
            cols = table_columns(cur, "response_suppressions")
            false_positive_reason = f"false positive: {reason}" if reason else "false positive"
            if cols:
                values = {
                    "device_id": uuid_text(incident.get("device_id"), required=False),
                    "incident_type": decode_hex_text(incident.get("incident_type")),
                    "source_system": decode_hex_text(incident.get("source_system")),
                    "reason": false_positive_reason,
                    "created_by": actor,
                    "is_enabled": True,
                    "created_at": utc_now(),
                    "updated_at": utc_now(),
                }
                if "expires_at" in cols:
                    values["expires_at"] = expires_at
                # Reuse an existing active false-positive suppression for the same device/type/source.
                cur.execute(
                    f"""
                    SELECT id::text AS id
                    FROM response_suppressions
                    WHERE COALESCE(is_enabled, true) = true
                      AND (expires_at IS NULL OR expires_at > now())
                      AND {response_suppression_device_id_condition(cur, "device_id", "%(device_id)s")}
                      AND incident_type IS NOT DISTINCT FROM %(incident_type)s
                      AND source_system IS NOT DISTINCT FROM %(source_system)s
                      AND COALESCE(reason, '') ILIKE '%%false positive%%'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    values,
                )
                existing = cur.fetchone()
                if existing:
                    suppression_id = uuid_text(existing.get("id"), required=False)
                else:
                    row = insert_row(cur, "response_suppressions", values, returning="id")
                    suppression_id = uuid_text(row.get("id"), required=False) if row else None
            rolled_back = rollback_active_actions_for_incident(cur, incident_id, actor, "false_positive")
            ignored_disabled = disable_response_ignores_for_incident(cur, incident, "ignore removed by false positive") if incident else []
            cur.execute("UPDATE incidents SET status='closed', closed_at=COALESCE(closed_at, now()), updated_at=now(), evidence_json = COALESCE(evidence_json, '{}'::jsonb) || %s::jsonb WHERE id=%s::uuid", (j({"false_positive": True, "false_positive_by": actor, "false_positive_reason": false_positive_reason, "false_positive_suppression_id": suppression_id}), incident_id))
            action_event(cur, None, incident_id, incident.get("device_id"), "incident_false_positive", actor, "Incident marked as false positive", {"reason": false_positive_reason, "suppression_id": suppression_id, "rolled_back_action_ids": rolled_back})
            sync_result = sync_aliases_and_rules(cur) if rolled_back else {"ok": True, "skipped": True}
            enforcer = trigger_policy_enforcer() if rolled_back else {"ok": True, "skipped": True}
        conn.commit()
    result = {"status": "ok", "incident_id": incident_id, "false_positive": True, "suppression_id": suppression_id, "disabled_ignore_ids": ignored_disabled, "rolled_back_action_ids": rolled_back, "sync": sync_result, "policy_enforcer": enforcer}
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def run_sync_only() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            sync_result = sync_aliases_and_rules(cur)
        conn.commit()
    result = {"status": "healthy" if sync_result.get("ok") else "degraded", "sync": sync_result}
    update_health(result["status"], result)
    print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="security-core Phase 6 response engine")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "sync-only", "simulate", "suggest", "apply", "apply-action", "rollback", "rollback-incident", "false-positive"])
    parser.add_argument("--incident-id", "--incident_id", dest="incident_id")
    parser.add_argument("--action-id", "--action_id", dest="action_id")
    # Backward-compatible flags used by the first Phase 6 API build.
    parser.add_argument("--simulate-incident", dest="simulate_incident_id")
    parser.add_argument("--suggest-incident", dest="suggest_incident_id")
    parser.add_argument("--apply-incident", dest="apply_incident_id")
    parser.add_argument("--rollback-action", dest="rollback_action_id")
    parser.add_argument("--false-positive-incident", dest="false_positive_incident_id")
    parser.add_argument("--rollback-incident", dest="rollback_incident_id")
    parser.add_argument("--action", dest="action")
    parser.add_argument("--actor", dest="actor", default="api")
    parser.add_argument("--reason", dest="reason", default=None)
    parser.add_argument("--ttl-minutes", "--ttl_minutes", dest="ttl_minutes", type=int, default=None)
    parser.add_argument("--ttl-hours", "--ttl_hours", dest="ttl_hours", type=int, default=None)
    args = parser.parse_known_args(argv)[0]
    if getattr(args, "simulate_incident_id", None):
        args.command = "simulate"
        args.incident_id = args.simulate_incident_id
    elif getattr(args, "suggest_incident_id", None):
        args.command = "suggest"
        args.incident_id = args.suggest_incident_id
    elif getattr(args, "apply_incident_id", None):
        args.command = "apply"
        args.incident_id = args.apply_incident_id
    elif getattr(args, "rollback_action_id", None):
        args.command = "rollback"
        args.action_id = args.rollback_action_id
    elif getattr(args, "rollback_incident_id", None):
        args.command = "rollback-incident"
        args.incident_id = args.rollback_incident_id
    elif getattr(args, "false_positive_incident_id", None):
        args.command = "false-positive"
        args.incident_id = args.false_positive_incident_id
    return args

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "run":
            run_worker()
        elif args.command == "sync-only":
            run_sync_only()
        elif args.command == "simulate":
            if not args.incident_id:
                raise RuntimeError("--incident-id is required")
            run_simulate(args.incident_id, args.action)
        elif args.command == "suggest":
            if not args.incident_id:
                raise RuntimeError("--incident-id is required")
            run_suggest(args.incident_id, args.action, args.actor, args.reason)
        elif args.command == "apply":
            if not args.incident_id:
                raise RuntimeError("--incident-id is required")
            run_apply_incident(args.incident_id, args.action, args.actor, args.reason, args.ttl_minutes)
        elif args.command == "apply-action":
            if not args.action_id:
                raise RuntimeError("--action-id is required")
            run_apply_action(args.action_id, args.actor, args.reason)
        elif args.command == "rollback":
            if not args.action_id:
                raise RuntimeError("--action-id is required")
            run_rollback(args.action_id, args.actor, args.reason)
        elif args.command == "rollback-incident":
            if not args.incident_id:
                raise RuntimeError("--incident-id is required")
            run_rollback_incident(args.incident_id, args.actor, args.reason)
        elif args.command == "false-positive":
            if not args.incident_id:
                raise RuntimeError("--incident-id is required")
            run_false_positive(args.incident_id, args.actor, args.reason, args.ttl_hours)
        return 0
    except Exception as exc:
        result = {"status": "failed", "error": str(exc)}
        update_health("failed", result)
        print(json.dumps(ascii_json_safe(result), indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
