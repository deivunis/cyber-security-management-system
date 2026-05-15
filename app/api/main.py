import datetime as dt
import json
import uuid
import os
import re
import hmac
import hashlib
import subprocess
from pathlib import Path as FilePath
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Path, Query, Security, Response
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse
from pydantic import BaseModel
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["SECURITY_CORE_API_KEY"]
LAN_CIDRS = [
    item.strip()
    for item in os.environ.get("SECURITY_CORE_LAN_CIDRS", "REDACTED").split(",")
    if item.strip()
]
DEFAULT_CATEGORY = "unknown"

BASE_DIR = FilePath(__file__).resolve().parent
CLASSIFICATION_RULES_CANDIDATES = [
    FilePath(os.environ.get("CLASSIFICATION_RULES_FILE", str(BASE_DIR / "classification_rules.json"))),
    BASE_DIR / "classification_rules.json",
    FilePath("/opt/security-core/config/classification_rules.json"),
    FilePath("/opt/security-core/app/worker/classification_rules.json"),
]
OUI_REGISTRY_CANDIDATES = [
    FilePath(os.environ.get("OUI_CACHE_FILE", str(BASE_DIR / "oui_registry.json"))),
    BASE_DIR / "oui_registry.json",
    FilePath("/opt/security-core/data/oui_registry.json"),
    FilePath("/opt/security-core/oui_registry.json"),
]

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=5,
    kwargs={"autocommit": True, "row_factory": dict_row},
)

app = FastAPI(title="security-core API", version="0.7.0", docs_url="/docs", redoc_url=None)

CORE_POLICY_TEMPLATE_NAMES = {
    'admin_device_policy',
    'camera_policy',
    'guest_device_policy',
    'media_device_policy',
    'sensor_lock_policy',
    'unknown_device_policy',
}


class ManualClassificationPayload(BaseModel):
    manual_vendor: str | None = None
    manual_model: str | None = None
    manual_category: str | None = None
    manual_firmware_version: str | None = None
    manual_hardware_version: str | None = None
    manual_serial_number: str | None = None


class IdentityConfirmationPayload(BaseModel):
    identity_confirmed: bool = True


class VulnerabilityMappingPayload(BaseModel):
    manual_cpe_23: str | None = None
    search_terms: list[str] | None = None
    notes: str | None = None


class PolicyAssignmentPayload(BaseModel):
    policy_name: str


class ACLByDevicePayload(BaseModel):
    by: str = "both"
    comment: str | None = None


class PolicyTemplateUpsertPayload(BaseModel):
    policy_name: str | None = None
    display_name: str | None = None
    description: str | None = None
    policy_scope: str = "device_category"
    is_enabled: bool = True
    access_mode: str = "normal"
    internet_allowed: bool = True
    dns_only: bool = False
    local_only: bool = False
    local_only_peers: str | list[str] | None = None
    geo_restrictions_enabled: bool = False
    geo_allowed_countries: str | list[str] | None = None
    quarantine_default: bool = False
    upnp_allowed: bool = True
    auto_assign_categories: str | list[str] | None = None

class IncidentStatusPayload(BaseModel):
    reason: str | None = None
    actor: str | None = "api"


class SecurityEventCreatePayload(BaseModel):
    source_system: str
    event_type: str
    severity: str = "low"
    title: str
    description: str | None = None
    device_id: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    country_code: str | None = None
    signature_id: str | None = None
    signature_name: str | None = None
    dedupe_key: str | None = None
    event_time: str | None = None
    raw_json: dict[str, Any] | None = None
    create_incident: bool = True



def require_api_key(authorization: str = Security(api_key_header)):
    expected = f"Bearer {API_KEY}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


def build_lan_filter(column_name: str = "current_ip"):
    if not LAN_CIDRS:
        return "TRUE", []
    parts = [f"{column_name} <<= %s::cidr" for _ in LAN_CIDRS]
    return "(" + " OR ".join(parts) + ")", LAN_CIDRS.copy()


def clean_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = to_text(value)
    return text or None


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return str(value).strip()
    return str(value).strip()


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


def normalize_uuid_text(value: Any) -> str:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="ignore")
    text = clean_optional_text(value)
    if not text:
        raise HTTPException(status_code=400, detail="Invalid device or policy UUID")
    try:
        return str(uuid.UUID(text))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid UUID") from exc


def normalize_ip_text(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    return text or None


def normalize_acl_match_value(match_type: str, value: Any) -> str | None:
    if match_type == "ip":
        return normalize_ip_text(value)
    if match_type == "mac":
        return normalize_mac(value)
    return clean_optional_text(value)


def parse_csv_list(values: Any) -> list[str]:
    result: list[str] = []
    if values is None:
        return result
    raw_values = values if isinstance(values, (list, tuple, set)) else [values]
    for raw in raw_values:
        text = clean_optional_text(raw)
        if not text:
            continue
        text = text.replace("\n", ",").replace(";", ",")
        parts = [part.strip() for part in text.split(',')]
        for part in parts:
            if part and part not in result:
                result.append(part)
    return result


def sanitize_policy_name(value: Any) -> str:
    text = clean_optional_text(value)
    if not text:
        raise HTTPException(status_code=400, detail="policy_name is required")
    text = text.lower().replace('-', '_').replace(' ', '_')
    text = re.sub(r'[^a-z0-9_]+', '', text)
    text = re.sub(r'_+', '_', text).strip('_')
    if not text:
        raise HTTPException(status_code=400, detail="Invalid policy_name")
    return text


def normalize_policy_scope(value: Any) -> str:
    text = clean_optional_text(value) or 'device_category'
    allowed = {'device_category', 'manual'}
    if text not in allowed:
        raise HTTPException(status_code=400, detail="policy_scope must be one of: device_category, manual")
    return text


def normalize_access_mode(value: Any) -> str:
    text = clean_optional_text(value) or 'normal'
    allowed = {'normal', 'dns_only', 'local_only', 'quarantine'}
    if text not in allowed:
        raise HTTPException(status_code=400, detail="access_mode must be one of: normal, dns_only, local_only, quarantine")
    return text

def bool_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = to_text(value).lower()
    return text in {"1", "true", "yes", "on"}


def derive_effective_mode(policy_json: dict[str, Any] | None) -> str:
    policy_json = dict(policy_json or {})
    requested_mode = normalize_access_mode(policy_json.get("access_mode") or "normal")
    if bool_flag(policy_json.get("quarantine_default")) or requested_mode == "quarantine":
        return "quarantine"
    if bool_flag(policy_json.get("local_only")) or requested_mode == "local_only":
        return "local_only"
    if bool_flag(policy_json.get("dns_only")) or requested_mode == "dns_only":
        return "dns_only"
    if policy_json and not bool_flag(policy_json.get("internet_allowed", True)):
        return "blocked_internet"
    return "normal"


def build_blacklist_policy_json() -> dict[str, Any]:
    return {
        "display_name": "Blacklist quarantine",
        "description": "ACL blacklist forces quarantine and full network isolation.",
        "access_mode": "quarantine",
        "internet_allowed": False,
        "dns_only": False,
        "local_only": False,
        "geo_restrictions_enabled": False,
        "geo_allowed_countries": [],
        "quarantine_default": True,
        "upnp_allowed": False,
        "local_only_peers": [],
        "auto_assign_categories": [],
    }


def build_whitelist_policy_json() -> dict[str, Any]:
    return {
        "display_name": "Whitelist override",
        "description": "ACL whitelist marks the device as trusted and eligible for explicit allow rules.",
        "access_mode": "normal",
        "internet_allowed": True,
        "dns_only": False,
        "local_only": False,
        "geo_restrictions_enabled": False,
        "geo_allowed_countries": [],
        "quarantine_default": False,
        "upnp_allowed": True,
        "local_only_peers": [],
        "auto_assign_categories": [],
    }


def fetch_policy_template_by_name(cur, policy_name: str) -> dict[str, Any]:
    cur.execute(
        """
        SELECT id::text AS id, policy_name, policy_scope, is_enabled, policy_json, created_at, updated_at
        FROM policy_templates
        WHERE policy_name = %s
        """,
        (policy_name,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy template not found")
    return dict(row)


def normalize_mac(value: Any) -> str | None:
    text = to_text(value).lower().replace("-", ":")
    parts = re.findall(r"[0-9a-f]{2}", text)
    if len(parts) == 6:
        return ":".join(parts)
    return None


def mac_to_hex(mac: Any) -> str | None:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    return "".join(ch for ch in normalized.upper() if ch in "0123456789ABCDEF")


def is_locally_administered_mac(mac: Any) -> bool:
    mac_hex = mac_to_hex(mac)
    if not mac_hex or len(mac_hex) < 2:
        return False
    return bool(int(mac_hex[:2], 16) & 0x02)


def load_json_from_candidates(candidates: list[FilePath], default: Any):
    for candidate in candidates:
        try:
            if candidate.exists():
                with candidate.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
        except Exception:
            continue
    return default


CLASSIFICATION_CONFIG = load_json_from_candidates(CLASSIFICATION_RULES_CANDIDATES, {})
OUI_REGISTRY_RAW = load_json_from_candidates(OUI_REGISTRY_CANDIDATES, {})
OUI_REGISTRY = {
    to_text(key).upper(): to_text(value)
    for key, value in (OUI_REGISTRY_RAW.items() if isinstance(OUI_REGISTRY_RAW, dict) else [])
    if to_text(key) and to_text(value)
}


def lookup_vendor_from_registry(mac: Any) -> tuple[str | None, str]:
    if is_locally_administered_mac(mac):
        return None, "private_mac"
    mac_hex = mac_to_hex(mac)
    if not mac_hex:
        return None, "unknown"
    for prefix_len in (9, 7, 6):
        vendor = OUI_REGISTRY.get(mac_hex[:prefix_len])
        if vendor:
            return vendor, "oui_registry"
    return None, "unknown"


def contains_any(text: str, values: list[str]) -> bool:
    if not values:
        return True
    return any(value.lower() in text for value in values)


def regex_any(text: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def ports_any(actual_ports: set[int], expected_ports: list[int]) -> bool:
    if not expected_ports:
        return True
    return any(int(port) in actual_ports for port in expected_ports)


def combined_identity_text(parts: list[Any]) -> str:
    return " ".join(to_text(part).lower() for part in parts if to_text(part)).strip()


def rule_matches(rule: dict[str, Any], context: dict[str, Any]) -> bool:
    checks = [
        contains_any(context["hostname"], rule.get("hostname_any") or []),
        regex_any(context["hostname"], rule.get("hostname_regex_any") or []),
        contains_any(context["vendor"], rule.get("vendor_any") or []),
        regex_any(context["vendor"], rule.get("vendor_regex_any") or []),
        contains_any(context["model"], rule.get("model_any") or []),
        regex_any(context["model"], rule.get("model_regex_any") or []),
        contains_any(context["identity"], rule.get("identity_any") or []),
        regex_any(context["identity"], rule.get("identity_regex_any") or []),
        ports_any(context["tcp_ports"], rule.get("tcp_ports_any") or []),
        ports_any(context["udp_ports"], rule.get("udp_ports_any") or []),
    ]
    if not all(checks):
        return False
    if rule.get("require_onvif") is True and not context["onvif_detected"]:
        return False
    allow_private_mac = rule.get("allow_private_mac")
    if allow_private_mac is True and not context["private_mac"]:
        return False
    if allow_private_mac is False and context["private_mac"]:
        return False
    return True


def classify_device(row: dict[str, Any], vendor_for_rules: Any = None, model_for_rules: Any = None) -> tuple[str, int, str]:
    current_ip = to_text(row.get("current_ip"))
    reserved = CLASSIFICATION_CONFIG.get("reserved_ip_categories") or {}
    if current_ip in reserved and isinstance(reserved[current_ip], dict):
        item = reserved[current_ip]
        return (
            to_text(item.get("category")) or DEFAULT_CATEGORY,
            int(item.get("confidence", 100) or 100),
            to_text(item.get("reason")) or "reserved_infra_ip",
        )

    context = {
        "hostname": to_text(row.get("hostname")).lower(),
        "vendor": to_text(vendor_for_rules if vendor_for_rules is not None else row.get("vendor")).lower(),
        "model": to_text(model_for_rules if model_for_rules is not None else row.get("model")).lower(),
        "identity": combined_identity_text(
            [
                row.get("hostname"),
                model_for_rules if model_for_rules is not None else row.get("model"),
                row.get("reverse_dns_name"),
                vendor_for_rules if vendor_for_rules is not None else row.get("vendor"),
            ]
        ),
        "tcp_ports": {int(port) for port in (row.get("open_tcp_ports") or []) if str(port).isdigit()},
        "udp_ports": {int(port) for port in (row.get("open_udp_ports") or []) if str(port).isdigit()},
        "private_mac": is_locally_administered_mac(row.get("mac_address")),
        "onvif_detected": bool(row.get("onvif_device_info") not in (None, {}, [])),
    }

    for rule in CLASSIFICATION_CONFIG.get("rules") or []:
        if isinstance(rule, dict) and rule_matches(rule, context):
            return (
                to_text(rule.get("category")) or DEFAULT_CATEGORY,
                int(rule.get("confidence", 85) or 85),
                to_text(rule.get("reason")) or "classification_rule",
            )

    default_item = CLASSIFICATION_CONFIG.get("default_category") or {}
    return (
        to_text(default_item.get("category")) or DEFAULT_CATEGORY,
        int(default_item.get("confidence", 0) or 0),
        to_text(default_item.get("reason")) or "no_match",
    )


def compute_effective_identity(row: dict[str, Any], payload: ManualClassificationPayload | None = None, clear_manual: bool = False) -> dict[str, Any]:
    auto_vendor, auto_vendor_source = lookup_vendor_from_registry(row.get("mac_address"))

    manual_vendor = None if clear_manual else clean_optional_text(payload.manual_vendor) if payload else clean_optional_text(row.get("manual_vendor"))
    manual_model = None if clear_manual else clean_optional_text(payload.manual_model) if payload else clean_optional_text(row.get("manual_model"))
    manual_category = None if clear_manual else clean_optional_text(payload.manual_category) if payload else clean_optional_text(row.get("manual_category"))
    manual_firmware = None if clear_manual else clean_optional_text(payload.manual_firmware_version) if payload else clean_optional_text(row.get("manual_firmware_version"))
    manual_hardware = None if clear_manual else clean_optional_text(payload.manual_hardware_version) if payload else clean_optional_text(row.get("manual_hardware_version"))
    manual_serial = None if clear_manual else clean_optional_text(payload.manual_serial_number) if payload else clean_optional_text(row.get("manual_serial_number"))

    vendor = manual_vendor or auto_vendor
    vendor_source = "manual" if manual_vendor else auto_vendor_source

    existing_model = None if to_text(row.get("model_source")) == "manual" and not manual_model else clean_optional_text(row.get("model"))
    existing_firmware = None if to_text(row.get("firmware_source")) == "manual" and not manual_firmware else clean_optional_text(row.get("firmware_version"))
    existing_hardware = None if to_text(row.get("hardware_source")) == "manual" and not manual_hardware else clean_optional_text(row.get("hardware_version"))
    existing_serial = None if to_text(row.get("serial_source")) == "manual" and not manual_serial else clean_optional_text(row.get("serial_number"))

    model = manual_model if manual_model is not None else existing_model
    firmware = manual_firmware if manual_firmware is not None else existing_firmware
    hardware = manual_hardware if manual_hardware is not None else existing_hardware
    serial = manual_serial if manual_serial is not None else existing_serial

    model_source = "manual" if manual_model else (to_text(row.get("model_source")) if existing_model else "unknown")
    firmware_source = "manual" if manual_firmware else (to_text(row.get("firmware_source")) if existing_firmware else "unknown")
    hardware_source = "manual" if manual_hardware else (to_text(row.get("hardware_source")) if existing_hardware else "unknown")
    serial_source = "manual" if manual_serial else (to_text(row.get("serial_source")) if existing_serial else "unknown")

    category, confidence, reason = classify_device(
        row,
        vendor_for_rules=vendor,
        model_for_rules=model,
    )
    category_source = "unknown" if category == DEFAULT_CATEGORY else "classification_rule"
    if manual_category:
        category = manual_category
        confidence = 100
        reason = "manual_override"
        category_source = "manual"

    return {
        "manual_vendor": manual_vendor,
        "manual_model": manual_model,
        "manual_category": manual_category,
        "manual_firmware_version": manual_firmware,
        "manual_hardware_version": manual_hardware,
        "manual_serial_number": manual_serial,
        "vendor": vendor,
        "model": model,
        "category": category,
        "firmware_version": firmware,
        "hardware_version": hardware,
        "serial_number": serial,
        "vendor_source": vendor_source or "unknown",
        "model_source": model_source or "unknown",
        "category_source": category_source or "unknown",
        "firmware_source": firmware_source or "unknown",
        "hardware_source": hardware_source or "unknown",
        "serial_source": serial_source or "unknown",
        "classification_confidence": int(confidence),
        "classification_reason": reason,
    }


DEVICE_LIST_FIELDS = """
    id::text AS id,
    device_key,
    mac_address,
    host(current_ip) AS current_ip,
    hostname,
    vendor,
    model,
    category,
    firmware_version,
    hardware_version,
    serial_number,
    vendor_source,
    model_source,
    category_source,
    firmware_source,
    hardware_source,
    serial_source,
    hostname_source,
    reverse_dns_name,
    classification_confidence,
    classification_reason,
    manual_vendor,
    manual_model,
    manual_category,
    manual_firmware_version,
    manual_hardware_version,
    manual_serial_number,
    identity_confirmed,
    identity_confirmed_at,
    status,
    is_online,
    risk_score,
    risk_level,
    active_policy,
    policy_source,
    policy_suggested,
    policy_suggested_source,
    policy_effective_mode,
    policy_last_applied_at,
    policy_effective_json,
    is_whitelisted,
    is_blacklisted,
    EXISTS (
        SELECT 1
        FROM access_control_lists acl
        WHERE acl.is_enabled IS TRUE
          AND acl.entry_type = 'whitelist'
          AND (
                (acl.match_type = 'ip' AND acl.match_value = host(devices.current_ip)) OR
                (acl.match_type = 'mac' AND lower(acl.match_value) = lower(COALESCE(devices.mac_address, '')))
          )
    ) AS acl_whitelisted,
    EXISTS (
        SELECT 1
        FROM access_control_lists acl
        WHERE acl.is_enabled IS TRUE
          AND acl.entry_type = 'blacklist'
          AND (
                (acl.match_type = 'ip' AND acl.match_value = host(devices.current_ip)) OR
                (acl.match_type = 'mac' AND lower(acl.match_value) = lower(COALESCE(devices.mac_address, '')))
          )
    ) AS acl_blacklisted,
    COALESCE((
        SELECT NULLIF(acl.comment, '')
        FROM access_control_lists acl
        WHERE acl.is_enabled IS TRUE
          AND (
                (acl.match_type = 'ip' AND acl.match_value = host(devices.current_ip)) OR
                (acl.match_type = 'mac' AND lower(acl.match_value) = lower(COALESCE(devices.mac_address, '')))
          )
        ORDER BY acl.updated_at DESC NULLS LAST, acl.created_at DESC NULLS LAST
        LIMIT 1
    ), '') AS acl_last_comment,
    COALESCE((
        SELECT dvo.manual_cpe_23
        FROM device_vulnerability_overrides dvo
        WHERE dvo.device_id = devices.id
        LIMIT 1
    ), '') AS vulnerability_manual_cpe_23,
    COALESCE((
        SELECT array_to_string(ARRAY(SELECT jsonb_array_elements_text(COALESCE(dvo.search_terms, '[]'::jsonb))), ', ')
        FROM device_vulnerability_overrides dvo
        WHERE dvo.device_id = devices.id
        LIMIT 1
    ), '') AS vulnerability_search_terms_text,
    COALESCE((
        SELECT dvo.notes
        FROM device_vulnerability_overrides dvo
        WHERE dvo.device_id = devices.id
        LIMIT 1
    ), '') AS vulnerability_mapping_notes,
    (
        SELECT dvo.updated_at
        FROM device_vulnerability_overrides dvo
        WHERE dvo.device_id = devices.id
        LIMIT 1
    ) AS vulnerability_mapping_updated_at,
    geo_restrictions_enabled,
    upnp_blocked,
    source_of_truth,
    discovery_sources,
    open_tcp_ports,
    open_udp_ports,
    vulnerability_count,
    kev_count,
    highest_cvss,
    highest_severity,
    vulnerability_recommendation,
    vulnerability_last_checked_at,
    vulnerability_summary_json,
    first_seen_at,
    last_seen_at,
    last_seen_dhcp_at,
    last_seen_arp_at,
    last_seen_scan_at,
    last_scan_at,
    last_offline_at,
    notes,
    created_at,
    updated_at
"""


def fetch_device_row(cur, device_id: str) -> dict[str, Any]:
    device_id = normalize_uuid_text(device_id)
    cur.execute(f"SELECT {DEVICE_LIST_FIELDS} FROM devices WHERE id = %s::uuid", (device_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    return dict(row)


def system_health_time_column(cur) -> str:
    """Return the deployed system_health timestamp column name.

    Different installed schema revisions use either check_at or last_check_at.
    The API must not fail startup just because one of them is absent.
    """
    try:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'system_health'
              AND column_name IN ('last_check_at', 'check_at', 'updated_at')
            """
        )
        columns = {row["column_name"] for row in cur.fetchall()}
        if "last_check_at" in columns:
            return "last_check_at"
        if "check_at" in columns:
            return "check_at"
        return "updated_at"
    except Exception:
        return "updated_at"


def mark_api_health(status: str):
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                time_col = system_health_time_column(cur)
                cur.execute(
                    f"""
                    UPDATE system_health
                    SET status = %s,
                        {time_col} = now(),
                        details_json = COALESCE(details_json, '{{}}'::jsonb) || jsonb_build_object('service', 'security-api')
                    WHERE component_name = 'security-api'
                    """,
                    (status,),
                )
    except Exception:
        # Health-row update must never prevent the API from starting/stopping.
        pass


@app.on_event("startup")
def startup():
    pool.open()
    mark_api_health('healthy')


@app.on_event("shutdown")
def shutdown():
    mark_api_health('stopped')
    pool.close()


@app.get("/health")
def health():
    """Lightweight API/DB health plus compact system_health component rows.

    This keeps the original unauthenticated health endpoint working for simple
    checks, but also exposes a small `components` list for Home Assistant.
    It supports both schema variants: `check_at` and `last_check_at`.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT now() AS db_time")
            row = cur.fetchone()
            components = []
            try:
                time_col = system_health_time_column(cur)
                cur.execute(
                    f"""
                    SELECT component_name,
                           component_type,
                           status,
                           {time_col} AS last_check_at,
                           {time_col} AS check_at,
                           version,
                           updated_at
                    FROM system_health
                    ORDER BY
                        CASE lower(COALESCE(status, ''))
                            WHEN 'critical' THEN 1
                            WHEN 'failed' THEN 2
                            WHEN 'error' THEN 3
                            WHEN 'degraded' THEN 4
                            WHEN 'warning' THEN 5
                            WHEN 'unknown' THEN 6
                            WHEN 'healthy' THEN 9
                            WHEN 'ok' THEN 9
                            ELSE 7
                        END,
                        component_name
                    LIMIT 200
                    """
                )
                components = cur.fetchall()
            except Exception:
                components = []
    ok_statuses = {"healthy", "ok"}
    bad_statuses = {"degraded", "warning", "failed", "critical", "error", "unhealthy", "unknown"}
    healthy_count = sum(1 for item in components if to_text(item.get("status")).lower() in ok_statuses)
    problem_count = sum(1 for item in components if to_text(item.get("status")).lower() in bad_statuses)
    return {
        "status": "ok",
        "database": "ok",
        "db_time": row["db_time"].isoformat(),
        "components": components,
        "component_total": len(components),
        "component_healthy": healthy_count,
        "component_problem": problem_count,
    }

@app.get("/api/v1/stats/devices")
def device_stats(_: None = Security(require_api_key)):
    lan_sql, lan_params = build_lan_filter("current_ip")
    sql = f"""
        SELECT
            COUNT(*)::int AS total_devices,
            COUNT(*) FILTER (WHERE is_online IS TRUE)::int AS online_devices,
            COUNT(*) FILTER (WHERE is_online IS FALSE)::int AS offline_devices,
            COUNT(*) FILTER (WHERE status = 'quarantined')::int AS quarantined_devices,
            COUNT(*) FILTER (WHERE status = 'blocked_internet')::int AS blocked_internet_devices,
            COUNT(*) FILTER (WHERE status = 'dns_only')::int AS dns_only_devices,
            COUNT(*) FILTER (WHERE category IS NULL OR category = '' OR category = '{DEFAULT_CATEGORY}')::int AS unknown_devices,
            COUNT(*) FILTER (WHERE COALESCE(identity_confirmed, FALSE) IS TRUE)::int AS confirmed_devices,
            COUNT(*) FILTER (WHERE COALESCE(identity_confirmed, FALSE) IS FALSE)::int AS unconfirmed_devices,
            COUNT(*) FILTER (WHERE COALESCE(vulnerability_count, 0) > 0)::int AS at_risk_devices,
            COUNT(*) FILTER (WHERE COALESCE(kev_count, 0) > 0)::int AS kev_devices,
            COUNT(*) FILTER (WHERE COALESCE(highest_severity, 'unknown') = 'critical' OR COALESCE(kev_count, 0) > 0)::int AS critical_risk_devices
        FROM devices
        WHERE {lan_sql}
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, lan_params)
            return cur.fetchone()


@app.get("/api/v1/devices")
@app.get("/api/v1/inventory")
def list_devices(
    status: str | None = Query(default=None),
    online: bool | None = Query(default=None),
    source: str | None = Query(default=None),
    confirmed: bool | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    clauses: list[str] = []
    params: list[Any] = []
    lan_sql, lan_params = build_lan_filter("current_ip")
    clauses.append(lan_sql)
    params.extend(lan_params)

    if status:
        clauses.append("status = %s")
        params.append(status)
    if online is not None:
        clauses.append("is_online = %s")
        params.append(online)
    if source:
        clauses.append("discovery_sources ? %s")
        params.append(source)
    if confirmed is not None:
        clauses.append("COALESCE(identity_confirmed, FALSE) = %s")
        params.append(confirmed)
    if q:
        wildcard = f"%{q}%"
        clauses.append(
            """
            (
                COALESCE(hostname, '') ILIKE %s OR
                COALESCE(vendor, '') ILIKE %s OR
                COALESCE(model, '') ILIKE %s OR
                COALESCE(category, '') ILIKE %s OR
                COALESCE(mac_address, '') ILIKE %s OR
                COALESCE(host(current_ip), '') ILIKE %s OR
                COALESCE(reverse_dns_name, '') ILIKE %s OR
                COALESCE(active_policy, '') ILIKE %s OR
                COALESCE(policy_effective_mode, '') ILIKE %s
            )
            """
        )
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard, wildcard, wildcard, wildcard, wildcard])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT {DEVICE_LIST_FIELDS}
        FROM devices
        {where_sql}
        ORDER BY is_online DESC, last_seen_at DESC NULLS LAST, hostname NULLS LAST, current_ip NULLS LAST
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT COUNT(*)::int AS total FROM devices {where_sql}"
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(count_sql, params)
            total = cur.fetchone()["total"]
            cur.execute(sql, params + [limit, offset])
            items = cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/devices/{device_id}")
@app.get("/api/v1/inventory/{device_id}")
def get_device_detail(
    device_id: str = Path(...),
    observations_limit: int = Query(default=20, ge=1, le=200),
    vulnerabilities_limit: int = Query(default=50, ge=1, le=200),
    _: None = Security(require_api_key),
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {DEVICE_LIST_FIELDS} FROM devices WHERE id = %s::uuid", (device_id,))
            device = cur.fetchone()
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            cur.execute(
                """
                SELECT
                    id,
                    host(observed_ip) AS observed_ip,
                    observed_hostname,
                    observed_mac_address,
                    observed_vendor,
                    observation_source,
                    observation_kind,
                    observed_at,
                    raw_json
                FROM device_observations
                WHERE device_id = %s::uuid
                ORDER BY observed_at DESC
                LIMIT %s
                """,
                (device_id, observations_limit),
            )
            observations = cur.fetchall()
            cur.execute(
                """
                SELECT
                    dvm.id::text AS id,
                    dvm.cve_id,
                    dvm.match_source,
                    dvm.match_confidence,
                    dvm.matched_vendor,
                    dvm.matched_model,
                    dvm.matched_version,
                    dvm.manual_cpe_override,
                    dvm.recommended_action,
                    dvm.is_kev,
                    dvm.cvss_base_score,
                    dvm.cvss_severity,
                    dvm.match_status,
                    dvm.evidence_json,
                    dvm.first_seen_at,
                    dvm.last_seen_at,
                    cc.description,
                    cc.published_at,
                    cc.last_modified_at,
                    cc.references_json,
                    cc.vendor_project,
                    cc.product_name
                FROM device_vulnerability_matches dvm
                LEFT JOIN cve_catalog cc ON cc.cve_id = dvm.cve_id
                WHERE dvm.device_id = %s::uuid
                  AND dvm.match_status = 'open'
                ORDER BY dvm.is_kev DESC, dvm.cvss_base_score DESC NULLS LAST, dvm.cve_id
                LIMIT %s
                """,
                (device_id, vulnerabilities_limit),
            )
            vulnerabilities = cur.fetchall()
            cur.execute(
                """
                SELECT
                    device_id::text AS device_id,
                    manual_cpe_23,
                    search_terms,
                    notes,
                    updated_by,
                    created_at,
                    updated_at
                FROM device_vulnerability_overrides
                WHERE device_id = %s::uuid
                """,
                (device_id,),
            )
            mapping = cur.fetchone()
    return {"item": device, "observations": observations, "vulnerabilities": vulnerabilities, "vulnerability_mapping": mapping}


@app.post("/api/v1/devices/{device_id}/manual-classification")
def set_manual_classification(payload: ManualClassificationPayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            current_row = fetch_device_row(cur, device_id)
            computed = compute_effective_identity(current_row, payload=payload, clear_manual=False)
            cur.execute(
                """
                UPDATE devices
                SET
                    manual_vendor = %s,
                    manual_model = %s,
                    manual_category = %s,
                    manual_firmware_version = %s,
                    manual_hardware_version = %s,
                    manual_serial_number = %s,
                    vendor = %s,
                    model = %s,
                    category = %s,
                    firmware_version = %s,
                    hardware_version = %s,
                    serial_number = %s,
                    vendor_source = %s,
                    model_source = %s,
                    category_source = %s,
                    firmware_source = %s,
                    hardware_source = %s,
                    serial_source = %s,
                    classification_confidence = %s,
                    classification_reason = %s,
                    identity_confirmed = TRUE,
                    identity_confirmed_at = now(),
                    updated_at = now()
                WHERE id = %s::uuid
                RETURNING id::text AS id
                """,
                (
                    computed["manual_vendor"],
                    computed["manual_model"],
                    computed["manual_category"],
                    computed["manual_firmware_version"],
                    computed["manual_hardware_version"],
                    computed["manual_serial_number"],
                    computed["vendor"],
                    computed["model"],
                    computed["category"],
                    computed["firmware_version"],
                    computed["hardware_version"],
                    computed["serial_number"],
                    computed["vendor_source"],
                    computed["model_source"],
                    computed["category_source"],
                    computed["firmware_source"],
                    computed["hardware_source"],
                    computed["serial_source"],
                    computed["classification_confidence"],
                    computed["classification_reason"],
                    device_id,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
    return {"status": "ok", "device_id": row["id"]}


@app.post("/api/v1/devices/{device_id}/manual-classification/clear")
def clear_manual_classification(device_id: str = Path(...), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            current_row = fetch_device_row(cur, device_id)
            computed = compute_effective_identity(current_row, payload=None, clear_manual=True)
            cur.execute(
                """
                UPDATE devices
                SET
                    manual_vendor = NULL,
                    manual_model = NULL,
                    manual_category = NULL,
                    manual_firmware_version = NULL,
                    manual_hardware_version = NULL,
                    manual_serial_number = NULL,
                    vendor = %s,
                    model = %s,
                    category = %s,
                    firmware_version = %s,
                    hardware_version = %s,
                    serial_number = %s,
                    vendor_source = %s,
                    model_source = %s,
                    category_source = %s,
                    firmware_source = %s,
                    hardware_source = %s,
                    serial_source = %s,
                    classification_confidence = %s,
                    classification_reason = %s,
                    identity_confirmed = FALSE,
                    identity_confirmed_at = NULL,
                    updated_at = now()
                WHERE id = %s::uuid
                RETURNING id::text AS id
                """,
                (
                    computed["vendor"],
                    computed["model"],
                    computed["category"],
                    computed["firmware_version"],
                    computed["hardware_version"],
                    computed["serial_number"],
                    computed["vendor_source"],
                    computed["model_source"],
                    computed["category_source"],
                    computed["firmware_source"],
                    computed["hardware_source"],
                    computed["serial_source"],
                    computed["classification_confidence"],
                    computed["classification_reason"],
                    device_id,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
    return {"status": "ok", "device_id": row["id"]}


@app.post("/api/v1/devices/{device_id}/identity-confirmation")
def set_identity_confirmation(payload: IdentityConfirmationPayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    confirmed = bool(payload.identity_confirmed)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE devices
                SET identity_confirmed = %s,
                    identity_confirmed_at = CASE WHEN %s THEN now() ELSE NULL END,
                    updated_at = now()
                WHERE id = %s::uuid
                RETURNING id::text AS id
                """,
                (confirmed, confirmed, device_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
    return {"status": "ok", "device_id": row["id"], "identity_confirmed": confirmed}


@app.post("/api/v1/devices/{device_id}/vulnerability-mapping")
def set_vulnerability_mapping(payload: VulnerabilityMappingPayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    manual_cpe_23 = clean_optional_text(payload.manual_cpe_23)
    search_terms = [clean_optional_text(item) for item in (payload.search_terms or [])]
    search_terms = [item for item in search_terms if item]
    notes = clean_optional_text(payload.notes)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            fetch_device_row(cur, device_id)
            cur.execute(
                """
                INSERT INTO device_vulnerability_overrides (
                    device_id, manual_cpe_23, search_terms, notes, updated_by, updated_at
                )
                VALUES (%s::uuid, %s, %s, %s, 'api', now())
                ON CONFLICT (device_id) DO UPDATE
                SET manual_cpe_23 = EXCLUDED.manual_cpe_23,
                    search_terms = EXCLUDED.search_terms,
                    notes = EXCLUDED.notes,
                    updated_by = 'api',
                    updated_at = now()
                RETURNING device_id::text AS device_id
                """,
                (device_id, manual_cpe_23, j(search_terms), notes),
            )
            row = cur.fetchone()
    return {"status": "ok", "device_id": row["device_id"]}


@app.post("/api/v1/devices/{device_id}/vulnerability-mapping/clear")
def clear_vulnerability_mapping(device_id: str = Path(...), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            fetch_device_row(cur, device_id)
            cur.execute("DELETE FROM device_vulnerability_overrides WHERE device_id = %s::uuid", (device_id,))
    return {"status": "ok", "device_id": device_id}


@app.get("/api/v1/stats/vulnerabilities")
def vulnerability_stats(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)::int AS open_matches,
                    COUNT(*) FILTER (WHERE is_kev IS TRUE)::int AS kev_matches,
                    COUNT(DISTINCT device_id)::int AS affected_devices,
                    COUNT(DISTINCT device_id) FILTER (WHERE is_kev IS TRUE)::int AS kev_devices,
                    MAX(cvss_base_score) AS highest_cvss
                FROM device_vulnerability_matches
                WHERE match_status = 'open'
                """
            )
            row = cur.fetchone() or {}
    return row





def load_enabled_policy_templates_map(cur) -> dict[str, dict[str, Any]]:
    cur.execute(
        """
        SELECT policy_name, policy_json
        FROM policy_templates
        WHERE is_enabled IS TRUE
        ORDER BY policy_name
        """
    )
    rows = cur.fetchall() or []
    return {to_text(row.get("policy_name")): dict(row.get("policy_json") or {}) for row in rows if to_text(row.get("policy_name"))}


def load_active_manual_assignment_for_device(cur, device_id: str) -> dict[str, Any] | None:
    cur.execute(
        """
        SELECT pt.policy_name, pt.policy_json, dpa.assigned_by, dpa.assigned_at
        FROM device_policy_assignments dpa
        JOIN policy_templates pt ON pt.id = dpa.policy_id
        WHERE dpa.device_id = %s::uuid
          AND dpa.is_active IS TRUE
          AND pt.is_enabled IS TRUE
        ORDER BY dpa.assigned_at DESC
        LIMIT 1
        """,
        (device_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def load_acl_sets(cur) -> dict[str, set[str]]:
    cur.execute(
        """
        SELECT entry_type, match_type, lower(match_value) AS match_value
        FROM access_control_lists
        WHERE is_enabled IS TRUE
        """
    )
    result = {
        "whitelist_ip": set(),
        "whitelist_mac": set(),
        "blacklist_ip": set(),
        "blacklist_mac": set(),
    }
    for row in cur.fetchall() or []:
        entry_type = to_text(row.get("entry_type")).lower()
        match_type = to_text(row.get("match_type")).lower()
        match_value = to_text(row.get("match_value")).lower()
        key = f"{entry_type}_{match_type}"
        if key in result and match_value:
            result[key].add(match_value)
    return result


def choose_auto_policy_name(category: Any, templates: dict[str, dict[str, Any]]) -> str | None:
    category_text = to_text(category).lower()
    for policy_name, policy_json in templates.items():
        auto_categories = [to_text(x).lower() for x in (policy_json.get("auto_assign_categories") or [])]
        if category_text and category_text in auto_categories:
            return policy_name
    if "unknown_device_policy" in templates:
        return "unknown_device_policy"
    return None


def build_immediate_policy_state(cur, device: dict[str, Any]) -> dict[str, Any]:
    device_id = normalize_uuid_text(device.get("id"))
    templates = load_enabled_policy_templates_map(cur)
    manual = load_active_manual_assignment_for_device(cur, device_id)
    acls = load_acl_sets(cur)

    ip_value = to_text(normalize_ip_text(device.get("current_ip")) or "").lower()
    mac_value = to_text(normalize_mac(device.get("mac_address")) or "").lower()
    is_whitelisted = bool((ip_value and ip_value in acls["whitelist_ip"]) or (mac_value and mac_value in acls["whitelist_mac"]))
    is_blacklisted = bool((ip_value and ip_value in acls["blacklist_ip"]) or (mac_value and mac_value in acls["blacklist_mac"]))

    suggested_name = choose_auto_policy_name(device.get("category"), templates)
    suggested_source = "category" if suggested_name else None

    active_name = None
    policy_source = "none"
    policy_json: dict[str, Any] = {}

    if manual:
        active_name = to_text(manual.get("policy_name")) or None
        policy_source = "manual" if active_name else "none"
        policy_json = dict(manual.get("policy_json") or {})

    if is_whitelisted and not is_blacklisted:
        active_name = "whitelist_override"
        policy_source = "acl_whitelist"
        policy_json = build_whitelist_policy_json()

    if is_blacklisted:
        active_name = "blacklist_quarantine"
        policy_source = "acl_blacklist"
        policy_json = build_blacklist_policy_json()

    requested_mode = normalize_access_mode(policy_json.get("access_mode") or "normal") if active_name else "normal"
    effective_mode = derive_effective_mode(policy_json) if active_name else "normal"
    geo_enabled = bool_flag(policy_json.get("geo_restrictions_enabled", False)) if active_name else False
    upnp_allowed = bool_flag(policy_json.get("upnp_allowed", True)) if active_name else True
    local_only_peers = policy_json.get("local_only_peers") or []
    geo_allowed_countries = [to_text(item).upper() for item in (policy_json.get("geo_allowed_countries") or []) if to_text(item)]

    effective_json = {
        "policy_name": active_name,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "source": policy_source,
        "is_whitelisted": is_whitelisted,
        "is_blacklisted": is_blacklisted,
        "internet_allowed": bool_flag(policy_json.get("internet_allowed", effective_mode == "normal")) if active_name else True,
        "dns_only": effective_mode == "dns_only",
        "local_only": effective_mode == "local_only",
        "blocked_internet": effective_mode == "blocked_internet",
        "quarantine": effective_mode == "quarantine",
        "geo_restrictions_enabled": geo_enabled,
        "geo_allowed_countries": geo_allowed_countries,
        "upnp_allowed": upnp_allowed,
        "upnp_blocked": not upnp_allowed,
        "local_only_peers": local_only_peers,
        "description": to_text(policy_json.get("description")),
    }

    return {
        "active_policy": active_name,
        "policy_source": policy_source,
        "policy_suggested": suggested_name,
        "policy_suggested_source": suggested_source,
        "policy_effective_mode": effective_mode,
        "policy_effective_json": effective_json,
        "is_whitelisted": is_whitelisted,
        "is_blacklisted": is_blacklisted,
        "geo_restrictions_enabled": geo_enabled,
        "upnp_blocked": not upnp_allowed,
    }


def apply_immediate_policy_state(cur, device_id: str) -> dict[str, Any]:
    device_id = normalize_uuid_text(device_id)
    device = fetch_device_row(cur, device_id)
    state = build_immediate_policy_state(cur, device)
    cur.execute(
        """
        UPDATE devices
        SET active_policy = %s,
            policy_source = %s,
            policy_suggested = %s,
            policy_suggested_source = %s,
            policy_effective_mode = %s,
            policy_last_applied_at = now(),
            policy_effective_json = %s,
            is_whitelisted = %s,
            is_blacklisted = %s,
            geo_restrictions_enabled = %s,
            upnp_blocked = %s,
            updated_at = now()
        WHERE id = %s::uuid
        RETURNING id::text AS id
        """,
        (
            state.get("active_policy"),
            state.get("policy_source") or "none",
            state.get("policy_suggested"),
            state.get("policy_suggested_source"),
            state.get("policy_effective_mode") or "normal",
            j(state.get("policy_effective_json") or {}),
            bool(state.get("is_whitelisted")),
            bool(state.get("is_blacklisted")),
            bool(state.get("geo_restrictions_enabled")),
            bool(state.get("upnp_blocked")),
            device_id,
        ),
    )
    row = cur.fetchone()
    return {**state, "device_id": row["id"] if row else device_id}




def trigger_policy_enforcer_now() -> dict[str, Any]:
    cmd = [
        os.environ.get("PYTHON_BIN", "/opt/security-core/venv/bin/python"),
        os.environ.get("POLICY_ENFORCER_SCRIPT", "/opt/security-core/app/worker/policy_enforcer.py"),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("POLICY_ENFORCER_TIMEOUT_SECONDS", "45")),
            check=False,
            env=os.environ.copy(),
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "").strip()[-1000:],
            "stderr": (proc.stderr or "").strip()[-1000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": ((exc.stdout or "") if isinstance(exc.stdout, str) else ""),
            "stderr": ((exc.stderr or "") if isinstance(exc.stderr, str) else ""),
            "timeout": True,
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "stderr": str(exc),
        }


def apply_immediate_policy_and_sync(device_id: str) -> dict[str, Any]:
    device_id = normalize_uuid_text(device_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            state = apply_immediate_policy_state(cur, device_id)
    enforcer = trigger_policy_enforcer_now()
    return {**state, "enforcer": enforcer}


def recompute_all_device_policy_state(cur) -> int:
    lan_sql, lan_params = build_lan_filter("current_ip")
    cur.execute(
        f"""
        SELECT id::text AS id
        FROM devices
        WHERE {lan_sql}
        ORDER BY id
        """,
        lan_params,
    )
    device_ids = [to_text(row.get("id")) for row in (cur.fetchall() or []) if to_text(row.get("id"))]
    for device_id in device_ids:
        apply_immediate_policy_state(cur, device_id)
    return len(device_ids)

@app.get("/api/v1/policies")
def list_policy_templates(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, policy_name, policy_scope, is_enabled, policy_json, created_at, updated_at
                FROM policy_templates
                ORDER BY policy_name
                """
            )
            return {"items": cur.fetchall()}


@app.post("/api/v1/policies")
def upsert_policy_template(payload: PolicyTemplateUpsertPayload, _: None = Security(require_api_key)):
    policy_name = sanitize_policy_name(payload.policy_name or payload.display_name)
    display_name = clean_optional_text(payload.display_name) or policy_name.replace('_', ' ').title()
    description = clean_optional_text(payload.description) or f"Custom policy {display_name}."
    policy_scope = normalize_policy_scope(payload.policy_scope)
    access_mode = normalize_access_mode(payload.access_mode)
    local_only_peers = parse_csv_list(payload.local_only_peers)
    geo_allowed_countries = [item.upper() for item in parse_csv_list(payload.geo_allowed_countries)]
    auto_assign_categories = [item.lower() for item in parse_csv_list(payload.auto_assign_categories)]
    policy_json = {
        "display_name": display_name,
        "description": description,
        "access_mode": access_mode,
        "internet_allowed": bool(payload.internet_allowed),
        "dns_only": bool(payload.dns_only),
        "local_only": bool(payload.local_only),
        "local_only_peers": local_only_peers,
        "geo_restrictions_enabled": bool(payload.geo_restrictions_enabled),
        "geo_allowed_countries": geo_allowed_countries,
        "quarantine_default": bool(payload.quarantine_default),
        "upnp_allowed": bool(payload.upnp_allowed),
        "auto_assign_categories": auto_assign_categories,
    }
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id
                FROM policy_templates
                WHERE policy_name = %s
                """,
                (policy_name,),
            )
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    UPDATE policy_templates
                    SET policy_scope = %s,
                        is_enabled = %s,
                        policy_json = %s,
                        updated_at = now()
                    WHERE policy_name = %s
                    RETURNING id::text AS id, policy_name, policy_scope, is_enabled, policy_json, created_at, updated_at
                    """,
                    (policy_scope, bool(payload.is_enabled), j(policy_json), policy_name),
                )
                row = cur.fetchone()
                action = 'updated'
            else:
                cur.execute(
                    """
                    INSERT INTO policy_templates (policy_name, policy_scope, is_enabled, policy_json, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, now(), now())
                    RETURNING id::text AS id, policy_name, policy_scope, is_enabled, policy_json, created_at, updated_at
                    """,
                    (policy_name, policy_scope, bool(payload.is_enabled), j(policy_json)),
                )
                row = cur.fetchone()
                action = 'created'
            recomputed_devices = recompute_all_device_policy_state(cur)
    enforcer = trigger_policy_enforcer_now()
    return {"status": "ok", "action": action, "item": row, "recomputed_devices": recomputed_devices, "enforcer": enforcer}




@app.delete("/api/v1/policies/{policy_name}")
def delete_policy_template(policy_name: str = Path(...), _: None = Security(require_api_key)):
    normalized_policy_name = sanitize_policy_name(policy_name)
    if normalized_policy_name in CORE_POLICY_TEMPLATE_NAMES:
        raise HTTPException(status_code=400, detail="Built-in policy templates cannot be deleted")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            policy = fetch_policy_template_by_name(cur, normalized_policy_name)
            policy_id = normalize_uuid_text(policy.get("id"))

            cur.execute("SELECT id::text AS id FROM devices ORDER BY id")
            device_ids = [to_text(row.get("id")) for row in (cur.fetchall() or []) if to_text(row.get("id"))]

            cur.execute(
                "UPDATE device_policy_assignments SET is_active = FALSE WHERE policy_id = %s::uuid",
                (policy_id,),
            )
            affected_assignments = cur.rowcount

            cur.execute(
                """
                UPDATE devices
                SET active_policy = NULL,
                    policy_source = 'none',
                    updated_at = now()
                WHERE active_policy = %s
                """,
                (normalized_policy_name,),
            )
            affected_devices = cur.rowcount

            cur.execute(
                "DELETE FROM policy_templates WHERE id = %s::uuid RETURNING id::text AS id",
                (policy_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Policy template not found")

            for device_id in device_ids:
                apply_immediate_policy_state(cur, device_id)

    enforcer = trigger_policy_enforcer_now()
    return {
        "status": "ok",
        "policy_name": normalized_policy_name,
        "deleted_policy_id": row["id"],
        "affected_assignments": affected_assignments,
        "affected_devices": affected_devices,
        "enforcer": enforcer,
    }

@app.get("/api/v1/stats/policies")
def policy_stats(_: None = Security(require_api_key)):
    result = {
        "total_policies": 0,
        "manual_assigned_devices": 0,
        "auto_assigned_devices": 0,
        "whitelisted_devices": 0,
        "blacklisted_devices": 0,
        "local_only_devices": 0,
        "geo_restricted_devices": 0,
        "upnp_blocked_devices": 0,
    }
    lan_sql, lan_params = build_lan_filter("current_ip")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT COUNT(*)::int AS value FROM policy_templates WHERE is_enabled IS TRUE")
                result["total_policies"] = int((cur.fetchone() or {}).get("value", 0))
            except Exception:
                pass

            device_queries = {
                "manual_assigned_devices": "COUNT(*)::int AS value FROM devices WHERE {where} AND COALESCE(policy_source, '') LIKE 'manual%'",
                "auto_assigned_devices": "COUNT(*)::int AS value FROM devices WHERE {where} AND COALESCE(policy_suggested, '') <> ''",
                "local_only_devices": "COUNT(*)::int AS value FROM devices WHERE {where} AND COALESCE(policy_effective_mode, 'normal') = 'local_only'",
                "geo_restricted_devices": "COUNT(*)::int AS value FROM devices WHERE {where} AND COALESCE(geo_restrictions_enabled, FALSE) IS TRUE",
                "upnp_blocked_devices": "COUNT(*)::int AS value FROM devices WHERE {where} AND COALESCE(upnp_blocked, FALSE) IS TRUE",
            }

            for key, fragment in device_queries.items():
                try:
                    cur.execute(f"SELECT {fragment.format(where=lan_sql)}", lan_params)
                    result[key] = int((cur.fetchone() or {}).get("value", 0))
                except Exception:
                    try:
                        cur.execute(f"SELECT {fragment.format(where='current_ip IS NOT NULL')}")
                        result[key] = int((cur.fetchone() or {}).get("value", 0))
                    except Exception:
                        result[key] = 0

            acl_join_sql = f"""
                SELECT COUNT(DISTINCT d.id)::int AS value
                FROM devices d
                JOIN access_control_lists acl
                  ON acl.is_enabled IS TRUE
                 AND acl.entry_type = %s
                 AND (
                      (acl.match_type = 'ip' AND acl.match_value = host(d.current_ip)) OR
                      (acl.match_type = 'mac' AND lower(acl.match_value) = lower(COALESCE(d.mac_address, '')))
                 )
                WHERE {lan_sql}
            """
            try:
                cur.execute(acl_join_sql, ['whitelist'] + lan_params)
                result["whitelisted_devices"] = int((cur.fetchone() or {}).get("value", 0))
            except Exception:
                result["whitelisted_devices"] = 0
            try:
                cur.execute(acl_join_sql, ['blacklist'] + lan_params)
                result["blacklisted_devices"] = int((cur.fetchone() or {}).get("value", 0))
            except Exception:
                result["blacklisted_devices"] = 0

    return result



@app.get("/api/v1/access-control-lists")
def list_access_control_lists(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, entry_type, match_type, match_value, comment, is_enabled, created_by, created_at, updated_at
                FROM access_control_lists
                ORDER BY entry_type, match_type, match_value
                """
            )
            return {"items": cur.fetchall()}


@app.post("/api/v1/devices/{device_id}/policy-assignment")
def assign_policy_template(payload: PolicyAssignmentPayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    policy_name = clean_optional_text(payload.policy_name)
    if not policy_name:
        raise HTTPException(status_code=400, detail="policy_name is required")
    device_id = normalize_uuid_text(device_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            fetch_device_row(cur, device_id)
            policy = fetch_policy_template_by_name(cur, policy_name)
            policy_id = normalize_uuid_text(policy.get("id"))
            if not policy.get("is_enabled", True):
                raise HTTPException(status_code=400, detail="Policy template is disabled")
            cur.execute(
                "UPDATE device_policy_assignments SET is_active = FALSE WHERE device_id = %s::uuid",
                (device_id,),
            )
            cur.execute(
                """
                INSERT INTO device_policy_assignments (device_id, policy_id, assigned_by, assigned_at, is_active)
                VALUES (%s::uuid, %s::uuid, 'manual_api', now(), TRUE)
                ON CONFLICT (device_id, policy_id)
                DO UPDATE SET assigned_by = 'manual_api', assigned_at = now(), is_active = TRUE
                RETURNING id::text AS id
                """,
                (device_id, policy_id),
            )
            cur.execute(
                """
                UPDATE devices
                SET active_policy = %s,
                    policy_source = 'manual_requested',
                    updated_at = now()
                WHERE id = %s::uuid
                RETURNING id::text AS id
                """,
                (policy_name, device_id),
            )
            row = cur.fetchone()
    result = apply_immediate_policy_and_sync(device_id)
    return {"status": "ok", "device_id": row["id"], "policy_name": policy_name, "enforcer": result.get("enforcer")}


@app.post("/api/v1/devices/{device_id}/policy-assignment/clear")
def clear_policy_assignment(device_id: str = Path(...), _: None = Security(require_api_key)):
    device_id = normalize_uuid_text(device_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            fetch_device_row(cur, device_id)
            cur.execute(
                "UPDATE device_policy_assignments SET is_active = FALSE WHERE device_id = %s::uuid",
                (device_id,),
            )
            cur.execute(
                """
                UPDATE devices
                SET active_policy = NULL,
                    policy_source = 'none',
                    updated_at = now()
                WHERE id = %s::uuid
                RETURNING id::text AS id
                """,
                (device_id,),
            )
            row = cur.fetchone()
    result = apply_immediate_policy_and_sync(device_id)
    return {"status": "ok", "device_id": row["id"], "enforcer": result.get("enforcer")}


@app.post("/api/v1/devices/{device_id}/access-list/whitelist")
def add_device_to_whitelist(payload: ACLByDevicePayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    return _upsert_device_acl(device_id, 'whitelist', payload)


@app.post("/api/v1/devices/{device_id}/access-list/blacklist")
def add_device_to_blacklist(payload: ACLByDevicePayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    return _upsert_device_acl(device_id, 'blacklist', payload)


@app.post("/api/v1/devices/{device_id}/access-list/clear")
def clear_device_acl(payload: ACLByDevicePayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    by = (clean_optional_text(payload.by) or 'both').lower()
    if by not in {'both', 'ip', 'mac'}:
        raise HTTPException(status_code=400, detail="by must be one of: both, ip, mac")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            device = fetch_device_row(cur, device_id)
            ip_value = normalize_ip_text(device.get('current_ip'))
            mac_value = normalize_mac(device.get('mac_address'))
            deleted = 0
            if by in {'both', 'ip'} and ip_value:
                cur.execute(
                    "DELETE FROM access_control_lists WHERE match_type = 'ip' AND match_value = %s",
                    (ip_value,),
                )
                deleted += cur.rowcount
            if by in {'both', 'mac'} and mac_value:
                cur.execute(
                    "DELETE FROM access_control_lists WHERE match_type = 'mac' AND lower(match_value) = %s",
                    (mac_value,),
                )
                deleted += cur.rowcount
    result = apply_immediate_policy_and_sync(device_id)
    return {"status": "ok", "device_id": device_id, "deleted": deleted, "enforcer": result.get("enforcer")}


def _upsert_device_acl(device_id: str, entry_type: str, payload: ACLByDevicePayload):
    device_id = normalize_uuid_text(device_id)
    by = (clean_optional_text(payload.by) or 'both').lower()
    if by not in {'both', 'ip', 'mac'}:
        raise HTTPException(status_code=400, detail="by must be one of: both, ip, mac")
    comment = clean_optional_text(payload.comment)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            device = fetch_device_row(cur, device_id)
            ip_value = normalize_ip_text(device.get('current_ip'))
            mac_value = normalize_mac(device.get('mac_address'))
            applied: list[dict[str, Any]] = []
            if by in {'both', 'ip'} and ip_value:
                cur.execute(
                    """
                    INSERT INTO access_control_lists (entry_type, match_type, match_value, comment, is_enabled, created_by, updated_at)
                    VALUES (%s, 'ip', %s, %s, TRUE, 'api', now())
                    ON CONFLICT (entry_type, match_type, match_value)
                    DO UPDATE SET comment = EXCLUDED.comment, is_enabled = TRUE, updated_at = now()
                    RETURNING id::text AS id
                    """,
                    (entry_type, ip_value, comment),
                )
                applied.append({"match_type": "ip", "match_value": ip_value, "id": cur.fetchone()["id"]})
            if by in {'both', 'mac'} and mac_value:
                cur.execute(
                    """
                    INSERT INTO access_control_lists (entry_type, match_type, match_value, comment, is_enabled, created_by, updated_at)
                    VALUES (%s, 'mac', %s, %s, TRUE, 'api', now())
                    ON CONFLICT (entry_type, match_type, match_value)
                    DO UPDATE SET comment = EXCLUDED.comment, is_enabled = TRUE, updated_at = now()
                    RETURNING id::text AS id
                    """,
                    (entry_type, mac_value, comment),
                )
                applied.append({"match_type": "mac", "match_value": mac_value, "id": cur.fetchone()["id"]})
            if not applied:
                raise HTTPException(status_code=400, detail="Selected device does not have the requested IP/MAC data")
    result = apply_immediate_policy_and_sync(device_id)
    return {"status": "ok", "device_id": device_id, "entry_type": entry_type, "items": applied, "enforcer": result.get("enforcer")}



SECURITY_CORE_OPEN_INCIDENT_STATUSES = {"open", "acknowledged", "in_progress"}
SECURITY_CORE_INCIDENT_STATUSES = SECURITY_CORE_OPEN_INCIDENT_STATUSES | {"closed", "resolved", "ignored"}
SECURITY_CORE_SEVERITIES = {"info", "low", "medium", "high", "critical"}
SECURITY_CORE_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_security_severity(value: Any) -> str:
    text = to_text(value).lower()
    if text in SECURITY_CORE_SEVERITIES:
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


def normalize_incident_status(value: Any) -> str:
    text = to_text(value).lower()
    if text in SECURITY_CORE_INCIDENT_STATUSES:
        return text
    raise HTTPException(status_code=400, detail="Invalid incident status")


def normalize_event_type(value: Any) -> str:
    text = clean_optional_text(value)
    if not text:
        raise HTTPException(status_code=400, detail="event_type is required")
    text = text.lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "", text)
    text = re.sub(r"_+", "_", text).strip("_")
    if not text:
        raise HTTPException(status_code=400, detail="Invalid event_type")
    return text


def security_event_dedupe_key(source_system: Any, event_type: Any, device_id: Any, src_ip: Any, dest_ip: Any, domain: Any, signature_id: Any, title: Any) -> str:
    parts = [
        to_text(source_system).lower(),
        normalize_event_type(event_type),
        to_text(device_id) or "-",
        normalize_ip_text(src_ip) or "-",
        normalize_ip_text(dest_ip) or "-",
        to_text(domain).lower() or "-",
        to_text(signature_id) or "-",
        to_text(title).lower()[:120],
    ]
    return "|".join(parts)


def find_device_id_for_event(cur, device_id: Any = None, src_ip: Any = None, dest_ip: Any = None) -> str | None:
    if device_id:
        try:
            return normalize_uuid_text(device_id)
        except HTTPException:
            return None

    candidate_ips = [normalize_ip_text(src_ip), normalize_ip_text(dest_ip)]
    for ip in candidate_ips:
        if not ip:
            continue
        cur.execute(
            """
            SELECT id::text AS id
            FROM devices
            WHERE current_ip = %s::inet
            ORDER BY last_seen_at DESC NULLS LAST
            LIMIT 1
            """,
            (ip,),
        )
        row = cur.fetchone()
        if row:
            return to_text(row.get("id")) or None
    return None


def upsert_security_event_and_incident(cur, payload: SecurityEventCreatePayload) -> dict[str, Any]:
    event_type = normalize_event_type(payload.event_type)
    severity = normalize_security_severity(payload.severity)
    source_system = clean_optional_text(payload.source_system) or "security-core"
    title = clean_optional_text(payload.title) or event_type.replace("_", " ").title()
    raw_json = payload.raw_json if isinstance(payload.raw_json, dict) else {}
    src_ip = normalize_ip_text(payload.src_ip)
    dest_ip = normalize_ip_text(payload.dest_ip)
    device_id = find_device_id_for_event(cur, payload.device_id, src_ip, dest_ip)
    dedupe_key = clean_optional_text(payload.dedupe_key) or security_event_dedupe_key(
        source_system,
        event_type,
        device_id,
        src_ip,
        dest_ip,
        payload.domain,
        payload.signature_id,
        title,
    )

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
            %s::uuid,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s::inet,
            %s,
            %s::inet,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            COALESCE(NULLIF(%s, '')::timestamptz, now()),
            %s,
            now()
        )
        RETURNING id::text AS id, event_time
        """,
        (
            device_id,
            source_system,
            event_type,
            severity,
            title,
            clean_optional_text(payload.description),
            src_ip,
            payload.src_port,
            dest_ip,
            payload.dest_port,
            clean_optional_text(payload.protocol),
            clean_optional_text(payload.domain),
            clean_optional_text(payload.country_code.upper() if payload.country_code else None),
            clean_optional_text(payload.signature_id),
            clean_optional_text(payload.signature_name),
            dedupe_key,
            clean_optional_text(payload.event_time),
            j(raw_json),
        ),
    )
    event_row = cur.fetchone()
    incident_id = None

    if payload.create_incident:
        description = clean_optional_text(payload.description) or f"{source_system} event: {title}"
        cur.execute(
            """
            SELECT id::text AS id, severity, event_count
            FROM incidents
            WHERE dedupe_key = %s
              AND status IN ('open', 'acknowledged', 'in_progress')
            LIMIT 1
            """,
            (dedupe_key,),
        )
        existing = cur.fetchone()
        if existing:
            old_severity = normalize_security_severity(existing.get("severity"))
            effective_severity = severity if SECURITY_CORE_SEVERITY_RANK[severity] > SECURITY_CORE_SEVERITY_RANK[old_severity] else old_severity
            incident_id = to_text(existing.get("id"))
            cur.execute(
                """
                UPDATE incidents
                SET
                    severity = %s,
                    title = %s,
                    description = COALESCE(NULLIF(%s, ''), description),
                    evidence_json = COALESCE(evidence_json, '{}'::jsonb) || jsonb_build_object(
                        'last_event_id', %s,
                        'last_event_time', %s,
                        'last_source_system', %s
                    ),
                    event_count = COALESCE(event_count, 0) + 1,
                    last_seen_at = %s,
                    updated_at = now()
                WHERE id = %s::uuid
                """,
                (
                    effective_severity,
                    title,
                    description,
                    event_row["id"],
                    event_row["event_time"],
                    source_system,
                    event_row["event_time"],
                    incident_id,
                ),
            )
        else:
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
                    %s::uuid,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    jsonb_build_object(
                        'first_event_id', %s,
                        'last_event_id', %s,
                        'source_system', %s,
                        'src_ip', %s,
                        'dest_ip', %s,
                        'domain', %s,
                        'signature_id', %s,
                        'signature_name', %s,
                        'raw', %s::jsonb
                    ),
                    'open',
                    %s,
                    1,
                    %s,
                    %s,
                    now(),
                    now()
                )
                RETURNING id::text AS id
                """,
                (
                    device_id,
                    event_type,
                    severity,
                    source_system,
                    title,
                    description,
                    event_row["id"],
                    event_row["id"],
                    source_system,
                    src_ip,
                    dest_ip,
                    clean_optional_text(payload.domain),
                    clean_optional_text(payload.signature_id),
                    clean_optional_text(payload.signature_name),
                    j(raw_json),
                    dedupe_key,
                    event_row["event_time"],
                    event_row["event_time"],
                ),
            )
            incident_id = to_text(cur.fetchone().get("id"))

        cur.execute(
            "UPDATE security_events SET incident_id = %s::uuid WHERE id = %s::uuid",
            (incident_id, event_row["id"]),
        )

    return {"event_id": event_row["id"], "incident_id": incident_id, "dedupe_key": dedupe_key}


@app.get("/api/v1/stats/incidents")
def incident_stats(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE status IN ('open', 'acknowledged', 'in_progress'))::int AS open_incidents,
                    COUNT(*) FILTER (WHERE status IN ('open', 'acknowledged', 'in_progress') AND severity = 'critical')::int AS critical_open_incidents,
                    COUNT(*) FILTER (WHERE status IN ('open', 'acknowledged', 'in_progress') AND severity = 'high')::int AS high_open_incidents,
                    COUNT(*) FILTER (WHERE status IN ('open', 'acknowledged', 'in_progress') AND severity = 'medium')::int AS medium_open_incidents,
                    COUNT(*) FILTER (WHERE status = 'closed')::int AS closed_incidents,
                    COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours')::int AS incidents_last_24h
                FROM incidents
                """
            )
            incidents = dict(cur.fetchone() or {})
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours')::int AS events_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND source_system ILIKE 'suricata%')::int AS suricata_alerts_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND source_system ILIKE 'adguard%')::int AS dns_events_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type ILIKE '%dns%block%')::int AS dns_blocks_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND (event_type ILIKE '%anomaly%' OR source_system ILIKE '%anomaly%'))::int AS anomalies_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND severity = 'critical')::int AS critical_events_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND severity = 'high')::int AS high_events_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND source_system = 'correlation-engine')::int AS correlations_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type = 'ids_dns_correlation')::int AS ids_dns_correlations_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type IN ('traffic_volume_spike','outbound_connection_burst','dns_request_rate_spike'))::int AS baseline_anomalies_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type = 'traffic_volume_spike')::int AS traffic_volume_spikes_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type = 'outbound_connection_burst')::int AS outbound_connection_bursts_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND event_type = 'new_destination_country')::int AS new_destination_country_events_last_24h,
                    COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours' AND source_system = 'opnsense_pf_states')::int AS opnsense_flow_events_last_24h
                FROM security_events
                """
            )
            events = dict(cur.fetchone() or {})
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE sample_time >= now() - interval '24 hours')::int AS opnsense_flow_events_last_24h,
                    COALESCE(SUM(bytes_delta) FILTER (WHERE sample_time >= now() - interval '24 hours'), 0)::bigint AS opnsense_flow_bytes_last_24h,
                    COUNT(DISTINCT country_code) FILTER (WHERE sample_time >= now() - interval '24 hours' AND country_code IS NOT NULL)::int AS opnsense_flow_countries_last_24h
                FROM device_traffic_samples
                """
            )
            flow = dict(cur.fetchone() or {})
    return {**incidents, **events, **flow}


@app.get("/api/v1/incidents")
def list_incidents(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source_system: str | None = Query(default=None),
    incident_type: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        if status == "open_like":
            clauses.append("i.status IN ('open', 'acknowledged', 'in_progress', 'ignored')")
        else:
            clauses.append("i.status = %s")
            params.append(normalize_incident_status(status))
    if severity:
        clauses.append("i.severity = %s")
        params.append(normalize_security_severity(severity))
    if source_system:
        clauses.append("i.source_system ILIKE %s")
        params.append(f"%{source_system}%")
    if incident_type:
        clauses.append("i.incident_type = %s")
        params.append(normalize_event_type(incident_type))
    if device_id:
        clauses.append("i.device_id = %s::uuid")
        params.append(normalize_uuid_text(device_id))
    if q:
        wildcard = f"%{q}%"
        clauses.append(
            """
            (
                i.title ILIKE %s OR
                COALESCE(i.description, '') ILIKE %s OR
                i.source_system ILIKE %s OR
                COALESCE(d.hostname, '') ILIKE %s OR
                COALESCE(d.vendor, '') ILIKE %s OR
                COALESCE(d.model, '') ILIKE %s OR
                COALESCE(host(d.current_ip), '') ILIKE %s
            )
            """
        )
        params.extend([wildcard] * 7)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base_sql = f"""
        FROM incidents i
        LEFT JOIN devices d ON d.id = i.device_id
        {where_sql}
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
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
                    i.first_seen_at,
                    i.last_seen_at,
                    i.created_at,
                    i.updated_at,
                    i.closed_at,
                    i.evidence_json,
                    d.hostname AS device_hostname,
                    d.vendor AS device_vendor,
                    d.model AS device_model,
                    d.category AS device_category,
                    host(d.current_ip) AS device_ip,
                    d.mac_address AS device_mac
                {base_sql}
                ORDER BY
                    CASE i.severity
                        WHEN 'critical' THEN 5
                        WHEN 'high' THEN 4
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2
                        WHEN 'info' THEN 1
                        ELSE 0
                    END DESC,
                    COALESCE(i.last_seen_at, i.created_at) DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_detail(
    incident_id: str = Path(...),
    events_limit: int = Query(default=100, ge=1, le=500),
    _: None = Security(require_api_key),
):
    incident_uuid = normalize_uuid_text(incident_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
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
                    i.evidence_json,
                    i.status,
                    i.dedupe_key,
                    i.event_count,
                    i.first_seen_at,
                    i.last_seen_at,
                    i.created_at,
                    i.updated_at,
                    i.closed_at,
                    d.hostname AS device_hostname,
                    d.vendor AS device_vendor,
                    d.model AS device_model,
                    d.category AS device_category,
                    host(d.current_ip) AS device_ip,
                    d.mac_address AS device_mac
                FROM incidents i
                LEFT JOIN devices d ON d.id = i.device_id
                WHERE i.id = %s::uuid
                """,
                (incident_uuid,),
            )
            incident = cur.fetchone()
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            cur.execute(
                """
                SELECT
                    id::text AS id,
                    source_system,
                    event_type,
                    severity,
                    title,
                    description,
                    host(src_ip) AS src_ip,
                    src_port,
                    host(dest_ip) AS dest_ip,
                    dest_port,
                    protocol,
                    domain,
                    country_code,
                    signature_id,
                    signature_name,
                    event_time,
                    raw_json,
                    created_at
                FROM security_events
                WHERE incident_id = %s::uuid
                ORDER BY event_time DESC
                LIMIT %s
                """,
                (incident_uuid, events_limit),
            )
            events = cur.fetchall()
            cur.execute(
                """
                SELECT id::text AS id, action_type, action_source, action_result, executed_at, details_json
                FROM actions
                WHERE incident_id = %s::uuid
                ORDER BY executed_at DESC
                LIMIT 100
                """,
                (incident_uuid,),
            )
            actions = cur.fetchall()
    return {"item": incident, "events": events, "actions": actions}






def _incident_payload_values(payload: Any, actor_query: str | None, reason_query: str | None) -> tuple[str, str | None]:
    payload_actor = None
    payload_reason = None

    if isinstance(payload, dict):
        payload_actor = payload.get("actor")
        payload_reason = payload.get("reason")
    elif payload is not None:
        payload_actor = getattr(payload, "actor", None)
        payload_reason = getattr(payload, "reason", None)

    actor_text = clean_optional_text(actor_query) or clean_optional_text(payload_actor) or "api"
    reason_text = clean_optional_text(reason_query) or clean_optional_text(payload_reason)
    return actor_text, reason_text


def _incident_uuid(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(normalize_uuid_text(value))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid incident UUID") from exc


def _update_incident_status(
    incident_id: str,
    new_status: str,
    actor: str,
    reason: str | None,
    allowed_current_statuses: set[str],
):
    incident_uuid = _incident_uuid(incident_id)
    actor_text = clean_optional_text(actor) or "api"
    reason_text = clean_optional_text(reason)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, status, device_id::text AS device_id
                FROM incidents
                WHERE id = %s
                """,
                (incident_uuid,),
            )
            current = cur.fetchone()

            if not current:
                raise HTTPException(status_code=404, detail="Incident not found")

            current_status = to_text(current.get("status")).lower()
            if current_status not in allowed_current_statuses:
                raise HTTPException(
                    status_code=409,
                    detail=f"Incident status is {current_status}; cannot change to {new_status}",
                )

            action_details = {
                "last_action": new_status,
                "last_action_actor": actor_text,
                "last_action_reason": reason_text,
                "last_action_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            if new_status == "closed":
                action_details.update({
                    "closed_by": actor_text,
                    "closed_reason": reason_text,
                })
                cur.execute(
                    """
                    UPDATE incidents
                    SET
                        status = 'closed',
                        closed_at = COALESCE(closed_at, now()),
                        updated_at = now(),
                        evidence_json = COALESCE(evidence_json, '{}'::jsonb) || %s::jsonb
                    WHERE id = %s
                    RETURNING id::text AS id, status, updated_at, closed_at, evidence_json
                    """,
                    (j(action_details), incident_uuid),
                )
            else:
                action_details.update({
                    "acknowledged_by": actor_text,
                    "acknowledged_reason": reason_text,
                })
                cur.execute(
                    """
                    UPDATE incidents
                    SET
                        status = 'acknowledged',
                        updated_at = now(),
                        evidence_json = COALESCE(evidence_json, '{}'::jsonb) || %s::jsonb
                    WHERE id = %s
                    RETURNING id::text AS id, status, updated_at, closed_at, evidence_json
                    """,
                    (j(action_details), incident_uuid),
                )

            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=500, detail="Incident status update failed")

            cleanup_result = {"rolled_back_action_ids": [], "disabled_suppression_ids": []}
            if new_status == "closed":
                cleanup_result = phase6_cleanup_incident_after_close(cur, str(incident_uuid), actor_text, reason_text)

    sync_result = None
    if new_status == "closed" and cleanup_result.get("rolled_back_action_ids"):
        try:
            sync_result = phase6_run_response_engine(["sync-only"])
        except Exception as exc:
            sync_result = {"status": "failed", "error": str(exc)}

    return {
        "status": "ok",
        "incident_id": str(incident_uuid),
        "incident_status": new_status,
        "previous_status": current_status,
        "actor": actor_text,
        "reason": reason_text,
        "cleanup": cleanup_result,
        "sync": sync_result,
    }


@app.post("/api/v1/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str = Path(...),
    payload: dict[str, Any] | None = Body(default=None),
    actor: str | None = Query(default=None),
    reason: str | None = Query(default=None),
    _: None = Security(require_api_key),
):
    actor_text, reason_text = _incident_payload_values(payload, actor, reason)
    return _update_incident_status(
        incident_id=incident_id,
        new_status="acknowledged",
        actor=actor_text,
        reason=reason_text,
        allowed_current_statuses={"open", "in_progress"},
    )


@app.post("/api/v1/incidents/{incident_id}/close")
def close_incident(
    incident_id: str = Path(...),
    payload: dict[str, Any] | None = Body(default=None),
    actor: str | None = Query(default=None),
    reason: str | None = Query(default=None),
    _: None = Security(require_api_key),
):
    actor_text, reason_text = _incident_payload_values(payload, actor, reason)
    return _update_incident_status(
        incident_id=incident_id,
        new_status="closed",
        actor=actor_text,
        reason=reason_text,
        allowed_current_statuses={"open", "acknowledged", "in_progress", "ignored"},
    )


@app.get("/api/v1/security-events")
def list_security_events(
    source_system: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    incident_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    clauses: list[str] = []
    params: list[Any] = []
    if source_system:
        clauses.append("se.source_system ILIKE %s")
        params.append(f"%{source_system}%")
    if event_type:
        clauses.append("se.event_type = %s")
        params.append(normalize_event_type(event_type))
    if severity:
        clauses.append("se.severity = %s")
        params.append(normalize_security_severity(severity))
    if device_id:
        clauses.append("se.device_id = %s::uuid")
        params.append(normalize_uuid_text(device_id))
    if incident_id:
        clauses.append("se.incident_id = %s::uuid")
        params.append(normalize_uuid_text(incident_id))
    if q:
        wildcard = f"%{q}%"
        clauses.append(
            """
            (
                se.title ILIKE %s OR
                COALESCE(se.description, '') ILIKE %s OR
                COALESCE(se.domain, '') ILIKE %s OR
                COALESCE(se.signature_name, '') ILIKE %s OR
                COALESCE(d.hostname, '') ILIKE %s OR
                COALESCE(host(se.src_ip), '') ILIKE %s OR
                COALESCE(host(se.dest_ip), '') ILIKE %s
            )
            """
        )
        params.extend([wildcard] * 7)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base_sql = f"""
        FROM security_events se
        LEFT JOIN devices d ON d.id = se.device_id
        LEFT JOIN incidents i ON i.id = se.incident_id
        {where_sql}
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
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
                    se.dedupe_key,
                    se.raw_json,
                    d.hostname AS device_hostname,
                    d.vendor AS device_vendor,
                    d.model AS device_model,
                    d.category AS device_category,
                    host(d.current_ip) AS device_ip,
                    i.status AS incident_status
                {base_sql}
                ORDER BY se.event_time DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.post("/api/v1/security-events")
def create_security_event(payload: SecurityEventCreatePayload, _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            result = upsert_security_event_and_incident(cur, payload)
    return {"status": "ok", **result}



@app.get("/api/v1/traffic-samples")
def list_traffic_samples(
    device_id: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    country_code: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    clauses: list[str] = []
    params: list[Any] = []
    if device_id:
        clauses.append("dts.device_id = %s::uuid")
        params.append(normalize_uuid_text(device_id))
    if direction:
        direction_text = clean_optional_text(direction)
        if direction_text not in {"outbound", "inbound", "local", "unknown"}:
            raise HTTPException(status_code=400, detail="Invalid direction")
        clauses.append("dts.direction = %s")
        params.append(direction_text)
    if country_code:
        cc = clean_optional_text(country_code).upper()
        if not re.fullmatch(r"[A-Z]{2}", cc):
            raise HTTPException(status_code=400, detail="Invalid country_code")
        clauses.append("dts.country_code = %s")
        params.append(cc)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    base_sql = f"""
        FROM device_traffic_samples dts
        LEFT JOIN devices d ON d.id = dts.device_id
        {where_sql}
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT
                    dts.id::text AS id,
                    dts.device_id::text AS device_id,
                    d.hostname AS device_hostname,
                    host(d.current_ip) AS device_ip,
                    dts.sample_time,
                    dts.source_system,
                    dts.direction,
                    host(dts.src_ip) AS src_ip,
                    dts.src_port,
                    host(dts.dest_ip) AS dest_ip,
                    dts.dest_port,
                    dts.protocol,
                    dts.country_code,
                    dts.bytes_delta,
                    dts.packets_delta,
                    dts.connection_count,
                    dts.raw_json
                {base_sql}
                ORDER BY dts.sample_time DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/system-health")
def get_system_health(
    include_details: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    _: None = Security(require_api_key),
):
    """Return Security Core component health rows for Home Assistant.

    The deployed schemas seen in this project may use either check_at or
    last_check_at. The default response is intentionally lightweight because
    Home Assistant stores REST json_attributes in entity attributes; large
    details_json payloads can make the component list appear empty or unstable.
    Use include_details=true only for API debugging.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            time_col = system_health_time_column(cur)
            details_expr = "details_json" if include_details else "'{}'::jsonb"
            cur.execute(
                f"""
                SELECT component_name,
                       component_type,
                       status,
                       {time_col} AS last_check_at,
                       {time_col} AS check_at,
                       version,
                       {details_expr} AS details_json,
                       updated_at
                FROM system_health
                ORDER BY
                    CASE lower(COALESCE(status, ''))
                        WHEN 'critical' THEN 1
                        WHEN 'failed' THEN 2
                        WHEN 'error' THEN 3
                        WHEN 'degraded' THEN 4
                        WHEN 'warning' THEN 5
                        WHEN 'unknown' THEN 6
                        WHEN 'healthy' THEN 9
                        WHEN 'ok' THEN 9
                        ELSE 7
                    END,
                    component_name
                LIMIT %s
                """,
                (limit,),
            )
            return {"items": cur.fetchall()}


# -----------------------------------------------------------------------------
# Phase 6 response API - fixed synchronous endpoints and cleanup helpers
# -----------------------------------------------------------------------------

RESPONSE_ENGINE_SCRIPT = os.environ.get("RESPONSE_ENGINE_SCRIPT", "/opt/security-core/app/worker/response_engine.py")
SECURITY_CORE_PYTHON = os.environ.get("SECURITY_CORE_PYTHON", "/opt/security-core/venv/bin/python")
RESPONSE_ENGINE_API_TIMEOUT_SECONDS = int(os.environ.get("RESPONSE_ENGINE_API_TIMEOUT_SECONDS", "120") or "120")

PHASE6_ACTIONS = {"auto", "notify_only", "dns_only", "ip_only", "internet_block", "quarantine", "rate_limit", "dynamic_firewall_block"}
PHASE6_ACTIVE_STATUSES = {"suggested", "approved", "pending", "applying", "applied", "applied_degraded"}


class ResponseApplyPayload(BaseModel):
    action_type: str | None = None
    reason: str | None = None
    actor: str | None = "api"
    ttl_minutes: int | None = None


class ResponseRollbackPayload(BaseModel):
    reason: str | None = None
    actor: str | None = "api"


class ResponseFalsePositivePayload(BaseModel):
    reason: str | None = None
    actor: str | None = "api"
    ttl_hours: int | None = None


class ResponseIgnorePayload(BaseModel):
    reason: str | None = None
    actor: str | None = "api"
    ttl_hours: int | None = None


class ResponseSuppressionPayload(BaseModel):
    scope: str | None = "incident_pattern"
    device_id: str | None = None
    incident_type: str | None = None
    source_system: str | None = None
    severity: str | None = None
    domain: str | None = None
    country_code: str | None = None
    signature_id: str | None = None
    title_pattern: str | None = None
    reason: str | None = None
    ttl_hours: int | None = None
    created_by: str | None = "api"


class ResponseDeviceOverridePayload(BaseModel):
    auto_response_enabled: bool | None = True
    max_auto_action: str | None = None
    preferred_action: str | None = None
    suppress_minutes: int | None = None
    suppress_ttl_hours: int | None = None
    notes: str | None = None
    updated_by: str | None = "api"


def phase6_table_exists(cur, table_name: str) -> bool:
    cur.execute("SELECT to_regclass(%s) IS NOT NULL AS exists", (f"public.{table_name}",))
    row = cur.fetchone()
    return bool(row and row.get("exists"))


def phase6_columns(cur, table_name: str) -> set[str]:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (table_name,),
    )
    return {to_text(row.get("column_name")) for row in (cur.fetchall() or [])}



def phase6_ensure_response_ignores(cur) -> None:
    """Runtime check only; DDL is applied by SQL migration.

    Running CREATE TABLE/INDEX from the API user caused "must be owner of table"
    after the migration had created response_ignores as postgres.
    """
    cur.execute("SELECT to_regclass('public.response_ignores') IS NOT NULL AS exists")
    row = cur.fetchone() or {}
    if not bool(row.get("exists")):
        raise RuntimeError("response_ignores table missing; run phase6_response_ignores_schema_fix38.sql")

def phase6_disable_response_ignores_for_incident(cur, incident_id: str, actor: str, reason: str | None = None) -> list[str]:
    if not phase6_table_exists(cur, "response_ignores"):
        return []
    cur.execute(
        """
        SELECT id::text AS id, device_id::text AS device_id, incident_type, source_system
        FROM incidents
        WHERE id=%s::uuid
        """,
        (incident_id,),
    )
    inc = cur.fetchone() or {}
    device_id = phase6_clean_text(inc.get("device_id"))
    incident_type = phase6_clean_text(inc.get("incident_type"))
    source_system = phase6_clean_text(inc.get("source_system"))
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
        (reason or "ignore removed", reason or "ignore removed", device_id, incident_type, source_system),
    )
    return [r["id"] for r in (cur.fetchall() or [])]


def phase6_column_udt(cur, table_name: str, column_name: str) -> str | None:
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
    return phase6_clean_text(row.get("udt_name")) if row else None


def phase6_bytea_uuid_text_expr(column_sql: str) -> str:
    encoded = f"encode({column_sql}, 'hex')"
    return (
        f"CASE WHEN {column_sql} IS NULL THEN NULL::text "
        f"WHEN octet_length({column_sql}) = 16 THEN "
        f"lower(substr({encoded},1,8)||'-'||substr({encoded},9,4)||'-'||substr({encoded},13,4)||'-'||substr({encoded},17,4)||'-'||substr({encoded},21,12)) "
        f"ELSE NULLIF(convert_from({column_sql}, 'UTF8'), '') END"
    )


def phase6_suppression_device_id_select_expr(cur, column_sql: str = "device_id") -> str:
    kind = phase6_column_udt(cur, "response_suppressions", "device_id")
    if kind == "bytea":
        return f"{phase6_bytea_uuid_text_expr(column_sql)} AS device_id"
    if kind == "uuid":
        return f"{column_sql}::text AS device_id"
    return f"NULLIF({column_sql}::text, '') AS device_id"


def phase6_suppression_device_id_condition(cur, column_sql: str = "device_id", placeholder: str = "%s") -> str:
    kind = phase6_column_udt(cur, "response_suppressions", "device_id")
    if kind == "bytea":
        return f"{phase6_bytea_uuid_text_expr(column_sql)} IS NOT DISTINCT FROM {placeholder}"
    if kind == "uuid":
        return f"{column_sql} IS NOT DISTINCT FROM {placeholder}::uuid"
    return f"NULLIF({column_sql}::text, '') IS NOT DISTINCT FROM {placeholder}"


def phase6_suppression_device_id_insert_expr(cur, placeholder: str = "%s") -> str:
    kind = phase6_column_udt(cur, "response_suppressions", "device_id")
    if kind == "bytea":
        return f"convert_to({placeholder}, 'UTF8')"
    if kind == "uuid":
        return f"{placeholder}::uuid"
    return placeholder


def phase6_json_loads(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def phase6_clean_action(value: Any) -> str:
    text = to_text(value).lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "", text)
    if text in {"", "auto"}:
        return "auto"
    if text not in PHASE6_ACTIONS:
        raise HTTPException(status_code=400, detail="Invalid response action_type")
    return text


def phase6_clean_text(value: Any) -> str | None:
    text = to_text(value)
    if text.startswith("\\x") and len(text) > 2:
        try:
            decoded = bytes.fromhex(text[2:]).decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded
        except Exception:
            pass
    return text or None


def phase6_suppression_public_row(row: dict[str, Any]) -> dict[str, Any]:
    # Convert legacy bytea/hex-looking text back to readable values for HA popups.
    for key in ("device_id", "scope", "incident_type", "source_system", "severity", "domain", "country_code", "signature_id", "signature_name", "title_pattern", "reason", "created_by"):
        if key in row:
            row[key] = phase6_clean_text(row.get(key))
    return row


def phase6_matching_ignore_cleanup(cur, incident_id: str, actor: str, reason: str | None) -> list[str]:
    """Disable active suppressions that match the selected incident.

    In HA these rows are shown as "aktyvūs ignoravimai" even when an older row was
    created with reason="false positive". Rollback/atšaukti is the user-facing way
    to remove the ignore/suppression for this exact incident/device/type pattern,
    so we remove all exact matches, not only rows whose reason contains "ignore".
    """
    if not phase6_table_exists(cur, "response_suppressions"):
        return []
    cur.execute(
        """
        SELECT device_id::text AS device_id, incident_type, source_system, evidence_json
        FROM incidents
        WHERE id=%s::uuid
        """,
        (incident_id,),
    )
    inc = cur.fetchone() or {}
    device_id = inc.get("device_id")
    incident_type = phase6_clean_text(inc.get("incident_type"))
    source_system = phase6_clean_text(inc.get("source_system"))
    evidence = inc.get("evidence_json") if isinstance(inc.get("evidence_json"), dict) else {}
    evidence_suppression_id = phase6_clean_text(evidence.get("ignore_suppression_id") or evidence.get("false_positive_suppression_id"))

    disabled: list[str] = []
    if evidence_suppression_id:
        cur.execute(
            """
            UPDATE response_suppressions
            SET is_enabled=false,
                updated_at=now(),
                reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN 'removed by rollback' ELSE ' | removed by rollback' END
            WHERE id=%s::uuid
              AND COALESCE(is_enabled, true) = true
            RETURNING id::text AS id
            """,
            (evidence_suppression_id,),
        )
        disabled.extend([row["id"] for row in (cur.fetchall() or [])])

    if not device_id or not incident_type:
        return sorted(set(disabled))

    device_condition = phase6_suppression_device_id_condition(cur, "device_id", "%s")
    cur.execute(
        f"""
        UPDATE response_suppressions
        SET is_enabled=false,
            updated_at=now(),
            reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN 'removed by rollback' ELSE ' | removed by rollback' END
        WHERE COALESCE(is_enabled, true) = true
          AND (expires_at IS NULL OR expires_at > now())
          AND {device_condition}
          AND incident_type IS NOT DISTINCT FROM %s
          AND source_system IS NOT DISTINCT FROM %s
        RETURNING id::text AS id
        """,
        (device_id, incident_type, source_system),
    )
    disabled.extend([row["id"] for row in (cur.fetchall() or [])])
    return sorted(set(disabled))

def phase6_child_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("DATABASE_URL", DATABASE_URL)
    env.setdefault("SECURITY_CORE_API_KEY", API_KEY)
    return env


def phase6_parse_worker_json(stdout: str) -> dict[str, Any]:
    text_out = (stdout or "").strip()
    if not text_out:
        return {}
    # response_engine prints one JSON object. If warnings are printed before it, parse from last '{'.
    for pos in [0] + [i for i, ch in enumerate(text_out) if ch == "{"][-10:]:
        try:
            obj = json.loads(text_out[pos:])
            return obj if isinstance(obj, dict) else {"result": obj}
        except Exception:
            continue
    return {"raw_stdout": text_out[-4000:]}


def phase6_run_response_engine(args: list[str]) -> dict[str, Any]:
    cmd = [SECURITY_CORE_PYTHON, RESPONSE_ENGINE_SCRIPT, *args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=RESPONSE_ENGINE_API_TIMEOUT_SECONDS,
        env=phase6_child_env(),
        check=False,
    )
    parsed = phase6_parse_worker_json(proc.stdout)
    parsed.setdefault("returncode", proc.returncode)
    if proc.stderr:
        parsed["stderr_tail"] = proc.stderr[-2000:]
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=parsed)
    return parsed


def phase6_cleanup_incident_after_close(cur, incident_id: str, actor: str, reason: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {"rolled_back_action_ids": [], "disabled_suppression_ids": []}
    incident_id = normalize_uuid_text(incident_id)
    if phase6_table_exists(cur, "response_actions"):
        cur.execute(
            """
            UPDATE response_actions
            SET status = 'rolled_back',
                rollback_by = %s,
                rollback_reason = COALESCE(%s, 'incident closed'),
                rolled_back_at = COALESCE(rolled_back_at, now()),
                updated_at = now()
            WHERE incident_id = %s::uuid
              AND status IN ('suggested','approved','pending','applying','applied','applied_degraded')
            RETURNING id::text AS id
            """,
            (actor, reason, incident_id),
        )
        result["rolled_back_action_ids"] = [row["id"] for row in (cur.fetchall() or [])]

    if phase6_table_exists(cur, "response_suppressions"):
        cur.execute("SELECT device_id::text AS device_id, incident_type, source_system FROM incidents WHERE id = %s::uuid", (incident_id,))
        inc = cur.fetchone() or {}
        device_id = inc.get("device_id")
        incident_type = phase6_clean_text(inc.get("incident_type"))
        source_system = phase6_clean_text(inc.get("source_system"))
        clauses = ["COALESCE(is_enabled, true) = true"]
        params: list[Any] = []
        # Disable only suppressions that actually match this incident pattern, not every row from the same source_system.
        if device_id:
            clauses.append("device_id = %s::uuid")
            params.append(device_id)
        if incident_type:
            clauses.append("incident_type = %s")
            params.append(incident_type)
        if source_system:
            clauses.append("source_system = %s")
            params.append(source_system)
        if len(clauses) > 1:
            cur.execute(
                f"""
                UPDATE response_suppressions
                SET is_enabled = false,
                    updated_at = now(),
                    reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN 'cleared on incident close' ELSE ' | cleared on incident close' END
                WHERE {' AND '.join(clauses)}
                RETURNING id::text AS id
                """,
                params,
            )
            result["disabled_suppression_ids"] = [row["id"] for row in (cur.fetchall() or [])]
    return result


@app.get("/api/v1/response/stats")
def phase6_response_stats(_: None = Security(require_api_key)):
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL not set")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "response_actions"):
                return {"suggested_actions": 0, "pending_actions": 0, "active_actions": 0, "degraded_actions": 0, "rolled_back_actions": 0, "expired_actions": 0, "actions_last_24h": 0, "active_suppressions": 0, "auto_response_mode": "missing_schema", "response_engine_enabled": False}
            cur.execute(
                """
                SELECT
                  COUNT(*) FILTER (WHERE status = 'suggested')::int AS suggested_actions,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying'))::int AS pending_actions,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded'))::int AS active_actions,
                  COUNT(*) FILTER (WHERE status = 'applied_degraded')::int AS degraded_actions,
                  COUNT(*) FILTER (WHERE status = 'rolled_back')::int AS rolled_back_actions,
                  COUNT(*) FILTER (WHERE status = 'expired')::int AS expired_actions,
                  COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours')::int AS actions_last_24h,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded') AND action_type='quarantine')::int AS active_quarantines,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded') AND action_type='internet_block')::int AS active_internet_blocks,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded') AND action_type='dns_only')::int AS active_dns_only,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded') AND action_type='rate_limit')::int AS active_rate_limits,
                  COUNT(*) FILTER (WHERE status IN ('approved','pending','applying','applied','applied_degraded') AND action_type='dynamic_firewall_block')::int AS active_dynamic_blocks
                FROM response_actions
                """
            )
            stats = dict(cur.fetchone() or {})
            # Fix44: after ignore handling was moved from legacy response_suppressions
            # to response_ignores, the HA tile still read active_suppressions
            # from /api/v1/response/stats. Count response_ignores first so the
            # "Aktyvūs ignoravimai" entity matches the popup/list endpoint.
            if phase6_table_exists(cur, "response_ignores"):
                cur.execute("""
                    SELECT COUNT(*)::int AS count
                    FROM response_ignores
                    WHERE COALESCE(is_enabled, true) = true
                      AND (expires_at IS NULL OR expires_at > now())
                """)
                stats["active_suppressions"] = cur.fetchone()["count"]
            elif phase6_table_exists(cur, "response_suppressions"):
                cur.execute("""
                    SELECT COUNT(*)::int AS count
                    FROM response_suppressions
                    WHERE COALESCE(is_enabled, true) = true
                      AND (expires_at IS NULL OR expires_at > now())
                      AND lower(COALESCE(reason, '')) LIKE %s
                """, ("ignore:%",))
                stats["active_suppressions"] = cur.fetchone()["count"]
            else:
                stats["active_suppressions"] = 0
            mode = "suggest_only"
            enabled = True
            if phase6_table_exists(cur, "response_settings"):
                cur.execute("SELECT setting_value FROM response_settings WHERE setting_key = 'auto_response_mode'")
                row = cur.fetchone()
                if row:
                    mode = to_text(row.get("setting_value")).strip('"') or mode
                cur.execute("SELECT setting_value FROM response_settings WHERE setting_key = 'response_engine_enabled'")
                row = cur.fetchone()
                if row:
                    enabled = str(row.get("setting_value")).lower() in {"true", "1", "yes", "on"}
            stats["auto_response_mode"] = mode
            stats["response_engine_enabled"] = enabled
            return stats


@app.get("/api/v1/response/settings")
def phase6_get_response_settings(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "response_settings"):
                return {"items": [], "settings": {}}
            cur.execute("SELECT setting_key, setting_value, updated_by, updated_at FROM response_settings ORDER BY setting_key")
            items = cur.fetchall()
            return {"items": items, "settings": {row["setting_key"]: phase6_json_loads(row["setting_value"]) for row in items}}


@app.post("/api/v1/response/settings/auto-response-mode/{mode}")
def phase6_set_auto_response_mode(mode: str = Path(...), payload: dict[str, Any] | None = Body(default=None), _: None = Security(require_api_key)):
    allowed = {"off", "suggest_only", "auto_low_risk", "auto_high_risk", "full_auto"}
    if mode not in allowed:
        raise HTTPException(status_code=400, detail=f"mode must be one of {sorted(allowed)}")
    actor = clean_optional_text((payload or {}).get("updated_by")) or "api"
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO response_settings(setting_key, setting_value, updated_by, created_at, updated_at)
                VALUES ('auto_response_mode', %s::jsonb, %s, now(), now())
                ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value, updated_by=EXCLUDED.updated_by, updated_at=now()
                """,
                (j(mode), actor),
            )
    return {"status": "ok", "auto_response_mode": mode, "updated_by": actor}


@app.get("/api/v1/response/actions")
def phase6_list_response_actions(status: str | None = Query(default=None), incident_id: str | None = Query(default=None), device_id: str | None = Query(default=None), limit: int = Query(default=200, ge=1, le=500), offset: int = Query(default=0, ge=0), _: None = Security(require_api_key)):
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        if status == "active":
            clauses.append("ra.status IN ('suggested','approved','pending','applying','applied','applied_degraded')")
        else:
            clauses.append("ra.status = %s")
            params.append(status)
    if incident_id:
        clauses.append("ra.incident_id = %s::uuid")
        params.append(normalize_uuid_text(incident_id))
    if device_id:
        clauses.append("ra.device_id = %s::uuid")
        params.append(normalize_uuid_text(device_id))
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "response_actions"):
                return {"total": 0, "limit": limit, "offset": offset, "items": []}
            base_sql = f"""
                FROM response_actions ra
                LEFT JOIN incidents i ON i.id = ra.incident_id
                LEFT JOIN devices d ON d.id = ra.device_id
                {where_sql}
            """
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT ra.id::text AS id, ra.incident_id::text AS incident_id, ra.device_id::text AS device_id,
                       ra.action_type, ra.action_mode, ra.status, ra.severity, ra.source_system, ra.incident_type,
                       ra.requested_by, ra.approved_by, ra.applied_by, ra.rollback_by, ra.reason, ra.ttl_minutes,
                       ra.expires_at, ra.suggested_at, ra.approved_at, ra.applied_at, ra.rollback_requested_at,
                       ra.rolled_back_at, ra.last_attempt_at, ra.params_json, ra.simulation_json, ra.result_json,
                       ra.created_at, ra.updated_at, i.title AS incident_title, i.status AS incident_status,
                       d.hostname AS device_hostname, host(d.current_ip) AS device_ip, d.category AS device_category
                {base_sql}
                ORDER BY ra.created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            return {"total": total, "limit": limit, "offset": offset, "items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}


@app.get("/api/v1/response/actions/{action_id}/events")
def phase6_response_action_events(action_id: str = Path(...), _: None = Security(require_api_key)):
    action_id = normalize_uuid_text(action_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "response_action_events"):
                return {"items": []}
            cur.execute(
                """
                SELECT id::text AS id, response_action_id::text AS response_action_id, incident_id::text AS incident_id,
                       device_id::text AS device_id, event_type, actor, message, details_json, created_at
                FROM response_action_events
                WHERE response_action_id = %s::uuid
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (action_id,),
            )
            return {"items": cur.fetchall()}


@app.post("/api/v1/response/run")
def phase6_run_response_engine_now(_: None = Security(require_api_key)):
    return phase6_run_response_engine(["run"])


@app.post("/api/v1/response/sync")
def phase6_sync_response_engine_now(_: None = Security(require_api_key)):
    return phase6_run_response_engine(["sync-only"])


@app.post("/api/v1/incidents/{incident_id}/response/simulate")
def phase6_simulate_incident_response(payload: ResponseApplyPayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    incident_id = normalize_uuid_text(incident_id)
    payload = payload or ResponseApplyPayload()
    args = ["simulate", "--incident-id", incident_id]
    if payload.action_type and phase6_clean_action(payload.action_type) != "auto":
        args += ["--action", phase6_clean_action(payload.action_type)]
    return phase6_run_response_engine(args)


@app.post("/api/v1/incidents/{incident_id}/response/suggest")
def phase6_suggest_incident_response(payload: ResponseApplyPayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    incident_id = normalize_uuid_text(incident_id)
    payload = payload or ResponseApplyPayload()
    args = ["suggest", "--incident-id", incident_id, "--actor", clean_optional_text(payload.actor) or "api"]
    if payload.action_type and phase6_clean_action(payload.action_type) != "auto":
        args += ["--action", phase6_clean_action(payload.action_type)]
    if payload.reason:
        args += ["--reason", payload.reason]
    return phase6_run_response_engine(args)


@app.post("/api/v1/incidents/{incident_id}/response/apply")
def phase6_apply_incident_response(payload: ResponseApplyPayload, incident_id: str = Path(...), _: None = Security(require_api_key)):
    incident_id = normalize_uuid_text(incident_id)
    args = ["apply", "--incident-id", incident_id, "--actor", clean_optional_text(payload.actor) or "api"]
    if payload.action_type and phase6_clean_action(payload.action_type) != "auto":
        args += ["--action", phase6_clean_action(payload.action_type)]
    if payload.reason:
        args += ["--reason", payload.reason]
    if payload.ttl_minutes is not None:
        args += ["--ttl-minutes", str(int(payload.ttl_minutes))]
    return phase6_run_response_engine(args)


@app.post("/api/v1/response/actions/{action_id}/apply")
def phase6_apply_response_action(payload: ResponseApplyPayload | None = Body(default=None), action_id: str = Path(...), _: None = Security(require_api_key)):
    action_id = normalize_uuid_text(action_id)
    payload = payload or ResponseApplyPayload()
    args = ["apply-action", "--action-id", action_id, "--actor", clean_optional_text(payload.actor) or "api"]
    if payload.reason:
        args += ["--reason", payload.reason]
    return phase6_run_response_engine(args)


@app.post("/api/v1/response/actions/{action_id}/rollback")
def phase6_rollback_response_action(payload: ResponseRollbackPayload | None = Body(default=None), action_id: str = Path(...), _: None = Security(require_api_key)):
    action_id = normalize_uuid_text(action_id)
    payload = payload or ResponseRollbackPayload()
    args = ["rollback", "--action-id", action_id, "--actor", clean_optional_text(payload.actor) or "api"]
    if payload.reason:
        args += ["--reason", payload.reason]
    return phase6_run_response_engine(args)


@app.post("/api/v1/incidents/{incident_id}/response/rollback")
def phase6_rollback_incident_response(payload: ResponseRollbackPayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    """Rollback incident response and remove dedicated Phase 6 ignore.

    Fix42 notes:
    - Ignore state lives in response_ignores only. Do not touch legacy response_suppressions
      because production had bytea/uuid schema drift there.
    - Do not touch evidence_json; older rows may contain bytea-like values that break JSONB
      serialization through psycopg.
    - If moving ignored -> acknowledged hits idx_incidents_open_dedupe_key, close duplicate
      open-like rows with the same dedupe_key first, then retry the selected incident.
    """
    incident_id = normalize_uuid_text(incident_id)
    payload = payload or ResponseRollbackPayload()
    actor = clean_optional_text(payload.actor) or "api"
    reason = clean_optional_text(payload.reason) or "rollback"

    rolled_back: list[str] = []
    disabled: list[str] = []
    duplicate_closed: list[str] = []
    warnings: list[str] = []
    incident_row: dict[str, Any] = {"id": incident_id, "status": None}

    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT i.id::text AS id,
                           i.status,
                           i.device_id::text AS device_id,
                           i.incident_type,
                           i.source_system,
                           i.dedupe_key
                    FROM incidents i
                    WHERE i.id=%s::uuid
                    """,
                    (incident_id,),
                )
                inc = cur.fetchone() or {}
                if not inc:
                    raise HTTPException(status_code=404, detail="Incident not found")

                device_id = phase6_clean_text(inc.get("device_id"))
                incident_type = phase6_clean_text(inc.get("incident_type"))
                source_system = phase6_clean_text(inc.get("source_system"))
                dedupe_key = phase6_clean_text(inc.get("dedupe_key"))
                incident_row = {"id": incident_id, "status": inc.get("status")}

                # 1) Roll back active response actions for this incident. Non-fatal.
                try:
                    if phase6_table_exists(cur, "response_actions"):
                        cur.execute(
                            """
                            UPDATE response_actions
                            SET status='rolled_back',
                                rollback_by=%s,
                                rollback_reason=%s,
                                rolled_back_at=COALESCE(rolled_back_at, now()),
                                updated_at=now()
                            WHERE incident_id=%s::uuid
                              AND status IN ('suggested','approved','pending','applying','applied','applied_degraded')
                            RETURNING id::text AS id
                            """,
                            (actor, reason, incident_id),
                        )
                        rolled_back = [r["id"] for r in (cur.fetchall() or [])]
                except Exception as exc:
                    warnings.append(f"response_actions_rollback_failed: {exc}")

                # 2) Disable dedicated ignores. Never query legacy response_suppressions here.
                try:
                    phase6_ensure_response_ignores(cur)
                    ignore_note = clean_optional_text(reason) or "ignore removed by rollback"
                    if device_id and incident_type:
                        cur.execute(
                            """
                            UPDATE response_ignores
                            SET is_enabled=false,
                                updated_at=now(),
                                reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN %s ELSE ' | ' || %s END
                            WHERE COALESCE(is_enabled, true)=true
                              AND (expires_at IS NULL OR expires_at > now())
                              AND (
                                    incident_id=%s::uuid
                                 OR (device_id=%s::uuid
                                     AND incident_type IS NOT DISTINCT FROM %s
                                     AND source_system IS NOT DISTINCT FROM %s)
                              )
                            RETURNING id::text AS id
                            """,
                            (ignore_note, ignore_note, incident_id, device_id, incident_type, source_system),
                        )
                    else:
                        cur.execute(
                            """
                            UPDATE response_ignores
                            SET is_enabled=false,
                                updated_at=now(),
                                reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN %s ELSE ' | ' || %s END
                            WHERE COALESCE(is_enabled, true)=true
                              AND (expires_at IS NULL OR expires_at > now())
                              AND incident_id=%s::uuid
                            RETURNING id::text AS id
                            """,
                            (ignore_note, ignore_note, incident_id),
                        )
                    disabled = [r["id"] for r in (cur.fetchall() or [])]
                except Exception as exc:
                    warnings.append(f"response_ignores_disable_failed: {exc}")

                # 3) Make selected incident visible again. If unique dedupe index blocks
                # ignored -> acknowledged, close duplicate open-like rows first and retry.
                try:
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status='acknowledged',
                            closed_at=NULL,
                            updated_at=now()
                        WHERE id=%s::uuid
                        RETURNING id::text AS id, status
                        """,
                        (incident_id,),
                    )
                    incident_row = cur.fetchone() or incident_row
                except Exception as exc:
                    msg = str(exc)
                    warnings.append(f"incident_status_acknowledged_initial_failed: {msg}")
                    try:
                        # In autocommit mode this is harmless; in non-autocommit mode it
                        # clears the failed transaction so the fallback can continue.
                        conn.rollback()
                    except Exception:
                        pass

                    if dedupe_key:
                        try:
                            cur.execute(
                                """
                                UPDATE incidents
                                SET status='closed',
                                    closed_at=COALESCE(closed_at, now()),
                                    updated_at=now()
                                WHERE id<>%s::uuid
                                  AND dedupe_key IS NOT DISTINCT FROM %s
                                  AND status IN ('open','acknowledged','ignored')
                                RETURNING id::text AS id
                                """,
                                (incident_id, dedupe_key),
                            )
                            duplicate_closed = [r["id"] for r in (cur.fetchall() or [])]
                            cur.execute(
                                """
                                UPDATE incidents
                                SET status='acknowledged',
                                    closed_at=NULL,
                                    updated_at=now()
                                WHERE id=%s::uuid
                                RETURNING id::text AS id, status
                                """,
                                (incident_id,),
                            )
                            incident_row = cur.fetchone() or incident_row
                        except Exception as exc2:
                            warnings.append(f"incident_status_acknowledged_after_duplicate_close_failed: {exc2}")
                            try:
                                conn.rollback()
                            except Exception:
                                pass

                    # Last-resort: do not leave selected incident as ignored if ignore was removed.
                    if incident_row.get("status") == "ignored":
                        try:
                            cur.execute(
                                """
                                UPDATE incidents
                                SET status='closed',
                                    closed_at=COALESCE(closed_at, now()),
                                    updated_at=now()
                                WHERE id=%s::uuid
                                RETURNING id::text AS id, status
                                """,
                                (incident_id,),
                            )
                            incident_row = cur.fetchone() or incident_row
                            warnings.append("incident_status_closed_as_last_resort")
                        except Exception as exc3:
                            warnings.append(f"incident_status_closed_last_resort_failed: {exc3}")
    except HTTPException:
        raise
    except Exception as exc:
        return {
            "status": "error",
            "error": "rollback_failed",
            "message": str(exc),
            "incident_id": incident_id,
            "rolled_back_action_ids": rolled_back,
            "disabled_ignore_ids": disabled,
            "duplicate_closed_incident_ids": duplicate_closed,
            "warnings": warnings,
        }

    try:
        sync = phase6_run_response_engine(["sync-only"])
    except Exception as exc:
        sync = {"ok": False, "warning": "sync_after_unignore_failed", "message": str(exc)}

    return {
        "status": "ok",
        "incident_id": incident_id,
        "incident_status": incident_row.get("status"),
        "rolled_back_action_ids": rolled_back,
        "disabled_ignore_ids": disabled,
        "duplicate_closed_incident_ids": duplicate_closed,
        "warnings": warnings,
        "sync": sync,
    }


def phase6_ignore_incident_type_for_device_impl(payload: ResponseIgnorePayload | None, incident_id: str) -> dict[str, Any]:
    """Ignore this incident type for this exact device using dedicated response_ignores table."""
    try:
        incident_id = normalize_uuid_text(incident_id)
        payload = payload or ResponseIgnorePayload()
        actor = clean_optional_text(payload.actor) or "api"
        reason = clean_optional_text(payload.reason) or "Ignored from Home Assistant"
        ttl_hours = 168 if payload.ttl_hours is None else int(payload.ttl_hours)
        expires_at = None if ttl_hours <= 0 else dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=ttl_hours)
        with pool.connection() as conn:
            with conn.cursor() as cur:
                phase6_ensure_response_ignores(cur)
                cur.execute(
                    """
                    SELECT i.id::text AS id,
                           i.device_id::text AS device_id,
                           host(d.current_ip) AS device_ip,
                           i.incident_type,
                           i.source_system,
                           i.status,
                           COALESCE(i.evidence_json, '{}'::jsonb) AS evidence_json
                    FROM incidents i
                    LEFT JOIN devices d ON d.id=i.device_id
                    WHERE i.id=%s::uuid
                    """,
                    (incident_id,),
                )
                inc = cur.fetchone()
                if not inc:
                    raise HTTPException(status_code=404, detail="Incident not found")
                device_id = phase6_clean_text(inc.get("device_id"))
                incident_type = phase6_clean_text(inc.get("incident_type"))
                source_system = phase6_clean_text(inc.get("source_system"))
                device_ip = phase6_clean_text(inc.get("device_ip"))
                if not device_id or not incident_type:
                    raise HTTPException(status_code=400, detail={"error": "incident_missing_device_or_type", "incident_id": incident_id, "device_id": device_id, "device_ip": device_ip, "incident_type": incident_type})
                cur.execute(
                    """
                    UPDATE response_ignores
                    SET is_enabled=false,
                        updated_at=now(),
                        reason = COALESCE(reason, '') || CASE WHEN COALESCE(reason, '') = '' THEN 'replaced by newer ignore' ELSE ' | replaced by newer ignore' END
                    WHERE COALESCE(is_enabled, true)=true
                      AND (expires_at IS NULL OR expires_at > now())
                      AND device_id=%s::uuid
                      AND incident_type IS NOT DISTINCT FROM %s
                      AND source_system IS NOT DISTINCT FROM %s
                    RETURNING id::text AS id
                    """,
                    (device_id, incident_type, source_system),
                )
                disabled_old = [r["id"] for r in (cur.fetchall() or [])]
                cur.execute(
                    """
                    INSERT INTO response_ignores(incident_id, device_id, incident_type, source_system, reason, created_by, expires_at, is_enabled, created_at, updated_at)
                    VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, true, now(), now())
                    RETURNING id::text AS id
                    """,
                    (incident_id, device_id, incident_type, source_system, f"ignore: {reason}", actor, expires_at),
                )
                ignore_id = cur.fetchone()["id"]
                rolled_back: list[str] = []
                if phase6_table_exists(cur, "response_actions"):
                    cur.execute(
                        """
                        UPDATE response_actions
                        SET status='rolled_back',
                            rollback_by=%s,
                            rollback_reason='ignored',
                            rolled_back_at=COALESCE(rolled_back_at, now()),
                            updated_at=now()
                        WHERE incident_id=%s::uuid
                          AND status IN ('suggested','approved','pending','applying','applied','applied_degraded')
                        RETURNING id::text AS id
                        """,
                        (actor, incident_id),
                    )
                    rolled_back = [r["id"] for r in (cur.fetchall() or [])]
                # Keep visible incident status update schema-safe: do not patch evidence_json.
                # The durable ignore state is stored in response_ignores and is the source of truth.
                incident_row = {"id": incident_id, "status": inc.get("status")}
                status_warning = None
                try:
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status='ignored',
                            closed_at=NULL,
                            updated_at=now()
                        WHERE id=%s::uuid
                        RETURNING id::text AS id, status
                        """,
                        (incident_id,),
                    )
                    incident_row = cur.fetchone() or incident_row
                except Exception as exc:
                    # Ignore is already active; do not fail the endpoint just because the visible status update failed.
                    status_warning = f"status_ignored_failed: {exc}"
        try:
            sync = phase6_run_response_engine(["sync-only"])
        except Exception as exc:
            sync = {"ok": False, "warning": "sync_after_ignore_failed", "message": str(exc)}
        return {"status": "ok", "incident_id": incident_id, "incident_status": incident_row.get("status"), "status_warning": status_warning, "device_id": device_id, "device_ip": device_ip, "incident_type": incident_type, "source_system": source_system, "ignore_id": ignore_id, "suppression_id": ignore_id, "disabled_old_ignore_ids": disabled_old, "rolled_back_action_ids": rolled_back, "sync": sync}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "ignore_failed", "message": str(exc), "incident_id": incident_id})


@app.post("/api/v1/incidents/{incident_id}/ignore")
def phase6_ignore_incident_type_for_device(payload: ResponseIgnorePayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    return phase6_ignore_incident_type_for_device_impl(payload, incident_id)


@app.post("/api/v1/incidents/{incident_id}/response/ignore")
def phase6_ignore_incident_type_for_device_alias(payload: ResponseIgnorePayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    return phase6_ignore_incident_type_for_device_impl(payload, incident_id)


@app.post("/api/v1/incidents/{incident_id}/ignore-force")
def phase6_ignore_incident_type_for_device_force(payload: ResponseIgnorePayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    # Extra stable alias used by Home Assistant fallback scripts.
    return phase6_ignore_incident_type_for_device_impl(payload, incident_id)


@app.post("/api/v1/incidents/{incident_id}/ignore-minimal")
def phase6_ignore_incident_type_for_device_minimal(payload: ResponseIgnorePayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    return phase6_ignore_incident_type_for_device_impl(payload, incident_id)


@app.post("/api/v1/incidents/{incident_id}/response/unignore")
def phase6_unignore_incident_type_for_device(payload: ResponseRollbackPayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    return phase6_rollback_incident_response(payload or ResponseRollbackPayload(reason="unignore"), incident_id)


@app.post("/api/v1/incidents/{incident_id}/false-positive")
def phase6_mark_incident_false_positive(payload: ResponseFalsePositivePayload | None = Body(default=None), incident_id: str = Path(...), _: None = Security(require_api_key)):
    incident_id = normalize_uuid_text(incident_id)
    payload = payload or ResponseFalsePositivePayload()
    args = ["false-positive", "--incident-id", incident_id, "--actor", clean_optional_text(payload.actor) or "api"]
    if payload.reason:
        args += ["--reason", payload.reason]
    if payload.ttl_hours is not None:
        args += ["--ttl-hours", str(int(payload.ttl_hours))]
    return phase6_run_response_engine(args)


@app.get("/api/v1/response/suppressions")
def phase6_list_suppressions(active_only: bool = Query(default=False), ignore_only: bool = Query(default=False), device_id: str | None = Query(default=None), limit: int = Query(default=200, ge=1, le=500), offset: int = Query(default=0, ge=0), _: None = Security(require_api_key)):
    """List ignores for Home Assistant using the dedicated response_ignores table."""
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                phase6_ensure_response_ignores(cur)
                clauses: list[str] = []
                params: list[Any] = []
                if active_only:
                    clauses.append("COALESCE(ri.is_enabled, true)=true AND (ri.expires_at IS NULL OR ri.expires_at > now())")
                if device_id:
                    clauses.append("ri.device_id=%s::uuid")
                    params.append(normalize_uuid_text(device_id))
                where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
                cur.execute(f"SELECT COUNT(*)::int AS total FROM response_ignores ri {where_sql}", params)
                total = cur.fetchone()["total"]
                cur.execute(
                    f"""
                    SELECT ri.id::text AS id,
                           ri.is_enabled,
                           'incident_pattern' AS scope,
                           ri.device_id::text AS device_id,
                           ri.incident_type,
                           ri.source_system,
                           NULL::text AS severity,
                           NULL::text AS domain,
                           NULL::text AS country_code,
                           NULL::text AS signature_id,
                           NULL::text AS signature_name,
                           NULL::text AS title_pattern,
                           ri.reason,
                           ri.created_by,
                           ri.expires_at,
                           ri.created_at,
                           ri.updated_at,
                           COALESCE(d.hostname, d.reverse_dns_name, d.mac_address, ri.device_id::text) AS device_hostname,
                           host(d.current_ip) AS device_ip
                    FROM response_ignores ri
                    LEFT JOIN devices d ON d.id=ri.device_id
                    {where_sql}
                    ORDER BY ri.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [limit, offset],
                )
                items = [phase6_suppression_public_row(dict(row)) for row in (cur.fetchall() or [])]
                return {"total": total, "limit": limit, "offset": offset, "items": items}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "list_ignores_failed", "message": str(exc)})


@app.post("/api/v1/response/suppressions")
def phase6_create_suppression(payload: ResponseSuppressionPayload, _: None = Security(require_api_key)):
    expires_at = None
    if payload.ttl_hours is not None and int(payload.ttl_hours) > 0:
        expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=int(payload.ttl_hours))
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "response_suppressions"):
                raise HTTPException(status_code=500, detail="response_suppressions table not found; run Phase 6 schema patch")
            cols = phase6_columns(cur, "response_suppressions")
            values = {
                "scope": phase6_clean_text(payload.scope) or "incident_pattern",
                "device_id": normalize_uuid_text(payload.device_id) if payload.device_id else None,
                "incident_type": phase6_clean_text(payload.incident_type),
                "source_system": phase6_clean_text(payload.source_system),
                "severity": phase6_clean_text(payload.severity),
                "domain": phase6_clean_text(payload.domain),
                "country_code": (phase6_clean_text(payload.country_code) or "").upper() or None,
                "signature_id": phase6_clean_text(payload.signature_id),
                "title_pattern": phase6_clean_text(payload.title_pattern),
                "reason": phase6_clean_text(payload.reason),
                "created_by": phase6_clean_text(payload.created_by) or "api",
                "expires_at": expires_at,
                "is_enabled": True,
            }
            # Do not create duplicate active ignores for the same device/type/source pattern.
            title_condition = "title_pattern IS NOT DISTINCT FROM %(title_pattern)s" if "title_pattern" in cols else "TRUE"
            cur.execute(
                f"""
                SELECT id::text AS id
                FROM response_suppressions
                WHERE COALESCE(is_enabled, true) = true
                  AND (expires_at IS NULL OR expires_at > now())
                  AND scope IS NOT DISTINCT FROM %(scope)s
                  AND {phase6_suppression_device_id_condition(cur, "device_id", "%(device_id)s")}
                  AND incident_type IS NOT DISTINCT FROM %(incident_type)s
                  AND source_system IS NOT DISTINCT FROM %(source_system)s
                  AND severity IS NOT DISTINCT FROM %(severity)s
                  AND domain IS NOT DISTINCT FROM %(domain)s
                  AND country_code IS NOT DISTINCT FROM %(country_code)s
                  AND signature_id IS NOT DISTINCT FROM %(signature_id)s
                  AND {title_condition}
                ORDER BY created_at DESC
                LIMIT 1
                """,
                values,
            )
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    UPDATE response_suppressions
                    SET reason = COALESCE(%(reason)s, reason),
                        created_by = %(created_by)s,
                        expires_at = %(expires_at)s,
                        is_enabled = true,
                        updated_at = now()
                    WHERE id = %(id)s::uuid
                    RETURNING id::text AS id
                    """,
                    {**values, "id": existing["id"]},
                )
                row = cur.fetchone()
                return {"status": "ok", "id": row["id"] if row else existing["id"], "deduplicated": True}
            insert_cols = ["scope", "device_id", "incident_type", "source_system", "severity", "domain", "country_code", "signature_id", "reason", "created_by", "expires_at", "is_enabled", "created_at", "updated_at"]
            insert_vals = ["%(scope)s", phase6_suppression_device_id_insert_expr(cur, "%(device_id)s"), "%(incident_type)s", "%(source_system)s", "%(severity)s", "%(domain)s", "%(country_code)s", "%(signature_id)s", "%(reason)s", "%(created_by)s", "%(expires_at)s", "%(is_enabled)s", "now()", "now()"]
            if "title_pattern" in cols:
                insert_cols.insert(8, "title_pattern")
                insert_vals.insert(8, "%(title_pattern)s")
            cur.execute(
                f"INSERT INTO response_suppressions({', '.join(insert_cols)}) VALUES ({', '.join(insert_vals)}) RETURNING id::text AS id",
                values,
            )
            row = cur.fetchone()
    return {"status": "ok", "id": row["id"] if row else None, "deduplicated": False}


@app.delete("/api/v1/response/suppressions/{suppression_id}")
def phase6_disable_suppression(suppression_id: str = Path(...), _: None = Security(require_api_key)):
    suppression_id = normalize_uuid_text(suppression_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE response_suppressions SET is_enabled=false, updated_at=now() WHERE id=%s::uuid RETURNING id::text AS id", (suppression_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Suppression not found")
    return {"status": "ok", "id": suppression_id, "is_enabled": False}


@app.get("/api/v1/response/device-overrides")
def phase6_list_device_overrides(limit: int = Query(default=200, ge=1, le=500), offset: int = Query(default=0, ge=0), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "device_response_overrides"):
                return {"total": 0, "items": []}
            cols = phase6_columns(cur, "device_response_overrides")
            id_expr = "dro.id::text" if "id" in cols else "dro.device_id::text"
            if "auto_response_enabled" in cols and "automation_enabled" in cols:
                auto_expr = "COALESCE(dro.auto_response_enabled, dro.automation_enabled, true)"
            elif "auto_response_enabled" in cols:
                auto_expr = "COALESCE(dro.auto_response_enabled, true)"
            elif "automation_enabled" in cols:
                auto_expr = "COALESCE(dro.automation_enabled, true)"
            else:
                auto_expr = "true"
            max_expr = "dro.max_auto_action" if "max_auto_action" in cols else "NULL::text"
            pref_expr = "dro.preferred_action" if "preferred_action" in cols else "NULL::text"
            suppress_expr = "dro.suppress_until" if "suppress_until" in cols else "NULL::timestamptz"
            notes_expr = "dro.notes" if "notes" in cols else "NULL::text"
            updated_by_expr = "dro.updated_by" if "updated_by" in cols else "NULL::text"
            created_expr = "dro.created_at" if "created_at" in cols else "NULL::timestamptz"
            updated_expr = "dro.updated_at" if "updated_at" in cols else "NULL::timestamptz"
            cur.execute("SELECT COUNT(*)::int AS total FROM device_response_overrides")
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT {id_expr} AS id, dro.device_id::text AS device_id,
                       d.hostname AS device_hostname, host(d.current_ip) AS device_ip,
                       {auto_expr} AS auto_response_enabled,
                       {max_expr} AS max_auto_action,
                       {pref_expr} AS preferred_action,
                       {suppress_expr} AS suppress_until,
                       {notes_expr} AS notes,
                       {updated_by_expr} AS updated_by,
                       {created_expr} AS created_at,
                       {updated_expr} AS updated_at
                FROM device_response_overrides dro
                LEFT JOIN devices d ON d.id = dro.device_id
                ORDER BY {updated_expr} DESC NULLS LAST
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            return {"total": total, "limit": limit, "offset": offset, "items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}


@app.post("/api/v1/devices/{device_id}/response-override")
def phase6_set_device_override(payload: ResponseDeviceOverridePayload, device_id: str = Path(...), _: None = Security(require_api_key)):
    device_id = normalize_uuid_text(device_id)
    suppress_until = None
    suppress_minutes = payload.suppress_minutes
    if suppress_minutes is None and payload.suppress_ttl_hours is not None:
        suppress_minutes = int(payload.suppress_ttl_hours) * 60
    if suppress_minutes is not None and int(suppress_minutes) > 0:
        suppress_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=int(suppress_minutes))
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase6_table_exists(cur, "device_response_overrides"):
                raise HTTPException(status_code=500, detail="device_response_overrides table not found; run Phase 6 schema patch")
            cols = phase6_columns(cur, "device_response_overrides")
            # phase6_response_schema_patch_v26.sql adds the modern columns; keep this endpoint tolerant anyway.
            insert_cols = ["device_id"]
            insert_vals = ["%s::uuid"]
            params: list[Any] = [device_id]
            updates: list[str] = []
            def add_col(name: str, value: Any):
                if name in cols:
                    insert_cols.append(name)
                    insert_vals.append("%s")
                    params.append(value)
                    updates.append(f"{name}=EXCLUDED.{name}")
            add_col("auto_response_enabled", payload.auto_response_enabled)
            add_col("automation_enabled", payload.auto_response_enabled)
            add_col("max_auto_action", payload.max_auto_action)
            add_col("preferred_action", payload.preferred_action)
            add_col("suppress_until", suppress_until)
            add_col("notes", payload.notes)
            add_col("updated_by", payload.updated_by or "api")
            if "created_at" in cols:
                insert_cols.append("created_at"); insert_vals.append("now()")
            if "updated_at" in cols:
                insert_cols.append("updated_at"); insert_vals.append("now()"); updates.append("updated_at=now()")
            returning = "id::text AS id" if "id" in cols else "device_id::text AS id"
            cur.execute(
                f"""
                INSERT INTO device_response_overrides({', '.join(insert_cols)})
                VALUES ({', '.join(insert_vals)})
                ON CONFLICT (device_id) DO UPDATE SET {', '.join(updates) if updates else 'device_id=EXCLUDED.device_id'}
                RETURNING {returning}
                """,
                params,
            )
            row = cur.fetchone()
    return {"status": "ok", "id": row["id"] if row else device_id, "device_id": device_id}


@app.delete("/api/v1/devices/{device_id}/response-override")
def phase6_delete_device_override(device_id: str = Path(...), _: None = Security(require_api_key)):
    device_id = normalize_uuid_text(device_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cols = phase6_columns(cur, "device_response_overrides") if phase6_table_exists(cur, "device_response_overrides") else set()
            returning = "id::text AS id" if "id" in cols else "device_id::text AS id"
            cur.execute(f"DELETE FROM device_response_overrides WHERE device_id=%s::uuid RETURNING {returning}", (device_id,))
            row = cur.fetchone()
    return {"status": "ok", "device_id": device_id, "deleted": bool(row)}


# -----------------------------------------------------------------------------
# Phase 7 audit, notifications, exports and reports API
# -----------------------------------------------------------------------------

PHASE7_REPORT_ENGINE_SCRIPT = os.environ.get("PHASE7_REPORT_ENGINE_SCRIPT", "/opt/security-core/app/worker/report_engine.py")
PHASE7_CAPTURE_DIR = FilePath(os.environ.get("PHASE7_CAPTURE_DIR", "/opt/security-core/captures"))
PHASE7_REPORT_DIR = FilePath(os.environ.get("PHASE7_REPORT_DIR", "/opt/security-core/reports"))
PHASE7_EXPORT_MAX_ROWS = int(os.environ.get("PHASE7_EXPORT_MAX_ROWS", "10000") or "10000")
PHASE7_PUBLIC_BASE_URL = (os.environ.get("PHASE7_PUBLIC_BASE_URL") or f"http://{SECURITY_CORE_BIND}:{os.environ.get('SECURITY_CORE_PORT', '8000')}").rstrip("/")
PHASE7_CAPTURE_WORKER_SCRIPT = os.environ.get("PHASE7_CAPTURE_WORKER_SCRIPT", "/opt/security-core/app/worker/capture_worker.py")


class Phase7ReportGeneratePayload(BaseModel):
    period_days: int = 7
    report_type: str = "weekly"
    output_format: str = "html"
    actor: str | None = "api"


class Phase7NotificationRulePayload(BaseModel):
    rule_name: str
    is_enabled: bool = True
    min_severity: str = "high"
    event_types: list[str] | None = None
    channels: list[str] | None = None
    cooldown_minutes: int = 60


class Phase7CaptureStartPayload(BaseModel):
    device_id: str | None = None
    device_ip: str | None = None
    duration_seconds: int | None = None
    interface_name: str | None = "lan"
    max_file_mb: int | None = None
    actor: str | None = "home-assistant"


class Phase7CaptureStopPayload(BaseModel):
    actor: str | None = "home-assistant"


def phase7_table_exists(cur, table_name: str) -> bool:
    cur.execute("SELECT to_regclass(%s) IS NOT NULL AS exists", (f"public.{table_name}",))
    return bool((cur.fetchone() or {}).get("exists"))


def phase7_clean_limit(limit: int, max_value: int | None = None) -> int:
    max_value = max_value or PHASE7_EXPORT_MAX_ROWS
    return max(1, min(int(limit), int(max_value)))


def phase7_period_clauses(column_name: str, from_time: str | None, to_time: str | None) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if from_time:
        clauses.append(f"{column_name} >= %s::timestamptz")
        params.append(from_time)
    if to_time:
        clauses.append(f"{column_name} <= %s::timestamptz")
        params.append(to_time)
    return clauses, params


def phase7_insert_audit_event(cur, actor_type: str, actor_name: str, event_type: str, target_type: str | None = None, target_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    if not phase7_table_exists(cur, "audit_events"):
        return
    cur.execute(
        """
        INSERT INTO audit_events(actor_type, actor_name, event_type, target_type, target_id, event_time, details_json)
        VALUES (%s, %s, %s, %s, %s, now(), %s)
        """,
        (actor_type, actor_name, event_type, target_type, target_id, j(details or {})),
    )


def phase7_csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    value = phase7_decode_json_safe(value)
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(ascii_json_safe(value), ensure_ascii=False, default=str)
    return phase7_decode_embedded_hex_text(value)


def phase7_csv_response(filename: str, rows: list[dict[str, Any]]) -> Response:
    import csv
    import io

    output = io.StringIO()
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    writer = csv.DictWriter(output, fieldnames=fieldnames or ["empty"])
    writer.writeheader()
    for row in rows:
        writer.writerow({key: phase7_csv_value(row.get(key)) for key in fieldnames})
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def phase7_db_text(value: Any) -> str:
    """Return safe text for values that may come back as bytes/memoryview.

    Important: older schema drift sometimes returns TEXT values as bytea. Some
    short strings, for example ``host REDACTED`` or ``detection-worker``, are
    exactly 16 bytes long. Those must be decoded as text, not rendered as UUIDs.
    Only fall back to UUID formatting when the 16 raw bytes are not printable
    UTF-8 text.
    """
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            decoded = raw.decode("utf-8", errors="strict").strip()
            if decoded and all((ch.isprintable() or ch in "\r\n\t") for ch in decoded):
                return decoded
        except Exception:
            pass
        if len(raw) == 16:
            try:
                return str(uuid.UUID(bytes=raw))
            except Exception:
                pass
        return raw.decode("utf-8", errors="ignore").strip()
    return str(value).strip()




def phase7_uuid_id_text(value: Any) -> str:
    """Normalize UUID-ish DB/API values to plain UUID text.

    This is deliberately stricter than phase7_db_text for report/capture IDs.
    It also cleans accidental string representations such as b'uuid'.
    """
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
    text = phase7_db_text(value).strip()
    if (text.startswith("b'") and text.endswith("'")) or (text.startswith('b"') and text.endswith('"')):
        text = text[2:-1].strip()
    if text.startswith("\\x") and len(text) == 34:
        return str(uuid.UUID(bytes=bytes.fromhex(text[2:])))
    return str(uuid.UUID(text))

def phase7_maybe_decode_hex_text(value: Any) -> str:
    text = phase7_db_text(value)
    if not text:
        return ""
    candidates: list[str] = []
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
        if decoded and all((ch.isprintable() or ch in "\r\n\t") for ch in decoded) and any(ch.isalpha() for ch in decoded):
            return decoded
    return text


def phase7_decode_embedded_hex_text(value: Any) -> str:
    text = phase7_db_text(value)
    if not text:
        return ""

    def repl(match):
        original = match.group(0)
        decoded = phase7_maybe_decode_hex_text(original)
        return decoded if decoded != original else original

    pattern = re.compile(
        r"(?<![0-9A-Fa-f])(?:"
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        r"|\\x[0-9A-Fa-f]{8,}"
        r"|[0-9A-Fa-f]{12,}"
        r")(?![0-9A-Fa-f])"
    )
    return pattern.sub(repl, text)


def phase7_decode_notification_row(row: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "rule_name",
        "channel",
        "status",
        "error_message",
        "incident_severity",
        "incident_title",
        "device_hostname",
        "device_ip",
    ):
        if key in row and row.get(key) is not None:
            row[key] = phase7_decode_embedded_hex_text(row.get(key))
    for key in ("message_title", "message_body"):
        if key in row and row.get(key) is not None:
            row[key] = phase7_decode_embedded_hex_text(row.get(key))
    return row


def phase7_decode_notification_rule_row(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("rule_name") is not None:
        row["rule_name"] = phase7_maybe_decode_hex_text(row.get("rule_name"))
    if isinstance(row.get("event_types"), list):
        row["event_types"] = [phase7_maybe_decode_hex_text(x) for x in row["event_types"]]
    if isinstance(row.get("channels"), list):
        row["channels"] = [phase7_maybe_decode_hex_text(x) for x in row["channels"]]
    return row




def phase7_decode_public_row(row: dict[str, Any]) -> dict[str, Any]:
    """Decode human-readable text fields that may be stored as bytea/hex-looking text."""
    text_keys = {
        "rule_name", "channel", "status", "error_message", "incident_severity", "incident_title",
        "device_hostname", "device_ip", "hostname", "current_ip", "vendor", "model", "category",
        "title", "description", "source_system", "incident_type", "event_type", "actor_type",
        "actor_name", "target_type", "target_id", "component_name", "component_type", "version",
        "interface_name", "bpf_filter", "file_path", "created_by", "report_type", "report_format",
        "generated_by", "country_code", "domain", "protocol", "severity", "policy_effective_mode",
        "message", "message_title", "message_body", "dedupe_key", "sha256", "download_url", "download_token",
    }
    for key, value in list(row.items()):
        if value is None:
            continue
        if key in text_keys:
            row[key] = phase7_decode_embedded_hex_text(value)
        elif isinstance(value, dict):
            row[key] = phase7_decode_json_safe(value)
        elif isinstance(value, list):
            row[key] = [phase7_decode_json_safe(v) for v in value]
    return row


def phase7_decode_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {phase7_maybe_decode_hex_text(k): phase7_decode_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [phase7_decode_json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview, str)):
        return phase7_decode_embedded_hex_text(value)
    return value

def phase7_public_token(kind: str, object_id: str | None = None) -> str:
    normalized_id = object_id
    if object_id and kind in {"report", "capture"}:
        try:
            normalized_id = phase7_uuid_id_text(object_id)
        except Exception:
            normalized_id = phase7_db_text(object_id)
    subject = f"{kind}:{normalized_id or '*'}"
    return hmac.new(API_KEY.encode("utf-8"), subject.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def phase7_verify_public_token(kind: str, object_id: str | None, token: str | None) -> None:
    expected = phase7_public_token(kind, object_id)
    if not token or not hmac.compare_digest(str(token), expected):
        raise HTTPException(status_code=401, detail="Invalid download token")


def phase7_public_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{PHASE7_PUBLIC_BASE_URL}{path}"


class Phase7UiSelectionPayload(BaseModel):
    selection_type: str
    object_id: str | None = None
    label: str | None = None
    actor: str | None = "home-assistant"


def phase7_ui_downloads_enabled() -> bool:
    return os.environ.get("PHASE7_BROWSER_DIRECT_DOWNLOADS", "true").lower() in {"1", "true", "yes", "on"}


def phase7_require_browser_download_enabled() -> None:
    if not phase7_ui_downloads_enabled():
        raise HTTPException(status_code=403, detail="Browser direct downloads are disabled")


def phase7_ensure_ui_state_table(cur) -> None:
    # The table is also created by phase7_ui_migration.sql. This defensive path
    # keeps the UI usable even if the SQL migration was forgotten.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS phase7_ui_state (
            selection_type TEXT PRIMARY KEY,
            object_id TEXT NULL,
            label TEXT NULL,
            updated_by TEXT NOT NULL DEFAULT 'api',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            details_json JSONB NOT NULL DEFAULT '{}'
        )
        """
    )


def phase7_set_ui_selection(cur, selection_type: str, object_id: str | None, label: str | None, actor: str | None = None) -> dict[str, Any]:
    selection_type = phase7_maybe_decode_hex_text(selection_type).strip().lower().replace(" ", "_")
    if selection_type not in {"report", "capture"}:
        raise HTTPException(status_code=400, detail="selection_type must be report or capture")
    object_id = clean_optional_text(object_id)
    label = clean_optional_text(label)
    if object_id in {"unknown", "unavailable", "none", "No reports", "No captures"}:
        object_id = None
    if object_id:
        # Validate UUID-like report/capture ids.
        object_id = normalize_uuid_text(object_id)
    actor = clean_optional_text(actor) or "api"
    phase7_ensure_ui_state_table(cur)
    cur.execute(
        """
        INSERT INTO phase7_ui_state(selection_type, object_id, label, updated_by, updated_at, details_json)
        VALUES (%s, %s, %s, %s, now(), %s)
        ON CONFLICT(selection_type)
        DO UPDATE SET object_id=EXCLUDED.object_id,
                      label=EXCLUDED.label,
                      updated_by=EXCLUDED.updated_by,
                      updated_at=now(),
                      details_json=EXCLUDED.details_json
        RETURNING selection_type, object_id, label, updated_by, updated_at
        """,
        (selection_type, object_id, label, actor, j({"source": "home_assistant"})),
    )
    row = dict(cur.fetchone())
    phase7_insert_audit_event(cur, "api", actor, f"ui_{selection_type}_selected", selection_type, object_id, {"label": label})
    return row


def phase7_get_ui_selection(cur, selection_type: str) -> str | None:
    selection_type = selection_type.strip().lower().replace(" ", "_")
    phase7_ensure_ui_state_table(cur)
    cur.execute("SELECT object_id FROM phase7_ui_state WHERE selection_type=%s", (selection_type,))
    row = cur.fetchone()
    return phase7_uuid_id_text(row.get("object_id")) if row and row.get("object_id") else None


def phase7_latest_report_id(cur) -> str | None:
    if not phase7_table_exists(cur, "generated_reports"):
        return None
    cur.execute("SELECT id::text AS id FROM generated_reports WHERE status='generated' ORDER BY created_at DESC LIMIT 1")
    row = cur.fetchone()
    return phase7_uuid_id_text(row.get("id")) if row else None




def phase7_latest_capture_id(cur) -> str | None:
    if not phase7_table_exists(cur, "packet_captures"):
        return None
    cur.execute("""
        SELECT id::text AS id
        FROM packet_captures
        WHERE status IN ('completed','empty')
          AND file_path IS NOT NULL
        ORDER BY CASE WHEN status='completed' THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
    """)
    row = cur.fetchone()
    return phase7_uuid_id_text(row.get("id")) if row else None

def phase7_file_response_from_report_id(report_id: str) -> FileResponse:
    report_id = phase7_uuid_id_text(report_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "generated_reports"):
                raise HTTPException(status_code=404, detail="Report table not found")
            cur.execute("SELECT file_path, report_format FROM generated_reports WHERE id = %s::uuid", (report_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Report not found")
    file_path = FilePath(phase7_db_text(row.get("file_path")))
    try:
        resolved = file_path.resolve()
        allowed = PHASE7_REPORT_DIR.resolve()
        if allowed not in resolved.parents and resolved != allowed:
            raise HTTPException(status_code=403, detail="Report path is outside allowed directory")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    report_format = (phase7_db_text(row.get("report_format")) or file_path.suffix.lstrip(".") or "html").lower()
    media_type = "application/pdf" if report_format == "pdf" else "text/html; charset=utf-8"
    return FileResponse(str(file_path), media_type=media_type, filename=file_path.name)


def phase7_file_response_from_capture_id(capture_id: str, allow_fallback: bool = False) -> FileResponse:
    capture_id = phase7_uuid_id_text(capture_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "packet_captures"):
                raise HTTPException(status_code=404, detail="Capture table not found")
            cur.execute("SELECT id::text AS id, file_path, status FROM packet_captures WHERE id = %s::uuid", (capture_id,))
            row = cur.fetchone()
            if (not row or phase7_db_text(row.get("status")) in {"failed", "deleted"}) and allow_fallback:
                fallback_id = phase7_latest_capture_id(cur)
                if fallback_id and fallback_id != capture_id:
                    cur.execute("SELECT id::text AS id, file_path, status FROM packet_captures WHERE id = %s::uuid", (fallback_id,))
                    row = cur.fetchone()
                    capture_id = fallback_id
            if not row:
                raise HTTPException(status_code=404, detail="Capture not found")
    status = phase7_db_text(row.get("status"))
    if status not in {"completed", "empty"}:
        raise HTTPException(status_code=409, detail=f"Capture is not ready for download: {status}")
    file_path = FilePath(phase7_db_text(row.get("file_path")))
    try:
        resolved = file_path.resolve()
        allowed = PHASE7_CAPTURE_DIR.resolve()
        if allowed not in resolved.parents and resolved != allowed:
            raise HTTPException(status_code=403, detail="Capture path is outside allowed directory")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if not file_path.exists() and status == "empty":
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            # Classic pcap global header, little-endian, empty packet list.
            file_path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
        except Exception:
            pass
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Capture file not found")
    if status == "empty" and file_path.stat().st_size == 0:
        file_path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    return FileResponse(str(file_path), media_type="application/vnd.tcpdump.pcap", filename=file_path.name)


@app.post("/api/v1/ui/selection")
def phase7_update_ui_selection(payload: Phase7UiSelectionPayload, _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            row = phase7_set_ui_selection(cur, payload.selection_type, payload.object_id, payload.label, payload.actor)
            return {"status": "ok", "selection": row}


@app.get("/api/v1/ui/selection")
def phase7_get_ui_selection_endpoint(selection_type: str = Query(default="report"), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            phase7_ensure_ui_state_table(cur)
            cur.execute("SELECT selection_type, object_id, label, updated_by, updated_at FROM phase7_ui_state WHERE selection_type=%s", (selection_type,))
            row = cur.fetchone()
            return {"selection": dict(row) if row else None}


@app.head("/api/v1/public/ui/selected-report/download")
@app.get("/api/v1/public/ui/selected-report/download")
def phase7_public_ui_selected_report_download():
    phase7_require_browser_download_enabled()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            rid = phase7_get_ui_selection(cur, "report")
    if not rid:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                rid = phase7_latest_report_id(cur)
    if not rid:
        raise HTTPException(status_code=404, detail="No report is selected")
    return phase7_file_response_from_report_id(rid)


@app.head("/api/v1/public/ui/latest-report/download")
@app.get("/api/v1/public/ui/latest-report/download")
def phase7_public_ui_latest_report_download():
    phase7_require_browser_download_enabled()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            rid = phase7_latest_report_id(cur)
    if not rid:
        raise HTTPException(status_code=404, detail="No generated report found")
    return phase7_file_response_from_report_id(rid)


@app.head("/api/v1/public/ui/selected-capture/download")
@app.get("/api/v1/public/ui/selected-capture/download")
def phase7_public_ui_selected_capture_download():
    phase7_require_browser_download_enabled()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cid = phase7_get_ui_selection(cur, "capture")
    if not cid:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cid = phase7_latest_capture_id(cur)
    if not cid:
        raise HTTPException(status_code=404, detail="No capture is selected")
    return phase7_file_response_from_capture_id(cid, allow_fallback=True)


@app.get("/api/v1/public/ui/exports/{export_name}")
def phase7_public_ui_export_download(export_name: str = Path(...), limit: int = Query(default=5000, ge=1, le=50000)):
    phase7_require_browser_download_enabled()
    raw = export_name.strip().lower()
    export_type = raw[:-4] if raw.endswith(".csv") else raw
    if export_type == "evidence-bundle.json":
        export_type = "evidence-bundle"
    if export_type not in {"incidents", "security-events", "traffic-samples", "audit-events", "evidence-bundle"}:
        raise HTTPException(status_code=404, detail="Unknown export")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if export_type == "evidence-bundle":
                data = {
                    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "incidents": phase7_export_query(cur, "incidents", None, None, None, None, None, None, limit),
                    "security_events": phase7_export_query(cur, "security-events", None, None, None, None, None, None, limit),
                    "audit_events": phase7_export_query(cur, "audit-events", None, None, None, None, None, None, limit),
                }
                return Response(
                    content=json.dumps(ascii_json_safe(data), ensure_ascii=False, default=str),
                    media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="security-core-evidence-bundle.json"'},
                )
            rows = phase7_export_query(cur, export_type, None, None, None, None, None, None, limit)
            filename = f"security-core-{export_type}.csv"
            return phase7_csv_response(filename, rows)


@app.get("/api/v1/audit-events")
def phase7_list_audit_events(
    actor_type: str | None = Query(default=None),
    actor_name: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    target_type: str | None = Query(default=None),
    target_id: str | None = Query(default=None),
    from_time: str | None = Query(default=None, alias="from"),
    to_time: str | None = Query(default=None, alias="to"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            audit_exists = phase7_table_exists(cur, "audit_events")
            response_events_exists = phase7_table_exists(cur, "response_action_events")
            if not audit_exists and not response_events_exists:
                return {"total": 0, "limit": limit, "offset": offset, "items": []}
            union_parts: list[str] = []
            if audit_exists:
                union_parts.append(
                    """
                    SELECT
                        'audit_events' AS source_table,
                        id::text AS id,
                        actor_type,
                        actor_name,
                        event_type,
                        target_type,
                        target_id,
                        event_time,
                        details_json
                    FROM audit_events
                    """
                )
            if response_events_exists:
                union_parts.append(
                    """
                    SELECT
                        'response_action_events' AS source_table,
                        id::text AS id,
                        'system' AS actor_type,
                        actor AS actor_name,
                        event_type,
                        'response_action' AS target_type,
                        response_action_id::text AS target_id,
                        created_at AS event_time,
                        jsonb_build_object(
                            'incident_id', incident_id::text,
                            'device_id', device_id::text,
                            'message', message,
                            'details', details_json
                        ) AS details_json
                    FROM response_action_events
                    """
                )
            clauses, params = phase7_period_clauses("event_time", from_time, to_time)
            if actor_type:
                clauses.append("actor_type = %s")
                params.append(actor_type)
            if actor_name:
                clauses.append("actor_name ILIKE %s")
                params.append(f"%{actor_name}%")
            if event_type:
                clauses.append("event_type ILIKE %s")
                params.append(f"%{event_type}%")
            if target_type:
                clauses.append("target_type = %s")
                params.append(target_type)
            if target_id:
                clauses.append("target_id = %s")
                params.append(target_id)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            base_sql = f"WITH events AS ({' UNION ALL '.join(union_parts)}) SELECT * FROM events {where_sql}"
            cur.execute(f"SELECT COUNT(*)::int AS total FROM ({base_sql}) x", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                {base_sql}
                ORDER BY event_time DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            return {"total": total, "limit": limit, "offset": offset, "items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}


@app.get("/api/v1/notifications/deliveries")
def phase7_list_notification_deliveries(
    status: str | None = Query(default=None),
    channel: str | None = Query(default=None),
    incident_id: str | None = Query(default=None),
    from_time: str | None = Query(default=None, alias="from"),
    to_time: str | None = Query(default=None, alias="to"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "notification_deliveries"):
                return {"total": 0, "limit": limit, "offset": offset, "items": []}
            clauses, params = phase7_period_clauses("nd.created_at", from_time, to_time)
            if status:
                clauses.append("nd.status = %s")
                params.append(status)
            if channel:
                clauses.append("nd.channel = %s")
                params.append(channel)
            if incident_id:
                clauses.append("nd.incident_id = %s::uuid")
                params.append(normalize_uuid_text(incident_id))
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            base_sql = f"""
                FROM notification_deliveries nd
                LEFT JOIN incidents i ON i.id = nd.incident_id
                LEFT JOIN devices d ON d.id = nd.device_id
                {where_sql}
            """
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT nd.id::text AS id,
                       nd.rule_name,
                       nd.channel,
                       nd.status,
                       nd.dedupe_key,
                       nd.incident_id::text AS incident_id,
                       nd.device_id::text AS device_id,
                       nd.message_title,
                       nd.message_body,
                       nd.response_json,
                       nd.error_message,
                       nd.sent_at,
                       nd.created_at,
                       i.severity AS incident_severity,
                       i.title AS incident_title,
                       d.hostname AS device_hostname,
                       host(d.current_ip) AS device_ip
                {base_sql}
                ORDER BY nd.created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = [phase7_decode_notification_row(dict(row)) for row in cur.fetchall()]
            return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/notifications/rules")
def phase7_list_notification_rules(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "notification_rules"):
                return {"items": []}
            cur.execute(
                """
                SELECT id::text AS id, rule_name, is_enabled, min_severity, event_types, channels,
                       cooldown_minutes, created_at, updated_at
                FROM notification_rules
                ORDER BY rule_name
                """
            )
            items = [phase7_decode_notification_rule_row(dict(row)) for row in cur.fetchall()]
            return {"items": items}


@app.post("/api/v1/notifications/rules")
def phase7_upsert_notification_rule(payload: Phase7NotificationRulePayload, _: None = Security(require_api_key)):
    rule_name = clean_optional_text(payload.rule_name)
    if not rule_name:
        raise HTTPException(status_code=400, detail="rule_name is required")
    min_severity = normalize_security_severity(payload.min_severity)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "notification_rules"):
                raise HTTPException(status_code=500, detail="Phase 7 schema is not installed")
            cur.execute(
                """
                INSERT INTO notification_rules(rule_name, is_enabled, min_severity, event_types, channels, cooldown_minutes, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (rule_name) DO UPDATE SET
                    is_enabled = EXCLUDED.is_enabled,
                    min_severity = EXCLUDED.min_severity,
                    event_types = EXCLUDED.event_types,
                    channels = EXCLUDED.channels,
                    cooldown_minutes = EXCLUDED.cooldown_minutes,
                    updated_at = now()
                RETURNING id::text AS id
                """,
                (
                    rule_name,
                    bool(payload.is_enabled),
                    min_severity,
                    j(payload.event_types or []),
                    j(payload.channels or ["ha_persistent"]),
                    int(payload.cooldown_minutes),
                ),
            )
            row = cur.fetchone()
            phase7_insert_audit_event(cur, "api", "api", "notification_rule_upsert", "notification_rule", row["id"], {"rule_name": rule_name})
            return {"status": "ok", "id": row["id"], "rule_name": rule_name}


@app.get("/api/v1/reports")
def phase7_list_reports(
    report_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "generated_reports"):
                return {"total": 0, "limit": limit, "offset": offset, "items": []}
            clauses: list[str] = []
            params: list[Any] = []
            if report_type:
                clauses.append("report_type = %s")
                params.append(report_type)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            cur.execute(f"SELECT COUNT(*)::int AS total FROM generated_reports {where_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT id::text AS id, report_type, report_format, period_start, period_end, title,
                       file_path, file_size_bytes, sha256, status, error_message, generated_by, created_at
                FROM generated_reports
                {where_sql}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]
            for item in items:
                rid = phase7_db_text(item.get("id"))
                token = phase7_public_token("report", rid)
                item["download_token"] = token
                item["download_url"] = phase7_public_url(f"/api/v1/public/reports/{rid}/download?token=REDACTED")
            return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.post("/api/v1/reports/generate")
def phase7_generate_report(payload: Phase7ReportGeneratePayload | None = Body(default=None), _: None = Security(require_api_key)):
    payload = payload or Phase7ReportGeneratePayload()
    period_days = max(1, min(int(payload.period_days), 90))
    output_format = (clean_optional_text(payload.output_format) or "html").lower()
    if output_format not in {"html", "pdf"}:
        raise HTTPException(status_code=400, detail="output_format must be html or pdf")
    script = FilePath(PHASE7_REPORT_ENGINE_SCRIPT)
    if not script.exists():
        raise HTTPException(status_code=500, detail=f"Report engine script not found: {script}")
    cmd = [SECURITY_CORE_PYTHON, str(script), "generate", "--period-days", str(period_days), "--format", output_format, "--report-type", clean_optional_text(payload.report_type) or "weekly", "--actor", clean_optional_text(payload.actor) or "api"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail={"error": "report_generation_failed", "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:]})
    try:
        result = json.loads(proc.stdout or "{}")
    except Exception:
        result = {"status": "ok", "stdout": proc.stdout}
    report_id = result.get("report_id") if isinstance(result, dict) else None
    if report_id:
        try:
            report_id = phase7_uuid_id_text(report_id)
            result["report_id"] = report_id
            token = phase7_public_token("report", report_id)
            result["download_url"] = phase7_public_url(f"/api/v1/public/reports/{report_id}/download?token=REDACTED")
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    phase7_set_ui_selection(cur, "report", report_id, result.get("title") or report_id, clean_optional_text(payload.actor) or "api")
        except Exception:
            pass
    return result


@app.get("/api/v1/reports/{report_id}/download")
def phase7_download_report(report_id: str = Path(...), _: None = Security(require_api_key)):
    report_id = phase7_uuid_id_text(report_id)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "generated_reports"):
                raise HTTPException(status_code=404, detail="Report table not found")
            cur.execute("SELECT file_path, title, report_format FROM generated_reports WHERE id = %s::uuid", (report_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Report not found")
    file_path = FilePath(phase7_db_text(row.get("file_path")))
    try:
        resolved = file_path.resolve()
        allowed = PHASE7_REPORT_DIR.resolve()
        if allowed not in resolved.parents and resolved != allowed:
            raise HTTPException(status_code=403, detail="Report path is outside allowed directory")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    media_type = "application/pdf" if phase7_db_text(row.get("report_format")) == "pdf" else "text/html"
    return FileResponse(str(file_path), media_type=media_type, filename=file_path.name)


@app.get("/api/v1/public/reports/{report_id}/download")
def phase7_public_download_report(report_id: str = Path(...), token: str | None = Query(default=None)):
    report_id = normalize_uuid_text(report_id)
    phase7_verify_public_token("report", report_id, token)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "generated_reports"):
                raise HTTPException(status_code=404, detail="Report table not found")
            cur.execute("SELECT file_path, title, report_format FROM generated_reports WHERE id = %s::uuid", (report_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Report not found")
    file_path = FilePath(phase7_db_text(row.get("file_path")))
    try:
        resolved = file_path.resolve()
        allowed = PHASE7_REPORT_DIR.resolve()
        if allowed not in resolved.parents and resolved != allowed:
            raise HTTPException(status_code=403, detail="Report path is outside allowed directory")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    media_type = "application/pdf" if phase7_db_text(row.get("report_format")) == "pdf" else "text/html"
    return FileResponse(str(file_path), media_type=media_type, filename=file_path.name)


@app.get("/api/v1/captures")
def phase7_list_captures(
    device_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: None = Security(require_api_key),
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "packet_captures"):
                return {"total": 0, "limit": limit, "offset": offset, "items": []}
            clauses: list[str] = []
            params: list[Any] = []
            if device_id:
                clauses.append("pc.device_id = %s::uuid")
                params.append(normalize_uuid_text(device_id))
            if status:
                clauses.append("pc.status = %s")
                params.append(status)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            base_sql = f"""
                FROM packet_captures pc
                LEFT JOIN devices d ON d.id = pc.device_id
                LEFT JOIN incidents i ON i.id = pc.incident_id
                {where_sql}
            """
            cur.execute(f"SELECT COUNT(*)::int AS total {base_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT pc.id::text AS id, pc.incident_id::text AS incident_id, pc.device_id::text AS device_id,
                       pc.device_ip::text AS device_ip, pc.interface_name, pc.bpf_filter, pc.status, pc.pid,
                       pc.file_path, pc.file_size_bytes, pc.sha256, pc.started_at, pc.stopped_at,
                       pc.duration_seconds, pc.max_file_mb, pc.error_message, pc.created_by, pc.created_at,
                       d.hostname AS device_hostname, i.title AS incident_title
                {base_sql}
                ORDER BY pc.created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            items = [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]
            for item in items:
                cid = phase7_db_text(item.get("id"))
                token = phase7_public_token("capture", cid)
                item["download_token"] = token
                item["download_url"] = phase7_public_url(f"/api/v1/public/captures/{cid}/download?token=REDACTED")
            return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.head("/api/v1/captures/{capture_id}/download")
@app.get("/api/v1/captures/{capture_id}/download")
def phase7_download_capture(capture_id: str = Path(...), _: None = Security(require_api_key)):
    return phase7_file_response_from_capture_id(capture_id)


@app.head("/api/v1/public/captures/{capture_id}/download")
@app.get("/api/v1/public/captures/{capture_id}/download")
def phase7_public_download_capture(capture_id: str = Path(...), token: str | None = Query(default=None)):
    capture_id = phase7_uuid_id_text(capture_id)
    phase7_verify_public_token("capture", capture_id, token)
    return phase7_file_response_from_capture_id(capture_id)


@app.post("/api/v1/captures/start")
def phase7_request_capture_start(payload: Phase7CaptureStartPayload, _: None = Security(require_api_key)):
    duration = max(10, min(int(payload.duration_seconds or int(os.environ.get("PHASE7_CAPTURE_DEFAULT_SECONDS", "120") or "120")), 3600))
    max_mb = max(1, min(int(payload.max_file_mb or int(os.environ.get("PHASE7_CAPTURE_MAX_MB", "50") or "50")), 1024))
    interface_name = clean_optional_text(payload.interface_name) or os.environ.get("PHASE7_CAPTURE_INTERFACE", "lan") or "lan"
    actor = clean_optional_text(payload.actor) or "home-assistant"

    raw_device_id = clean_optional_text(payload.device_id)
    if raw_device_id and raw_device_id.lower() in {"unknown", "unavailable", "none", "null", "no devices"}:
        raw_device_id = None
    device_id = normalize_uuid_text(raw_device_id) if raw_device_id else None

    raw_device_ip = clean_optional_text(payload.device_ip)
    if raw_device_ip and raw_device_ip.lower() in {"unknown", "unavailable", "none", "null", "no-ip", "no devices"}:
        raw_device_ip = None
    device_ip = normalize_ip_text(raw_device_ip) if raw_device_ip else None

    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "packet_captures"):
                raise HTTPException(status_code=500, detail="Phase 7 capture schema is not installed")

            if device_id and not device_ip:
                cur.execute("SELECT host(current_ip) AS ip FROM devices WHERE id=%s::uuid", (device_id,))
                row = cur.fetchone()
                if row:
                    device_ip = normalize_ip_text(row.get("ip"))

            if device_ip and not device_id and phase7_table_exists(cur, "devices"):
                cur.execute(
                    """
                    SELECT id::text AS id
                    FROM devices
                    WHERE current_ip IS NOT NULL
                      AND host(current_ip) = %s
                    ORDER BY last_seen_at DESC NULLS LAST
                    LIMIT 1
                    """,
                    (device_ip,),
                )
                row = cur.fetchone()
                if row:
                    device_id = normalize_uuid_text(row.get("id"))

            if not device_ip:
                raise HTTPException(status_code=400, detail="device_ip or online device_id with current_ip is required")

            PHASE7_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_ip = str(device_ip).replace(".", "-").replace(":", "-")
            requested_file_path = str(PHASE7_CAPTURE_DIR / f"security-core-capture-{safe_ip}-{stamp}.pcap")
            bpf_filter = f"host {device_ip}"
            cur.execute(
                """
                INSERT INTO packet_captures(
                    device_id, device_ip, interface_name, bpf_filter, status, file_path,
                    duration_seconds, max_file_mb, created_by, created_at, updated_at
                ) VALUES (NULLIF(%s::text, '')::uuid, %s::inet, %s, %s, 'requested', %s, %s, %s, %s, now(), now())
                RETURNING id::text AS id
                """,
                (device_id or "", device_ip, interface_name, bpf_filter, requested_file_path, duration, max_mb, actor),
            )
            capture_id = phase7_uuid_id_text(cur.fetchone()["id"])
            phase7_insert_audit_event(cur, "api", actor, "capture_requested", "packet_capture", capture_id, {"device_id": device_id, "device_ip": device_ip, "duration_seconds": duration, "max_file_mb": max_mb, "interface_name": interface_name})
            try:
                phase7_set_ui_selection(cur, "capture", capture_id, f"{device_ip} | requested | {capture_id}", actor)
            except Exception:
                pass
            token = phase7_public_token("capture", capture_id)
            return {
                "status": "requested",
                "capture_id": capture_id,
                "device_id": device_id,
                "device_ip": device_ip,
                "duration_seconds": duration,
                "max_file_mb": max_mb,
                "interface_name": interface_name,
                "download_token": token,
                "download_url": phase7_public_url(f"/api/v1/public/captures/{capture_id}/download?token=REDACTED"),
            }


@app.post("/api/v1/captures/{capture_id}/stop")
def phase7_request_capture_stop(capture_id: str = Path(...), payload: Phase7CaptureStopPayload | None = Body(default=None), _: None = Security(require_api_key)):
    payload = payload or Phase7CaptureStopPayload()
    capture_id = phase7_uuid_id_text(capture_id)
    actor = clean_optional_text(payload.actor) or "home-assistant"
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if not phase7_table_exists(cur, "packet_captures"):
                raise HTTPException(status_code=500, detail="Phase 7 capture schema is not installed")
            cur.execute(
                """
                UPDATE packet_captures
                SET status = CASE WHEN status IN ('running','starting','requested') THEN 'stop_requested' ELSE status END,
                    error_message = CASE WHEN status IN ('running','starting','requested') THEN NULL ELSE error_message END,
                    updated_at=now()
                WHERE id=%s::uuid
                RETURNING id::text AS id, status
                """,
                (capture_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Capture not found")
            phase7_insert_audit_event(cur, "api", actor, "capture_stop_requested", "packet_capture", capture_id, {"status": row.get("status")})
            return {"status": "stop_requested", "capture_id": capture_id, "current_status": row.get("status")}


def phase7_export_query(cur, export_type: str, from_time: str | None, to_time: str | None, device_id: str | None, incident_id: str | None, severity: str | None, source_system: str | None, limit: int) -> list[dict[str, Any]]:
    limit = phase7_clean_limit(limit)
    clauses: list[str] = []
    params: list[Any] = []
    if export_type == "incidents":
        clauses, params = phase7_period_clauses("i.created_at", from_time, to_time)
        if device_id:
            clauses.append("i.device_id = %s::uuid")
            params.append(normalize_uuid_text(device_id))
        if incident_id:
            clauses.append("i.id = %s::uuid")
            params.append(normalize_uuid_text(incident_id))
        if severity:
            clauses.append("i.severity = %s")
            params.append(normalize_security_severity(severity))
        if source_system:
            clauses.append("i.source_system ILIKE %s")
            params.append(f"%{source_system}%")
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"""
            SELECT i.id::text AS id, i.device_id::text AS device_id, d.hostname AS device_hostname, host(d.current_ip) AS device_ip,
                   i.incident_type, i.severity, i.source_system, i.title, i.description, i.status,
                   i.event_count, i.first_seen_at, i.last_seen_at, i.created_at, i.updated_at, i.closed_at, i.dedupe_key,
                   i.evidence_json
            FROM incidents i
            LEFT JOIN devices d ON d.id = i.device_id
            {where_sql}
            ORDER BY i.created_at DESC
            LIMIT %s
            """,
            params + [limit],
        )
    elif export_type == "security-events":
        clauses, params = phase7_period_clauses("se.event_time", from_time, to_time)
        if device_id:
            clauses.append("se.device_id = %s::uuid")
            params.append(normalize_uuid_text(device_id))
        if incident_id:
            clauses.append("se.incident_id = %s::uuid")
            params.append(normalize_uuid_text(incident_id))
        if severity:
            clauses.append("se.severity = %s")
            params.append(normalize_security_severity(severity))
        if source_system:
            clauses.append("se.source_system ILIKE %s")
            params.append(f"%{source_system}%")
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"""
            SELECT se.id::text AS id, se.incident_id::text AS incident_id, se.device_id::text AS device_id,
                   d.hostname AS device_hostname, host(d.current_ip) AS device_ip, se.source_system, se.event_type,
                   se.severity, se.title, se.description, host(se.src_ip) AS src_ip, se.src_port,
                   host(se.dest_ip) AS dest_ip, se.dest_port, se.protocol, se.domain, se.country_code,
                   se.signature_id, se.signature_name, se.event_time, se.dedupe_key, se.raw_json
            FROM security_events se
            LEFT JOIN devices d ON d.id = se.device_id
            {where_sql}
            ORDER BY se.event_time DESC
            LIMIT %s
            """,
            params + [limit],
        )
    elif export_type == "traffic-samples":
        clauses, params = phase7_period_clauses("dts.sample_time", from_time, to_time)
        if device_id:
            clauses.append("dts.device_id = %s::uuid")
            params.append(normalize_uuid_text(device_id))
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"""
            SELECT dts.id::text AS id, dts.device_id::text AS device_id, d.hostname AS device_hostname, host(d.current_ip) AS device_ip,
                   dts.sample_time, dts.source_system, dts.direction, host(dts.src_ip) AS src_ip, dts.src_port,
                   host(dts.dest_ip) AS dest_ip, dts.dest_port, dts.protocol, dts.country_code, dts.bytes_delta,
                   dts.packets_delta, dts.connection_count, dts.state_key, dts.raw_json
            FROM device_traffic_samples dts
            LEFT JOIN devices d ON d.id = dts.device_id
            {where_sql}
            ORDER BY dts.sample_time DESC
            LIMIT %s
            """,
            params + [limit],
        )
    elif export_type == "audit-events":
        audit_exists = phase7_table_exists(cur, "audit_events")
        response_events_exists = phase7_table_exists(cur, "response_action_events")
        if not audit_exists and not response_events_exists:
            return []
        union_parts: list[str] = []
        if audit_exists:
            union_parts.append(
                """
                SELECT
                    'audit_events' AS source_table,
                    id::text AS id,
                    actor_type,
                    actor_name,
                    event_type,
                    target_type,
                    target_id,
                    event_time,
                    details_json
                FROM audit_events
                """
            )
        if response_events_exists:
            union_parts.append(
                """
                SELECT
                    'response_action_events' AS source_table,
                    id::text AS id,
                    'system' AS actor_type,
                    actor AS actor_name,
                    event_type,
                    'response_action' AS target_type,
                    response_action_id::text AS target_id,
                    created_at AS event_time,
                    jsonb_build_object(
                        'incident_id', incident_id::text,
                        'device_id', device_id::text,
                        'message', message,
                        'details', details_json
                    ) AS details_json
                FROM response_action_events
                """
            )
        clauses, params = phase7_period_clauses("event_time", from_time, to_time)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"""
            WITH events AS ({' UNION ALL '.join(union_parts)})
            SELECT * FROM events
            {where_sql}
            ORDER BY event_time DESC
            LIMIT %s
            """,
            params + [limit],
        )
    else:
        raise HTTPException(status_code=404, detail="Unknown export type")
    return [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]


def phase7_export_csv(export_type: str, from_time: str | None, to_time: str | None, device_id: str | None, incident_id: str | None, severity: str | None, source_system: str | None, limit: int) -> Response:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            rows = phase7_export_query(cur, export_type, from_time, to_time, device_id, incident_id, severity, source_system, limit)
    return phase7_csv_response(f"security-core-{export_type}.csv", rows)


def phase7_public_export_url(export_type: str) -> str:
    token = phase7_public_token("export", export_type)
    suffix = "evidence-bundle.json" if export_type == "evidence-bundle" else f"{export_type}.csv"
    return phase7_public_url(f"/api/v1/public/exports/{suffix}?limit=5000&token=REDACTED")


@app.get("/api/v1/exports/links")
def phase7_export_links(_: None = Security(require_api_key)):
    export_types = ["incidents", "security-events", "traffic-samples", "audit-events", "evidence-bundle"]
    return {"items": [{"export_type": et, "download_url": phase7_public_export_url(et)} for et in export_types]}


@app.get("/api/v1/public/exports/{export_name}")
def phase7_public_export_download(export_name: str = Path(...), token: str | None = Query(default=None), limit: int = Query(default=5000, ge=1, le=50000)):
    clean = phase7_db_text(export_name).strip().lower()
    mapping = {
        "incidents.csv": "incidents",
        "security-events.csv": "security-events",
        "traffic-samples.csv": "traffic-samples",
        "audit-events.csv": "audit-events",
        "evidence-bundle.json": "evidence-bundle",
    }
    export_type = mapping.get(clean)
    if not export_type:
        raise HTTPException(status_code=404, detail="Unknown export")
    phase7_verify_public_token("export", export_type, token)
    if export_type == "evidence-bundle":
        bundle = phase7_export_evidence_bundle(limit=min(int(limit), 10000), _=None)  # type: ignore[arg-type]
        return Response(
            content=json.dumps(ascii_json_safe(bundle), ensure_ascii=False, default=str),
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="security-core-evidence-bundle.json"'},
        )
    return phase7_export_csv(export_type, None, None, None, None, None, None, limit)


@app.get("/api/v1/exports/incidents.csv")
def phase7_export_incidents_csv(from_time: str | None = Query(default=None, alias="from"), to_time: str | None = Query(default=None, alias="to"), device_id: str | None = None, incident_id: str | None = None, severity: str | None = None, source_system: str | None = None, limit: int = Query(default=5000, ge=1, le=50000), _: None = Security(require_api_key)):
    return phase7_export_csv("incidents", from_time, to_time, device_id, incident_id, severity, source_system, limit)


@app.get("/api/v1/exports/security-events.csv")
def phase7_export_security_events_csv(from_time: str | None = Query(default=None, alias="from"), to_time: str | None = Query(default=None, alias="to"), device_id: str | None = None, incident_id: str | None = None, severity: str | None = None, source_system: str | None = None, limit: int = Query(default=5000, ge=1, le=50000), _: None = Security(require_api_key)):
    return phase7_export_csv("security-events", from_time, to_time, device_id, incident_id, severity, source_system, limit)


@app.get("/api/v1/exports/traffic-samples.csv")
def phase7_export_traffic_samples_csv(from_time: str | None = Query(default=None, alias="from"), to_time: str | None = Query(default=None, alias="to"), device_id: str | None = None, incident_id: str | None = None, severity: str | None = None, source_system: str | None = None, limit: int = Query(default=5000, ge=1, le=50000), _: None = Security(require_api_key)):
    return phase7_export_csv("traffic-samples", from_time, to_time, device_id, incident_id, severity, source_system, limit)


@app.get("/api/v1/exports/audit-events.csv")
def phase7_export_audit_events_csv(from_time: str | None = Query(default=None, alias="from"), to_time: str | None = Query(default=None, alias="to"), device_id: str | None = None, incident_id: str | None = None, severity: str | None = None, source_system: str | None = None, limit: int = Query(default=5000, ge=1, le=50000), _: None = Security(require_api_key)):
    return phase7_export_csv("audit-events", from_time, to_time, device_id, incident_id, severity, source_system, limit)


@app.get("/api/v1/exports/evidence-bundle.json")
def phase7_export_evidence_bundle(from_time: str | None = Query(default=None, alias="from"), to_time: str | None = Query(default=None, alias="to"), device_id: str | None = None, incident_id: str | None = None, severity: str | None = None, source_system: str | None = None, limit: int = Query(default=2000, ge=1, le=10000), _: None = Security(require_api_key)):
    limit = phase7_clean_limit(limit, 10000)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            bundle = {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "filters": {"from": from_time, "to": to_time, "device_id": device_id, "incident_id": incident_id, "severity": severity, "source_system": source_system, "limit": limit},
                "incidents": phase7_export_query(cur, "incidents", from_time, to_time, device_id, incident_id, severity, source_system, limit),
                "security_events": phase7_export_query(cur, "security-events", from_time, to_time, device_id, incident_id, severity, source_system, limit),
                "traffic_samples": phase7_export_query(cur, "traffic-samples", from_time, to_time, device_id, incident_id, None, None, limit),
            }
            if phase7_table_exists(cur, "generated_reports"):
                cur.execute("SELECT COUNT(*)::int AS total FROM generated_reports")
                bundle["report_count"] = cur.fetchone()["total"]
            return ascii_json_safe(bundle)


@app.get("/api/v1/stats/phase7")
def phase7_stats(_: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            result: dict[str, Any] = {}
            if phase7_table_exists(cur, "audit_events"):
                cur.execute("SELECT COUNT(*) FILTER (WHERE event_time >= now() - interval '24 hours')::int AS audit_events_last_24h FROM audit_events")
                result.update(dict(cur.fetchone() or {}))
            else:
                result["audit_events_last_24h"] = 0
            if phase7_table_exists(cur, "notification_deliveries"):
                cur.execute("SELECT COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours')::int AS notifications_last_24h, COUNT(*) FILTER (WHERE status='failed' AND created_at >= now() - interval '24 hours')::int AS notification_failures_last_24h FROM notification_deliveries")
                result.update(dict(cur.fetchone() or {}))
            else:
                result.update({"notifications_last_24h": 0, "notification_failures_last_24h": 0})
            if phase7_table_exists(cur, "generated_reports"):
                cur.execute("SELECT COUNT(*)::int AS generated_reports, MAX(created_at) AS last_report_at FROM generated_reports WHERE status='generated'")
                result.update(dict(cur.fetchone() or {}))
            else:
                result.update({"generated_reports": 0, "last_report_at": None})
            if phase7_table_exists(cur, "packet_captures"):
                cur.execute("SELECT COUNT(*) FILTER (WHERE status='running')::int AS running_captures, COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours')::int AS captures_last_24h FROM packet_captures")
                result.update(dict(cur.fetchone() or {}))
            else:
                result.update({"running_captures": 0, "captures_last_24h": 0})
            return result


@app.get("/api/v1/stats/top-risky-devices")
def phase7_top_risky_devices(limit: int = Query(default=10, ge=1, le=50), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, hostname, host(current_ip) AS current_ip, mac_address, vendor, model, category,
                       risk_score, risk_level, vulnerability_count, kev_count, highest_cvss, highest_severity,
                       status, policy_effective_mode, last_seen_at
                FROM devices
                ORDER BY COALESCE(kev_count, 0) DESC,
                         COALESCE(highest_cvss, 0) DESC,
                         COALESCE(vulnerability_count, 0) DESC,
                         COALESCE(risk_score, 0) DESC,
                         last_seen_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return {"items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}


@app.get("/api/v1/stats/geo-communications")
def phase7_geo_communications(hours: int = Query(default=24, ge=1, le=720), limit: int = Query(default=50, ge=1, le=200), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT dts.country_code,
                       COUNT(*)::int AS sample_count,
                       COUNT(DISTINCT dts.device_id)::int AS device_count,
                       COALESCE(SUM(dts.bytes_delta), 0)::bigint AS bytes_total,
                       MAX(dts.sample_time) AS last_seen_at
                FROM device_traffic_samples dts
                WHERE dts.sample_time >= now() - (%s::text || ' hours')::interval
                  AND dts.country_code IS NOT NULL
                GROUP BY dts.country_code
                ORDER BY bytes_total DESC, sample_count DESC
                LIMIT %s
                """,
                (hours, limit),
            )
            return {"hours": hours, "items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}


@app.get("/api/v1/stats/dns-summary")
def phase7_dns_summary(hours: int = Query(default=24, ge=1, le=720), limit: int = Query(default=50, ge=1, le=200), _: None = Security(require_api_key)):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT se.device_id::text AS device_id, d.hostname AS device_hostname, host(d.current_ip) AS device_ip,
                       COUNT(*)::int AS dns_events,
                       COUNT(*) FILTER (WHERE se.event_type ILIKE '%%block%%')::int AS dns_blocks,
                       COUNT(DISTINCT se.domain)::int AS unique_domains,
                       MAX(se.event_time) AS last_seen_at
                FROM security_events se
                LEFT JOIN devices d ON d.id = se.device_id
                WHERE se.event_time >= now() - (%s::text || ' hours')::interval
                  AND se.source_system ILIKE 'adguard%%'
                GROUP BY se.device_id, d.hostname, d.current_ip
                ORDER BY dns_blocks DESC, dns_events DESC
                LIMIT %s
                """,
                (hours, limit),
            )
            return {"hours": hours, "items": [phase7_decode_public_row(dict(row)) for row in cur.fetchall()]}
