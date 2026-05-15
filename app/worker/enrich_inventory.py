import csv
import io
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ENV_FILES = [
    "/etc/security-core/security-core.env",
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

ENRICH_MAX_DEVICES_PER_RUN = int(getenv_any(["ENRICH_MAX_DEVICES_PER_RUN"], "200"))
OUI_REFRESH_ENABLED = getenv_any(["OUI_REFRESH_ENABLED"], "true").lower() == "true"
OUI_REFRESH_MAX_AGE_HOURS = int(getenv_any(["OUI_REFRESH_MAX_AGE_HOURS"], "168"))
OUI_CACHE_FILE = Path(getenv_any(["OUI_CACHE_FILE"], "/opt/security-core/data/oui_registry.json"))
IEEE_OUI_CSV_URL = getenv_any(["IEEE_OUI_CSV_URL"], "https://standards-oui.ieee.org/oui/oui.csv")
IEEE_MAM_CSV_URL = getenv_any(["IEEE_MAM_CSV_URL"], "https://standards-oui.ieee.org/oui28/mam.csv")
IEEE_OUI36_CSV_URL = getenv_any(["IEEE_OUI36_CSV_URL"], "https://standards-oui.ieee.org/oui36/oui36.csv")
LOCAL_OUI_FILES = [
    item.strip()
    for item in getenv_any(
        ["LOCAL_OUI_FILES"],
        "/usr/share/ieee-data/oui.txt,/usr/share/ieee-data/mam.txt,/usr/share/ieee-data/oui36.txt,/usr/share/wireshark/manuf",
    ).split(",")
    if item.strip()
]
CLASSIFICATION_RULES_FILE = Path(
    getenv_any(
        ["CLASSIFICATION_RULES_FILE"],
        "/opt/security-core/config/classification_rules.json",
    )
)
FALLBACK_RULE_PATHS = [
    Path("/opt/security-core/config/classification_rules.json"),
    Path("/opt/security-core/classification_rules.json"),
    Path("/opt/security-core/app/worker/classification_rules.json"),
]

SUPPORTED_REQUIRE_KEYS = {
    "require_private_mac",
    "require_onvif",
}


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


def normalize_mac(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    parts = re.findall(r"[0-9a-fA-F]{2}", text.replace("-", ":"))
    if len(parts) == 6:
        return ":".join(part.lower() for part in parts)
    return None


def mac_to_hex(value: Any) -> str | None:
    mac = normalize_mac(value)
    if not mac:
        return None
    return "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")


def is_locally_administered_mac(mac: Any) -> bool:
    mac_hex = mac_to_hex(mac)
    if not mac_hex or len(mac_hex) < 2:
        return False
    return bool(int(mac_hex[:2], 16) & 0x02)


def add_prefix_entry(registry: dict[str, str], prefix: Any, vendor: Any):
    clean_prefix = "".join(ch for ch in to_text(prefix).upper() if ch in "0123456789ABCDEF")
    clean_vendor = to_text(vendor)
    if clean_prefix and clean_vendor:
        registry.setdefault(clean_prefix, clean_vendor)


def load_cached_registry(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {to_text(k): to_text(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_cached_registry(path: Path, registry: dict[str, str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def cache_is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < (OUI_REFRESH_MAX_AGE_HOURS * 3600)


def fetch_ieee_csv(url: str) -> list[dict[str, str]]:
    response = requests.get(
        url,
        timeout=20,
        verify=True,
        headers={"User-Agent": "security-core-phase2/1.0"},
    )
    response.raise_for_status()
    reader = csv.DictReader(io.StringIO(response.text))
    return [{to_text(k): to_text(v) for k, v in row.items()} for row in reader if isinstance(row, dict)]


def parse_ieee_text_file(path: str) -> dict[str, str]:
    registry: dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return registry
    pattern = re.compile(r"^\s*([0-9A-Fa-f-]+)\s+\(hex\)\s+(.+?)\s*$")
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = pattern.match(line)
                if match:
                    add_prefix_entry(registry, match.group(1), match.group(2))
    except Exception:
        pass
    return registry


def parse_wireshark_manuf(path: str) -> dict[str, str]:
    registry: dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return registry
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"\s+", line, maxsplit=2)
                if len(parts) >= 2:
                    add_prefix_entry(registry, parts[0], parts[1])
    except Exception:
        pass
    return registry


def build_vendor_registry() -> tuple[dict[str, str], str]:
    if cache_is_fresh(OUI_CACHE_FILE):
        cached = load_cached_registry(OUI_CACHE_FILE)
        if cached:
            return cached, "cache"

    if OUI_REFRESH_ENABLED:
        try:
            online: dict[str, str] = {}
            for row in fetch_ieee_csv(IEEE_OUI_CSV_URL):
                add_prefix_entry(online, row.get("Assignment"), row.get("Organization Name"))
            for row in fetch_ieee_csv(IEEE_MAM_CSV_URL):
                add_prefix_entry(online, row.get("Assignment"), row.get("Organization Name"))
            for row in fetch_ieee_csv(IEEE_OUI36_CSV_URL):
                add_prefix_entry(online, row.get("Assignment"), row.get("Organization Name"))
            if online:
                save_cached_registry(OUI_CACHE_FILE, online)
                return online, "ieee_online"
        except Exception:
            pass

    local_registry: dict[str, str] = {}
    for path in LOCAL_OUI_FILES:
        if path.endswith("/manuf"):
            local_registry.update(parse_wireshark_manuf(path))
        else:
            local_registry.update(parse_ieee_text_file(path))
    if local_registry:
        save_cached_registry(OUI_CACHE_FILE, local_registry)
        return local_registry, "local_files"
    return {}, "none"


VENDOR_REGISTRY, VENDOR_REGISTRY_SOURCE = build_vendor_registry()


def lookup_vendor_from_registry(mac: Any) -> str | None:
    mac_hex = mac_to_hex(mac)
    if not mac_hex:
        return None
    for prefix_len in (9, 7, 6):
        vendor = VENDOR_REGISTRY.get(mac_hex[:prefix_len])
        if vendor:
            return vendor
    return None


DEFAULT_RULES = {
    "default_category": {"category": "unknown", "confidence": 0, "reason": "no_match"},
    "reserved_ip_categories": {},
    "rules": [],
}


def load_rules() -> tuple[dict[str, Any], str]:
    paths_to_try: list[Path] = [CLASSIFICATION_RULES_FILE]
    if CLASSIFICATION_RULES_FILE not in FALLBACK_RULE_PATHS:
        paths_to_try.extend(FALLBACK_RULE_PATHS)
    else:
        paths_to_try.extend([p for p in FALLBACK_RULE_PATHS if p != CLASSIFICATION_RULES_FILE])

    seen: set[str] = set()
    for path in paths_to_try:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data, str(path)
        except Exception:
            continue
    return DEFAULT_RULES, "embedded_default"


RULES, RULES_PATH = load_rules()


def json_ports_to_list(value: Any) -> list[int]:
    if isinstance(value, list):
        out: list[int] = []
        for item in value:
            try:
                out.append(int(item))
            except Exception:
                pass
        return out
    return []


def value_matches_any(text: str, patterns: list[Any]) -> bool:
    if not patterns:
        return True
    return any(to_text(pattern).lower() in text for pattern in patterns)


def value_matches_regex_any(text: str, patterns: list[Any]) -> bool:
    if not patterns:
        return True
    for pattern in patterns:
        try:
            if re.search(to_text(pattern), text, re.I):
                return True
        except re.error:
            continue
    return False


def contains_unsupported_require_key(rule: dict[str, Any]) -> bool:
    for key in rule:
        if key.startswith("require_") and key not in SUPPORTED_REQUIRE_KEYS:
            return True
    return False


def build_identity_text(device: dict[str, Any], vendor_override: str | None = None) -> str:
    parts = [
        to_text(device.get("hostname")),
        to_text(vendor_override or device.get("vendor")),
        to_text(device.get("model")),
        to_text(device.get("firmware_version")),
        to_text(device.get("hardware_version")),
        to_text(device.get("serial_number")),
        to_text(device.get("reverse_dns_name")),
        normalize_json_blob(device.get("onvif_device_info")),
    ]
    return " ".join(part for part in parts if part).lower()


def normalize_json_blob(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
    except Exception:
        return to_text(value).lower()


def rule_disqualifies(value: str, any_none: list[Any] | None = None, regex_none: list[Any] | None = None) -> bool:
    if any_none and value_matches_any(value, any_none):
        return True
    if regex_none and value_matches_regex_any(value, regex_none):
        return True
    return False


def device_has_onvif(device: dict[str, Any]) -> bool:
    value = device.get("onvif_device_info")
    if value is None:
        return False
    if isinstance(value, dict):
        return bool(value)
    text = normalize_json_blob(value)
    return text not in ("", "{}", "null")


def classify_from_rules(device: dict[str, Any]) -> tuple[str | None, int, str | None]:
    current_ip = to_text(device.get("current_ip"))
    hostname = normalize_text(device.get("hostname"))
    vendor = normalize_text(device.get("vendor"))
    model = normalize_text(device.get("model"))
    identity = build_identity_text(device)
    tcp_ports = set(json_ports_to_list(device.get("open_tcp_ports")))
    reserved = RULES.get("reserved_ip_categories") or {}
    default_category = RULES.get("default_category") or {"category": "unknown", "confidence": 0, "reason": "no_match"}

    if current_ip in reserved and isinstance(reserved[current_ip], dict):
        item = reserved[current_ip]
        return (
            to_text(item.get("category")) or None,
            int(item.get("confidence") or 100),
            to_text(item.get("reason")) or "reserved_infra_ip",
        )

    mac_is_private = is_locally_administered_mac(device.get("mac_address"))

    for rule in RULES.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        if contains_unsupported_require_key(rule):
            continue

        if rule.get("require_private_mac") and not mac_is_private:
            continue
        if rule.get("disallow_private_mac") and mac_is_private:
            continue
        if rule.get("require_onvif") and not device_has_onvif(device):
            continue

        if rule_disqualifies(
            hostname,
            rule.get("hostname_any_none") or rule.get("hostname_none"),
            rule.get("hostname_regex_none"),
        ):
            continue
        if rule_disqualifies(
            vendor,
            rule.get("vendor_any_none") or rule.get("vendor_none"),
            rule.get("vendor_regex_none"),
        ):
            continue
        if rule_disqualifies(
            model,
            rule.get("model_any_none") or rule.get("model_none"),
            rule.get("model_regex_none"),
        ):
            continue
        if rule_disqualifies(
            identity,
            rule.get("identity_any_none") or rule.get("identity_none"),
            rule.get("identity_regex_none"),
        ):
            continue

        if rule.get("hostname_any") and not value_matches_any(hostname, rule.get("hostname_any") or []):
            continue
        if rule.get("vendor_any") and not value_matches_any(vendor, rule.get("vendor_any") or []):
            continue
        if rule.get("model_any") and not value_matches_any(model, rule.get("model_any") or []):
            continue

        if rule.get("hostname_regex_any") and not value_matches_regex_any(hostname, rule.get("hostname_regex_any") or []):
            continue
        if rule.get("vendor_regex_any") and not value_matches_regex_any(vendor, rule.get("vendor_regex_any") or []):
            continue
        if rule.get("model_regex_any") and not value_matches_regex_any(model, rule.get("model_regex_any") or []):
            continue
        if rule.get("identity_regex_any") and not value_matches_regex_any(identity, rule.get("identity_regex_any") or []):
            continue
        if rule.get("identity_any") and not value_matches_any(identity, rule.get("identity_any") or []):
            continue

        ports_any = {int(item) for item in (rule.get("tcp_ports_any") or [])}
        if ports_any and not (ports_any & tcp_ports):
            continue

        disallowed_ports = {int(item) for item in (rule.get("tcp_ports_none") or [])}
        if disallowed_ports and (disallowed_ports & tcp_ports):
            continue

        category = to_text(rule.get("category")) or None
        confidence = int(rule.get("confidence") or 95)
        reason = to_text(rule.get("reason")) or "classification_rule"
        if category:
            return category, confidence, reason

    return (
        to_text(default_category.get("category")) or None,
        int(default_category.get("confidence") or 0),
        to_text(default_category.get("reason")) or "no_match",
    )


def get_device_columns(conn: psycopg.Connection) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'devices'
            """
        )
        columns: set[str] = set()
        for row in cur.fetchall():
            if isinstance(row, dict):
                columns.add(to_text(row.get("column_name")))
            else:
                try:
                    columns.add(to_text(row[0]))
                except Exception:
                    columns.add(to_text(row))
        return {item for item in columns if item}


def load_devices() -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        columns = get_device_columns(conn)
        onvif_select = "onvif_device_info" if "onvif_device_info" in columns else "'{}'::jsonb AS onvif_device_info"
        reverse_dns_select = "reverse_dns_name" if "reverse_dns_name" in columns else "NULL::text AS reverse_dns_name"
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    id,
                    host(current_ip) AS current_ip,
                    hostname,
                    mac_address,
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
                    classification_confidence,
                    classification_reason,
                    manual_vendor,
                    manual_model,
                    manual_category,
                    manual_firmware_version,
                    manual_hardware_version,
                    manual_serial_number,
                    identity_confirmed,
                    open_tcp_ports,
                    {reverse_dns_select},
                    {onvif_select}
                FROM devices
                WHERE current_ip IS NOT NULL
                ORDER BY last_seen_at DESC NULLS LAST
                LIMIT %s
                """,
                (ENRICH_MAX_DEVICES_PER_RUN,),
            )
            return cur.fetchall()


def write_results(device: dict[str, Any], best: dict[str, Any]):
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE devices
                SET
                    vendor = %s,
                    vendor_source = %s,
                    category = %s,
                    category_source = %s,
                    classification_confidence = %s,
                    classification_reason = %s,

                    model = %s,
                    model_source = %s,
                    firmware_version = %s,
                    firmware_source = %s,
                    hardware_version = %s,
                    hardware_source = %s,
                    serial_number = %s,
                    serial_source = %s,

                    updated_at = now()
                WHERE id = %s
                """,
                (
                    best.get("vendor"),
                    best.get("vendor_source") or "unknown",
                    best.get("category"),
                    best.get("category_source") or "unknown",
                    int(best.get("classification_confidence") or 0),
                    best.get("classification_reason"),
                    best.get("model"),
                    best.get("model_source") or "unknown",
                    best.get("firmware_version"),
                    best.get("firmware_source") or "unknown",
                    best.get("hardware_version"),
                    best.get("hardware_source") or "unknown",
                    best.get("serial_number"),
                    best.get("serial_source") or "unknown",
                    device["id"],
                ),
            )
        conn.commit()


def update_health(details: dict[str, Any]):
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE system_health
                SET
                    status = 'healthy',
                    last_check_at = now(),
                    details_json = %s,
                    updated_at = now()
                WHERE component_name = 'security-inventory-enrich'
                """,
                (Jsonb(details),),
            )
        conn.commit()


def derive_best_values(device: dict[str, Any]) -> dict[str, Any]:
    manual_vendor = to_text(device.get("manual_vendor")) or None
    manual_model = to_text(device.get("manual_model")) or None
    manual_category = to_text(device.get("manual_category")) or None
    manual_firmware = to_text(device.get("manual_firmware_version")) or None
    manual_hardware = to_text(device.get("manual_hardware_version")) or None
    manual_serial = to_text(device.get("manual_serial_number")) or None

    vendor = manual_vendor
    vendor_source = "manual" if manual_vendor else "unknown"
    if not vendor:
        vendor = lookup_vendor_from_registry(device.get("mac_address"))
        if vendor:
            vendor_source = "oui_registry" if not is_locally_administered_mac(device.get("mac_address")) else "private_mac"

    category = manual_category
    category_source = "manual" if manual_category else "unknown"
    confidence = 100 if manual_category else 0
    reason = "manual_override" if manual_category else None
    if not category:
        category, confidence, reason = classify_from_rules(
            {
                **device,
                "vendor": vendor or device.get("vendor"),
            }
        )
        if category:
            category_source = "classification_rule" if category != "unknown" else "unknown"

    model = manual_model
    firmware = manual_firmware
    hardware = manual_hardware
    serial = manual_serial

    return {
        "vendor": vendor,
        "vendor_source": vendor_source,
        "category": category,
        "category_source": category_source,
        "classification_confidence": confidence,
        "classification_reason": reason,
        "model": model,
        "model_source": "manual" if model else "unknown",
        "firmware_version": firmware,
        "firmware_source": "manual" if firmware else "unknown",
        "hardware_version": hardware,
        "hardware_source": "manual" if hardware else "unknown",
        "serial_number": serial,
        "serial_source": "manual" if serial else "unknown",
    }


def main():
    devices = load_devices()
    enriched = 0
    classified = 0
    with_vendor = 0

    for device in devices:
        best = derive_best_values(device)
        write_results(device, best)
        enriched += 1
        if best.get("category") and best.get("category") != "unknown":
            classified += 1
        if best.get("vendor"):
            with_vendor += 1

    update_health(
        {
            "devices_seen": len(devices),
            "devices_enriched": enriched,
            "devices_classified": classified,
            "devices_with_vendor": with_vendor,
            "vendor_registry_source": VENDOR_REGISTRY_SOURCE,
            "vendor_registry_entries": len(VENDOR_REGISTRY),
            "oui_cache_file": str(OUI_CACHE_FILE),
            "classification_rules_file": RULES_PATH,
            "classification_rule_count": len(RULES.get("rules") or []),
        }
    )


if __name__ == "__main__":
    main()
