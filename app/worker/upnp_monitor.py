import json
import re
import warnings
from pathlib import Path
from typing import Any

import requests

from detection_common import (
    clean_optional_text,
    connect,
    create_security_event,
    getenv_any,
    normalize_ip,
    to_text,
    update_health,
)


COMPONENT = "security-upnp-monitor"
OPNSENSE_URL = getenv_any(["OPNSENSE_URL"], "").rstrip("/")
OPNSENSE_AUTH_B64 = getenv_any(["OPNSENSE_AUTH_B64"], "")
OPNSENSE_VERIFY_SSL = getenv_any(["OPNSENSE_VERIFY_SSL"], "false").lower() == "true"
UPNP_LEASES_FILE = Path(getenv_any(["UPNP_LEASES_FILE", "MINIUPNPD_LEASES_FILE"], "/var/db/miniupnpd.leases"))
CREATE_UNEXPECTED_MAPPING_INCIDENTS = getenv_any(["UPNP_CREATE_UNEXPECTED_MAPPING_INCIDENTS"], "true").lower() in {"1", "true", "yes", "on"}
UPNP_MONITOR_ENABLED = getenv_any(["UPNP_MONITOR_ENABLED"], "true").lower() in {"1", "true", "yes", "on"}
UPNP_MONITOR_REQUIRE_SOURCE = getenv_any(["UPNP_MONITOR_REQUIRE_SOURCE"], "false").lower() in {"1", "true", "yes", "on"}
HTTP_TIMEOUT = int(getenv_any(["UPNP_HTTP_TIMEOUT"], "20"))

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def opnsense_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if OPNSENSE_AUTH_B64:
        headers["Authorization"] = f"Basic {OPNSENSE_AUTH_B64}"
    return headers


def extract_mappings(data: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        candidates = []
        for key in (
            "mappings",
            "leases",
            "rules",
            "rows",
            "items",
            "status",
            "data",
            "natpmp",
            "upnp",
        ):
            value = data.get(key)
            if isinstance(value, list):
                candidates.extend(value)
            elif isinstance(value, dict):
                candidates.extend(extract_mappings(value))
        if not candidates and any(
            key in data
            for key in (
                "internal_client",
                "internal_ip",
                "external_port",
                "intPort",
                "extPort",
                "intClient",
            )
        ):
            candidates = [data]
    else:
        candidates = []

    for item in candidates:
        if not isinstance(item, dict):
            continue
        internal_ip = normalize_ip(
            item.get("internal_client")
            or item.get("internal_ip")
            or item.get("client")
            or item.get("intClient")
            or item.get("lan_ip")
            or item.get("internalClient")
        )
        external_port = item.get("external_port") or item.get("extPort") or item.get("externalPort") or item.get("port")
        internal_port = item.get("internal_port") or item.get("intPort") or item.get("internalPort")
        proto = clean_optional_text(item.get("protocol") or item.get("proto"))
        description = clean_optional_text(item.get("description") or item.get("desc") or item.get("comment"))
        if internal_ip and external_port:
            rows.append(
                {
                    "internal_ip": internal_ip,
                    "external_port": int(external_port) if str(external_port).isdigit() else external_port,
                    "internal_port": int(internal_port) if str(internal_port).isdigit() else internal_port,
                    "protocol": proto,
                    "description": description,
                    "raw": item,
                    "source": "opnsense_api",
                }
            )
    return rows


def request_opnsense_endpoint(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    url = f"{OPNSENSE_URL}{endpoint}"
    info: dict[str, Any] = {"method": method, "endpoint": endpoint}
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=opnsense_headers(),
            json=payload,
            timeout=HTTP_TIMEOUT,
            verify=OPNSENSE_VERIFY_SSL,
        )
        info["http_status"] = response.status_code
        if response.status_code >= 400:
            return [], info
        body = (response.text or "").strip()
        if not body:
            info["empty_body"] = True
            return [], info
        data = response.json()
        rows = extract_mappings(data)
        info["mappings"] = len(rows)
        return rows, info
    except Exception as exc:
        info["error"] = str(exc)
        return [], info


def try_json_endpoints() -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    if not OPNSENSE_URL or not OPNSENSE_AUTH_B64:
        return [], [{"error": "missing_opnsense_url_or_auth"}], False

    attempts = [
        ("GET", "/api/upnp/service/status", None),
        ("GET", "/api/miniupnpd/service/status", None),
        ("GET", "/api/miniupnpd/settings/get", None),
        ("GET", "/api/diagnostics/upnp/status", None),
        ("POST", "/api/upnp/service/status", {}),
        ("POST", "/api/miniupnpd/service/status", {}),
        ("POST", "/api/diagnostics/upnp/status", {}),
    ]
    endpoint_results: list[dict[str, Any]] = []
    any_reachable = False

    for method, endpoint, payload in attempts:
        rows, info = request_opnsense_endpoint(method, endpoint, payload)
        endpoint_results.append(info)
        if info.get("http_status") is not None and int(info.get("http_status", 999)) < 500:
            any_reachable = True
        if rows:
            return rows, endpoint_results, any_reachable

    return [], endpoint_results, any_reachable


def parse_miniupnpd_leases(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    info: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return [], info
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        info["lines"] = len(lines)
    except Exception as exc:
        info["error"] = str(exc)
        return [], info

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = re.split(r"\s+", line)
        proto = None
        ext_port = None
        int_ip = None
        int_port = None
        desc = None

        if len(parts) >= 4 and parts[0].upper() in {"TCP", "UDP"}:
            proto = parts[0].upper()
            ext_port = parts[1]
            int_ip = normalize_ip(parts[2])
            int_port = parts[3]
            desc = " ".join(parts[4:]) if len(parts) > 4 else None
        elif len(parts) >= 5:
            for part in parts:
                ip = normalize_ip(part)
                if ip:
                    int_ip = ip
                    numbers = [p for p in parts if str(p).isdigit()]
                    if numbers:
                        ext_port = numbers[0]
                        int_port = numbers[1] if len(numbers) > 1 else numbers[0]
                    proto_match = [p.upper() for p in parts if p.upper() in {"TCP", "UDP"}]
                    proto = proto_match[0] if proto_match else None
                    desc = line
                    break

        if int_ip and ext_port:
            rows.append(
                {
                    "internal_ip": int_ip,
                    "external_port": int(ext_port) if str(ext_port).isdigit() else ext_port,
                    "internal_port": int(int_port) if str(int_port).isdigit() else int_port,
                    "protocol": proto,
                    "description": desc,
                    "raw": {"line": line},
                    "source": "miniupnpd_leases_file",
                }
            )
    info["mappings"] = len(rows)
    return rows, info


def load_mappings() -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    api_rows, endpoint_results, api_reachable = try_json_endpoints()
    if api_rows:
        return api_rows, "opnsense_api", {"endpoint_results": endpoint_results, "api_reachable": api_reachable}

    file_rows, file_info = parse_miniupnpd_leases(UPNP_LEASES_FILE)
    if file_rows:
        return file_rows, "leases_file", {"endpoint_results": endpoint_results, "api_reachable": api_reachable, "leases_file": file_info}

    source = "none"
    if api_reachable:
        source = "opnsense_api_empty"
    elif file_info.get("exists"):
        source = "leases_file_empty"

    return [], source, {"endpoint_results": endpoint_results, "api_reachable": api_reachable, "leases_file": file_info}


def bool_policy_flag(policy_json: Any, key: str, default: bool) -> bool:
    if not isinstance(policy_json, dict):
        return default
    value = policy_json.get(key, default)
    if isinstance(value, bool):
        return value
    return to_text(value).lower() in {"1", "true", "yes", "on"}


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


def process() -> dict[str, Any]:
    if not UPNP_MONITOR_ENABLED:
        details = {
            "enabled": False,
            "message": "UPnP/NAT-PMP monitoring is disabled by UPNP_MONITOR_ENABLED=false.",
        }
        update_health(COMPONENT, "detection-worker", "healthy", details)
        return {"status": "healthy", **details}

    mappings, source, source_details = load_mappings()
    if not mappings:
        health_status = "degraded" if UPNP_MONITOR_REQUIRE_SOURCE and source == "none" else "healthy"
        details = {
            "source": source,
            "opnsense_url": OPNSENSE_URL or None,
            "leases_file": str(UPNP_LEASES_FILE),
            "mappings_seen": 0,
            "events_created": 0,
            "require_source": UPNP_MONITOR_REQUIRE_SOURCE,
            "message": "No active UPnP/NAT-PMP mappings found. This is healthy if UPnP is disabled or no clients opened ports.",
            **source_details,
        }
        update_health(COMPONENT, "detection-worker", health_status, details)
        return {"status": health_status, **details}

    emitted = 0
    with connect() as conn:
        with conn.cursor() as cur:
            for mapping in mappings:
                internal_ip = normalize_ip(mapping.get("internal_ip"))
                if not internal_ip:
                    continue
                cur.execute(
                    """
                    SELECT
                        id::text AS device_id,
                        hostname,
                        host(current_ip) AS ip,
                        policy_effective_json
                    FROM devices
                    WHERE current_ip = %s::inet
                    LIMIT 1
                    """,
                    (internal_ip,),
                )
                device = cur.fetchone()
                if not device:
                    continue
                device_id = to_text(device.get("device_id"))
                policy_json = device.get("policy_effective_json") or {}
                upnp_allowed = bool_policy_flag(policy_json, "upnp_allowed", True)
                event_type = "unexpected_upnp_mapping" if upnp_allowed else "blocked_policy_upnp_mapping"
                severity = "medium" if upnp_allowed else "high"
                name = to_text(device.get("hostname")) or internal_ip
                proto = clean_optional_text(mapping.get("protocol"))
                external_port = mapping.get("external_port")
                internal_port = mapping.get("internal_port")
                title = f"UPnP mapping detected: {name}"
                description = f"UPnP/NAT-PMP mapping {proto or ''} external port {external_port} -> {internal_ip}:{internal_port or external_port}."
                if not upnp_allowed:
                    description += " Device policy does not allow UPnP."
                dedupe = f"upnp|{event_type}|{device_id}|{proto or '-'}|{external_port}|{internal_port or '-'}"
                if already_emitted(cur, dedupe):
                    continue
                result = create_security_event(
                    cur,
                    source_system="upnp-monitor",
                    event_type=event_type,
                    severity=severity,
                    title=title,
                    description=description,
                    device_id=device_id,
                    src_ip=internal_ip,
                    dest_port=int(external_port) if str(external_port).isdigit() else None,
                    protocol=proto,
                    raw_json=mapping,
                    dedupe_key=dedupe,
                    create_incident=(CREATE_UNEXPECTED_MAPPING_INCIDENTS or not upnp_allowed),
                )
                if result.get("event_id"):
                    emitted += 1
        conn.commit()

    details = {"source": source, "mappings_seen": len(mappings), "events_created": emitted, **source_details}
    update_health(COMPONENT, "detection-worker", "healthy", details)
    return {"status": "healthy", **details}


def main():
    try:
        result = process()
    except Exception as exc:
        details = {"error": str(exc)}
        update_health(COMPONENT, "detection-worker", "degraded", details)
        result = {"status": "degraded", **details}
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
