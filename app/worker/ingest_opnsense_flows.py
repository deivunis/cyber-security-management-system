import datetime as dt
import gzip
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

import requests

from detection_common import (
    LAN_NETWORKS,
    clean_optional_text,
    connect,
    getenv_any,
    ip_in_lan,
    load_state,
    normalize_country_code,
    normalize_ip,
    save_state,
    to_text,
    update_health,
    j,
)

COMPONENT = "security-opnsense-flow-ingest"
OPNSENSE_URL = getenv_any(["OPNSENSE_URL"], "https://REDACTED").rstrip("/")
OPNSENSE_AUTH_B64 = getenv_any(["OPNSENSE_AUTH_B64"], "")
OPNSENSE_VERIFY_SSL = getenv_any(["OPNSENSE_VERIFY_SSL"], "false").lower() == "true"
FLOW_MAX_ROWS = int(getenv_any(["OPNSENSE_FLOW_MAX_ROWS"], "2000"))
FLOW_STATE_CACHE_SIZE = int(getenv_any(["OPNSENSE_FLOW_STATE_CACHE_SIZE"], "10000"))
MIN_BYTES_DELTA = int(getenv_any(["OPNSENSE_FLOW_MIN_BYTES_DELTA"], "1"))
GEOIP_MMDB_PATH = getenv_any(["GEOIP_MMDB_PATH", "SECURITY_CORE_GEOIP_MMDB_PATH"], "")
GEOIP_COUNTRY_CACHE = Path(getenv_any(["GEOIP_COUNTRY_CACHE"], "/opt/security-core/state/geoip_country_cache.json"))

IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
IP_PORT_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def headers() -> dict[str, str]:
    if not OPNSENSE_AUTH_B64:
        raise RuntimeError("OPNSENSE_AUTH_B64 is not set")
    return {
        "Authorization": f"Basic {OPNSENSE_AUTH_B64}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def opnsense_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"{OPNSENSE_URL}{endpoint}"
    if method.upper() == "POST":
        response = requests.post(url, headers=headers(), json=payload or {}, timeout=30, verify=OPNSENSE_VERIFY_SSL)
    else:
        response = requests.get(url, headers=headers(), timeout=30, verify=OPNSENSE_VERIFY_SSL)
    response.raise_for_status()
    try:
        data = response.json()
    except Exception:
        return {"raw_text": response.text}
    return data if isinstance(data, dict) else {"items": data}


def fetch_state_payloads() -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    attempts = [
        ("POST", "/api/diagnostics/firewall/query_states", {"current": 1, "rowCount": FLOW_MAX_ROWS, "searchPhrase": "", "sort": {}}),
        ("GET", "/api/diagnostics/firewall/pf_states", None),
        ("POST", "/api/diagnostics/firewall/query_pf_top", {"current": 1, "rowCount": FLOW_MAX_ROWS, "searchPhrase": "", "sort": {}}),
    ]
    errors: list[dict[str, Any]] = []
    for method, endpoint, body in attempts:
        try:
            data = opnsense_request(method, endpoint, body)
            data["_security_core_endpoint"] = endpoint
            data["_security_core_method"] = method
            payloads.append(data)
            if extract_rows(data):
                break
        except requests.HTTPError as exc:
            errors.append({"endpoint": endpoint, "method": method, "http_status": getattr(exc.response, "status_code", None)})
        except Exception as exc:
            errors.append({"endpoint": endpoint, "method": method, "error": str(exc)})
    if not payloads:
        return [{"_security_core_errors": errors}]
    if errors:
        payloads[0]["_security_core_errors"] = errors
    return payloads


def extract_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("rows", "items", "states", "data", "records", "result"):
        value = data.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = extract_rows(value)
            if nested:
                return nested
    found: list[Any] = []
    for value in data.values():
        if isinstance(value, list) and value and all(isinstance(item, (dict, str)) for item in value):
            found.extend(value)
        elif isinstance(value, dict):
            nested = extract_rows(value)
            if nested:
                found.extend(nested)
    return found


def parse_endpoint(value: Any) -> tuple[str | None, int | None]:
    text = to_text(value)
    if not text:
        return None, None
    text = text.strip().strip("[]")
    match = IP_PORT_RE.search(text)
    if not match:
        return normalize_ip(text), None
    ip = normalize_ip(match.group("ip"))
    port = None
    try:
        if match.group("port"):
            port = int(match.group("port"))
    except Exception:
        port = None
    return ip, port


def get_any(row: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in row and row.get(key) not in (None, ""):
            return row.get(key)
    lower = {str(k).lower(): k for k in row.keys()}
    for key in keys:
        real = lower.get(key.lower())
        if real is not None and row.get(real) not in (None, ""):
            return row.get(real)
    return None


def int_value(value: Any) -> int:
    """Best-effort integer parser for OPNsense pf state counters.

    OPNsense query_states commonly returns byte/packet counters as arrays like
    [bytes_to_source, bytes_to_destination]. The previous parser treated lists as
    plain text and produced 0, which made bytes_delta/packets_delta and flow
    statistics useless.
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, (list, tuple, set)):
        return sum(int_value(item) for item in value)
    if isinstance(value, dict):
        total = 0
        for key in (
            "total", "bytes", "packets", "in", "out", "in_bytes", "out_bytes",
            "bytes_in", "bytes_out", "packets_in", "packets_out",
        ):
            if key in value:
                total += int_value(value.get(key))
        if total:
            return total
        return sum(int_value(v) for v in value.values())

    text = to_text(value).replace(",", "").strip()
    if not text:
        return 0

    if text.startswith("[") and text.endswith("]"):
        nums = re.findall(r"-?\d+(?:\.\d+)?", text)
        if nums:
            return int(sum(float(n) for n in nums))

    text = text.replace(" ", "")
    units = [("gib", 1024**3), ("gb", 1024**3), ("mib", 1024**2), ("mb", 1024**2), ("kib", 1024), ("kb", 1024), ("b", 1)]
    low = text.lower()
    for suffix, multiplier in units:
        if low.endswith(suffix):
            try:
                return int(float(low[: -len(suffix)]) * multiplier)
            except Exception:
                return 0
    try:
        return int(float(text))
    except Exception:
        return 0

def row_to_state(row: Any) -> dict[str, Any] | None:
    raw = row
    if isinstance(row, str):
        ips = IP_RE.findall(row)
        if len(ips) < 2:
            return None
        src_ip, src_port = parse_endpoint(ips[0])
        dest_ip, dest_port = parse_endpoint(ips[1])
        proto = ""
        for candidate in ("tcp", "udp", "icmp", "gre", "ip-in-ip"):
            if candidate in row.lower():
                proto = candidate.upper()
                break
        return {
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": proto or None,
            "bytes_total": 0,
            "packets_total": 0,
            "raw": {"line": row},
        }
    if not isinstance(row, dict):
        return None

    src_value = get_any(row, ["src", "source", "src_ip", "source_ip", "source_address", "lan", "from"])
    dst_value = get_any(row, ["dst", "dest", "destination", "dest_ip", "destination_ip", "destination_address", "remote", "to"])
    src_ip, src_port = parse_endpoint(src_value)
    dest_ip, dest_port = parse_endpoint(dst_value)

    if not src_ip:
        src_ip = normalize_ip(get_any(row, ["srcip", "sourceip", "src_addr", "saddr"]))
    if not dest_ip:
        dest_ip = normalize_ip(get_any(row, ["dstip", "destip", "dst_addr", "daddr"]))
    if src_port is None:
        try:
            src_port = int(get_any(row, ["src_port", "sport", "source_port"]) or 0) or None
        except Exception:
            src_port = None
    if dest_port is None:
        try:
            dest_port = int(get_any(row, ["dest_port", "dst_port", "dport", "destination_port"]) or 0) or None
        except Exception:
            dest_port = None

    if not src_ip or not dest_ip:
        text = json.dumps(row, default=str)
        ips = IP_RE.findall(text)
        if len(ips) >= 2:
            src_ip = src_ip or normalize_ip(ips[0])
            dest_ip = dest_ip or normalize_ip(ips[1])
    if not src_ip or not dest_ip:
        return None

    proto = clean_optional_text(get_any(row, ["proto", "protocol", "pr"]))
    bytes_total = int_value(get_any(row, ["bytes", "bytes_total", "bytes_inout", "traffic", "size"]))
    if not bytes_total:
        bytes_total = int_value(get_any(row, ["bytes_in", "bytes_out", "inbytes", "outbytes"]))
    packets_total = int_value(get_any(row, ["packets", "pkts", "packets_total"]))
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": proto,
        "bytes_total": bytes_total,
        "packets_total": packets_total,
        "raw": raw,
    }


def direction_for(src_ip: str | None, dest_ip: str | None) -> str:
    src_lan = ip_in_lan(src_ip)
    dst_lan = ip_in_lan(dest_ip)
    if src_lan and not dst_lan:
        return "outbound"
    if dst_lan and not src_lan:
        return "inbound"
    if src_lan and dst_lan:
        return "local"
    return "unknown"


def device_ip_for(direction: str, src_ip: str | None, dest_ip: str | None) -> str | None:
    if direction in {"outbound", "local"} and ip_in_lan(src_ip):
        return src_ip
    if direction == "inbound" and ip_in_lan(dest_ip):
        return dest_ip
    if ip_in_lan(src_ip):
        return src_ip
    if ip_in_lan(dest_ip):
        return dest_ip
    return None


def state_key(item: dict[str, Any]) -> str:
    return "|".join([
        to_text(item.get("protocol")).upper(),
        to_text(item.get("src_ip")),
        to_text(item.get("src_port")),
        to_text(item.get("dest_ip")),
        to_text(item.get("dest_port")),
    ])


class GeoLookup:
    def __init__(self):
        self.reader = None
        self.reader_kind: str | None = None
        self.cache: dict[str, str | None] = {}
        self.loaded = False

    def load(self):
        if self.loaded:
            return
        self.loaded = True
        try:
            if GEOIP_COUNTRY_CACHE.exists():
                data = json.loads(GEOIP_COUNTRY_CACHE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.cache = {str(k): (str(v) if v else None) for k, v in data.items()}
        except Exception:
            self.cache = {}

        if not GEOIP_MMDB_PATH:
            return

        try:
            import maxminddb  # type: ignore
            self.reader = maxminddb.open_database(GEOIP_MMDB_PATH)
            self.reader_kind = "maxminddb"
            return
        except Exception:
            self.reader = None
            self.reader_kind = None

        try:
            import geoip2.database  # type: ignore
            self.reader = geoip2.database.Reader(GEOIP_MMDB_PATH)
            self.reader_kind = "geoip2"
        except Exception:
            self.reader = None
            self.reader_kind = None

    def _country_from_mapping(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return None

        for key in ("country", "country_code", "countryCode", "iso_code", "isoCode", "country_iso_code"):
            value = data.get(key)
            if isinstance(value, str):
                country = normalize_country_code(value)
                if country:
                    return country
            if isinstance(value, dict):
                nested = self._country_from_mapping(value)
                if nested:
                    return nested

        country_obj = data.get("country")
        if isinstance(country_obj, dict):
            for key in ("iso_code", "isoCode", "code"):
                country = normalize_country_code(country_obj.get(key))
                if country:
                    return country

        for value in data.values():
            if isinstance(value, dict):
                nested = self._country_from_mapping(value)
                if nested:
                    return nested
        return None

    def country(self, ip_value: Any) -> str | None:
        ip = normalize_ip(ip_value)
        if not ip:
            return None
        try:
            obj = ipaddress.ip_address(ip)
            if obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_link_local:
                return None
        except Exception:
            return None
        self.load()
        if ip in self.cache:
            return normalize_country_code(self.cache.get(ip))

        country = None
        if self.reader is not None:
            try:
                if self.reader_kind == "maxminddb":
                    record = self.reader.get(ip)
                    country = self._country_from_mapping(record)
                else:
                    response = self.reader.country(ip)
                    country = normalize_country_code(getattr(response.country, "iso_code", None))
                    if not country:
                        country = self._country_from_mapping(getattr(response, "raw", None))
            except Exception:
                country = None
        self.cache[ip] = country
        return country

    def save(self):
        if not self.loaded:
            return
        try:
            GEOIP_COUNTRY_CACHE.parent.mkdir(parents=True, exist_ok=True)
            GEOIP_COUNTRY_CACHE.write_text(json.dumps(self.cache, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass

def find_device(cur, ip_value: Any) -> str | None:
    ip = normalize_ip(ip_value)
    if not ip:
        return None
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
    return to_text(row.get("id")) if row else None


def insert_sample(cur, item: dict[str, Any], prev_state: dict[str, Any], geo: GeoLookup) -> bool:
    key = state_key(item)
    direction = direction_for(item.get("src_ip"), item.get("dest_ip"))
    device_ip = device_ip_for(direction, item.get("src_ip"), item.get("dest_ip"))
    device_id = find_device(cur, device_ip)
    if not device_id:
        return False

    previous = prev_state.get(key) if isinstance(prev_state.get(key), dict) else {}
    bytes_total = int(item.get("bytes_total") or 0)
    packets_total = int(item.get("packets_total") or 0)
    bytes_delta = bytes_total - int(previous.get("bytes_total") or 0) if bytes_total else 0
    packets_delta = packets_total - int(previous.get("packets_total") or 0) if packets_total else 0
    if bytes_delta < 0:
        bytes_delta = bytes_total
    if packets_delta < 0:
        packets_delta = packets_total

    # Record new flows even without byte counters so country/new-connection logic has data.
    is_new_state = key not in prev_state
    if not is_new_state and bytes_delta < MIN_BYTES_DELTA and packets_delta <= 0:
        return False

    remote_ip = item.get("dest_ip") if direction == "outbound" else item.get("src_ip")
    country_code = geo.country(remote_ip)
    cur.execute(
        """
        INSERT INTO device_traffic_samples (
            device_id, sample_time, source_system, direction,
            src_ip, src_port, dest_ip, dest_port, protocol, country_code,
            bytes_delta, packets_delta, connection_count, state_key, raw_json, created_at
        ) VALUES (
            %s::uuid, now(), 'opnsense_pf_states', %s,
            %s::inet, %s, %s::inet, %s, NULLIF(%s,''), NULLIF(%s,''),
            %s, %s, 1, %s, %s::jsonb, now()
        )
        """,
        (
            device_id,
            direction,
            item.get("src_ip"),
            item.get("src_port"),
            item.get("dest_ip"),
            item.get("dest_port"),
            clean_optional_text(item.get("protocol")) or "",
            country_code or "",
            bytes_delta,
            packets_delta,
            key,
            j({"raw_state": item.get("raw"), "bytes_total": bytes_total, "packets_total": packets_total, "state_key": key}),
        ),
    )
    return True


def trim_state(current_state: dict[str, Any]) -> dict[str, Any]:
    if len(current_state) <= FLOW_STATE_CACHE_SIZE:
        return current_state
    items = list(current_state.items())[-FLOW_STATE_CACHE_SIZE:]
    return dict(items)


def process() -> dict[str, Any]:
    state = load_state("opnsense_flow_ingest")
    prev_flows = state.get("flows") if isinstance(state.get("flows"), dict) else {}
    payloads = fetch_state_payloads()
    rows: list[Any] = []
    endpoints: list[str] = []
    for payload in payloads:
        rows.extend(extract_rows(payload))
        if payload.get("_security_core_endpoint"):
            endpoints.append(to_text(payload.get("_security_core_endpoint")))
    geo = GeoLookup()
    parsed = 0
    inserted = 0
    current_flows: dict[str, Any] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            for row in rows[:FLOW_MAX_ROWS]:
                item = row_to_state(row)
                if not item:
                    continue
                parsed += 1
                key = state_key(item)
                current_flows[key] = {
                    "bytes_total": int(item.get("bytes_total") or 0),
                    "packets_total": int(item.get("packets_total") or 0),
                    "last_seen_at": utc_now().isoformat(),
                }
                if insert_sample(cur, item, prev_flows, geo):
                    inserted += 1
        conn.commit()
    geo.save()
    state["flows"] = trim_state(current_flows)
    state["last_run_at"] = utc_now().isoformat()
    state["last_rows_read"] = len(rows)
    state["last_rows_parsed"] = parsed
    save_state("opnsense_flow_ingest", state)
    details = {
        "opnsense_url": OPNSENSE_URL,
        "endpoints_used": sorted(set(endpoints)),
        "rows_read": len(rows),
        "states_parsed": parsed,
        "samples_inserted": inserted,
        "geoip_enabled": bool(GEOIP_MMDB_PATH),
    }
    status = "healthy" if parsed or payloads else "degraded"
    update_health(COMPONENT, "detection-worker", status, details, version="phase5-complete-5a5b-keep5c")
    return {"status": status, **details}


def main():
    try:
        result = process()
    except Exception as exc:
        details = {"error": str(exc), "opnsense_url": OPNSENSE_URL}
        update_health(COMPONENT, "detection-worker", "degraded", details, version="phase5-complete-5a5b-keep5c")
        result = {"status": "degraded", **details}
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
