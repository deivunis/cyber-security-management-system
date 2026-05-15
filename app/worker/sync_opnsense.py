import ipaddress
import json
import os
import warnings
from typing import Any

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from requests import HTTPError

DATABASE_URL = os.environ["DATABASE_URL"]
OPNSENSE_URL = os.environ["OPNSENSE_URL"].rstrip("/")
OPNSENSE_AUTH = f"Basic {os.environ['OPNSENSE_AUTH_B64']}"
OPNSENSE_VERIFY_SSL = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"
DEVICE_OFFLINE_MINUTES = int(os.environ.get("DEVICE_OFFLINE_MINUTES", "2"))
LAN_CIDRS = [
    item.strip()
    for item in os.environ.get("SECURITY_CORE_LAN_CIDRS", "REDACTED").split(",")
    if item.strip()
]

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def parse_lan_networks():
    networks = []
    for cidr in LAN_CIDRS:
        networks.append(ipaddress.ip_network(cidr, strict=False))
    return networks


LAN_NETWORKS = parse_lan_networks()


def ip_in_lan(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(ip_obj in network for network in LAN_NETWORKS)


def normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    return text or None


def normalize_mac(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower().replace("-", ":")
    return text or None


def unique_list(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def request_json(session: requests.Session, method: str, url: str, payload: dict[str, Any] | None = None):
    response = session.request(
        method=method,
        url=url,
        json=payload,
        headers={"Content-Type": "application/json"} if payload is not None else None,
        timeout=20,
        verify=OPNSENSE_VERIFY_SSL,
    )
    response.raise_for_status()
    body = (response.text or "").strip()
    if not body:
        return {}
    return response.json()


def alias_ip_set(rows):
    result = set()
    if not rows:
        return result
    for row in rows:
        if isinstance(row, dict):
            ip = row.get("address") or row.get("ip") or row.get("name")
            ip = normalize_ip(ip)
            if ip:
                result.add(ip)
        elif isinstance(row, str):
            ip = normalize_ip(row)
            if ip:
                result.add(ip)
    return result


def safe_get_alias_set(session, alias_name, optional_empty=False):
    url = f"{OPNSENSE_URL}/api/firewall/alias_util/list/{alias_name}"
    try:
        response = session.get(url, timeout=20, verify=OPNSENSE_VERIFY_SSL)

        if response.status_code == 200:
            body = (response.text or "").strip()
            if not body:
                return set(), ("optional_empty" if optional_empty else "empty"), None
            data = json.loads(body)
            if isinstance(data, dict):
                return alias_ip_set(data.get("rows")), "alias_util", None
            if isinstance(data, list):
                return alias_ip_set(data), "alias_util", None
            return set(), None, {
                "alias_name": alias_name,
                "error": "alias_unexpected_format",
                "raw_type": str(type(data)),
            }

        if optional_empty and response.status_code in (400, 404):
            return set(), "optional_empty", None

        response.raise_for_status()
        return set(), None, None

    except HTTPError as exc:
        status_code = exc.response.status_code if getattr(exc, "response", None) is not None else None
        return set(), None, {
            "alias_name": alias_name,
            "error": "alias_list_failed",
            "http_status": status_code,
            "message": str(exc),
        }
    except Exception as exc:
        return set(), None, {
            "alias_name": alias_name,
            "error": "alias_list_exception",
            "message": str(exc),
        }


def safe_get_kea_leases(session):
    try:
        data = request_json(
            session,
            "POST",
            f"{OPNSENSE_URL}/api/kea/leases4/search/",
            {
                "current": 1,
                "rowCount": 1000,
                "searchPhrase": "",
                "sort": {},
            },
        )
        rows = data.get("rows") if isinstance(data, dict) else []
        filtered_rows = []
        for row in rows or []:
            ip = resolve_ip(row)
            if ip and ip_in_lan(ip):
                filtered_rows.append(row)
        return filtered_rows, "kea_search", None
    except Exception as exc:
        return [], None, {
            "source": "opnsense_kea",
            "error": "leases_fetch_failed",
            "message": str(exc),
        }


def extract_rows(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("rows", "items", "arp", "neighbors"):
        if isinstance(data.get(key), list):
            return data.get(key) or []
    return []


def safe_get_arp_rows(session):
    attempts = [
        ("POST", f"{OPNSENSE_URL}/api/diagnostics/interface/search_arp", {"current": 1, "rowCount": 2000, "searchPhrase": "", "sort": {}}),
        ("GET", f"{OPNSENSE_URL}/api/diagnostics/interface/search_arp", None),
        ("GET", f"{OPNSENSE_URL}/api/diagnostics/interface/get_arp", None),
        ("GET", f"{OPNSENSE_URL}/api/diagnostics/interface/getArp", None),
    ]

    last_error = None
    for method, url, payload in attempts:
        try:
            data = request_json(session, method, url, payload)
            rows = extract_rows(data)
            filtered_rows = []
            for row in rows:
                ip = resolve_ip(row)
                if ip and ip_in_lan(ip):
                    filtered_rows.append(row)
            if filtered_rows or isinstance(data, dict):
                return filtered_rows, url.rsplit("/", 1)[-1], None
        except Exception as exc:
            last_error = {
                "source": "opnsense_arp",
                "error": "arp_fetch_failed",
                "endpoint": url,
                "message": str(exc),
            }
    return [], None, last_error


def resolve_hostname(row):
    for key in ("hostname", "host", "hostname_local", "name", "client-hostname"):
        value = row.get(key)
        if value:
            return str(value).strip()
    return None


def resolve_ip(row):
    for key in ("address", "ip", "ipaddr", "ip-address", "ipAddress"):
        value = normalize_ip(row.get(key))
        if value:
            return value
    return None


def resolve_mac(row):
    for key in ("hwaddr", "mac", "macaddr", "mac-address", "lladdr"):
        value = normalize_mac(row.get(key))
        if value:
            return value
    return None


def ensure_bundle(bundles, ip, mac):
    if mac and mac in bundles:
        return bundles[mac]
    ip_key = f"ip:{ip}" if ip else None
    if ip_key and ip_key in bundles:
        bundle = bundles.pop(ip_key)
        if mac:
            bundle["mac"] = mac
            bundles[mac] = bundle
            return bundle
        bundles[ip_key] = bundle
        return bundle

    key = mac or ip_key
    if key not in bundles:
        bundles[key] = {
            "ip": ip,
            "mac": mac,
            "hostname": None,
            "sources": [],
            "rows": [],
            "last_seen_dhcp": False,
            "last_seen_arp": False,
        }
    return bundles[key]


def merge_observation(bundles, row, source_name):
    ip = resolve_ip(row)
    mac = resolve_mac(row)
    hostname = resolve_hostname(row)

    if ip and not ip_in_lan(ip):
        return

    if not ip and not mac:
        return

    bundle = ensure_bundle(bundles, ip, mac)
    if ip and not bundle.get("ip"):
        bundle["ip"] = ip
    if mac and not bundle.get("mac"):
        bundle["mac"] = mac
    if hostname and not bundle.get("hostname"):
        bundle["hostname"] = hostname
    bundle["sources"] = unique_list(bundle["sources"] + [source_name])
    bundle["rows"].append({"source": source_name, "raw": row})
    if source_name == "opnsense_kea":
        bundle["last_seen_dhcp"] = True
        if hostname:
            bundle["hostname"] = hostname
    if source_name == "opnsense_arp":
        bundle["last_seen_arp"] = True


def find_existing_device(cur, mac, ip):
    if mac:
        cur.execute(
            """
            SELECT id, device_key, mac_address, host(current_ip) AS current_ip, discovery_sources
            FROM devices
            WHERE mac_address = %s
            LIMIT 1
            """,
            (mac,),
        )
        row = cur.fetchone()
        if row:
            return row

    if ip:
        cur.execute(
            """
            SELECT id, device_key, mac_address, host(current_ip) AS current_ip, discovery_sources
            FROM devices
            WHERE current_ip = %s::inet OR device_key = %s
            ORDER BY last_seen_at DESC
            LIMIT 1
            """,
            (ip, f"ip:{ip}"),
        )
        row = cur.fetchone()
        if row:
            return row

    return None


def write_device(cur, bundle, status):
    ip = bundle.get("ip")
    mac = bundle.get("mac")
    hostname = bundle.get("hostname")
    discovery_sources = bundle.get("sources") or []
    existing = find_existing_device(cur, mac, ip)
    arp_seen = bool(bundle.get("last_seen_arp", False))
    dhcp_seen = bool(bundle.get("last_seen_dhcp", False))

    if existing:
        new_device_key = mac or existing["device_key"] or (f"ip:{ip}" if ip else None)
        cur.execute(
            """
            UPDATE devices
            SET
                device_key = COALESCE(%s, device_key),
                mac_address = COALESCE(%s, mac_address),
                current_ip = COALESCE(%s::inet, current_ip),
                hostname = COALESCE(NULLIF(%s, ''), hostname),
                source_of_truth = 'security-core',
                discovery_sources = (
                    SELECT to_jsonb(ARRAY(
                        SELECT DISTINCT value
                        FROM jsonb_array_elements_text(COALESCE(devices.discovery_sources, '[]'::jsonb) || %s::jsonb) AS t(value)
                        ORDER BY value
                    ))
                ),
                last_seen_dhcp_at = CASE WHEN %s THEN now() ELSE last_seen_dhcp_at END,
                last_seen_arp_at = CASE WHEN %s THEN now() ELSE last_seen_arp_at END,
                updated_at = now()
            WHERE id = %s
            RETURNING id
            """,
            (
                new_device_key,
                mac,
                ip,
                hostname,
                Jsonb(discovery_sources),
                dhcp_seen,
                arp_seen,
                existing["id"],
            ),
        )
        return cur.fetchone()["id"]

    device_key = mac or f"ip:{ip}"
    cur.execute(
        """
        INSERT INTO devices (
            device_key,
            mac_address,
            current_ip,
            hostname,
            first_seen_at,
            last_seen_at,
            last_seen_dhcp_at,
            last_seen_arp_at,
            status,
            is_online,
            source_of_truth,
            discovery_sources
        )
        VALUES (
            %s,
            %s,
            %s::inet,
            %s,
            now(),
            now(),
            CASE WHEN %s THEN now() ELSE NULL END,
            CASE WHEN %s THEN now() ELSE NULL END,
            %s,
            TRUE,
            'security-core',
            %s
        )
        RETURNING id
        """,
        (
            device_key,
            mac,
            ip,
            hostname,
            dhcp_seen,
            arp_seen,
            status,
            Jsonb(discovery_sources),
        ),
    )
    return cur.fetchone()["id"]


def insert_observation(cur, device_id, bundle, source_name, raw_row):
    observed_ip = resolve_ip(raw_row) or bundle.get("ip")
    if observed_ip and not ip_in_lan(observed_ip):
        return

    cur.execute(
        """
        INSERT INTO device_observations (
            device_id,
            observed_ip,
            observed_hostname,
            observed_mac_address,
            observation_source,
            observation_kind,
            observed_at,
            raw_json
        )
        VALUES (%s, %s::inet, %s, %s, %s, 'passive', now(), %s)
        """,
        (
            device_id,
            observed_ip,
            resolve_hostname(raw_row) or bundle.get("hostname"),
            resolve_mac(raw_row) or bundle.get("mac"),
            source_name,
            Jsonb(raw_row),
        ),
    )


def update_system_health(cur, details):
    cur.execute(
        """
        UPDATE system_health
        SET status = 'healthy',
            last_check_at = now(),
            details_json = %s
        WHERE component_name = 'opnsense'
        """,
        (Jsonb(details),),
    )

    cur.execute(
        """
        UPDATE system_health
        SET status = 'healthy',
            last_check_at = now(),
            details_json = %s
        WHERE component_name = 'security-worker'
        """,
        (Jsonb({"job": "sync_opnsense", **details}),),
    )


def insert_audit(cur, event_type, details):
    cur.execute(
        """
        INSERT INTO audit_events (
            actor_type,
            actor_name,
            event_type,
            target_type,
            target_id,
            event_time,
            details_json
        )
        VALUES ('system', 'security-worker', %s, 'system', 'opnsense', now(), %s)
        """,
        (event_type, Jsonb(details)),
    )


def mark_stale_devices_offline(cur):
    cur.execute(
        f"""
        UPDATE devices
        SET
            is_online = FALSE,
            status = CASE
                WHEN status IN ('quarantined', 'blocked_internet', 'dns_only') THEN status
                ELSE 'offline'
            END,
            last_offline_at = CASE WHEN is_online IS TRUE THEN now() ELSE last_offline_at END,
            updated_at = now()
        WHERE COALESCE(
                GREATEST(last_seen_at, last_seen_scan_at),
                last_seen_at,
                last_seen_scan_at
              ) < now() - interval '{DEVICE_OFFLINE_MINUTES} minutes'
          AND (
                current_ip <<= ANY (ARRAY[{", ".join(["%s::cidr" for _ in LAN_CIDRS])}])
              )
        """,
        LAN_CIDRS,
    )
    return cur.rowcount


def main():
    session = requests.Session()
    session.headers.update({"Authorization": OPNSENSE_AUTH})

    lease_rows, lease_source, lease_error = safe_get_kea_leases(session)
    arp_rows, arp_source, arp_error = safe_get_arp_rows(session)

    q_ips, q_source, q_err = safe_get_alias_set(session, "QUARANTINE_HOSTS", optional_empty=False)
    b_ips, b_source, b_err = safe_get_alias_set(session, "INTERNET_BLOCK_HOSTS", optional_empty=False)
    d_ips, d_source, d_err = safe_get_alias_set(session, "DNS_ONLY_HOSTS", optional_empty=True)

    issues = [item for item in [lease_error, arp_error, q_err, b_err, d_err] if item]

    bundles = {}
    for row in lease_rows:
        merge_observation(bundles, row, "opnsense_kea")
    for row in arp_rows:
        merge_observation(bundles, row, "opnsense_arp")

    merged_count = 0
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            for bundle in bundles.values():
                ip = bundle.get("ip")
                if not ip or not ip_in_lan(ip):
                    continue

                if ip in q_ips:
                    status = "quarantined"
                elif ip in b_ips:
                    status = "blocked_internet"
                elif ip in d_ips:
                    status = "dns_only"
                else:
                    status = "online"

                device_id = write_device(cur, bundle, status)
                for row_item in bundle["rows"]:
                    insert_observation(cur, device_id, bundle, row_item["source"], row_item["raw"])
                merged_count += 1

            stale_count = mark_stale_devices_offline(cur)

            health_details = {
                "lan_cidrs": LAN_CIDRS,
                "leases_count": len(lease_rows),
                "arp_count": len(arp_rows),
                "merged_count": merged_count,
                "stale_offline_count": stale_count,
                "quarantine_count": len(q_ips),
                "internet_block_count": len(b_ips),
                "dns_only_count": len(d_ips),
                "leases_source": lease_source,
                "arp_source": arp_source,
                "quarantine_source": q_source,
                "internet_block_source": b_source,
                "dns_only_source": d_source,
                "inventory_issues": issues,
            }
            update_system_health(cur, health_details)
            insert_audit(cur, "opnsense_inventory_sync_completed", health_details)
        conn.commit()


if __name__ == "__main__":
    main()
