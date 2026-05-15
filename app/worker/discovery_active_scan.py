import ipaddress
import os
import shutil
import subprocess
import warnings
import xml.etree.ElementTree as ET
from typing import Any

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DATABASE_URL = os.environ["DATABASE_URL"]
OPNSENSE_URL = os.environ["OPNSENSE_URL"].rstrip("/")
OPNSENSE_AUTH = f"Basic {os.environ['OPNSENSE_AUTH_B64']}"
OPNSENSE_VERIFY_SSL = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"

ACTIVE_SCAN_SUBNETS = [
    item.strip()
    for item in os.environ.get("ACTIVE_SCAN_SUBNETS", "REDACTED").split(",")
    if item.strip()
]
ACTIVE_SCAN_TOP_PORTS = int(os.environ.get("ACTIVE_SCAN_TOP_PORTS", "20"))
ACTIVE_SCAN_UDP_TOP_PORTS = int(os.environ.get("ACTIVE_SCAN_UDP_TOP_PORTS", "10"))
ACTIVE_SCAN_HOST_TIMEOUT = os.environ.get("ACTIVE_SCAN_HOST_TIMEOUT", "15s")
DEVICE_OFFLINE_MINUTES = int(os.environ.get("DEVICE_OFFLINE_MINUTES", "2"))
LAN_CIDRS = [
    item.strip()
    for item in os.environ.get("SECURITY_CORE_LAN_CIDRS", "REDACTED").split(",")
    if item.strip()
]

NMAP_BIN = shutil.which(os.environ.get("NMAP_BIN", "nmap")) or "/usr/bin/nmap"
RUNNING_AS_ROOT = os.geteuid() == 0

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def parse_networks(values: list[str]):
    networks = []
    for cidr in values:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def parse_lan_networks():
    networks = []
    for cidr in LAN_CIDRS:
        networks.append(ipaddress.ip_network(cidr, strict=False))
    return networks


LAN_NETWORKS = parse_lan_networks()
ACTIVE_SCAN_NETWORKS = parse_networks(ACTIVE_SCAN_SUBNETS)


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


def request_json(session: requests.Session, method: str, url: str):
    response = session.request(method=method, url=url, timeout=20, verify=OPNSENSE_VERIFY_SSL)
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
        else:
            ip = row
        ip = normalize_ip(ip)
        if ip:
            result.add(ip)
    return result


def safe_get_alias_set(session, alias_name, optional_empty=False):
    url = f"{OPNSENSE_URL}/api/firewall/alias_util/list/{alias_name}"
    try:
        data = request_json(session, "GET", url)
        if isinstance(data, dict):
            return alias_ip_set(data.get("rows")), "alias_util", None
        if isinstance(data, list):
            return alias_ip_set(data), "alias_util", None
        return set(), None, None
    except Exception as exc:
        if optional_empty:
            return set(), "optional_empty", None
        return set(), None, {
            "alias_name": alias_name,
            "error": "alias_list_failed",
            "message": str(exc),
        }


def run_nmap(command: list[str]) -> ET.Element | None:
    proc = subprocess.run(command, capture_output=True, text=True)
    stdout = (proc.stdout or "").strip()
    if proc.returncode != 0 and not stdout:
        return None
    if not stdout:
        return None
    try:
        return ET.fromstring(stdout)
    except ET.ParseError:
        return None


def ip_in_active_scan_networks(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(ip_obj in network for network in ACTIVE_SCAN_NETWORKS)


def discover_hosts() -> tuple[dict[str, dict[str, Any]], bool]:
    command = [NMAP_BIN, "-sn", "-n", "-PR", "-PE", "-oX", "-", *ACTIVE_SCAN_SUBNETS]
    root = run_nmap(command)
    hosts: dict[str, dict[str, Any]] = {}

    if root is None:
        return hosts, False

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None
        for address in host.findall("address"):
            addr_type = address.attrib.get("addrtype")
            if addr_type == "ipv4":
                ip = normalize_ip(address.attrib.get("addr"))
            elif addr_type == "mac":
                mac = normalize_mac(address.attrib.get("addr"))
                vendor = address.attrib.get("vendor")

        if not ip or not ip_in_lan(ip):
            continue

        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.attrib.get("name")

        hosts[ip] = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "open_tcp_ports": [],
            "open_udp_ports": [],
            "raw_host_discovery": ET.tostring(host, encoding="unicode"),
        }

    return hosts, True


def enrich_tcp_ports(hosts: dict[str, dict[str, Any]]):
    if not hosts or ACTIVE_SCAN_TOP_PORTS <= 0:
        return

    scan_mode = "-sS" if RUNNING_AS_ROOT else "-sT"

    command = [
        NMAP_BIN,
        "-Pn",
        "-n",
        scan_mode,
        "--open",
        "--top-ports",
        str(ACTIVE_SCAN_TOP_PORTS),
        "--host-timeout",
        ACTIVE_SCAN_HOST_TIMEOUT,
        "-oX",
        "-",
        *hosts.keys(),
    ]

    root = run_nmap(command)
    if root is None:
        return

    for host in root.findall("host"):
        ip = None
        for address in host.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip = normalize_ip(address.attrib.get("addr"))
                break
        if not ip or ip not in hosts or not ip_in_lan(ip):
            continue

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                ports.append(int(port.attrib.get("portid")))
        hosts[ip]["open_tcp_ports"] = sorted(set(ports))
        hosts[ip]["raw_tcp_scan"] = ET.tostring(host, encoding="unicode")


def enrich_udp_ports(hosts: dict[str, dict[str, Any]]):
    if not hosts or ACTIVE_SCAN_UDP_TOP_PORTS <= 0:
        return
    if not RUNNING_AS_ROOT:
        return

    command = [
        NMAP_BIN,
        "-Pn",
        "-n",
        "-sU",
        "--open",
        "--top-ports",
        str(ACTIVE_SCAN_UDP_TOP_PORTS),
        "--host-timeout",
        ACTIVE_SCAN_HOST_TIMEOUT,
        "-oX",
        "-",
        *hosts.keys(),
    ]

    root = run_nmap(command)
    if root is None:
        return

    for host in root.findall("host"):
        ip = None
        for address in host.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip = normalize_ip(address.attrib.get("addr"))
                break
        if not ip or ip not in hosts or not ip_in_lan(ip):
            continue

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                ports.append(int(port.attrib.get("portid")))
        hosts[ip]["open_udp_ports"] = sorted(set(ports))
        hosts[ip]["raw_udp_scan"] = ET.tostring(host, encoding="unicode")


def find_existing_device(cur, mac, ip):
    if mac:
        cur.execute(
            """
            SELECT id, device_key
            FROM devices
            WHERE mac_address = %s
            LIMIT 1
            """,
            (mac,),
        )
        row = cur.fetchone()
        if row:
            return row

    cur.execute(
        """
        SELECT id, device_key
        FROM devices
        WHERE current_ip = %s::inet OR device_key = %s
        ORDER BY last_seen_at DESC
        LIMIT 1
        """,
        (ip, f"ip:{ip}"),
    )
    return cur.fetchone()


def write_device(cur, host, status):
    ip = host["ip"]
    mac = host.get("mac")
    hostname = host.get("hostname")
    vendor = host.get("vendor")
    sources = ["active_nmap"]
    existing = find_existing_device(cur, mac, ip)

    if existing:
        cur.execute(
            """
            UPDATE devices
            SET
                device_key = COALESCE(%s, device_key),
                mac_address = COALESCE(%s, mac_address),
                current_ip = %s::inet,
                hostname = COALESCE(NULLIF(%s, ''), hostname),
                vendor = CASE
                    WHEN NULLIF(manual_vendor, '') IS NOT NULL THEN manual_vendor
                    ELSE COALESCE(NULLIF(%s, ''), vendor)
                END,
                vendor_source = CASE
                    WHEN NULLIF(manual_vendor, '') IS NOT NULL THEN 'manual'
                    ELSE vendor_source
                END,
                status = %s,
                is_online = TRUE,
                source_of_truth = 'security-core',
                discovery_sources = (
                    SELECT to_jsonb(ARRAY(
                        SELECT DISTINCT value
                        FROM jsonb_array_elements_text(COALESCE(devices.discovery_sources, '[]'::jsonb) || %s::jsonb) AS t(value)
                        ORDER BY value
                    ))
                ),
                open_tcp_ports = %s,
                open_udp_ports = %s,
                last_seen_at = now(),
                last_seen_scan_at = now(),
                last_scan_at = now(),
                updated_at = now()
            WHERE id = %s
            RETURNING id
            """,
            (
                mac,
                mac,
                ip,
                hostname,
                vendor,
                status,
                Jsonb(sources),
                Jsonb(host.get("open_tcp_ports", [])),
                Jsonb(host.get("open_udp_ports", [])),
                existing["id"],
            ),
        )
        return cur.fetchone()["id"]

    cur.execute(
        """
        INSERT INTO devices (
            device_key,
            mac_address,
            current_ip,
            hostname,
            vendor,
            first_seen_at,
            last_seen_at,
            last_seen_scan_at,
            last_scan_at,
            status,
            is_online,
            source_of_truth,
            discovery_sources,
            open_tcp_ports,
            open_udp_ports
        )
        VALUES (
            %s,
            %s,
            %s::inet,
            %s,
            %s,
            now(),
            now(),
            now(),
            now(),
            %s,
            TRUE,
            'security-core',
            %s,
            %s,
            %s
        )
        RETURNING id
        """,
        (
            mac or f"ip:{ip}",
            mac,
            ip,
            hostname,
            vendor,
            status,
            Jsonb(sources),
            Jsonb(host.get("open_tcp_ports", [])),
            Jsonb(host.get("open_udp_ports", [])),
        ),
    )
    return cur.fetchone()["id"]


def insert_observation(cur, device_id, host):
    if not ip_in_lan(host["ip"]):
        return

    raw_json = {
        "host_discovery": host.get("raw_host_discovery"),
        "tcp_scan": host.get("raw_tcp_scan"),
        "udp_scan": host.get("raw_udp_scan"),
        "open_tcp_ports": host.get("open_tcp_ports", []),
        "open_udp_ports": host.get("open_udp_ports", []),
        "scanner_user_mode": "root" if RUNNING_AS_ROOT else "unprivileged",
    }
    cur.execute(
        """
        INSERT INTO device_observations (
            device_id,
            observed_ip,
            observed_hostname,
            observed_mac_address,
            observed_vendor,
            observation_source,
            observation_kind,
            observed_at,
            raw_json
        )
        VALUES (%s, %s::inet, %s, %s, %s, 'active_nmap', 'active', now(), %s)
        """,
        (
            device_id,
            host["ip"],
            host.get("hostname"),
            host.get("mac"),
            host.get("vendor"),
            Jsonb(raw_json),
        ),
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
        VALUES ('system', 'security-active-scan', %s, 'system', 'inventory', now(), %s)
        """,
        (event_type, Jsonb(details)),
    )


def mark_unseen_scanned_devices_offline(cur, seen_ips: list[str]):
    if not ACTIVE_SCAN_SUBNETS:
        return 0

    subnet_placeholders = ", ".join(["%s::cidr" for _ in ACTIVE_SCAN_SUBNETS])
    params: list[Any] = list(ACTIVE_SCAN_SUBNETS)

    seen_filter = ""
    if seen_ips:
        seen_filter = " AND host(current_ip) <> ALL(%s::text[])"
        params.append(seen_ips)

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
        WHERE current_ip IS NOT NULL
          AND current_ip <<= ANY (ARRAY[{subnet_placeholders}])
          AND is_online IS TRUE
          {seen_filter}
        """,
        params,
    )
    return cur.rowcount



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


def update_system_health(cur, details):
    cur.execute(
        """
        UPDATE system_health
        SET status = 'healthy',
            last_check_at = now(),
            details_json = %s
        WHERE component_name = 'security-active-scan'
        """,
        (Jsonb(details),),
    )


def main():
    if not os.path.exists(NMAP_BIN):
        raise RuntimeError(f"nmap not found at {NMAP_BIN}")

    session = requests.Session()
    session.headers.update({"Authorization": OPNSENSE_AUTH})

    q_ips, _, _ = safe_get_alias_set(session, "QUARANTINE_HOSTS")
    b_ips, _, _ = safe_get_alias_set(session, "INTERNET_BLOCK_HOSTS")
    d_ips, _, _ = safe_get_alias_set(session, "DNS_ONLY_HOSTS", optional_empty=True)

    hosts, host_discovery_ok = discover_hosts()
    enrich_tcp_ports(hosts)
    enrich_udp_ports(hosts)

    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            for host in hosts.values():
                ip = host["ip"]
                if not ip_in_lan(ip):
                    continue

                if ip in q_ips:
                    status = "quarantined"
                elif ip in b_ips:
                    status = "blocked_internet"
                elif ip in d_ips:
                    status = "dns_only"
                else:
                    status = "online"

                device_id = write_device(cur, host, status)
                insert_observation(cur, device_id, host)

            unseen_offline_count = 0
            if host_discovery_ok and hosts:
                unseen_offline_count = mark_unseen_scanned_devices_offline(cur, sorted(hosts.keys()))

            stale_count = mark_stale_devices_offline(cur)
            details = {
                "lan_cidrs": LAN_CIDRS,
                "subnets": ACTIVE_SCAN_SUBNETS,
                "hosts_up": len(hosts),
                "host_discovery_ok": host_discovery_ok,
                "scanner_mode": "root" if RUNNING_AS_ROOT else "unprivileged",
                "tcp_top_ports": ACTIVE_SCAN_TOP_PORTS,
                "udp_top_ports_requested": ACTIVE_SCAN_UDP_TOP_PORTS,
                "udp_scan_enabled": RUNNING_AS_ROOT and ACTIVE_SCAN_UDP_TOP_PORTS > 0,
                "unseen_offline_count": unseen_offline_count,
                "stale_offline_count": stale_count,
            }
            update_system_health(cur, details)
            insert_audit(cur, "active_inventory_scan_completed", details)
        conn.commit()


if __name__ == "__main__":
    main()
