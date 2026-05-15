import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DEFAULT_ENV_FILE = os.environ.get("SECURITY_CORE_ENV_FILE", "/etc/security-core/security-core.env")


def load_env_file(path: str) -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ[key] = value


load_env_file(DEFAULT_ENV_FILE)

DATABASE_URL = os.environ["DATABASE_URL"]
DEEP_SCAN_ENABLED = os.environ.get("DEEP_SCAN_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
DEEP_SCAN_TCP_PORTS = os.environ.get("DEEP_SCAN_TCP_PORTS", "1-65535").strip()
DEEP_SCAN_UDP_PORTS = os.environ.get("DEEP_SCAN_UDP_PORTS", "53,67,68,69,123,161,1900,5353,6666,6667,7000").strip()
DEEP_SCAN_NMAP_TIMING = os.environ.get("DEEP_SCAN_NMAP_TIMING", "T3").strip()
DEEP_SCAN_VERSION_INTENSITY = os.environ.get("DEEP_SCAN_VERSION_INTENSITY", "2").strip()
DEEP_SCAN_TARGET_ONLINE_ONLY = os.environ.get("DEEP_SCAN_TARGET_ONLINE_ONLY", "true").strip().lower() in {"1", "true", "yes", "on"}


def parse_ports_json(value: Any) -> list[int]:
    if isinstance(value, list):
        out = []
        for item in value:
            try:
                out.append(int(item))
            except Exception:
                pass
        return out
    return []


def load_targets() -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            if DEEP_SCAN_TARGET_ONLINE_ONLY:
                cur.execute(
                    """
                    SELECT id::text AS id, host(current_ip) AS ip, open_tcp_ports, open_udp_ports
                    FROM devices
                    WHERE is_online IS TRUE AND current_ip IS NOT NULL
                    ORDER BY current_ip
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id::text AS id, host(current_ip) AS ip, open_tcp_ports, open_udp_ports
                    FROM devices
                    WHERE current_ip IS NOT NULL
                    ORDER BY current_ip
                    """
                )
            return cur.fetchall()


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    summary = {"tcp": [], "udp": []}
    if not xml_text.strip():
        return summary
    root = ET.fromstring(xml_text)
    for port in root.findall(".//port"):
        state_el = port.find("state")
        if state_el is None or state_el.attrib.get("state") != "open":
            continue
        proto = port.attrib.get("protocol")
        item = int(port.attrib.get("portid", "0"))
        if proto == "tcp":
            summary["tcp"].append(item)
        elif proto == "udp":
            summary["udp"].append(item)
    return summary


def run_nmap(ip: str, proto: str, ports: str) -> list[int]:
    cmd = ["nmap", "-Pn", "-sV", f"-{DEEP_SCAN_NMAP_TIMING}", "--version-light", "--version-intensity", DEEP_SCAN_VERSION_INTENSITY, "-oX", "-", "-p", ports]
    if proto == "tcp":
        cmd.insert(2, "-sS")
    else:
        cmd.insert(2, "-sU")
    cmd.append(ip)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if proc.returncode not in (0, 1):
            return []
        return parse_nmap_xml(proc.stdout).get(proto, [])
    except Exception:
        return []


def update_device(device_id: str, tcp: list[int], udp: list[int], old_tcp: Any, old_udp: Any):
    new_tcp = sorted(set(parse_ports_json(old_tcp)) | set(tcp))
    new_udp = sorted(set(parse_ports_json(old_udp)) | set(udp))
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE devices
                SET
                    open_tcp_ports = %s,
                    open_udp_ports = %s,
                    last_scan_at = now(),
                    last_seen_scan_at = now(),
                    updated_at = now()
                WHERE id::text = %s
                """,
                (Jsonb(new_tcp), Jsonb(new_udp), str(device_id)),
            )
        conn.commit()


def update_health(processed: int):
    details = {
        "processed_devices": processed,
        "tcp_ports": DEEP_SCAN_TCP_PORTS,
        "udp_ports": DEEP_SCAN_UDP_PORTS,
    }
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
                WHERE component_name = 'security-nightly-deep-scan'
                """,
                (Jsonb(details),),
            )
        conn.commit()


def main():
    if not DEEP_SCAN_ENABLED:
        update_health(0)
        return

    processed = 0
    for device in load_targets():
        tcp = run_nmap(device["ip"], "tcp", DEEP_SCAN_TCP_PORTS)
        udp = run_nmap(device["ip"], "udp", DEEP_SCAN_UDP_PORTS)
        update_device(device["id"], tcp, udp, device.get("open_tcp_ports"), device.get("open_udp_ports"))
        processed += 1

    update_health(processed)


if __name__ == "__main__":
    main()
