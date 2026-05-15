#!/usr/bin/env python3
"""Phase 7 packet capture worker.

Hotfix v2:
- robust UUID/text decoding for psycopg/schema drift;
- no bytea-to-uuid casts from Python bytes;
- Path() never receives bytes;
- default tcpdump interface is safe for Debian (any), while legacy "lan" maps to fallback when no OS interface named lan exists;
- capture rows are marked failed instead of being left in starting state if tcpdump cannot start.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from detection_common import connect, getenv_any, j, to_text, update_health

COMPONENT = "security-capture-worker"
VERSION = "phase7-captures-v4-systemd-survive-duration-probe"
CAPTURE_DIR = Path(getenv_any(["PHASE7_CAPTURE_DIR"], "/opt/security-core/captures"))
TCPDUMP_BIN = getenv_any(["PHASE7_TCPDUMP_BIN"], shutil.which("tcpdump") or "/usr/sbin/tcpdump")
DEFAULT_INTERFACE = getenv_any(["PHASE7_CAPTURE_INTERFACE"], "any") or "any"
FALLBACK_INTERFACE = getenv_any(["PHASE7_CAPTURE_FALLBACK_INTERFACE"], "any") or "any"
LAN_INTERFACE_ALIAS = getenv_any(["PHASE7_CAPTURE_LAN_INTERFACE"], FALLBACK_INTERFACE) or FALLBACK_INTERFACE
WAN_INTERFACE_ALIAS = getenv_any(["PHASE7_CAPTURE_WAN_INTERFACE"], FALLBACK_INTERFACE) or FALLBACK_INTERFACE
DEFAULT_DURATION = int(getenv_any(["PHASE7_CAPTURE_DEFAULT_SECONDS"], "120") or "120")
DEFAULT_MAX_MB = int(getenv_any(["PHASE7_CAPTURE_MAX_MB"], "50") or "50")
DISABLE_TCPDUMP_PRIV_DROP = getenv_any(["PHASE7_TCPDUMP_DISABLE_PRIVDROP"], "true").lower() in {"1", "true", "yes", "on"}
ACTIVE_PROBE_ENABLED = getenv_any(["PHASE7_CAPTURE_ACTIVE_PROBE"], "true").lower() in {"1", "true", "yes", "on"}
ACTIVE_PROBE_COUNT = int(getenv_any(["PHASE7_CAPTURE_ACTIVE_PROBE_COUNT"], "3") or "3")
ACTIVE_PROBE_TIMEOUT = int(getenv_any(["PHASE7_CAPTURE_ACTIVE_PROBE_TIMEOUT"], "1") or "1")
ACTIVE_PROBE_INTERVAL = int(getenv_any(["PHASE7_CAPTURE_ACTIVE_PROBE_INTERVAL"], "3") or "3")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def db_text(value: Any) -> str:
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


def normalize_ip(value: Any) -> str:
    text = db_text(value)
    if not text:
        raise ValueError("device_ip is required")
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    return str(ipaddress.ip_address(text))


def normalize_interface(value: Any) -> str:
    requested = db_text(value) or DEFAULT_INTERFACE
    aliases = {"lan": LAN_INTERFACE_ALIAS, "wan": WAN_INTERFACE_ALIAS}
    candidate = aliases.get(requested.lower(), requested)
    if candidate == "any" or Path(f"/sys/class/net/{candidate}").exists():
        return candidate
    if FALLBACK_INTERFACE == "any" or Path(f"/sys/class/net/{FALLBACK_INTERFACE}").exists():
        return FALLBACK_INTERFACE
    return candidate


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()




def stderr_path_for_capture(path: Path) -> Path:
    return Path(str(path) + ".stderr")


def read_short_file(path: Path, limit: int = 4000) -> str:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8", errors="ignore")[-limit:].strip()
    except Exception:
        pass
    return ""


def maybe_start_active_probe(ip: str, duration: int | None = None) -> None:
    """Generate a small amount of deterministic traffic during the capture window.

    Security-core usually runs as a VM/LXC, so it cannot see arbitrary LAN traffic
    unless the switch/AP provides port mirroring or the capture is performed on the
    firewall. This probe creates traffic between security-core and the selected
    device so the PCAP can contain evidence even without port mirroring.
    """
    if not ACTIVE_PROBE_ENABLED:
        return
    ping_bin = shutil.which("ping") or "/usr/bin/ping"
    if not Path(ping_bin).exists():
        return
    duration = max(1, int(duration or DEFAULT_DURATION))
    interval = max(1, int(ACTIVE_PROBE_INTERVAL or 3))
    timeout = max(1, int(ACTIVE_PROBE_TIMEOUT or 1))
    # Run periodic single pings for the whole capture duration. Use shell only for
    # simple time arithmetic; ip is already normalized by ipaddress.ip_address().
    script = (
        f'end=$((SECONDS+{duration})); '
        f'while [ "$SECONDS" -lt "$end" ]; do '
        f'{ping_bin} -c 1 -W {timeout} {ip} >/dev/null 2>&1; '
        f'sleep {interval}; '
        f'done'
    )
    try:
        subprocess.Popen(
            ["/bin/sh", "-c", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass

def process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def find_device_id_by_ip(cur, ip: str) -> str | None:
    cur.execute("SELECT id::text AS id FROM devices WHERE current_ip = %s::inet LIMIT 1", (ip,))
    row = cur.fetchone()
    return uuid_text_or_none(row.get("id")) if row else None


def mark_capture_failed(capture_id: str, error: str) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE packet_captures
                SET status='failed', error_message=%s, stopped_at=COALESCE(stopped_at, now()), updated_at=now()
                WHERE id=NULLIF(%s::text, '')::uuid
                """,
                (error[:1000], capture_id),
            )
        conn.commit()


def start_capture(device_ip: str, duration: int, interface: str, max_mb: int, incident_id: str | None, device_id: str | None, actor: str) -> dict[str, Any]:
    ip = normalize_ip(device_ip)
    duration = max(10, min(int(duration or DEFAULT_DURATION), 3600))
    max_mb = max(1, min(int(max_mb or DEFAULT_MAX_MB), 1024))
    interface = normalize_interface(interface)
    incident_id = uuid_text_or_none(incident_id)
    device_id = uuid_text_or_none(device_id)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    safe_ip = ip.replace(".", "-").replace(":", "-")
    file_path = CAPTURE_DIR / f"security-core-capture-{safe_ip}-{stamp}.pcap"
    bpf_filter = f"host {ip}"

    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "packet_captures"):
                raise RuntimeError("packet_captures table does not exist; run Phase 7 migration")
            if not device_id:
                device_id = find_device_id_by_ip(cur, ip)
            cur.execute(
                """
                INSERT INTO packet_captures(
                    incident_id, device_id, device_ip, interface_name, bpf_filter, status,
                    file_path, duration_seconds, max_file_mb, created_by, created_at, started_at
                ) VALUES (NULLIF(%s::text, '')::uuid, NULLIF(%s::text, '')::uuid, %s::inet, %s, %s, 'starting', %s, %s, %s, %s, now(), now())
                RETURNING id::text AS id
                """,
                (incident_id or "", device_id or "", ip, interface, bpf_filter, str(file_path), duration, max_mb, actor),
            )
            capture_id = uuid_text_or_none(cur.fetchone().get("id"))
            if not capture_id:
                raise RuntimeError("failed to create capture id")
        conn.commit()

    tcpdump_bin = TCPDUMP_BIN if Path(TCPDUMP_BIN).exists() else (shutil.which("tcpdump") or TCPDUMP_BIN)
    cmd = [
        "/usr/bin/timeout",
        "--signal=INT",
        str(duration),
        tcpdump_bin,
        "-i",
        interface,
        "-s",
        "0",
        "-n",
        "-U",
        "-C",
        str(max_mb),
        "-W",
        "1",
        "-w",
        str(file_path),
    ]
    if DISABLE_TCPDUMP_PRIV_DROP:
        cmd.extend(["-Z", "root"])
    cmd.append(bpf_filter)
    err_path = stderr_path_for_capture(file_path)
    try:
        err_handle = err_path.open("ab")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err_handle, start_new_session=True)
        err_handle.close()
        time.sleep(0.5)
        maybe_start_active_probe(ip, duration)
    except Exception as exc:
        mark_capture_failed(capture_id, str(exc))
        raise

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE packet_captures
                SET status='running', pid=%s, command_json=%s, updated_at=now()
                WHERE id=NULLIF(%s::text, '')::uuid
                """,
                (proc.pid, j(cmd), capture_id),
            )
            if table_exists(cur, "audit_events"):
                cur.execute(
                    """
                    INSERT INTO audit_events(actor_type, actor_name, event_type, target_type, target_id, details_json)
                    VALUES ('worker', %s, 'capture_started', 'packet_capture', %s, %s)
                    """,
                    (COMPONENT, capture_id, j({"device_ip": ip, "interface": interface, "duration": duration, "file_path": str(file_path)})),
                )
        conn.commit()
    update_health(COMPONENT, "capture-worker", "healthy", {"started_capture_id": capture_id, "pid": proc.pid, "interface": interface}, VERSION)
    return {"status": "ok", "capture_id": capture_id, "pid": proc.pid, "file_path": str(file_path), "duration_seconds": duration, "interface": interface}



def build_capture_file_path(ip: str) -> Path:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    safe_ip = ip.replace(".", "-").replace(":", "-")
    return CAPTURE_DIR / f"security-core-capture-{safe_ip}-{stamp}.pcap"


def start_existing_capture(row: dict[str, Any], actor: str = "capture-worker") -> dict[str, Any]:
    row_id = uuid_text_or_none(row.get("id"))
    if not row_id:
        raise RuntimeError("capture row id is required")
    ip = normalize_ip(row.get("device_ip"))
    duration = max(10, min(int(row.get("duration_seconds") or DEFAULT_DURATION), 3600))
    max_mb = max(1, min(int(row.get("max_file_mb") or DEFAULT_MAX_MB), 1024))
    interface = normalize_interface(row.get("interface_name") or DEFAULT_INTERFACE)
    file_path_text = db_text(row.get("file_path"))
    file_path = Path(file_path_text) if file_path_text else build_capture_file_path(ip)
    bpf_filter = db_text(row.get("bpf_filter")) or f"host {ip}"
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    tcpdump_bin = TCPDUMP_BIN if Path(TCPDUMP_BIN).exists() else (shutil.which("tcpdump") or TCPDUMP_BIN)
    cmd = [
        "/usr/bin/timeout",
        "--signal=INT",
        str(duration),
        tcpdump_bin,
        "-i",
        interface,
        "-s",
        "0",
        "-n",
        "-U",
        "-C",
        str(max_mb),
        "-W",
        "1",
        "-w",
        str(file_path),
    ]
    if DISABLE_TCPDUMP_PRIV_DROP:
        cmd.extend(["-Z", "root"])
    cmd.append(bpf_filter)
    err_path = stderr_path_for_capture(file_path)

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE packet_captures
                SET status='starting', interface_name=%s, bpf_filter=%s, file_path=%s,
                    duration_seconds=%s, max_file_mb=%s, started_at=COALESCE(started_at, now()), updated_at=now()
                WHERE id=NULLIF(%s::text, '')::uuid
                """,
                (interface, bpf_filter, str(file_path), duration, max_mb, row_id),
            )
        conn.commit()

    try:
        err_handle = err_path.open("ab")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err_handle, start_new_session=True)
        err_handle.close()
        time.sleep(0.5)
        maybe_start_active_probe(ip, duration)
    except Exception as exc:
        mark_capture_failed(row_id, str(exc))
        raise

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE packet_captures
                SET status='running', pid=%s, command_json=%s, updated_at=now()
                WHERE id=NULLIF(%s::text, '')::uuid
                """,
                (proc.pid, j(cmd), row_id),
            )
            if table_exists(cur, "audit_events"):
                cur.execute(
                    """
                    INSERT INTO audit_events(actor_type, actor_name, event_type, target_type, target_id, details_json)
                    VALUES ('worker', %s, 'capture_started', 'packet_capture', %s, %s)
                    """,
                    (COMPONENT, row_id, j({"device_ip": ip, "interface": interface, "duration": duration, "file_path": str(file_path), "requested_by": db_text(row.get("created_by"))})),
                )
        conn.commit()
    return {"capture_id": row_id, "pid": proc.pid, "file_path": str(file_path), "duration_seconds": duration, "interface": interface}


def process_requests(limit: int = 5, actor: str = "capture-worker") -> dict[str, Any]:
    started = 0
    stopped = 0
    failed = 0
    errors: list[dict[str, Any]] = []

    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "packet_captures"):
                return {"status": "ok", "started": 0, "stopped": 0, "failed": 0, "reason": "schema_missing"}
            cur.execute(
                """
                SELECT id::text AS id, pid, status
                FROM packet_captures
                WHERE status='stop_requested'
                ORDER BY updated_at
                LIMIT %s
                """,
                (limit,),
            )
            stop_rows = cur.fetchall()
        conn.commit()

    for row in stop_rows:
        row_id = uuid_text_or_none(row.get("id"))
        if not row_id:
            continue
        try:
            pid = int(row.get("pid") or 0)
            if pid and process_alive(pid):
                try:
                    os.killpg(pid, signal.SIGINT)
                except Exception:
                    try:
                        os.kill(pid, signal.SIGINT)
                    except Exception:
                        pass
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE packet_captures
                        SET status='stopping', updated_at=now()
                        WHERE id=NULLIF(%s::text, '')::uuid AND status='stop_requested'
                        """,
                        (row_id,),
                    )
                conn.commit()
            stopped += 1
        except Exception as exc:
            failed += 1
            errors.append({"capture_id": row_id, "error": str(exc)})

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text AS id, incident_id::text AS incident_id, device_id::text AS device_id,
                       device_ip::text AS device_ip, interface_name, bpf_filter, file_path,
                       duration_seconds, max_file_mb, created_by
                FROM packet_captures
                WHERE status='requested'
                ORDER BY created_at
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        conn.commit()

    for row in rows:
        row_id = uuid_text_or_none(row.get("id")) or ""
        try:
            start_existing_capture(dict(row), actor=actor)
            started += 1
        except Exception as exc:
            failed += 1
            errors.append({"capture_id": row_id, "error": str(exc)})

    finalized_result = finalize(actor=actor)
    update_health(COMPONENT, "capture-worker", "healthy" if failed == 0 else "degraded", {"started": started, "stopped": stopped, "failed": failed, "errors": errors, "finalized": finalized_result.get("finalized")}, VERSION)
    return {"status": "ok", "started": started, "stopped": stopped, "failed": failed, "finalized": finalized_result.get("finalized", 0), "errors": errors}

def stop_capture(capture_id: str, actor: str) -> dict[str, Any]:
    capture_id = uuid_text_or_none(capture_id)
    if not capture_id:
        raise ValueError("valid capture_id is required")
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "packet_captures"):
                raise RuntimeError("packet_captures table does not exist")
            cur.execute("SELECT id::text AS id, pid, file_path FROM packet_captures WHERE id=NULLIF(%s::text, '')::uuid", (capture_id,))
            row = cur.fetchone()
            if not row:
                raise RuntimeError("capture not found")
            pid = int(row.get("pid") or 0)
            if pid and process_alive(pid):
                try:
                    os.killpg(pid, signal.SIGINT)
                except Exception:
                    try:
                        os.kill(pid, signal.SIGINT)
                    except Exception:
                        pass
        conn.commit()
    return finalize(capture_id=capture_id, actor=actor)


def finalize(capture_id: str | None = None, actor: str = "capture-worker") -> dict[str, Any]:
    capture_id = uuid_text_or_none(capture_id)
    finalized = 0
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "packet_captures"):
                return {"status": "ok", "finalized": 0, "reason": "schema_missing"}
            if capture_id:
                cur.execute("SELECT id::text AS id, pid, file_path FROM packet_captures WHERE id=NULLIF(%s::text, '')::uuid", (capture_id,))
            else:
                cur.execute("SELECT id::text AS id, pid, file_path FROM packet_captures WHERE status IN ('starting','running','stopping') ORDER BY created_at")
            rows = cur.fetchall()
            for row in rows:
                row_id = uuid_text_or_none(row.get("id"))
                if not row_id:
                    continue
                pid = int(row.get("pid") or 0)
                if pid and process_alive(pid):
                    continue
                path = Path(db_text(row.get("file_path")))
                size = path.stat().st_size if path.exists() else 0
                stderr_text = read_short_file(stderr_path_for_capture(path))
                status = "completed" if path.exists() and size > 24 else "empty"
                error_message = None
                if status == "empty":
                    # tcpdump informational lines are kept so the UI explains why the file is empty.
                    lower_err = stderr_text.lower()
                    if any(token in lower_err for token in ("permission denied", "no such device", "syntax error", "can't open", "cannot open", "you don't have permission")):
                        status = "failed"
                    error_message = stderr_text[-1000:] if stderr_text else "No packets captured. The device may be offline, block ICMP, or this VM cannot see LAN traffic without a routed path/port mirroring."
                digest = sha256_file(path)
                cur.execute(
                    """
                    UPDATE packet_captures
                    SET status=%s, stopped_at=COALESCE(stopped_at, now()), file_size_bytes=%s, sha256=%s,
                        error_message=COALESCE(%s, error_message), updated_at=now()
                    WHERE id=NULLIF(%s::text, '')::uuid
                    """,
                    (status, size, digest, error_message, row_id),
                )
                if table_exists(cur, "audit_events"):
                    cur.execute(
                        """
                        INSERT INTO audit_events(actor_type, actor_name, event_type, target_type, target_id, details_json)
                        VALUES ('worker', %s, 'capture_finalized', 'packet_capture', %s, %s)
                        """,
                        (actor, row_id, j({"status": status, "file_size_bytes": size, "sha256": digest})),
                    )
                finalized += 1
        conn.commit()
    update_health(COMPONENT, "capture-worker", "healthy", {"finalized": finalized}, VERSION)
    return {"status": "ok", "finalized": finalized}


def cleanup(keep_days: int) -> dict[str, Any]:
    cutoff = utc_now() - dt.timedelta(days=keep_days)
    removed = 0
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "packet_captures"):
                return {"status": "ok", "removed": 0, "reason": "schema_missing"}
            cur.execute("SELECT id::text AS id, file_path FROM packet_captures WHERE created_at < %s AND status IN ('completed','empty','failed','stopped')", (cutoff,))
            for row in cur.fetchall():
                row_id = uuid_text_or_none(row.get("id"))
                path = Path(db_text(row.get("file_path")))
                try:
                    resolved = path.resolve()
                    allowed = CAPTURE_DIR.resolve()
                    if path.exists() and (allowed in resolved.parents or resolved == allowed):
                        path.unlink()
                except Exception:
                    pass
                if row_id:
                    cur.execute("UPDATE packet_captures SET status='deleted', updated_at=now() WHERE id=NULLIF(%s::text, '')::uuid", (row_id,))
                    removed += 1
        conn.commit()
    update_health(COMPONENT, "capture-worker", "healthy", {"cleanup_removed": removed}, VERSION)
    return {"status": "ok", "removed": removed}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("start")
    s.add_argument("--device-ip", required=True)
    s.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    s.add_argument("--interface", default=DEFAULT_INTERFACE)
    s.add_argument("--max-mb", type=int, default=DEFAULT_MAX_MB)
    s.add_argument("--incident-id", default=None)
    s.add_argument("--device-id", default=None)
    s.add_argument("--actor", default="manual")
    st = sub.add_parser("stop")
    st.add_argument("--capture-id", required=True)
    st.add_argument("--actor", default="manual")
    f = sub.add_parser("finalize")
    f.add_argument("--capture-id", default=None)
    f.add_argument("--actor", default="capture-worker")
    pr = sub.add_parser("process-requests")
    pr.add_argument("--limit", type=int, default=5)
    pr.add_argument("--actor", default="capture-worker")
    c = sub.add_parser("cleanup")
    c.add_argument("--keep-days", type=int, default=14)
    args = parser.parse_args()
    try:
        if args.command == "start":
            result = start_capture(args.device_ip, args.duration, args.interface, args.max_mb, args.incident_id, args.device_id, args.actor)
        elif args.command == "stop":
            result = stop_capture(args.capture_id, args.actor)
        elif args.command == "finalize":
            result = finalize(args.capture_id, args.actor)
        elif args.command == "process-requests":
            result = process_requests(args.limit, args.actor)
        else:
            result = cleanup(args.keep_days)
        print(json.dumps(result, default=str), flush=True)
        return 0
    except Exception as exc:
        update_health(COMPONENT, "capture-worker", "error", {"error": str(exc)}, VERSION)
        print(json.dumps({"status": "error", "error": str(exc)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
