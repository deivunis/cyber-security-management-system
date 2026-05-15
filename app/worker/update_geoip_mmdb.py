#!/usr/bin/env python3
"""
Security Core GeoIP MMDB updater.

Downloads a local GeoIP MMDB file from GEOIP_MMDB_URL and writes it atomically to
GEOIP_MMDB_PATH. Intended for IPinfo Lite MMDB or any compatible MaxMind MMDB URL.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import psycopg
    from psycopg.types.json import Jsonb
except Exception:  # pragma: no cover - optional health reporting only
    psycopg = None
    Jsonb = None


COMPONENT_NAME = "security-geoip-mmdb-update"
COMPONENT_TYPE = "detection-worker"


def getenv_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def getenv_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def mask_url(url: str) -> str:
    # Avoid printing API tokens in journald/system_health.
    return url.split("?", 1)[0] + "?token=REDACTED" if "?" in url else url


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_probably_mmdb(path: Path) -> bool:
    # MaxMind DB files contain this marker near the end of the file.
    marker = b"\xab\xcd\xefMaxMind.com"
    try:
        with path.open("rb") as f:
            if path.stat().st_size <= 0:
                return False
            f.seek(max(0, path.stat().st_size - 131072))
            tail = f.read()
        return marker in tail
    except Exception:
        return False


def write_health(status: str, details: dict[str, Any]) -> None:
    database_url = os.getenv("DATABASE_URL")
    if not database_url or psycopg is None or Jsonb is None:
        return

    safe_details = json.loads(json.dumps(details, default=str))
    try:
        with psycopg.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO system_health (
                        component_name,
                        component_type,
                        status,
                        last_check_at,
                        details_json
                    )
                    VALUES (%s, %s, %s, now(), %s)
                    ON CONFLICT (component_name)
                    DO UPDATE SET
                        component_type = EXCLUDED.component_type,
                        status = EXCLUDED.status,
                        last_check_at = now(),
                        details_json = EXCLUDED.details_json
                    """,
                    (COMPONENT_NAME, COMPONENT_TYPE, status, Jsonb(safe_details)),
                )
    except Exception as exc:
        print(json.dumps({"health_update_error": str(exc)}, indent=2), flush=True)


def rotate_backup(target: Path, keep: int) -> None:
    if keep <= 0 or not target.exists():
        return

    backup_dir = target.parent / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{target.name}.{stamp}.bak"
    shutil.copy2(target, backup_path)

    backups = sorted(backup_dir.glob(f"{target.name}.*.bak"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[keep:]:
        try:
            old.unlink()
        except FileNotFoundError:
            pass


def download_file(url: str, destination_tmp: Path, timeout: int) -> None:
    headers = {"User-Agent": "security-core-geoip-updater/1.0"}
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise RuntimeError(f"download returned HTTP {status}")
        with destination_tmp.open("wb") as f:
            shutil.copyfileobj(response, f, length=1024 * 1024)


def main() -> int:
    url = os.getenv("GEOIP_MMDB_URL", "").strip()
    path_raw = os.getenv("GEOIP_MMDB_PATH", "").strip()
    timeout = getenv_int("GEOIP_MMDB_TIMEOUT_SECONDS", 180)
    min_bytes = getenv_int("GEOIP_MMDB_MIN_BYTES", 100_000)
    backup_keep = getenv_int("GEOIP_MMDB_BACKUP_KEEP", 3)
    validate_mmdb = getenv_bool("GEOIP_MMDB_VALIDATE_FORMAT", True)

    if not url or not path_raw:
        details = {
            "status": "degraded",
            "message": "GEOIP_MMDB_URL or GEOIP_MMDB_PATH is not configured.",
            "url_configured": bool(url),
            "path_configured": bool(path_raw),
        }
        print(json.dumps(details, indent=2, sort_keys=True), flush=True)
        write_health("degraded", details)
        return 2

    target = Path(path_raw)
    target.parent.mkdir(parents=True, exist_ok=True)

    before_sha = sha256_file(target) if target.exists() else None
    before_size = target.stat().st_size if target.exists() else 0

    try:
        with tempfile.NamedTemporaryFile(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent), delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            download_file(url, tmp_path, timeout)
            downloaded_size = tmp_path.stat().st_size
            if downloaded_size < min_bytes:
                raise RuntimeError(f"downloaded file too small: {downloaded_size} bytes < {min_bytes} bytes")
            if validate_mmdb and not is_probably_mmdb(tmp_path):
                raise RuntimeError("downloaded file does not look like a MaxMind MMDB file")

            after_sha = sha256_file(tmp_path)
            changed = after_sha != before_sha
            if changed:
                rotate_backup(target, backup_keep)
                os.replace(tmp_path, target)
            else:
                tmp_path.unlink(missing_ok=True)

            try:
                target.chmod(0o640)
            except Exception:
                pass

            details = {
                "status": "healthy",
                "message": "GeoIP MMDB is available and up to date." if not changed else "GeoIP MMDB downloaded and replaced atomically.",
                "url": mask_url(url),
                "path": str(target),
                "changed": changed,
                "size_bytes": target.stat().st_size,
                "previous_size_bytes": before_size,
                "sha256": sha256_file(target),
                "validated_mmdb_marker": is_probably_mmdb(target),
                "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            print(json.dumps(details, indent=2, sort_keys=True), flush=True)
            write_health("healthy", details)
            return 0
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError, OSError) as exc:
        details = {
            "status": "degraded",
            "message": "GeoIP MMDB update failed.",
            "error": str(exc),
            "url": mask_url(url),
            "path": str(target),
            "existing_file_available": target.exists(),
            "existing_size_bytes": target.stat().st_size if target.exists() else 0,
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        print(json.dumps(details, indent=2, sort_keys=True), flush=True)
        # If an existing DB remains available, keep the component degraded but do not destroy it.
        write_health("degraded", details)
        return 1


if __name__ == "__main__":
    sys.exit(main())
