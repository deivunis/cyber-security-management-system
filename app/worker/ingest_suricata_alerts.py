import datetime as dt
import hashlib
import json
from collections import deque
from typing import Any

import requests

from detection_common import (
    clean_optional_text,
    connect,
    create_security_event,
    getenv_any,
    load_state,
    normalize_ip,
    save_state,
    to_text,
    update_health,
)


COMPONENT = "security-suricata-ingest"

# Default mode is OPNsense IDS API. No SSH is required.
# Optional fallback: local_file for a mounted/copied eve.json.
SURICATA_SOURCE = getenv_any(["SURICATA_SOURCE", "SECURITY_CORE_SURICATA_SOURCE"], "opnsense_api").lower()

OPNSENSE_URL = getenv_any(["OPNSENSE_URL"], "https://REDACTED").rstrip("/")
OPNSENSE_AUTH_B64 = getenv_any(["OPNSENSE_AUTH_B64"], "")
OPNSENSE_VERIFY_SSL = getenv_any(["OPNSENSE_VERIFY_SSL"], "false").lower() == "true"
OPNSENSE_IDS_ROW_COUNT = int(getenv_any(["OPNSENSE_IDS_ROW_COUNT", "SURICATA_MAX_EVENTS_PER_RUN"], "500"))
OPNSENSE_IDS_SEARCH_PHRASE = getenv_any(["OPNSENSE_IDS_SEARCH_PHRASE"], "")
OPNSENSE_IDS_FILE_ID = getenv_any(["OPNSENSE_IDS_FILE_ID"], "")

SURICATA_EVE_JSON = getenv_any(["SURICATA_EVE_JSON", "SECURITY_CORE_SURICATA_EVE_JSON"], "")
SURICATA_SEEN_CACHE_SIZE = int(getenv_any(["SURICATA_SEEN_CACHE_SIZE"], "5000"))
MAX_EVENTS_PER_RUN = int(getenv_any(["SURICATA_MAX_EVENTS_PER_RUN"], "500"))
CREATE_INCIDENTS = getenv_any(["SURICATA_CREATE_INCIDENTS"], "true").lower() in {"1", "true", "yes", "on"}


def parse_time(value: Any) -> dt.datetime | None:
    text = to_text(value)
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except Exception:
        return None


def row_event_time(item: dict[str, Any]) -> dt.datetime | None:
    for key in ("timestamp", "", "datetime", "event_time"):
        parsed = parse_time(item.get(key))
        if parsed:
            return parsed
    date_value = to_text(item.get("date"))
    time_value = to_text(item.get("time"))
    if date_value and time_value:
        parsed = parse_time(f"{date_value}T{time_value}")
        if parsed:
            return parsed
    return parse_time(time_value or date_value)

def map_alert_severity(value: Any) -> str:
    try:
        sev = int(value)
    except Exception:
        return "medium"
    # Suricata convention: 1 is highest, 3 is lower priority.
    if sev <= 1:
        return "critical"
    if sev == 2:
        return "high"
    if sev == 3:
        return "medium"
    return "low"


def classify_alert(alert: dict[str, Any]) -> str:
    signature = to_text(alert.get("signature") or alert.get("alert") or alert.get("msg")).lower()
    category = to_text(alert.get("category") or alert.get("alert_category")).lower()
    combined = f"{signature} {category}"
    if "scan" in combined or "nmap" in combined or "recon" in combined:
        return "port_scan"
    if "malware" in combined or "trojan" in combined or "botnet" in combined or "c2" in combined or "command and control" in combined:
        return "malware_traffic"
    if "exploit" in combined or "shellcode" in combined or "web application attack" in combined:
        return "exploit_attempt"
    if "dns" in combined:
        return "suspicious_dns"
    return "ids_alert"


def get_any(item: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in item and item.get(key) not in (None, ""):
            return item.get(key)
    return None


def nested_alert(row: dict[str, Any]) -> dict[str, Any]:
    raw_alert = row.get("alert")
    if isinstance(raw_alert, dict):
        return dict(raw_alert)

    return {
        "action": get_any(row, ["alert_action", "action"]),
        "gid": get_any(row, ["gid", "generator_id"]),
        "signature_id": get_any(row, ["signature_id", "sid", "rule_sid"]),
        "rev": get_any(row, ["rev", "revision"]),
        "signature": get_any(row, ["alert", "signature", "msg", "description"]),
        "category": get_any(row, ["category", "alert_category", "classtype"]),
        "severity": get_any(row, ["severity", "alert_severity", "priority"]),
    }


def event_hash(item: dict[str, Any]) -> str:
    preferred = [
        get_any(item, ["filepos", "file_pos", "id"]),
        get_any(item, ["timestamp", "time", "date"]),
        get_any(item, ["src_ip", "source_ip"]),
        get_any(item, ["dest_ip", "dst_ip", "destination_ip"]),
        get_any(item, ["signature_id", "sid"]),
        get_any(item, ["alert", "signature", "msg"]),
    ]
    raw = "|".join(to_text(value) for value in preferred if to_text(value))
    if not raw:
        raw = json.dumps(item, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def opnsense_headers() -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if OPNSENSE_AUTH_B64:
        headers["Authorization"] = f"Basic {OPNSENSE_AUTH_B64}"
    return headers


def read_opnsense_api_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not OPNSENSE_AUTH_B64:
        raise RuntimeError("OPNSENSE_AUTH_B64 is not set; OPNsense API requires key:secret Basic Auth")

    payload: dict[str, Any] = {
        "current": 1,
        "rowCount": OPNSENSE_IDS_ROW_COUNT,
        "searchPhrase": OPNSENSE_IDS_SEARCH_PHRASE,
    }
    if OPNSENSE_IDS_FILE_ID:
        payload["fileid"] = OPNSENSE_IDS_FILE_ID

    url = f"{OPNSENSE_URL}/api/ids/service/query_alerts"
    response = requests.post(
        url,
        headers=opnsense_headers(),
        json=payload,
        timeout=30,
        verify=OPNSENSE_VERIFY_SSL,
    )
    response.raise_for_status()
    data = response.json()
    rows = data.get("rows") if isinstance(data, dict) else []
    if not isinstance(rows, list):
        rows = []

    state = load_state("suricata_opnsense_api")
    seen = deque(state.get("seen") or [], maxlen=SURICATA_SEEN_CACHE_SIZE)
    seen_set = set(seen)
    new_rows: list[dict[str, Any]] = []

    # OPNsense usually returns latest rows first. Reverse so event order is chronological.
    for row in reversed([row for row in rows if isinstance(row, dict)]):
        digest = event_hash(row)
        if digest in seen_set:
            continue
        seen.append(digest)
        seen_set.add(digest)
        new_rows.append(row)
        if len(new_rows) >= MAX_EVENTS_PER_RUN:
            break

    return new_rows, {
        "mode": "opnsense_api",
        "url": url,
        "row_count_requested": OPNSENSE_IDS_ROW_COUNT,
        "raw_rows_read": len(rows),
        "new_rows_after_dedupe": len(new_rows),
        "_state_name": "suricata_opnsense_api",
        "_next_state": {"seen": list(seen)},
    }


def read_local_eve_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from pathlib import Path

    if not SURICATA_EVE_JSON:
        raise FileNotFoundError("SURICATA_EVE_JSON is not set for SURICATA_SOURCE=local_file")
    path = Path(SURICATA_EVE_JSON)
    if not path.exists():
        raise FileNotFoundError(f"Suricata eve.json not found: {path}")

    state = load_state("suricata_eve_local")
    previous_inode = state.get("inode")
    previous_offset = int(state.get("offset") or 0)

    stat = path.stat()
    inode = stat.st_ino
    size = stat.st_size
    offset = previous_offset if previous_inode == inode and previous_offset <= size else 0

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        handle.seek(offset)
        while len(rows) < MAX_EVENTS_PER_RUN:
            line = handle.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
        new_offset = handle.tell()

    return rows, {
        "mode": "local_file",
        "path": str(path),
        "rows_read": len(rows),
        "_state_name": "suricata_eve_local",
        "_next_state": {"inode": inode, "offset": new_offset, "size": size, "path": str(path)},
    }


def read_suricata_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if SURICATA_SOURCE in {"opnsense_api", "api", "opnsense"}:
        return read_opnsense_api_rows()
    if SURICATA_SOURCE in {"local_file", "file", "eve_json"}:
        return read_local_eve_rows()
    raise RuntimeError(f"Unsupported SURICATA_SOURCE={SURICATA_SOURCE}. Use opnsense_api or local_file.")


def process() -> dict[str, Any]:
    try:
        rows, state = read_suricata_rows()
    except Exception as exc:
        details = {
            "source": SURICATA_SOURCE,
            "opnsense_url": OPNSENSE_URL,
            "local_path": SURICATA_EVE_JSON,
            "error": str(exc),
        }
        update_health(COMPONENT, "detection-worker", "degraded", details)
        return {"status": "degraded", **details}

    processed = 0
    skipped = 0
    incident_events = 0

    pending_state_name = state.pop("_state_name", None)
    pending_next_state = state.pop("_next_state", None)

    with connect() as conn:
        with conn.cursor() as cur:
            for item in rows:
                event_type_raw = to_text(item.get("event_type")).lower()
                # OPNsense IDS API rows can be flattened and may not expose event_type.
                if event_type_raw and event_type_raw != "alert":
                    skipped += 1
                    continue

                alert = nested_alert(item)
                signature_name = clean_optional_text(alert.get("signature"))
                signature_id = clean_optional_text(alert.get("signature_id"))
                if not signature_name and not signature_id:
                    skipped += 1
                    continue

                src_ip = normalize_ip(get_any(item, ["src_ip", "source_ip", "source", "src"]))
                dest_ip = normalize_ip(get_any(item, ["dest_ip", "dst_ip", "destination_ip", "destination", "dst"]))
                src_port = get_any(item, ["src_port", "source_port", "sport"])
                dest_port = get_any(item, ["dest_port", "dst_port", "destination_port", "dport"])
                proto = clean_optional_text(get_any(item, ["proto", "protocol", "app_proto"]))
                event_type = classify_alert(alert)
                severity = map_alert_severity(alert.get("severity"))
                category = clean_optional_text(alert.get("category"))
                action = clean_optional_text(alert.get("action"))
                title = signature_name or f"Suricata {event_type.replace('_', ' ')}"
                description = f"OPNsense Suricata alert: {title}"
                if category:
                    description += f" ({category})"
                if action:
                    description += f"; action={action}"

                result = create_security_event(
                    cur,
                    source_system="suricata",
                    event_type=event_type,
                    severity=severity,
                    title=title,
                    description=description,
                    src_ip=src_ip,
                    src_port=int(src_port) if str(src_port).isdigit() else None,
                    dest_ip=dest_ip,
                    dest_port=int(dest_port) if str(dest_port).isdigit() else None,
                    protocol=proto,
                    signature_id=signature_id,
                    signature_name=signature_name,
                    event_time=row_event_time(item),
                    raw_json={"opnsense_ids_api_row": item, "alert": alert},
                    dedupe_key=f"suricata|{event_type}|{src_ip or '-'}|{dest_ip or '-'}|{signature_id or signature_name or '-'}",
                    create_incident=CREATE_INCIDENTS,
                )
                processed += 1
                if result.get("incident_id"):
                    incident_events += 1
        conn.commit()

    if pending_state_name and isinstance(pending_next_state, dict):
        save_state(pending_state_name, pending_next_state)

    details = {**state, "source": SURICATA_SOURCE, "alerts_processed": processed, "skipped": skipped, "events_with_incident": incident_events}
    update_health(COMPONENT, "detection-worker", "healthy", details)
    return {"status": "healthy", **details}


def main():
    result = process()
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
