#!/usr/bin/env python3
"""Phase 7 HTML/PDF report generator for security-core."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from detection_common import connect, getenv_any, j, to_text, update_health

COMPONENT = "security-report-engine"
VERSION = "phase7-reports-v3"
REPORT_DIR = Path(getenv_any(["PHASE7_REPORT_DIR"], "/opt/security-core/reports"))
ENABLE_PDF = getenv_any(["PHASE7_REPORT_ENABLE_PDF"], "false").lower() in {"1", "true", "yes", "on"}
WKHTMLTOPDF_BIN = getenv_any(["PHASE7_WKHTMLTOPDF_BIN"], shutil.which("wkhtmltopdf") or "")
WEASYPRINT_BIN = getenv_any(["PHASE7_WEASYPRINT_BIN"], shutil.which("weasyprint") or "")


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




def maybe_decode_hex_text(value: Any) -> str:
    text = db_text(value)
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


def decode_embedded_hex_text(value: Any) -> str:
    text = db_text(value)
    if not text:
        return ""
    def repl(match):
        original = match.group(0)
        decoded = maybe_decode_hex_text(original)
        return decoded if decoded != original else original
    pattern = re.compile(
        r"(?<![0-9A-Fa-f])(?:"
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        r"|\\x[0-9A-Fa-f]{8,}"
        r"|[0-9A-Fa-f]{12,}"
        r")(?![0-9A-Fa-f])"
    )
    return pattern.sub(repl, text)

def uuid_text(value: Any) -> str | None:
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


def scalar_row(cur, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    cur.execute(sql, params)
    return dict(cur.fetchone() or {})


def fetch_all(cur, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    cur.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


def h(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        value = value.isoformat()
    return html.escape(decode_embedded_hex_text(value))


def render_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return "<p class='muted'>Duomenų nėra.</p>"
    head = "".join(f"<th>{h(label)}</th>" for key, label in columns)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{h(row.get(key))}</td>" for key, label in columns) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def collect_data(period_start: dt.datetime, period_end: dt.datetime) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            data: dict[str, Any] = {
                "period_start": period_start,
                "period_end": period_end,
                "generated_at": utc_now(),
            }
            data["devices"] = scalar_row(
                cur,
                """
                SELECT COUNT(*)::int AS total_devices,
                       COUNT(*) FILTER (WHERE is_online)::int AS online_devices,
                       COUNT(*) FILTER (WHERE NOT is_online)::int AS offline_devices,
                       COUNT(*) FILTER (WHERE category IS NULL OR category='' OR category='unknown')::int AS unknown_devices,
                       COUNT(*) FILTER (WHERE COALESCE(vulnerability_count,0)>0)::int AS vulnerable_devices,
                       COUNT(*) FILTER (WHERE COALESCE(kev_count,0)>0)::int AS kev_devices
                FROM devices
                """,
            )
            data["incidents"] = scalar_row(
                cur,
                """
                SELECT COUNT(*)::int AS total_incidents,
                       COUNT(*) FILTER (WHERE status IN ('open','acknowledged','in_progress'))::int AS open_incidents,
                       COUNT(*) FILTER (WHERE severity='critical')::int AS critical_incidents,
                       COUNT(*) FILTER (WHERE severity='high')::int AS high_incidents,
                       COUNT(*) FILTER (WHERE severity='medium')::int AS medium_incidents,
                       COUNT(*) FILTER (WHERE severity='low')::int AS low_incidents
                FROM incidents
                WHERE created_at BETWEEN %s AND %s
                """,
                (period_start, period_end),
            )
            data["security_events"] = scalar_row(
                cur,
                """
                SELECT COUNT(*)::int AS total_events,
                       COUNT(*) FILTER (WHERE source_system ILIKE 'adguard%%')::int AS adguard_events,
                       COUNT(*) FILTER (WHERE event_type ILIKE '%%block%%')::int AS block_events,
                       COUNT(*) FILTER (WHERE source_system ILIKE 'suricata%%')::int AS suricata_events,
                       COUNT(*) FILTER (WHERE source_system ILIKE '%%anomaly%%' OR event_type ILIKE '%%spike%%' OR event_type ILIKE '%%burst%%')::int AS anomaly_events
                FROM security_events
                WHERE event_time BETWEEN %s AND %s
                """,
                (period_start, period_end),
            )
            data["traffic"] = scalar_row(
                cur,
                """
                SELECT COUNT(*)::int AS traffic_samples,
                       COALESCE(SUM(bytes_delta),0)::bigint AS bytes_total,
                       COUNT(DISTINCT country_code) FILTER (WHERE country_code IS NOT NULL)::int AS country_count
                FROM device_traffic_samples
                WHERE sample_time BETWEEN %s AND %s
                """,
                (period_start, period_end),
            )
            data["top_incidents"] = fetch_all(
                cur,
                """
                SELECT i.severity, i.status, i.title, i.source_system, i.incident_type,
                       d.hostname AS device_hostname, host(d.current_ip) AS device_ip, i.created_at
                FROM incidents i
                LEFT JOIN devices d ON d.id = i.device_id
                WHERE i.created_at BETWEEN %s AND %s
                ORDER BY CASE i.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
                         i.created_at DESC
                LIMIT 25
                """,
                (period_start, period_end),
            )
            data["top_risky_devices"] = fetch_all(
                cur,
                """
                SELECT hostname, host(current_ip) AS current_ip, vendor, model, category,
                       vulnerability_count, kev_count, highest_cvss, highest_severity, status, policy_effective_mode
                FROM devices
                ORDER BY COALESCE(kev_count,0) DESC, COALESCE(highest_cvss,0) DESC, COALESCE(vulnerability_count,0) DESC, COALESCE(risk_score,0) DESC
                LIMIT 15
                """,
            )
            data["dns_summary"] = fetch_all(
                cur,
                """
                SELECT d.hostname AS device_hostname, host(d.current_ip) AS device_ip,
                       COUNT(*)::int AS dns_events,
                       COUNT(*) FILTER (WHERE se.event_type ILIKE '%%block%%')::int AS dns_blocks,
                       COUNT(DISTINCT se.domain)::int AS unique_domains
                FROM security_events se
                LEFT JOIN devices d ON d.id = se.device_id
                WHERE se.event_time BETWEEN %s AND %s
                  AND se.source_system ILIKE 'adguard%%'
                GROUP BY d.hostname, d.current_ip
                ORDER BY dns_blocks DESC, dns_events DESC
                LIMIT 15
                """,
                (period_start, period_end),
            )
            data["geo_summary"] = fetch_all(
                cur,
                """
                SELECT country_code, COUNT(*)::int AS samples, COUNT(DISTINCT device_id)::int AS devices,
                       COALESCE(SUM(bytes_delta),0)::bigint AS bytes_total
                FROM device_traffic_samples
                WHERE sample_time BETWEEN %s AND %s
                  AND country_code IS NOT NULL
                GROUP BY country_code
                ORDER BY bytes_total DESC, samples DESC
                LIMIT 15
                """,
                (period_start, period_end),
            )
            if table_exists(cur, "response_actions"):
                data["responses"] = scalar_row(
                    cur,
                    """
                    SELECT COUNT(*)::int AS response_actions,
                           COUNT(*) FILTER (WHERE status='applied')::int AS applied,
                           COUNT(*) FILTER (WHERE status='applied_degraded')::int AS degraded,
                           COUNT(*) FILTER (WHERE status='rolled_back')::int AS rolled_back,
                           COUNT(*) FILTER (WHERE action_type='quarantine')::int AS quarantines,
                           COUNT(*) FILTER (WHERE action_type='internet_block')::int AS internet_blocks,
                           COUNT(*) FILTER (WHERE action_type='rate_limit')::int AS rate_limits,
                           COUNT(*) FILTER (WHERE action_type='dynamic_firewall_block')::int AS dynamic_blocks
                    FROM response_actions
                    WHERE created_at BETWEEN %s AND %s OR updated_at BETWEEN %s AND %s
                    """,
                    (period_start, period_end, period_start, period_end),
                )
            else:
                data["responses"] = {}
            if table_exists(cur, "audit_events"):
                data["audit"] = scalar_row(cur, "SELECT COUNT(*)::int AS audit_events FROM audit_events WHERE event_time BETWEEN %s AND %s", (period_start, period_end))
            else:
                data["audit"] = {"audit_events": 0}
            data["health"] = fetch_all(
                cur,
                """
                SELECT component_name, component_type, status, last_check_at, version
                FROM system_health
                ORDER BY component_name
                LIMIT 100
                """,
            )
            return data


def render_html(data: dict[str, Any]) -> str:
    devices = data.get("devices", {})
    incidents = data.get("incidents", {})
    events = data.get("security_events", {})
    traffic = data.get("traffic", {})
    responses = data.get("responses", {})
    audit = data.get("audit", {})
    recommendations = []
    if int(incidents.get("critical_incidents") or 0) > 0:
        recommendations.append("Peržiūrėti critical incidentus ir patikrinti, ar pritaikyti containment veiksmai buvo sėkmingi.")
    if int(devices.get("unknown_devices") or 0) > 0:
        recommendations.append("Patvirtinti nežinomų įrenginių tapatybę ir priskirti tinkamas politikų šablonų taisykles.")
    if int(devices.get("kev_devices") or 0) > 0:
        recommendations.append("Prioritetiškai atnaujinti arba izoliuoti įrenginius, turinčius CISA KEV pažeidžiamumų.")
    if int(responses.get("degraded") or 0) > 0:
        recommendations.append("Patikrinti degraded response veiksmus OPNsense pusėje ir sutvarkyti enforcement klaidas.")
    if not recommendations:
        recommendations.append("Kritinių neatitikimų šiuo laikotarpiu nerasta; tęsti stebėseną ir periodiškai testuoti reagavimo scenarijus.")

    return f"""<!doctype html>
<html lang="lt">
<head>
<meta charset="utf-8">
<title>Security Core ataskaita</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }}
h1, h2 {{ color: #111827; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0 24px; }}
.card {{ border: 1px solid #d1d5db; border-radius: 10px; padding: 14px; background: #f9fafb; }}
.card .value {{ font-size: 28px; font-weight: bold; margin-top: 6px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; font-size: 13px; }}
th, td {{ border: 1px solid #d1d5db; padding: 7px; text-align: left; vertical-align: top; }}
th {{ background: #f3f4f6; }}
.muted {{ color: #6b7280; }}
.footer {{ margin-top: 40px; font-size: 12px; color: #6b7280; }}
</style>
</head>
<body>
<h1>Security Core savaitinė saugumo ataskaita</h1>
<p class="muted">Laikotarpis: {h(data.get('period_start'))} – {h(data.get('period_end'))}. Sugeneruota: {h(data.get('generated_at'))}.</p>

<h2>Santrauka</h2>
<div class="grid">
  <div class="card">Įrenginiai<div class="value">{h(devices.get('total_devices'))}</div></div>
  <div class="card">Online<div class="value">{h(devices.get('online_devices'))}</div></div>
  <div class="card">Nežinomi<div class="value">{h(devices.get('unknown_devices'))}</div></div>
  <div class="card">Atviri incidentai<div class="value">{h(incidents.get('open_incidents'))}</div></div>
  <div class="card">Critical incidentai<div class="value">{h(incidents.get('critical_incidents'))}</div></div>
  <div class="card">DNS/IDS/Anomaly įvykiai<div class="value">{h(events.get('total_events'))}</div></div>
  <div class="card">Response veiksmai<div class="value">{h(responses.get('response_actions'))}</div></div>
  <div class="card">Audito įrašai<div class="value">{h(audit.get('audit_events'))}</div></div>
</div>

<h2>Aptikimo statistika</h2>
<div class="grid">
  <div class="card">AdGuard įvykiai<div class="value">{h(events.get('adguard_events'))}</div></div>
  <div class="card">DNS blokavimai<div class="value">{h(events.get('block_events'))}</div></div>
  <div class="card">Suricata įvykiai<div class="value">{h(events.get('suricata_events'))}</div></div>
  <div class="card">Anomalijos<div class="value">{h(events.get('anomaly_events'))}</div></div>
  <div class="card">Srauto mėginiai<div class="value">{h(traffic.get('traffic_samples'))}</div></div>
  <div class="card">Šalys<div class="value">{h(traffic.get('country_count'))}</div></div>
</div>

<h2>Response / prevencijos veiksmai</h2>
<div class="grid">
  <div class="card">Pritaikyti<div class="value">{h(responses.get('applied'))}</div></div>
  <div class="card">Degraded<div class="value">{h(responses.get('degraded'))}</div></div>
  <div class="card">Rollback<div class="value">{h(responses.get('rolled_back'))}</div></div>
  <div class="card">Karantinai<div class="value">{h(responses.get('quarantines'))}</div></div>
  <div class="card">Internet block<div class="value">{h(responses.get('internet_blocks'))}</div></div>
  <div class="card">Rate limit<div class="value">{h(responses.get('rate_limits'))}</div></div>
</div>

<h2>Prioritetiniai incidentai</h2>
{render_table(data.get('top_incidents', []), [('severity','Severity'),('status','Būsena'),('title','Pavadinimas'),('source_system','Šaltinis'),('incident_type','Tipas'),('device_hostname','Įrenginys'),('device_ip','IP'),('created_at','Sukurta')])}

<h2>Rizikingiausi įrenginiai</h2>
{render_table(data.get('top_risky_devices', []), [('hostname','Įrenginys'),('current_ip','IP'),('vendor','Gamintojas'),('model','Modelis'),('category','Kategorija'),('vulnerability_count','CVE'),('kev_count','KEV'),('highest_cvss','CVSS'),('highest_severity','Severity'),('status','Būsena'),('policy_effective_mode','Politika')])}

<h2>DNS santrauka pagal įrenginį</h2>
{render_table(data.get('dns_summary', []), [('device_hostname','Įrenginys'),('device_ip','IP'),('dns_events','DNS įvykiai'),('dns_blocks','Blokavimai'),('unique_domains','Unikalūs domenai')])}

<h2>GeoIP komunikacijos</h2>
{render_table(data.get('geo_summary', []), [('country_code','Šalis'),('samples','Mėginiai'),('devices','Įrenginiai'),('bytes_total','Baitai')])}

<h2>Rekomendacijos</h2>
<ul>{''.join(f'<li>{h(item)}</li>' for item in recommendations)}</ul>

<h2>Sistemos būklė</h2>
{render_table(data.get('health', []), [('component_name','Komponentas'),('component_type','Tipas'),('status','Būsena'),('last_check_at','Paskutinis tikrinimas'),('version','Versija')])}

<div class="footer">Ataskaita sugeneruota security-core Phase 7 report engine.</div>
</body>
</html>"""


def sha256_file(path: Path) -> str:
    hsh = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hsh.update(chunk)
    return hsh.hexdigest()


def insert_report(report_type: str, fmt: str, period_start: dt.datetime, period_end: dt.datetime, title: str, file_path: Path, status: str, generated_by: str, error: str | None = None) -> str | None:
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "generated_reports"):
                raise RuntimeError("generated_reports table does not exist; run Phase 7 migration")
            size = file_path.stat().st_size if file_path.exists() else None
            digest = sha256_file(file_path) if file_path.exists() else None
            cur.execute(
                """
                INSERT INTO generated_reports(report_type, report_format, period_start, period_end, title, file_path, file_size_bytes, sha256, status, error_message, generated_by, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                RETURNING id::text AS id
                """,
                (report_type, fmt, period_start, period_end, title, str(file_path), size, digest, status, error, generated_by),
            )
            report_id = uuid_text(cur.fetchone().get("id"))
            if table_exists(cur, "audit_events"):
                cur.execute(
                    """
                    INSERT INTO audit_events(actor_type, actor_name, event_type, target_type, target_id, details_json)
                    VALUES ('worker', %s, 'report_generated', 'generated_report', %s, %s)
                    """,
                    (COMPONENT, report_id, j({"report_type": report_type, "format": fmt, "file_path": str(file_path)})),
                )
        conn.commit()
        return report_id


def generate(period_days: int, fmt: str, report_type: str, actor: str) -> dict[str, Any]:
    period_end = utc_now()
    period_start = period_end - dt.timedelta(days=period_days)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = period_end.strftime("%Y%m%dT%H%M%SZ")
    title = f"Security Core {report_type} report {period_start.date()} - {period_end.date()}"
    html_path = REPORT_DIR / f"security-core-{report_type}-{stamp}.html"
    data = collect_data(period_start, period_end)
    html_text = render_html(data)
    html_path.write_text(html_text, encoding="utf-8")
    output_path = html_path
    final_format = "html"

    if fmt == "pdf":
        if not ENABLE_PDF:
            raise RuntimeError("PDF requested, but PHASE7_REPORT_ENABLE_PDF=false. Use --format html or enable/install weasyprint/wkhtmltopdf.")
        pdf_path = html_path.with_suffix(".pdf")
        if WEASYPRINT_BIN:
            proc = subprocess.run([WEASYPRINT_BIN, str(html_path), str(pdf_path)], capture_output=True, text=True, timeout=180)
            tool_name = "weasyprint"
        elif WKHTMLTOPDF_BIN:
            proc = subprocess.run([WKHTMLTOPDF_BIN, str(html_path), str(pdf_path)], capture_output=True, text=True, timeout=180)
            tool_name = "wkhtmltopdf"
        else:
            raise RuntimeError("PDF requested, but neither weasyprint nor wkhtmltopdf is available. Use --format html.")
        if proc.returncode != 0:
            raise RuntimeError(f"{tool_name} failed: {(proc.stderr or proc.stdout)[-1000:]}")
        output_path = pdf_path
        final_format = "pdf"

    report_id = insert_report(report_type, final_format, period_start, period_end, title, output_path, "generated", actor)
    update_health(COMPONENT, "report-worker", "healthy", {"report_id": report_id, "file_path": str(output_path), "format": final_format}, VERSION)
    return {"status": "ok", "report_id": report_id, "file_path": str(output_path), "format": final_format, "title": title}


def cleanup(keep_days: int) -> dict[str, Any]:
    cutoff = utc_now() - dt.timedelta(days=keep_days)
    removed = 0
    with connect() as conn:
        with conn.cursor() as cur:
            if not table_exists(cur, "generated_reports"):
                return {"status": "ok", "removed": 0, "reason": "schema_missing"}
            cur.execute("SELECT id::text AS id, file_path FROM generated_reports WHERE created_at < %s", (cutoff,))
            for row in cur.fetchall():
                path = Path(db_text(row.get("file_path")))
                try:
                    if path.exists() and REPORT_DIR.resolve() in path.resolve().parents:
                        path.unlink()
                except Exception:
                    pass
                rid = uuid_text(row.get("id"))
                if rid:
                    cur.execute("DELETE FROM generated_reports WHERE id = NULLIF(%s::text, '')::uuid", (rid,))
                removed += 1
        conn.commit()
    update_health(COMPONENT, "report-worker", "healthy", {"cleanup_removed": removed}, VERSION)
    return {"status": "ok", "removed": removed}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--period-days", type=int, default=7)
    g.add_argument("--format", choices=["html", "pdf"], default="html")
    g.add_argument("--report-type", default="weekly")
    g.add_argument("--actor", default="report-engine")
    c = sub.add_parser("cleanup")
    c.add_argument("--keep-days", type=int, default=90)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            result = generate(max(1, min(args.period_days, 90)), args.format, args.report_type, args.actor)
        else:
            result = cleanup(max(7, args.keep_days))
        print(json.dumps(result, default=str), flush=True)
        return 0
    except Exception as exc:
        update_health(COMPONENT, "report-worker", "error", {"error": str(exc)}, VERSION)
        print(json.dumps({"status": "error", "error": str(exc)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
