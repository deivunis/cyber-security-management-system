import ipaddress
import hashlib
import json
import os
import re
import warnings
from urllib.parse import quote
from typing import Any
from urllib.parse import urlparse

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from requests import HTTPError

DATABASE_URL = os.environ["DATABASE_URL"]
OPNSENSE_URL = os.environ["OPNSENSE_URL"].rstrip("/")
OPNSENSE_AUTH = f"Basic {os.environ['OPNSENSE_AUTH_B64']}"
OPNSENSE_VERIFY_SSL = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"
LAN_CIDRS = [item.strip() for item in os.environ.get("SECURITY_CORE_LAN_CIDRS", "REDACTED").split(",") if item.strip()]

QUARANTINE_ALIAS = os.environ.get("POLICY_QUARANTINE_ALIAS", "QUARANTINE_HOSTS")
INTERNET_BLOCK_ALIAS = os.environ.get("POLICY_INTERNET_BLOCK_ALIAS", "INTERNET_BLOCK_HOSTS")
DNS_ONLY_ALIAS = os.environ.get("POLICY_DNS_ONLY_ALIAS", "DNS_ONLY_HOSTS")
LOCAL_ONLY_ALIAS = os.environ.get("POLICY_LOCAL_ONLY_ALIAS", "LOCAL_ONLY_HOSTS")
GEO_RESTRICT_ALIAS = os.environ.get("POLICY_GEO_RESTRICT_ALIAS", "GEO_RESTRICT_HOSTS")
UPNP_BLOCK_ALIAS = os.environ.get("POLICY_UPNP_BLOCK_ALIAS", "UPNP_BLOCK_HOSTS")
WHITELIST_ALIAS = os.environ.get("POLICY_WHITELIST_ALIAS", "WHITELIST_HOSTS")
LOCAL_ONLY_PEERS_ALIAS = os.environ.get("POLICY_LOCAL_ONLY_PEERS_ALIAS", "LOCAL_ONLY_PEER_HOSTS")
UPNP_CONTROL_TARGETS_ALIAS = os.environ.get("POLICY_UPNP_CONTROL_TARGETS_ALIAS", "UPNP_CONTROL_TARGETS")
GEO_ALLOWED_ALIAS_PREFIX = os.environ.get("POLICY_GEO_ALLOWED_ALIAS_PREFIX", "GEO_ALLOWED_")
GEO_ALLOWED_ALIAS_SUFFIX = os.environ.get("POLICY_GEO_ALLOWED_ALIAS_SUFFIX", "_HOSTS")
POLICY_ENFORCE_INTERFACE = os.environ.get("POLICY_ENFORCE_INTERFACE", "lan")
POLICY_ENFORCE_IPPROTOCOL = os.environ.get("POLICY_ENFORCE_IPPROTOCOL", "inet")
POLICY_RULE_PREFIX = os.environ.get("POLICY_RULE_PREFIX", "SECURITY_CORE_POLICY")

CORE_SOURCE_ALIASES = {
    QUARANTINE_ALIAS,
    INTERNET_BLOCK_ALIAS,
    DNS_ONLY_ALIAS,
    LOCAL_ONLY_ALIAS,
    GEO_RESTRICT_ALIAS,
    UPNP_BLOCK_ALIAS,
}
OPTIONAL_ALIASES = {WHITELIST_ALIAS, LOCAL_ONLY_PEERS_ALIAS, UPNP_CONTROL_TARGETS_ALIAS}

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return str(value).strip()
    return str(value).strip()


def bool_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return to_text(value).lower() in {"1", "true", "yes", "on"}


def normalize_ip(value: Any) -> str | None:
    text = to_text(value)
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return None


def normalize_mac(value: Any) -> str | None:
    text = to_text(value).lower().replace("-", ":")
    parts = re.findall(r"[0-9a-f]{2}", text)
    if len(parts) == 6:
        return ":".join(parts)
    return None


def normalize_access_mode(value: Any) -> str:
    text = to_text(value).lower() or "normal"
    if text not in {"normal", "dns_only", "local_only", "quarantine"}:
        return "normal"
    return text


def normalize_country_codes(values: Any) -> list[str]:
    result: list[str] = []
    if values is None:
        return result
    raw_values = values if isinstance(values, (list, tuple, set)) else [values]
    for raw in raw_values:
        text = to_text(raw)
        if not text:
            continue
        text = text.replace("\n", ",").replace(";", ",")
        parts = [part.strip().upper() for part in text.split(",")]
        for part in parts:
            if re.fullmatch(r"[A-Z]{2}", part) and part not in result:
                result.append(part)
    return result


def normalize_peer_values(values: Any) -> list[str]:
    result: list[str] = []
    if values is None:
        return result
    raw_values = values if isinstance(values, (list, tuple, set)) else [values]
    for raw in raw_values:
        text = to_text(raw)
        if not text:
            continue
        text = text.replace("\n", ",").replace(";", ",")
        parts = [part.strip() for part in text.split(",")]
        for part in parts:
            if part and part not in result:
                result.append(part)
    return result


def derive_effective_mode(policy_json: dict[str, Any] | None) -> str:
    policy_json = dict(policy_json or {})
    requested_mode = normalize_access_mode(policy_json.get("access_mode") or "normal")
    if bool_flag(policy_json.get("quarantine_default")) or requested_mode == "quarantine":
        return "quarantine"
    if bool_flag(policy_json.get("local_only")) or requested_mode == "local_only":
        return "local_only"
    if bool_flag(policy_json.get("dns_only")) or requested_mode == "dns_only":
        return "dns_only"
    if policy_json and not bool_flag(policy_json.get("internet_allowed", True)):
        return "blocked_internet"
    return "normal"


def build_blacklist_policy_json() -> dict[str, Any]:
    return {
        "display_name": "Blacklist quarantine",
        "description": "ACL blacklist forces quarantine and full network isolation.",
        "access_mode": "quarantine",
        "internet_allowed": False,
        "dns_only": False,
        "local_only": False,
        "geo_restrictions_enabled": False,
        "geo_allowed_countries": [],
        "quarantine_default": True,
        "upnp_allowed": False,
        "local_only_peers": [],
        "auto_assign_categories": [],
    }


def build_whitelist_policy_json() -> dict[str, Any]:
    return {
        "display_name": "Whitelist override",
        "description": "ACL whitelist marks the device as trusted and eligible for explicit allow rules.",
        "access_mode": "normal",
        "internet_allowed": True,
        "dns_only": False,
        "local_only": False,
        "geo_restrictions_enabled": False,
        "geo_allowed_countries": [],
        "quarantine_default": False,
        "upnp_allowed": True,
        "local_only_peers": [],
        "auto_assign_categories": [],
    }


def ascii_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {to_text(k): ascii_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [ascii_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [ascii_json_safe(v) for v in value]
    if isinstance(value, str):
        return value.encode("ascii", "ignore").decode("ascii")
    return value


def j(value: Any) -> Jsonb:
    return Jsonb(ascii_json_safe(value))


def parse_lan_networks() -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(cidr, strict=False) for cidr in LAN_CIDRS]


LAN_NETWORKS = parse_lan_networks()


def ip_in_lan(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(ip_obj in network for network in LAN_NETWORKS)


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




def parse_json_body(response):
    body = (response.text or "").strip()
    if not body:
        return {}
    try:
        return response.json()
    except Exception:
        return {"raw": body}


def get_alias_uuid(session: requests.Session, alias_name: str) -> str | None:
    candidates = [
        f"{OPNSENSE_URL}/api/firewall/alias/get_alias_u_u_i_d/{quote(alias_name, safe='')}",
        f"{OPNSENSE_URL}/api/firewall/alias/getAliasUUID/{quote(alias_name, safe='')}",
    ]
    for url in candidates:
        try:
            response = session.get(url, timeout=20, verify=OPNSENSE_VERIFY_SSL)
            if response.status_code == 404:
                continue
            response.raise_for_status()
            data = parse_json_body(response)
            if isinstance(data, dict):
                for key in ("uuid", "result", "alias_uuid"):
                    value = to_text(data.get(key))
                    if value and value not in {"not found", "failed"}:
                        return value
            elif isinstance(data, str):
                value = to_text(data)
                if value and value not in {"not found", "failed"}:
                    return value
        except Exception:
            continue
    return None


def ensure_alias_definition(session: requests.Session, alias_name: str, alias_type: str, content: Any, description: str, issues: list[dict[str, Any]], proto: str = ""):
    if alias_type == "geoip":
        countries = normalize_country_codes(content)
        alias_content = "\n".join(countries)
        network_content = ",".join(countries)
    else:
        alias_content = to_text(content)
        network_content = alias_content.replace("\n", ",") if alias_content else ""

    payload = {
        "alias": {
            "enabled": "1",
            "name": alias_name,
            "type": alias_type,
            "proto": proto,
            "categories": "",
            "updatefreq": "",
            "content": alias_content,
            "interface": "",
            "counters": "0",
            "description": description,
        },
        "network_content": network_content,
        "authgroup_content": "",
    }
    try:
        alias_uuid = get_alias_uuid(session, alias_name)
        if alias_uuid:
            request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/set_item/{alias_uuid}", payload)
        else:
            request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/add_item", payload)
        return True
    except Exception as exc:
        if alias_type == "geoip" and network_content and "," in network_content:
            alt_payload = dict(payload)
            alt_payload["alias"] = dict(payload["alias"])
            alt_payload["alias"]["content"] = network_content
            try:
                alias_uuid = get_alias_uuid(session, alias_name)
                if alias_uuid:
                    request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/set_item/{alias_uuid}", alt_payload)
                else:
                    request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/add_item", alt_payload)
                return True
            except Exception as exc2:
                issues.append({"alias_name": alias_name, "error": "alias_definition_failed", "message": str(exc2), "alias_type": alias_type, "attempt": "comma_fallback"})
                return False
        issues.append({"alias_name": alias_name, "error": "alias_definition_failed", "message": str(exc), "alias_type": alias_type})
        return False


def search_alias_items(session: requests.Session, search_phrase: str = "", row_count: int = 1000) -> list[dict[str, Any]]:
    urls = [
        f"{OPNSENSE_URL}/api/firewall/alias/search_item?current=1&rowCount={row_count}&searchPhrase={quote(search_phrase, safe='')}",
        f"{OPNSENSE_URL}/api/firewall/alias/searchItem?current=1&rowCount={row_count}&searchPhrase={quote(search_phrase, safe='')}",
    ]
    for url in urls:
        try:
            response = session.get(url, timeout=20, verify=OPNSENSE_VERIFY_SSL)
            response.raise_for_status()
            data = parse_json_body(response)
            rows = (data.get("rows") if isinstance(data, dict) else []) or []
            if isinstance(rows, list):
                return rows
        except Exception:
            continue
    return []


def managed_runtime_alias_names(session: requests.Session) -> set[str]:
    names: set[str] = set()
    for row in search_alias_items(session, ""):
        name = to_text(row.get("name"))
        description = to_text(row.get("description"))
        if "Managed by security-core" in description and (name.startswith("POLICY_") or name.startswith("SCP_")):
            names.add(name)
    return names


def delete_alias_definition(session: requests.Session, alias_name: str, issues: list[dict[str, Any]]) -> bool:
    alias_uuid = get_alias_uuid(session, alias_name)
    if not alias_uuid:
        return False
    try:
        request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/del_item/{alias_uuid}", {})
        return True
    except Exception as exc:
        issues.append({"alias_name": alias_name, "error": "alias_delete_failed", "message": str(exc)})
        return False


def search_rule_by_description(session: requests.Session, description: str) -> dict[str, Any] | None:
    url = f"{OPNSENSE_URL}/api/firewall/filter/searchRule?current=1&rowCount=200&searchPhrase={quote(description, safe='')}"
    try:
        response = session.get(url, timeout=20, verify=OPNSENSE_VERIFY_SSL)
        response.raise_for_status()
        data = parse_json_body(response)
        rows = data.get("rows") if isinstance(data, dict) else []
        for row in rows or []:
            if to_text(row.get("description")) == description:
                return row
    except Exception:
        return None
    return None


def ensure_filter_rule(session: requests.Session, rule: dict[str, Any], issues: list[dict[str, Any]]):
    description = to_text(rule.get("description"))
    if not description:
        return False
    payload = {"rule": rule}
    try:
        existing = search_rule_by_description(session, description)
        if existing and to_text(existing.get("uuid")):
            request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/filter/set_rule/{existing['uuid']}", payload)
        else:
            request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/filter/add_rule", payload)
        return True
    except Exception as exc:
        issues.append({"rule_description": description, "error": "rule_ensure_failed", "message": str(exc)})
        return False


def delete_filter_rule(session: requests.Session, description: str, issues: list[dict[str, Any]]):
    existing = search_rule_by_description(session, description)
    if not existing or not to_text(existing.get("uuid")):
        return False
    try:
        response = session.post(f"{OPNSENSE_URL}/api/firewall/filter/del_rule/{existing['uuid']}", timeout=20, verify=OPNSENSE_VERIFY_SSL)
        response.raise_for_status()
        return True
    except Exception as exc:
        issues.append({"rule_description": description, "error": "rule_delete_failed", "message": str(exc)})
        return False


def filter_apply(session: requests.Session):
    try:
        request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/filter/apply", {})
        return None
    except Exception as exc:
        return {"error": "filter_apply_failed", "message": str(exc)}


def build_rule(
    description: str,
    action: str,
    source_alias: str,
    destination_alias: str,
    sequence: int,
    protocol: str = "any",
    destination_port: str = "",
    log_enabled: bool = False,
) -> dict[str, Any]:
    rule = {
        "enabled": "1",
        "action": action,
        "quick": "1",
        "interface": POLICY_ENFORCE_INTERFACE,
        "direction": "in",
        "ipprotocol": POLICY_ENFORCE_IPPROTOCOL,
        "protocol": protocol,
        "source_net": source_alias or "any",
        "source_not": "0",
        "destination_net": destination_alias or "any",
        "destination_not": "0",
        "destination_port": destination_port,
        "log": "1" if log_enabled else "0",
        "sequence": str(sequence),
        "description": description,
    }
    return rule


def policy_geo_dest_alias(policy_name: str) -> str:
    return policy_runtime_alias(policy_name, "GEO_ALLOWED")

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
            return set(), None, {"alias_name": alias_name, "error": "alias_unexpected_format", "raw_type": str(type(data))}
        if optional_empty and response.status_code in (400, 404):
            return set(), "optional_empty", None
        response.raise_for_status()
        return set(), None, None
    except HTTPError as exc:
        status_code = exc.response.status_code if getattr(exc, "response", None) is not None else None
        return set(), None, {"alias_name": alias_name, "error": "alias_list_failed", "http_status": status_code, "message": str(exc)}
    except Exception as exc:
        return set(), None, {"alias_name": alias_name, "error": "alias_list_exception", "message": str(exc)}


def alias_change(session: requests.Session, alias_name: str, action: str, address: str):
    try:
        request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias_util/{action}/{alias_name}", {"address": address})
        return None
    except Exception as exc:
        return {"alias_name": alias_name, "action": action, "address": address, "error": "alias_change_failed", "message": str(exc)}


def alias_reconfigure(session: requests.Session):
    try:
        request_json(session, "POST", f"{OPNSENSE_URL}/api/firewall/alias/reconfigure", {})
        return None
    except Exception as exc:
        return {"error": "alias_reconfigure_failed", "message": str(exc)}


def load_policy_templates(cur) -> dict[str, dict[str, Any]]:
    cur.execute(
        """
        SELECT id::text AS id, policy_name, policy_json
        FROM policy_templates
        WHERE is_enabled IS TRUE
        ORDER BY policy_name
        """
    )
    rows = cur.fetchall() or []
    return {to_text(row["policy_name"]): dict(row) for row in rows}


def load_manual_assignments(cur) -> dict[str, dict[str, Any]]:
    cur.execute(
        """
        SELECT DISTINCT ON (dpa.device_id)
            dpa.device_id::text AS device_id,
            pt.policy_name,
            pt.policy_json,
            dpa.assigned_by,
            dpa.assigned_at
        FROM device_policy_assignments dpa
        JOIN policy_templates pt ON pt.id = dpa.policy_id
        WHERE dpa.is_active IS TRUE
          AND pt.is_enabled IS TRUE
        ORDER BY dpa.device_id, dpa.assigned_at DESC
        """
    )
    rows = cur.fetchall() or []
    return {to_text(row["device_id"]): dict(row) for row in rows}


def load_access_lists(cur) -> dict[str, set[str]]:
    cur.execute(
        """
        SELECT entry_type, match_type, match_value
        FROM access_control_lists
        WHERE is_enabled IS TRUE
        """
    )
    result = {
        "whitelist_ip": set(),
        "whitelist_mac": set(),
        "blacklist_ip": set(),
        "blacklist_mac": set(),
    }
    for row in cur.fetchall() or []:
        entry_type = to_text(row.get("entry_type")).lower()
        match_type = to_text(row.get("match_type")).lower()
        raw_value = row.get("match_value")
        value = normalize_ip(raw_value) if match_type == "ip" else normalize_mac(raw_value) if match_type == "mac" else None
        key = f"{entry_type}_{match_type}"
        if key in result and value:
            result[key].add(value.lower())
    return result


def load_devices(cur) -> list[dict[str, Any]]:
    params = LAN_CIDRS.copy()
    sql = f"""
        SELECT
            id::text AS id,
            device_key,
            host(current_ip) AS current_ip,
            mac_address,
            hostname,
            reverse_dns_name,
            vendor,
            model,
            category,
            active_policy,
            policy_source,
            policy_effective_mode,
            policy_effective_json,
            is_online,
            status,
            identity_confirmed
        FROM devices
        WHERE current_ip IS NOT NULL
          AND ({' OR '.join(['current_ip <<= %s::cidr' for _ in LAN_CIDRS])})
        ORDER BY is_online DESC, current_ip
    """
    cur.execute(sql, params)
    return cur.fetchall() or []


def choose_auto_policy(device: dict[str, Any], templates: dict[str, dict[str, Any]]) -> str | None:
    category = to_text(device.get("category")).lower()
    for policy_name, policy in templates.items():
        auto_categories = [to_text(x).lower() for x in ((policy.get("policy_json") or {}).get("auto_assign_categories") or [])]
        if category and category in auto_categories:
            return policy_name
    if "unknown_device_policy" in templates:
        return "unknown_device_policy"
    return None


def parse_local_peer_map() -> dict[str, list[str]]:
    raw = os.environ.get("POLICY_LOCAL_PEER_MAP_JSON", "{}")
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    result: dict[str, list[str]] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            values = value if isinstance(value, list) else [value]
            result[to_text(key).lower()] = [ip for item in values if (ip := normalize_ip(item)) and ip_in_lan(ip)]
    return result


LOCAL_PEER_MAP = parse_local_peer_map()


def device_lookup_tokens(device: dict[str, Any]) -> set[str]:
    return {
        token
        for token in [
            to_text(device.get("hostname")).lower(),
            to_text(device.get("device_key")).lower(),
            to_text(device.get("reverse_dns_name")).lower().rstrip('.'),
            to_text(device.get("category")).lower(),
            to_text(device.get("vendor")).lower(),
            to_text(device.get("model")).lower(),
        ]
        if token
    }


def resolve_peer_targets(peer_tokens: list[str], devices: list[dict[str, Any]]) -> tuple[set[str], list[str]]:
    resolved: set[str] = set()
    unresolved: list[str] = []
    indexed = [(device, device_lookup_tokens(device)) for device in devices]
    for raw_token in peer_tokens:
        token = to_text(raw_token).strip()
        if not token:
            continue
        token_lc = token.lower().rstrip('.')
        if token_lc in {"127.0.0.1", "localhost"}:
            unresolved.append(token)
            continue
        direct_ip = normalize_ip(token_lc)
        if direct_ip:
            if ip_in_lan(direct_ip):
                resolved.add(direct_ip)
            else:
                unresolved.append(token)
            continue
        mapped = LOCAL_PEER_MAP.get(token_lc, [])
        if mapped:
            resolved.update(mapped)
            continue
        exact = []
        fuzzy = []
        for device, tokens in indexed:
            ip_value = normalize_ip(device.get("current_ip"))
            if not ip_value or not ip_in_lan(ip_value):
                continue
            if token_lc in tokens:
                exact.append(ip_value)
            elif any(token_lc in candidate for candidate in tokens):
                fuzzy.append(ip_value)
        if exact:
            resolved.update(exact)
        elif fuzzy:
            resolved.update(fuzzy)
        else:
            unresolved.append(token)
    return resolved, sorted(set(unresolved))


def policy_country_alias(country_code: str) -> str:
    cc = re.sub(r"[^A-Z]", "", to_text(country_code).upper())[:2]
    return f"{GEO_ALLOWED_ALIAS_PREFIX}{cc}{GEO_ALLOWED_ALIAS_SUFFIX}" if cc else ""


def policy_runtime_alias(policy_name: str, suffix: str) -> str:
    raw_name = to_text(policy_name).upper()
    token = re.sub(r"[^A-Z0-9]+", "_", raw_name).strip("_") or "POLICY"
    digest = hashlib.sha1(raw_name.encode("utf-8", errors="ignore")).hexdigest()[:8].upper()
    code_map = {
        "GEO_HOSTS": "GH",
        "GEO_ALLOWED": "GC",
        "LOCAL_HOSTS": "LH",
        "LOCAL_PEERS": "LP",
    }
    suffix_code = code_map.get(to_text(suffix).upper())
    if not suffix_code:
        suffix_token = re.sub(r"[^A-Z0-9]+", "_", to_text(suffix).upper()).strip("_") or "X"
        suffix_code = suffix_token[:2]
    base = f"SCP_{token[:12]}_{digest}_{suffix_code}"
    return base[:31]


def firewall_host_ip() -> str | None:
    parsed = urlparse(OPNSENSE_URL)
    return normalize_ip(parsed.hostname)


UPNP_CONTROL_TARGETS = {item for item in [firewall_host_ip(), "239.255.255.250"] if item}
for item in [part.strip() for part in os.environ.get("POLICY_UPNP_CONTROL_TARGETS", "").split(",") if part.strip()]:
    ip = normalize_ip(item)
    if ip:
        UPNP_CONTROL_TARGETS.add(ip)


def compute_effective_policy(
    device: dict[str, Any],
    templates: dict[str, dict[str, Any]],
    manual_assignments: dict[str, dict[str, Any]],
    acls: dict[str, set[str]],
    devices: list[dict[str, Any]],
):
    device_id = to_text(device.get("id"))
    ip_value = to_text(normalize_ip(device.get("current_ip")) or "").lower()
    mac_value = to_text(normalize_mac(device.get("mac_address")) or "").lower()
    is_whitelisted = bool((ip_value and ip_value in acls["whitelist_ip"]) or (mac_value and mac_value in acls["whitelist_mac"]))
    is_blacklisted = bool((ip_value and ip_value in acls["blacklist_ip"]) or (mac_value and mac_value in acls["blacklist_mac"]))

    suggested_name = choose_auto_policy(device, templates)
    suggested_source = "category" if suggested_name else None

    active_name = None
    source = "none"
    policy_json: dict[str, Any] = {}

    manual = manual_assignments.get(device_id)
    if manual:
        active_name = to_text(manual.get("policy_name"))
        source = "manual" if active_name else "none"
        policy_json = dict(manual.get("policy_json") or {})

    if is_whitelisted and not is_blacklisted:
        active_name = "whitelist_override"
        source = "acl_whitelist"
        policy_json = build_whitelist_policy_json()

    if is_blacklisted:
        active_name = "blacklist_quarantine"
        source = "acl_blacklist"
        policy_json = build_blacklist_policy_json()

    requested_mode = normalize_access_mode(policy_json.get("access_mode") or "normal") if active_name else "normal"
    effective_mode = derive_effective_mode(policy_json) if active_name else "normal"
    geo_enabled = bool_flag(policy_json.get("geo_restrictions_enabled", False)) if active_name else False
    upnp_allowed = bool_flag(policy_json.get("upnp_allowed", True)) if active_name else True
    local_only_peers = [to_text(item) for item in (normalize_peer_values(policy_json.get("local_only_peers"))) if to_text(item)]
    geo_allowed_countries = normalize_country_codes(policy_json.get("geo_allowed_countries"))
    resolved_peer_ips, unresolved_peer_tokens = resolve_peer_targets(local_only_peers, devices) if effective_mode == "local_only" else (set(), [])
    geo_country_aliases = [policy_country_alias(cc) for cc in geo_allowed_countries if policy_country_alias(cc)] if geo_enabled else []
    policy_geo_dest = policy_geo_dest_alias(active_name) if active_name and geo_enabled and active_name not in {"whitelist_override", "blacklist_quarantine"} else ""

    source_aliases: set[str] = set()
    if is_whitelisted:
        source_aliases.add(WHITELIST_ALIAS)
    if effective_mode == "quarantine":
        source_aliases.update({QUARANTINE_ALIAS, INTERNET_BLOCK_ALIAS})
    elif effective_mode == "dns_only":
        source_aliases.update({DNS_ONLY_ALIAS, INTERNET_BLOCK_ALIAS})
    elif effective_mode == "local_only":
        source_aliases.update({LOCAL_ONLY_ALIAS, INTERNET_BLOCK_ALIAS})
    elif effective_mode == "blocked_internet":
        source_aliases.add(INTERNET_BLOCK_ALIAS)
    if geo_enabled and not is_whitelisted and not is_blacklisted:
        source_aliases.add(GEO_RESTRICT_ALIAS)
    if not upnp_allowed and not is_whitelisted and not is_blacklisted:
        source_aliases.add(UPNP_BLOCK_ALIAS)

    effective_json = {
        "policy_name": active_name,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "source": source,
        "is_whitelisted": is_whitelisted,
        "is_blacklisted": is_blacklisted,
        "internet_allowed": bool_flag(policy_json.get("internet_allowed", effective_mode == "normal")) if active_name else True,
        "dns_only": effective_mode == "dns_only",
        "local_only": effective_mode == "local_only",
        "blocked_internet": effective_mode == "blocked_internet",
        "quarantine": effective_mode == "quarantine",
        "geo_restrictions_enabled": geo_enabled,
        "geo_allowed_countries": geo_allowed_countries,
        "geo_country_aliases": geo_country_aliases,
        "upnp_allowed": upnp_allowed,
        "upnp_blocked": not upnp_allowed,
        "local_only_peers": local_only_peers,
        "resolved_local_only_peer_ips": sorted(resolved_peer_ips),
        "unresolved_local_only_peer_tokens": unresolved_peer_tokens,
        "enforced_aliases": sorted(source_aliases),
        "description": to_text(policy_json.get("description")),
    }
    policy_local_host_alias = policy_runtime_alias(active_name, "LOCAL_HOSTS") if active_name and effective_mode == "local_only" and active_name not in {"whitelist_override", "blacklist_quarantine"} else ""
    policy_local_peer_alias = policy_runtime_alias(active_name, "LOCAL_PEERS") if active_name and effective_mode == "local_only" and active_name not in {"whitelist_override", "blacklist_quarantine"} else ""
    policy_geo_host_alias = policy_runtime_alias(active_name, "GEO_HOSTS") if active_name and geo_enabled and active_name not in {"whitelist_override", "blacklist_quarantine"} else ""
    if policy_local_host_alias:
        source_aliases.add(policy_local_host_alias)
    if policy_geo_host_alias:
        source_aliases.add(policy_geo_host_alias)
    effective_json["policy_local_host_alias"] = policy_local_host_alias
    effective_json["policy_local_peer_alias"] = policy_local_peer_alias
    effective_json["policy_geo_host_alias"] = policy_geo_host_alias
    effective_json["policy_geo_dest_alias"] = policy_geo_dest
    return {
        "active_policy": active_name,
        "policy_source": source,
        "policy_suggested": suggested_name,
        "policy_suggested_source": suggested_source,
        "policy_effective_mode": effective_mode,
        "policy_effective_json": effective_json,
        "is_whitelisted": is_whitelisted,
        "is_blacklisted": is_blacklisted,
        "geo_restrictions_enabled": geo_enabled,
        "upnp_blocked": not upnp_allowed,
        "source_aliases": source_aliases,
        "resolved_local_only_peer_ips": resolved_peer_ips,
        "geo_country_aliases": geo_country_aliases,
        "unresolved_local_only_peer_tokens": unresolved_peer_tokens,
        "policy_local_host_alias": policy_local_host_alias,
        "policy_local_peer_alias": policy_local_peer_alias,
        "policy_geo_host_alias": policy_geo_host_alias,
        "policy_geo_dest_alias": policy_geo_dest,
    }


def update_device_state(cur, device_id: str, state: dict[str, Any]):
    cur.execute(
        """
        UPDATE devices
        SET
            active_policy = %s,
            policy_source = %s,
            policy_suggested = %s,
            policy_suggested_source = %s,
            policy_effective_mode = %s,
            policy_last_applied_at = now(),
            policy_effective_json = %s,
            is_whitelisted = %s,
            is_blacklisted = %s,
            geo_restrictions_enabled = %s,
            upnp_blocked = %s,
            updated_at = now()
        WHERE id = %s::uuid
        """,
        (
            state.get("active_policy"),
            state.get("policy_source") or "none",
            state.get("policy_suggested"),
            state.get("policy_suggested_source"),
            state.get("policy_effective_mode") or "normal",
            j(state.get("policy_effective_json") or {}),
            bool(state.get("is_whitelisted")),
            bool(state.get("is_blacklisted")),
            bool(state.get("geo_restrictions_enabled")),
            bool(state.get("upnp_blocked")),
            to_text(device_id),
        ),
    )


def insert_audit(cur, event_type: str, details: dict[str, Any]):
    cur.execute(
        """
        INSERT INTO audit_events (actor_type, actor_name, event_type, target_type, target_id, event_time, details_json)
        VALUES ('system', 'security-policy-enforcer', %s, 'system', 'policy-engine', now(), %s)
        """,
        (event_type, j(details)),
    )


def update_health(cur, status: str, details: dict[str, Any]):
    cur.execute(
        """
        UPDATE system_health
        SET
            status = %s,
            last_check_at = now(),
            details_json = %s,
            updated_at = now()
        WHERE component_name = 'security-policy-enforcer'
        """,
        (status, j(details)),
    )


def ensure_policy_alias_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_alias_managed_entries (
            alias_name TEXT NOT NULL,
            address INET NOT NULL,
            PRIMARY KEY (alias_name, address)
        )
        """
    )


def load_managed_aliases(cur, alias_names: set[str], current_aliases: dict[str, set[str]]) -> dict[str, set[str]]:
    ensure_policy_alias_table(cur)
    managed = {alias_name: set() for alias_name in alias_names}
    cur.execute("SELECT alias_name, host(address) AS address FROM policy_alias_managed_entries")
    rows = cur.fetchall() or []
    for row in rows:
        alias_name = to_text(row.get("alias_name"))
        address = normalize_ip(row.get("address"))
        if alias_name in managed and address:
            managed[alias_name].add(address)
    return managed


def save_managed_aliases(cur, managed: dict[str, set[str]]):
    ensure_policy_alias_table(cur)
    cur.execute("TRUNCATE TABLE policy_alias_managed_entries")
    values = []
    for alias_name, addresses in managed.items():
        for address in sorted(addresses):
            values.append((alias_name, address))
    if values:
        cur.executemany(
            "INSERT INTO policy_alias_managed_entries (alias_name, address) VALUES (%s, %s::inet)",
            values,
        )


def reconcile_alias(session: requests.Session, alias_name: str, desired_managed: set[str], current: set[str], managed_current: set[str], alias_source: str | None, issues: list[dict[str, Any]]):
    if alias_source == "optional_empty" and desired_managed:
        issues.append({
            "alias_name": alias_name,
            "error": "alias_missing_create_manually",
            "desired_count": len(desired_managed),
        })
        return {"added": 0, "removed": 0, "missing": True}

    changed = {"added": 0, "removed": 0}
    for address in sorted(desired_managed - current):
        issue = alias_change(session, alias_name, "add", address)
        if issue:
            issues.append(issue)
        else:
            changed["added"] += 1
    for address in sorted((managed_current - desired_managed) & current):
        issue = alias_change(session, alias_name, "delete", address)
        if issue:
            issues.append(issue)
        else:
            changed["removed"] += 1
    return changed


def allocate_rule_sequences(desired_rules: dict[str, dict[str, Any]]) -> None:
    def sort_key(description: str):
        normalized_group = description.replace("_PASS_", "_").replace("_BLOCK_", "_")
        if "_PASS_" in description:
            action_order = 0
        elif "_BLOCK_" in description:
            action_order = 1
        else:
            action_order = 2
        return (normalized_group, action_order, description)

    ordered = sorted(desired_rules, key=sort_key)
    base_sequence = 500
    for idx, description in enumerate(ordered):
        desired_rules[description]["sequence"] = str(base_sequence + idx)


def main():
    session = requests.Session()
    session.headers.update({"Authorization": OPNSENSE_AUTH})

    issues: list[dict[str, Any]] = []
    desired: dict[str, set[str]] = {
        QUARANTINE_ALIAS: set(),
        INTERNET_BLOCK_ALIAS: set(),
        DNS_ONLY_ALIAS: set(),
        LOCAL_ONLY_ALIAS: set(),
        GEO_RESTRICT_ALIAS: set(),
        UPNP_BLOCK_ALIAS: set(),
        WHITELIST_ALIAS: set(),
        LOCAL_ONLY_PEERS_ALIAS: set(),
        UPNP_CONTROL_TARGETS_ALIAS: set(UPNP_CONTROL_TARGETS),
    }
    desired_geo_aliases: dict[str, list[str]] = {}
    desired_rules: dict[str, dict[str, Any]] = {}
    unresolved_peers_by_device: dict[str, list[str]] = {}

    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            templates = load_policy_templates(cur)
            manual_assignments = load_manual_assignments(cur)
            acls = load_access_lists(cur)
            devices = load_devices(cur)
            # Ensure every enabled policy with GeoIP enabled gets its own two runtime aliases
            # even if no device is currently assigned to that policy.
            for policy_name, template in templates.items():
                policy_json = dict(template.get("policy_json") or {})
                if not bool_flag(policy_json.get("geo_restrictions_enabled", False)):
                    continue
                countries = normalize_country_codes(policy_json.get("geo_allowed_countries"))
                if not countries:
                    continue
                geo_host_alias = policy_runtime_alias(policy_name, "GEO_HOSTS")
                geo_dest_alias = policy_geo_dest_alias(policy_name)
                if geo_host_alias:
                    desired.setdefault(geo_host_alias, set())
                if geo_dest_alias:
                    desired_geo_aliases[geo_dest_alias] = countries
            processed = 0
            for device in devices:
                ip_value = normalize_ip(device.get("current_ip"))
                if not ip_value or not ip_in_lan(ip_value):
                    continue
                state = compute_effective_policy(device, templates, manual_assignments, acls, devices)
                update_device_state(cur, device["id"], state)
                for alias_name in state.get("source_aliases") or set():
                    desired.setdefault(alias_name, set()).add(ip_value)
                for peer_ip in state.get("resolved_local_only_peer_ips") or set():
                    desired[LOCAL_ONLY_PEERS_ALIAS].add(peer_ip)
                    if state.get("policy_local_peer_alias"):
                        desired.setdefault(state.get("policy_local_peer_alias"), set()).add(peer_ip)
                if state.get("policy_local_host_alias"):
                    desired.setdefault(state.get("policy_local_host_alias"), set()).add(ip_value)
                if state.get("policy_geo_host_alias"):
                    desired.setdefault(state.get("policy_geo_host_alias"), set()).add(ip_value)
                if state.get("policy_geo_dest_alias") and state.get("policy_effective_json", {}).get("geo_allowed_countries"):
                    desired_geo_aliases[state.get("policy_geo_dest_alias")] = normalize_country_codes(state.get("policy_effective_json", {}).get("geo_allowed_countries"))
                    pass_desc = f"{POLICY_RULE_PREFIX}_GEO_PASS_{to_text(state.get('active_policy')).upper()}"
                    block_desc = f"{POLICY_RULE_PREFIX}_GEO_BLOCK_{to_text(state.get('active_policy')).upper()}"
                    desired_rules[pass_desc] = build_rule(
                        pass_desc,
                        "pass",
                        state.get("policy_geo_host_alias"),
                        state.get("policy_geo_dest_alias"),
                        0,
                        log_enabled=True,
                    )
                    desired_rules[block_desc] = build_rule(
                        block_desc,
                        "block",
                        state.get("policy_geo_host_alias"),
                        "any",
                        0,
                        log_enabled=True,
                    )
                if state.get("policy_local_host_alias") and state.get("policy_local_peer_alias"):
                    pass_desc = f"{POLICY_RULE_PREFIX}_LOCAL_PASS_{to_text(state.get('active_policy')).upper()}"
                    block_desc = f"{POLICY_RULE_PREFIX}_LOCAL_BLOCK_{to_text(state.get('active_policy')).upper()}"
                    desired_rules[pass_desc] = build_rule(pass_desc, "pass", state.get("policy_local_host_alias"), state.get("policy_local_peer_alias"), 0)
                    desired_rules[block_desc] = build_rule(block_desc, "block", state.get("policy_local_host_alias"), "any", 0)
                unresolved = state.get("unresolved_local_only_peer_tokens") or []
                if unresolved:
                    unresolved_peers_by_device[to_text(device.get("hostname") or device.get("id"))] = unresolved
                processed += 1

            alias_sources: dict[str, Any] = {}
            current_aliases: dict[str, set[str]] = {}
            alias_names = set(desired)
            required_aliases = CORE_SOURCE_ALIASES
            shared_aliases = CORE_SOURCE_ALIASES | OPTIONAL_ALIASES
            runtime_host_aliases = {name for name in alias_names if name.startswith("SCP_") and name not in desired_geo_aliases}

            # IMPORTANT: do not rewrite shared alias definitions like QUARANTINE_HOSTS or
            # INTERNET_BLOCK_HOSTS. Home Assistant and manual OPNsense actions can place
            # entries there directly; overwriting the alias definition content would wipe them.
            # Only security-core runtime aliases that are owned exclusively by the policy engine
            # are rewritten via alias definition content.
            runtime_host_contents = {alias_name: sorted(desired.get(alias_name, set())) for alias_name in runtime_host_aliases}
            for alias_name in sorted(runtime_host_aliases):
                alias_content = "\n".join(runtime_host_contents.get(alias_name, []))
                ensure_alias_definition(session, alias_name, "host", alias_content, f"Managed by security-core ({alias_name})", issues)
            for geo_alias_name, countries in sorted(desired_geo_aliases.items()):
                content = ",".join(sorted(set([to_text(x).upper() for x in countries if to_text(x)])))
                ensure_alias_definition(session, geo_alias_name, "geoip", content, f"Managed by security-core GeoIP ({geo_alias_name})", issues, proto="IPv4,IPv6")
            existing_runtime_aliases = managed_runtime_alias_names(session)
            stale_runtime_aliases = sorted(existing_runtime_aliases - runtime_host_aliases - set(desired_geo_aliases))
            for alias_name in sorted(alias_names):
                optional = alias_name not in required_aliases
                # Runtime aliases are synchronized through the alias definition content,
                # not via alias_util table edits. For shared aliases we still inspect the
                # current live table content so that only policy-managed entries are updated.
                if alias_name in runtime_host_aliases:
                    current_aliases[alias_name] = set(runtime_host_contents.get(alias_name, []))
                    alias_sources[alias_name] = "definition_content"
                    continue
                alias_set, alias_source, alias_issue = safe_get_alias_set(session, alias_name, optional_empty=optional)
                current_aliases[alias_name] = alias_set
                alias_sources[alias_name] = alias_source
                if alias_issue:
                    issues.append(alias_issue)

            managed_current = load_managed_aliases(cur, alias_names - runtime_host_aliases, current_aliases)
            alias_changes = {}
            needs_reconfigure = False
            for alias_name in sorted(alias_names):
                if alias_name in runtime_host_aliases:
                    alias_changes[alias_name] = {"added": 0, "removed": 0, "source": "definition_content"}
                    # The definition content has already been rewritten above. Reconfigure later.
                    continue
                changed = reconcile_alias(
                    session,
                    alias_name,
                    desired.get(alias_name, set()),
                    current_aliases.get(alias_name, set()),
                    managed_current.get(alias_name, set()),
                    alias_sources.get(alias_name),
                    issues,
                )
                alias_changes[alias_name] = changed
                if changed.get("added") or changed.get("removed"):
                    needs_reconfigure = True
            if runtime_host_aliases or desired_geo_aliases or stale_runtime_aliases:
                needs_reconfigure = True

            deleted_runtime_aliases = []
            for alias_name in stale_runtime_aliases:
                if delete_alias_definition(session, alias_name, issues):
                    deleted_runtime_aliases.append(alias_name)
                    needs_reconfigure = True

            if needs_reconfigure or desired_geo_aliases or deleted_runtime_aliases:
                issue = alias_reconfigure(session)
                if issue:
                    issues.append(issue)

            allocate_rule_sequences(desired_rules)

            existing_managed_rule_descriptions = set()
            for prefix in (f"{POLICY_RULE_PREFIX}_GEO_", f"{POLICY_RULE_PREFIX}_LOCAL_"):
                url = f"{OPNSENSE_URL}/api/firewall/filter/searchRule?current=1&rowCount=500&searchPhrase={quote(prefix, safe='')}"
                try:
                    response = session.get(url, timeout=20, verify=OPNSENSE_VERIFY_SSL)
                    response.raise_for_status()
                    data = parse_json_body(response)
                    for row in (data.get("rows") if isinstance(data, dict) else []) or []:
                        desc = to_text(row.get("description"))
                        if desc.startswith(prefix):
                            existing_managed_rule_descriptions.add(desc)
                except Exception as exc:
                    issues.append({"error": "rule_search_failed", "prefix": prefix, "message": str(exc)})
            for description, rule in desired_rules.items():
                ensure_filter_rule(session, rule, issues)
            for stale in sorted(existing_managed_rule_descriptions - set(desired_rules)):
                delete_filter_rule(session, stale, issues)
            if desired_rules or existing_managed_rule_descriptions:
                issue = filter_apply(session)
                if issue:
                    issues.append(issue)

            save_managed_aliases(cur, desired)
            details = {
                "processed_devices": processed,
                "alias_sources": alias_sources,
                "alias_changes": alias_changes,
                "desired_counts": {name: len(values) for name, values in desired.items()},
                "desired_geo_aliases": desired_geo_aliases,
                "deleted_runtime_aliases": deleted_runtime_aliases,
                "managed_rules": sorted(desired_rules),
                "unresolved_local_only_peers": unresolved_peers_by_device,
                "issues": issues,
            }
            update_health(cur, "degraded" if issues else "healthy", details)
            insert_audit(cur, "policy_reconcile_completed", details)
        conn.commit()


if __name__ == "__main__":
    main()
