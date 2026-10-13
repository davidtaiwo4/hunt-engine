SOURCE_FIELD_MAP = {
    "auth": {
        "1": {"identity": "username", "event_type": "action"},
        "2": {"identity": "identity", "event_type": "result"},
        "3": {"identity": "username", "event_type": "action"},
    },
    "web": {
        "1": {"method": "method", "path": "path"},
        "2": {"method": "method", "path": "path"},
        "3": {"method": "method", "path": "path"},
    },
"dns": {
        "1": {"query": "query"},
        "2": {"query": "query"},
        "3": {"query": "query"},
    },
"firewall": {
        "1": {"action": "action"},
        "2": {"action": "result"},
        "3": {"action": "action"},
    },
"endpoint": {
        "1": {"event_type": "event"},
        "2": {"event_type": "event_name"},
        "3": {"event_type": "event"},
    },
}

SOURCE_CONSTANTS = {
    "web": {"event_type": "web_request"},
    "dns": {"event_type": "dns_query"},
}


def normalize_row(source: str, row: dict) -> dict:
    time_value = row.get("timestamp") or row.get("event_time") or row.get("time")
    if not time_value:
        return {"quarantine_reason": "missing_time"}

    version = str(row.get("schema_version", ""))
    field_map = SOURCE_FIELD_MAP.get(source, {}).get(version)
    if field_map is None:
        return {"quarantine_reason": "unknown_schema_version"}

    data = row.get("record") if version == "3" else row
    data = data or {}

    extracted = {output_key: data.get(raw_key) for output_key, raw_key in field_map.items()}

    if any(value in (None, "") for value in extracted.values()):
        return {"quarantine_reason": "incomplete_fields"}

    result = {"time": time_value, **extracted}

    if source == "firewall":
        result["event_type"] = "network_deny" if extracted.get("action") == "deny" else "network_allow"
    else:
        result.update(SOURCE_CONSTANTS.get(source, {}))

    return result

def normalize_auth_row(row: dict) -> dict:
    return normalize_row("auth", row)


def normalize_web_row(row: dict) -> dict:
    return normalize_row("web", row)

def normalize_dns_row(row: dict) -> dict:
    return normalize_row("dns", row)

def normalize_firewall_row(row: dict) -> dict:
    return normalize_row("firewall", row)

def normalize_endpoint_row(row: dict) -> dict:
    return normalize_row("endpoint", row)
