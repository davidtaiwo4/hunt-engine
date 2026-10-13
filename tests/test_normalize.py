from src.normalize import normalize_auth_row


def test_auth_v1_normalizes():
    row = {
        "schema_version": "1",
        "timestamp": "2026-07-13T08:00:00Z",
        "username": "a",
        "action": "login_success"
    }
    result = normalize_auth_row(row)
    assert result["identity"] == "a"
    assert result["event_type"] == "login_success"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_auth_v2_normalizes():
    row = {
        "schema_version": "2",
        "event_time": "2026-07-13T08:00:00Z",
        "identity": "a",
        "result": "login_success"
    }
    result = normalize_auth_row(row)
    assert result["identity"] == "a"
    assert result["event_type"] == "login_success"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_auth_v3_normalizes():
    row = {
        "schema_version": "3",
        "time": "2026-07-13T08:00:00Z",
        "record": {"username": "a", "action": "login_success"}
    }
    result = normalize_auth_row(row)
    assert result["identity"] == "a"
    assert result["event_type"] == "login_success"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_auth_missing_time_is_quarantined():
    row = {"schema_version": "2", "identity": "a"}
    result = normalize_auth_row(row)
    assert result["quarantine_reason"] == "missing_time"


def test_auth_unknown_schema_is_quarantined():
    row = {"schema_version": "99", "timestamp": "2026-07-13T08:00:00Z"}
    result = normalize_auth_row(row)
    assert result["quarantine_reason"] == "unknown_schema_version"

def test_auth_row_with_time_key_but_null_value_is_quarantined():
    row = {
        "schema_version": "2",
        "missing_time": True,
        "time": None,
        "timestamp": None,
        "event_time": None,
        "identity": None,
        "result": None
    }
    result = normalize_auth_row(row)
    assert result["quarantine_reason"] == "missing_time"
from src.normalize import normalize_web_row


def test_web_v1_normalizes():
    row = {
        "schema_version": "1",
        "timestamp": "2026-07-13T08:00:00Z",
        "method": "GET",
        "path": "/"
    }
    result = normalize_web_row(row)
    assert result["event_type"] == "web_request"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_web_v2_normalizes():
    row = {
        "schema_version": "2",
        "event_time": "2026-07-13T08:00:00Z",
        "method": "GET",
        "path": "/"
    }
    result = normalize_web_row(row)
    assert result["event_type"] == "web_request"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_web_v3_normalizes():
    row = {
        "schema_version": "3",
        "time": "2026-07-13T08:00:00Z",
        "record": {"method": "GET", "path": "/"}
    }
    result = normalize_web_row(row)
    assert result["event_type"] == "web_request"
    assert result["time"] == "2026-07-13T08:00:00Z"


def test_web_missing_time_is_quarantined():
    row = {"schema_version": "2", "method": "GET"}
    result = normalize_web_row(row)
    assert result["quarantine_reason"] == "missing_time"


def test_web_unknown_schema_is_quarantined():
    row = {"schema_version": "99", "timestamp": "2026-07-13T08:00:00Z"}
    result = normalize_web_row(row)
    assert result["quarantine_reason"] == "unknown_schema_version"


def test_web_row_with_null_time_value_is_quarantined():
    row = {
        "schema_version": "2",
        "time": None,
        "timestamp": None,
        "event_time": None,
        "method": None,
        "path": None
    }
    result = normalize_web_row(row)
    assert result["quarantine_reason"] == "missing_time"

from src.normalize import normalize_dns_row


def test_dns_v1_normalizes():
    row = {"schema_version": "1", "timestamp": "2026-07-13T08:00:00Z", "query": "x.invalid"}
    result = normalize_dns_row(row)
    assert result["event_type"] == "dns_query"
    assert result["query"] == "x.invalid"


def test_dns_v2_normalizes():
    row = {"schema_version": "2", "event_time": "2026-07-13T08:00:00Z", "query": "x.invalid"}
    result = normalize_dns_row(row)
    assert result["event_type"] == "dns_query"


def test_dns_v3_normalizes():
    row = {"schema_version": "3", "time": "2026-07-13T08:00:00Z", "record": {"query": "x.invalid"}}
    result = normalize_dns_row(row)
    assert result["event_type"] == "dns_query"


def test_dns_missing_time_is_quarantined():
    row = {"schema_version": "2", "query": "x.invalid"}
    result = normalize_dns_row(row)
    assert result["quarantine_reason"] == "missing_time"

from src.normalize import normalize_firewall_row


def test_firewall_v1_normalizes():
    row = {"schema_version": "1", "timestamp": "2026-07-13T08:00:00Z", "action": "deny"}
    result = normalize_firewall_row(row)
    assert result["event_type"] == "network_deny"
    assert result["action"] == "deny"


def test_firewall_v2_normalizes():
    row = {"schema_version": "2", "event_time": "2026-07-13T08:00:00Z", "result": "deny"}
    result = normalize_firewall_row(row)
    assert result["event_type"] == "network_deny"
    assert result["action"] == "deny"


def test_firewall_v3_normalizes():
    row = {"schema_version": "3", "time": "2026-07-13T08:00:00Z", "record": {"action": "deny"}}
    result = normalize_firewall_row(row)
    assert result["event_type"] == "network_deny"


def test_firewall_missing_time_is_quarantined():
    row = {"schema_version": "2", "result": "deny"}
    result = normalize_firewall_row(row)
    assert result["quarantine_reason"] == "missing_time"

def test_firewall_allow_action_is_labeled_correctly():
    row = {"schema_version": "1", "timestamp": "2026-07-13T08:00:00Z", "action": "allow"}
    result = normalize_firewall_row(row)
    assert result["event_type"] == "network_allow"

from src.normalize import normalize_endpoint_row


def test_endpoint_v1_normalizes():
    row = {"schema_version": "1", "timestamp": "2026-07-13T09:05:00Z", "event": "process_start"}
    result = normalize_endpoint_row(row)
    assert result["event_type"] == "process_start"


def test_endpoint_v2_normalizes():
    row = {"schema_version": "2", "event_time": "2026-07-13T09:05:00Z", "event_name": "process_start"}
    result = normalize_endpoint_row(row)
    assert result["event_type"] == "process_start"


def test_endpoint_v3_normalizes():
    row = {"schema_version": "3", "time": "2026-07-13T09:05:00Z", "record": {"event": "process_start"}}
    result = normalize_endpoint_row(row)
    assert result["event_type"] == "process_start"


def test_endpoint_missing_time_is_quarantined():
    row = {"schema_version": "2", "event_name": "process_start"}
    result = normalize_endpoint_row(row)
    assert result["quarantine_reason"] == "missing_time"
