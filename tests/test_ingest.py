import json
from src.ingest import parse_json_line, read_source_file


def test_valid_json_line_parses():
    result = parse_json_line('{"schema_version": "1", "action": "login_success"}')
    assert result["action"] == "login_success"


def test_malformed_json_is_quarantined():
    result = parse_json_line("{broken")
    assert result["quarantine_reason"] == "invalid_json"


def test_read_source_file_tracks_line_numbers(tmp_path):
    test_file = tmp_path / "sample.jsonl"
    test_file.write_text(
        '{"schema_version":"1","action":"login_success"}\n'
        '{broken\n'
        '{"schema_version":"1","action":"login_failed"}\n'
    )

    results = list(read_source_file(str(test_file)))

    assert len(results) == 3
    assert results[0] == (1, {"schema_version": "1", "action": "login_success"})
    assert results[1][0] == 2
    assert results[1][1]["quarantine_reason"] == "invalid_json"
    assert results[2] == (3, {"schema_version": "1", "action": "login_failed"})


def test_read_source_file_flags_empty_lines(tmp_path):
    test_file = tmp_path / "sample.jsonl"
    test_file.write_text(
        '{"schema_version":"1","action":"login_success"}\n'
        '\n'
        '{"schema_version":"1","action":"login_failed"}\n'
    )

    results = list(read_source_file(str(test_file)))

    assert len(results) == 3
    assert results[1][1]["quarantine_reason"] == "empty_line"
