from datetime import datetime

import pytest

from log_ingestor.parsers import SyslogParser, JSONLogParser, AutoParser
from log_ingestor.parsers.base import ParseError


def test_syslog_parses_basic_line():
    p = SyslogParser()
    ev = p.parse_line(
        "2025-03-06 08:45:32 WARNING 192.168.1.105 Failed login attempt for user 'root'"
    )
    assert ev.timestamp == datetime(2025, 3, 6, 8, 45, 32)
    assert ev.severity == "WARNING"
    assert ev.source_ip == "192.168.1.105"
    assert ev.username == "root"
    assert ev.event_type == "failed_login"


def test_syslog_classifies_successful_login():
    p = SyslogParser()
    ev = p.parse_line("2025-03-06 08:23:11 INFO 192.168.1.1 User 'admin' logged in successfully")
    assert ev.event_type == "successful_login"
    assert ev.username == "admin"


def test_syslog_rejects_garbage():
    p = SyslogParser()
    with pytest.raises(ParseError):
        p.parse_line("not a log line")


def test_json_parser_field_mapping():
    p = JSONLogParser()
    ev = p.parse_line(
        '{"timestamp":"2025-03-06T11:00:00Z","level":"warn","src_ip":"1.2.3.4",'
        '"user":"root","event":"failed_login","msg":"bad password"}'
    )
    assert ev.severity == "WARN"
    assert ev.source_ip == "1.2.3.4"
    assert ev.username == "root"
    assert ev.event_type == "failed_login"
    assert ev.message == "bad password"


def test_json_parser_keeps_extras():
    p = JSONLogParser()
    ev = p.parse_line('{"timestamp":"2025-03-06T11:00:00Z","custom_field":"x","msg":"hi"}')
    assert ev.extra == {"custom_field": "x"}


def test_auto_detects_syslog_then_json():
    p = AutoParser()
    ev1 = p.parse_line("2025-03-06 08:23:11 INFO 192.168.1.1 User 'admin' logged in successfully")
    assert ev1.severity == "INFO"
    # Mixed-format follow-up should still parse via fallback
    ev2 = p.parse_line('{"timestamp":"2025-03-06T11:00:00Z","msg":"hi","level":"INFO"}')
    assert ev2.message == "hi"


def test_parse_stream_skips_bad_lines_in_lenient_mode():
    p = SyslogParser()
    lines = [
        "2025-03-06 08:23:11 INFO 192.168.1.1 User 'admin' logged in successfully",
        "garbage line",
        "2025-03-06 08:23:12 INFO 192.168.1.2 User 'bob' logged in successfully",
    ]
    events = p.parse_lines(lines)
    assert len(events) == 2
    assert p.skipped == 1
