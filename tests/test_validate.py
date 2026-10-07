from dataclasses import replace
from datetime import datetime

import pytest

from src.etl.parser import parse_line
from src.etl.validate import check_event, validate

NOW = datetime(2024, 12, 31)
EVENT = parse_line(
    "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2", 2024
)


def test_valid_event_passes():
    assert check_event(EVENT, NOW) is None


def test_ipv6_source_is_valid():
    assert check_event(replace(EVENT, source_ip="2001:db8::1"), NOW) is None


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"username": ""}, "missing_field"),
        ({"username": "   "}, "missing_field"),
        ({"host": ""}, "missing_field"),
        ({"source_ip": ""}, "missing_field"),
        ({"event_type": "login_maybe"}, "schema_error"),
        ({"source_port": "22"}, "schema_error"),
        ({"is_invalid_user": "no"}, "schema_error"),
        ({"repeat_count": 0}, "schema_error"),
        ({"event_time": "2024-12-10"}, "schema_error"),
        ({"source_ip": "999.1.1.1"}, "invalid_ip"),
        ({"source_ip": "example.com"}, "invalid_ip"),
        ({"source_port": 0}, "invalid_port"),
        ({"source_port": 70000}, "invalid_port"),
        ({"event_time": datetime(1999, 1, 1)}, "invalid_timestamp"),
        ({"event_time": datetime(2025, 1, 2)}, "invalid_timestamp"),
    ],
)
def test_invalid_events_are_rejected_with_reason(changes, reason):
    problem = check_event(replace(EVENT, **changes), NOW)
    assert problem is not None and problem[0] == reason


def test_timestamp_within_tolerance_is_accepted():
    assert check_event(replace(EVENT, event_time=datetime(2024, 12, 31, 12)), NOW) is None


def test_duplicates_keep_first_occurrence():
    other = replace(EVENT, raw_line=EVENT.raw_line.replace("42393", "42394"), source_port=42394)
    valid, rejected = validate([(1, EVENT), (2, other), (7, EVENT)], NOW)

    assert [line_no for line_no, _ in valid] == [1, 2]
    assert [(r.line_no, r.reason) for r in rejected] == [(7, "duplicate")]
    assert "satır 1" in rejected[0].detail


def test_invalid_copy_is_not_reported_as_duplicate():
    bad = replace(EVENT, source_ip="999.1.1.1")
    valid, rejected = validate([(1, bad), (2, bad)], NOW)
    assert valid == []
    assert [r.reason for r in rejected] == ["invalid_ip", "invalid_ip"]
