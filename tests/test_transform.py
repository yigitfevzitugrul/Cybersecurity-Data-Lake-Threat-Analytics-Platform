from src.etl.extract import RawLine
from src.etl.parser import parse_line
from src.etl.transform import event_hash, normalize_ip, transform

LINE = "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2"


def test_event_hash_is_deterministic():
    assert event_hash(parse_line(LINE, 2024)) == event_hash(parse_line(LINE + "\n", 2024))


def test_event_hash_differs_by_year_and_content():
    base = event_hash(parse_line(LINE, 2024))
    assert base != event_hash(parse_line(LINE, 2025))
    assert base != event_hash(parse_line(LINE.replace("42393", "42394"), 2024))


def test_normalize_ip():
    assert normalize_ip("1.2.3.4") == "1.2.3.4"
    assert normalize_ip("::ffff:1.2.3.4") == "1.2.3.4"
    assert normalize_ip("2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip("999.1.1.1") == "999.1.1.1"


def test_transform_splits_events_rejected_and_irrelevant():
    lines = [
        RawLine(1, LINE),
        RawLine(2, "Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]"),
        RawLine(3, "bozuk satir"),
        RawLine(4, "Feb 30 10:00:00 LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"),
        RawLine(5, "Dec 10 07:13:43 LabSZ sshd[1]: Failed password for root from ::ffff:5.36.59.76 port 1 ssh2"),
    ]
    events, rejected, irrelevant = transform(lines, 2024)

    assert [line_no for line_no, _ in events] == [1, 5]
    assert events[1][1].source_ip == "5.36.59.76"
    assert irrelevant == 1
    assert [(r.line_no, r.reason) for r in rejected] == [(3, "malformed_line"), (4, "invalid_timestamp")]
    assert rejected[0].raw_line == "bozuk satir"
