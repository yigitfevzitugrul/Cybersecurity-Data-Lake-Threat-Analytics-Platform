from src.etl.load import event_hash
from src.etl.parser import parse_line

LINE = "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2"


def test_event_hash_is_deterministic():
    assert event_hash(parse_line(LINE, 2024)) == event_hash(parse_line(LINE + "\n", 2024))


def test_event_hash_differs_by_year_and_content():
    base = event_hash(parse_line(LINE, 2024))
    assert base != event_hash(parse_line(LINE, 2025))
    assert base != event_hash(parse_line(LINE.replace("42393", "42394"), 2024))
