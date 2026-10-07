from collections import Counter
from datetime import date

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS, ParseError, parse_line
from src.generator.generate import generate

START = date(2026, 3, 1)


def _events(lines):
    events = []
    for line in lines:
        try:
            event = parse_line(line, START.year)
        except ParseError as exc:
            raise AssertionError(f"üretilen satır ayrıştırılamadı: {line!r} ({exc})")
        if event is not None:
            events.append(event)
    return events


def test_same_seed_same_output():
    assert generate(START, days=2, seed=7) == generate(START, days=2, seed=7)
    assert generate(START, days=2, seed=7)[0] != generate(START, days=2, seed=8)[0]


def test_lines_are_time_ordered_and_parseable():
    lines, _ = generate(START, days=3, seed=1)
    times = [e.event_time for e in _events(lines)]
    assert times == sorted(times)
    assert times[0].date() >= START


def test_each_day_has_one_attack_of_each_type():
    _, labels = generate(START, days=3, seed=1)
    counts = Counter(a["attack_type"] for a in labels["attacks"])
    assert counts == {
        "brute_force": 3,
        "password_spray": 3,
        "success_after_failures": 3,
        "off_hours_new_ip_login": 3,
    }
    ips = [a["source_ip"] for a in labels["attacks"]]
    assert len(ips) == len(set(ips))


def test_labels_match_parsed_events():
    lines, labels = generate(START, days=3, seed=1)
    events = _events(lines)
    for attack in labels["attacks"]:
        from_ip = [e for e in events if e.source_ip == attack["source_ip"]]
        failed = [e for e in from_ip if e.event_type == LOGIN_FAILED]
        succeeded = [e for e in from_ip if e.event_type == LOGIN_SUCCESS]
        assert len(failed) == attack["failed_attempts"]
        assert bool(succeeded) == attack["succeeded"]
        assert {e.username for e in from_ip} == set(attack["target_users"])
        assert min(e.event_time for e in from_ip).isoformat() == attack["start_time"]
        assert max(e.event_time for e in from_ip).isoformat() == attack["end_time"]


def test_legit_users_only_succeed_from_home_or_labeled_ip():
    lines, labels = generate(START, days=3, seed=1)
    allowed = set(labels["legit_users"].values()) | {
        a["source_ip"] for a in labels["attacks"] if a["succeeded"]
    }
    for e in _events(lines):
        if e.event_type == LOGIN_SUCCESS:
            assert e.source_ip in allowed
