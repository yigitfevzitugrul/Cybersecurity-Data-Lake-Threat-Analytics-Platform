from datetime import datetime, timedelta

from src.detection.engine import load_config
from src.detection.rules import (
    Event,
    detect_auth_anomaly,
    detect_brute_force,
    detect_password_spray,
    detect_suspicious_ip,
    run_rules,
)

CONFIG = load_config()
T0 = datetime(2026, 3, 2, 10, 0, 0)  # mesai içi
ATTACKER = "203.0.113.50"
HOME = "10.20.0.10"


def failed(seconds, user="alice", ip=ATTACKER, invalid=False, attempts=1, host="srv"):
    return Event(T0 + timedelta(seconds=seconds), host, "login_failed", user, invalid, ip, attempts)


def success(seconds, user="alice", ip=HOME, host="srv"):
    return Event(T0 + timedelta(seconds=seconds), host, "login_success", user, False, ip, 1)


# --- brute_force ---

def test_brute_force_detected():
    events = [failed(i * 3) for i in range(12)]
    (alert,) = detect_brute_force(events, CONFIG["brute_force"])
    assert (alert.source_ip, alert.username, alert.attempt_count) == (ATTACKER, "alice", 12)
    assert (alert.window_start, alert.window_end) == (events[0].time, events[-1].time)
    assert alert.severity == "medium"


def test_brute_force_below_threshold_is_ignored():
    assert detect_brute_force([failed(i * 3) for i in range(9)], CONFIG["brute_force"]) == []


def test_brute_force_counts_repeated_messages():
    events = [failed(0, attempts=5), failed(10, attempts=5)]
    (alert,) = detect_brute_force(events, CONFIG["brute_force"])
    assert alert.attempt_count == 10


def test_slow_brute_force_is_not_detected():
    # 7 dakikada bir deneme: hiçbir 5 dakikalık pencerede eşik aşılmaz.
    events = [failed(i * 420) for i in range(30)]
    assert detect_brute_force(events, CONFIG["brute_force"]) == []


def test_brute_force_is_per_user_and_per_session():
    events = [failed(i * 3, user="alice") for i in range(12)]
    events += [failed(40 + i * 3, user="bob") for i in range(5)]
    events += [failed(3600 + i * 3, user="alice") for i in range(60)]
    alerts = detect_brute_force(sorted(events), CONFIG["brute_force"])
    assert [(a.username, a.attempt_count, a.severity) for a in alerts] == [
        ("alice", 12, "medium"),
        ("alice", 60, "high"),
    ]


# --- password_spray ---

def test_password_spray_detected():
    events = [failed(i * 10, user=f"user{i}", invalid=True) for i in range(12)]
    (alert,) = detect_password_spray(events, CONFIG["password_spray"])
    assert alert.username is None
    assert (alert.distinct_users, alert.attempt_count, alert.severity) == (12, 12, "medium")


def test_password_spray_needs_enough_distinct_users():
    events = [failed(i * 10, user=f"user{i}") for i in range(9)]
    assert detect_password_spray(events, CONFIG["password_spray"]) == []


def test_many_attempts_per_user_is_not_spray():
    events = [failed(u * 100 + i, user=f"user{u}") for u in range(10) for i in range(5)]
    assert detect_password_spray(sorted(events), CONFIG["password_spray"]) == []


def test_users_spread_over_a_long_time_are_not_spray():
    # 20 dakikada bir farklı kullanıcı: 30 dakikalık pencereye en fazla 2 kullanıcı sığar.
    events = [failed(i * 1200, user=f"user{i}") for i in range(15)]
    assert detect_password_spray(events, CONFIG["password_spray"]) == []


# --- suspicious_ip ---

def test_suspicious_ip_counts_root_and_invalid_users_only():
    events = [failed(0, user="root"), failed(5, user="admin", invalid=True), failed(10, user="alice")]
    events += [failed(20 + i, user="oracle", invalid=True) for i in range(3)]
    (alert,) = detect_suspicious_ip(events, CONFIG["suspicious_ip"])
    assert alert.attempt_count == 5
    assert alert.details["root_attempts"] == 1
    assert alert.details["invalid_user_attempts"] == 4
    assert alert.severity == "low"


def test_few_probes_are_ignored():
    events = [failed(i, user="root") for i in range(4)]
    assert detect_suspicious_ip(events, CONFIG["suspicious_ip"]) == []


def test_probing_many_hosts_is_suspicious_even_with_few_attempts():
    events = [failed(i, user="root", host=f"srv{i}") for i in range(3)]
    (alert,) = detect_suspicious_ip(events, CONFIG["suspicious_ip"])
    assert alert.severity == "medium"
    assert alert.details["hosts"] == ["srv0", "srv1", "srv2"]


# --- auth_anomaly ---

def test_normal_login_is_not_anomalous():
    assert detect_auth_anomaly([success(0)], CONFIG["auth_anomaly"]) == []


def test_success_after_failures_from_unknown_ip_is_critical():
    events = [failed(i * 2) for i in range(6)] + [success(20, ip=ATTACKER)]
    (alert,) = detect_auth_anomaly(events, CONFIG["auth_anomaly"])
    assert alert.severity == "critical"
    assert alert.details["reasons"] == ["success_after_failures"]
    assert alert.attempt_count == 6
    assert alert.window_start == events[-1].time


def test_success_after_failures_from_known_ip_is_downgraded():
    history = [success(-86400 * d) for d in (3, 2, 1)]
    events = history + [failed(i * 2, ip=HOME) for i in range(6)] + [success(20)]
    (alert,) = detect_auth_anomaly(events, CONFIG["auth_anomaly"])
    assert alert.severity == "medium"


def test_typo_before_login_is_not_anomalous():
    events = [failed(0, ip=HOME), failed(5, ip=HOME), success(10)]
    assert detect_auth_anomaly(events, CONFIG["auth_anomaly"]) == []


def test_old_failures_are_not_counted():
    events = [failed(i * 2, ip=HOME) for i in range(6)] + [success(3600)]
    assert detect_auth_anomaly(events, CONFIG["auth_anomaly"]) == []


def test_failures_before_a_login_are_not_counted_for_the_next_login():
    events = [failed(i * 2, ip=HOME) for i in range(6)] + [success(20), success(600)]
    alerts = detect_auth_anomaly(events, CONFIG["auth_anomaly"])
    assert [a.window_start for a in alerts] == [events[6].time]


def test_new_ip_needs_login_history():
    # Geçmişi olmayan kullanıcının ilk girişleri "yeni IP" sayılmaz.
    assert detect_auth_anomaly([success(0, ip=ATTACKER)], CONFIG["auth_anomaly"]) == []

    history = [success(-86400 * d) for d in (3, 2, 1)]
    (alert,) = detect_auth_anomaly(history + [success(0, ip=ATTACKER)], CONFIG["auth_anomaly"])
    assert alert.details["reasons"] == ["new_ip"]
    assert alert.severity == "medium"


def test_new_ip_is_only_new_once():
    history = [success(-86400 * d) for d in (3, 2, 1)]
    events = history + [success(0, ip=ATTACKER), success(60, ip=ATTACKER)]
    assert len(detect_auth_anomaly(events, CONFIG["auth_anomaly"])) == 1


def test_off_hours_login():
    night = Event(datetime(2026, 3, 2, 3, 0), "srv", "login_success", "alice", False, HOME, 1)
    (alert,) = detect_auth_anomaly([night], CONFIG["auth_anomaly"])
    assert alert.details["reasons"] == ["off_hours"]
    assert alert.severity == "low"

    edge_in = Event(datetime(2026, 3, 2, 7, 0), "srv", "login_success", "alice", False, HOME, 1)
    edge_out = Event(datetime(2026, 3, 2, 20, 0), "srv", "login_success", "alice", False, HOME, 1)
    alerts = detect_auth_anomaly([edge_in, edge_out], CONFIG["auth_anomaly"])
    assert [a.window_start.hour for a in alerts] == [20]


def test_new_ip_at_night_is_high():
    history = [success(-86400 * d) for d in (3, 2, 1)]
    night = Event(datetime(2026, 3, 3, 3, 0), "srv", "login_success", "alice", False, ATTACKER, 1)
    (alert,) = detect_auth_anomaly(history + [night], CONFIG["auth_anomaly"])
    assert alert.details["reasons"] == ["new_ip", "off_hours"]
    assert alert.severity == "high"


def test_run_rules_returns_alerts_sorted_by_time():
    events = [failed(i * 3, user="root") for i in range(12)]
    alerts = run_rules(events, CONFIG)
    assert {a.rule for a in alerts} == {"brute_force", "suspicious_ip"}
    assert alerts == sorted(alerts, key=lambda a: (a.window_start, a.rule))
