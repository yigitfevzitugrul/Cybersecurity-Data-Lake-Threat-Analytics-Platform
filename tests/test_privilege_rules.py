"""Yetki yükseltme kuralları: privilege_abuse, sensitive_command, escalation_chain."""
from datetime import datetime, timedelta

import pytest

from src.detection.engine import load_config
from src.detection.rules import Alert, Event, PrivEvent, run_rules
from src.detection.rules import detect_escalation_chain, detect_privilege_abuse, detect_sensitive_command

CONFIG = load_config()
T0 = datetime(2026, 3, 2, 10, 0, 0)


def priv(seconds, event_type, user="dave", command=None, attempts=1, program=None):
    program = program or ("su" if event_type.startswith("su_") else "sudo")
    return PrivEvent(T0 + timedelta(seconds=seconds), "srv", program, event_type, user, "root", command, attempts)


# --- privilege_abuse ---

def test_repeated_su_failures_are_abuse():
    events = [priv(i * 10, "su_failure") for i in range(6)]
    (alert,) = detect_privilege_abuse(events, CONFIG["privilege_abuse"])
    assert (alert.rule, alert.username, alert.source_ip, alert.attempt_count, alert.severity) == (
        "privilege_abuse", "dave", None, 6, "high")
    assert alert.details["failures_by_type"] == {"su_failure": 6}


def test_sudo_failures_are_weighted_by_reported_attempts():
    events = [priv(0, "sudo_auth_failure", attempts=3)]
    (alert,) = detect_privilege_abuse(events, CONFIG["privilege_abuse"])
    assert (alert.attempt_count, alert.severity) == (3, "medium")


def test_single_mistakes_are_not_abuse():
    events = [priv(0, "sudo_auth_failure", user="alice"), priv(5, "sudo_command", user="alice", command="/usr/bin/id"),
              priv(600, "sudo_not_allowed", user="erin")]
    assert detect_privilege_abuse(events, CONFIG["privilege_abuse"]) == []


def test_failures_far_apart_are_separate_sessions():
    events = [priv(0, "su_failure"), priv(10, "su_failure"), priv(3600, "su_failure")]
    assert detect_privilege_abuse(events, CONFIG["privilege_abuse"]) == []


# --- sensitive_command ---

@pytest.mark.parametrize("command, sensitive", [
    ("/bin/cat /etc/shadow", True),
    ("/usr/bin/vim /etc/sudoers", True),
    ("/usr/sbin/visudo", True),
    ("/usr/sbin/useradd -o -u 0 -g 0 -M sysupdate", True),
    ("/usr/bin/passwd root", True),
    ("/bin/chmod u+s /bin/bash", True),
    ("/bin/chmod 4755 /tmp/x", True),
    ("/bin/chmod 0755 /tmp/x", False),
    ("/bin/bash", False),
    ("/usr/bin/apt update", False),
    ("/usr/bin/tail -n 100 /var/log/syslog", False),
])
def test_sensitive_command_patterns(command, sensitive):
    alerts = detect_sensitive_command([priv(0, "sudo_command", user="alice", command=command)],
                                      CONFIG["sensitive_command"])
    assert bool(alerts) is sensitive


def test_denied_sensitive_command_is_not_a_sensitive_command_alert():
    # Reddedilen komut çalışmamıştır; o durum privilege_abuse'un işidir.
    events = [priv(0, "sudo_not_allowed", command="/bin/cat /etc/shadow")]
    assert detect_sensitive_command(events, CONFIG["sensitive_command"]) == []


def test_sensitive_commands_in_one_session_make_one_alert():
    events = [priv(0, "sudo_command", user="bob", command="/bin/cat /etc/shadow"),
              priv(30, "sudo_command", user="bob", command="/usr/sbin/useradd -o -u 0 x")]
    (alert,) = detect_sensitive_command(events, CONFIG["sensitive_command"])
    assert alert.details["commands"] == ["/bin/cat /etc/shadow", "/usr/sbin/useradd -o -u 0 x"]


# --- escalation_chain ---

def login_alert(severity, user="dave", ip="203.0.113.9", at=T0):
    return Alert("auth_anomaly", severity, ip, user, at, at, 20, 1, {"reasons": ["success_after_failures"]})


def test_privilege_activity_after_suspicious_login_is_a_chain():
    events = [priv(120, "sudo_not_allowed", command="list"), priv(160, "su_failure")]
    (alert,) = detect_escalation_chain(events, [login_alert("critical")], CONFIG["escalation_chain"])
    assert (alert.rule, alert.severity, alert.source_ip, alert.username) == (
        "escalation_chain", "critical", "203.0.113.9", "dave")
    assert (alert.window_start, alert.window_end, alert.attempt_count) == (T0, events[-1].time, 2)
    assert alert.details["minutes_after_login"] == 2.0


@pytest.mark.parametrize("login, events", [
    (login_alert("medium"), [priv(120, "su_failure")]),                     # şüpheli sayılmayan giriş
    (login_alert("critical", user="erin"), [priv(120, "su_failure")]),     # başka hesap
    (login_alert("critical"), [priv(2 * 3600, "su_failure")]),              # takip penceresi dışında
    (login_alert("critical"), [priv(-60, "su_failure")]),                  # girişten önce
])
def test_no_chain_without_a_matching_suspicious_login(login, events):
    assert detect_escalation_chain(events, [login], CONFIG["escalation_chain"]) == []


def test_run_rules_combines_both_event_kinds():
    auth = [Event(T0 + timedelta(seconds=i * 2), "srv", "login_failed", "dave", False, "203.0.113.9", 1)
            for i in range(6)]
    auth.append(Event(T0 + timedelta(seconds=20), "srv", "login_success", "dave", False, "203.0.113.9", 1))
    privilege = [priv(120, "su_failure"), priv(130, "su_failure"), priv(140, "su_failure")]

    alerts = run_rules(auth, CONFIG, privilege)
    assert {a.rule for a in alerts} >= {"auth_anomaly", "privilege_abuse", "escalation_chain"}
    assert alerts == sorted(alerts, key=lambda a: (a.window_start, a.rule, a.source_ip or "", a.username or ""))
    # Yetki olayı yoksa yeni kurallar çalışmaz; eski davranış aynen korunur.
    assert {a.rule for a in run_rules(auth, CONFIG)} <= {"brute_force", "suspicious_ip", "auth_anomaly"}
