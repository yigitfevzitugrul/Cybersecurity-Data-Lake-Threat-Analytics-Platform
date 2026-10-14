"""MITRE ATT&CK eşlemesi."""
from datetime import datetime

import pytest

from src.detection.engine import load_config
from src.detection.mitre import TECHNIQUES, classify, reference_rows, technique_url
from src.detection.rules import Alert, PrivEvent, detect_sensitive_command

CONFIG = load_config()
T0 = datetime(2026, 3, 2, 10, 0, 0)


def alert(rule, **details):
    return Alert(rule, "high", "203.0.113.9", "dave", T0, T0, 10, 1, details)


@pytest.mark.parametrize("rule, details, tactic, techniques", [
    ("brute_force", {}, "Credential Access", ["T1110.001"]),
    ("password_spray", {}, "Credential Access", ["T1110.003"]),
    ("suspicious_ip", {}, "Credential Access", ["T1110"]),
    ("auth_anomaly", {"reasons": ["new_ip", "off_hours"]}, "Initial Access", ["T1078.003"]),
    ("auth_anomaly", {"reasons": ["success_after_failures"]}, "Initial Access", ["T1078.003", "T1110.001"]),
    ("privilege_abuse", {"failures_by_type": {"sudo_not_allowed": 2, "sudo_auth_failure": 3}},
     "Privilege Escalation", ["T1548.003"]),
    # Yalnızca su ile parola tahmini: kimlik bilgisi elde etme girişimi.
    ("privilege_abuse", {"failures_by_type": {"su_failure": 6}}, "Credential Access", ["T1110.001"]),
    ("sensitive_command", {"techniques": ["T1003.008", "T1136.001"]}, "Credential Access", ["T1003.008", "T1136.001"]),
    ("escalation_chain", {"privilege_events": {"sudo_command": 3}}, "Privilege Escalation", ["T1078.003", "T1548.003"]),
    ("escalation_chain", {"privilege_events": {"su_failure": 3}}, "Privilege Escalation", ["T1078.003", "T1110.001"]),
])
def test_every_rule_maps_to_attack(rule, details, tactic, techniques):
    assert classify(alert(rule, **details)) == (tactic, techniques)


def priv(seconds, command):
    return PrivEvent(T0.replace(second=seconds), "srv", "sudo", "sudo_command", "bob", "root", command, 1)


@pytest.mark.parametrize("command, technique", [
    ("/bin/cat /etc/shadow", "T1003.008"),
    ("/usr/bin/vim /etc/sudoers", "T1548.003"),
    ("/usr/sbin/visudo", "T1548.003"),
    ("/usr/sbin/useradd -o -u 0 -g 0 -M sysupdate", "T1136.001"),
    ("/usr/bin/passwd root", "T1098"),
    ("/bin/chmod u+s /bin/bash", "T1548.001"),
])
def test_sensitive_command_records_matched_technique(command, technique):
    (result,) = detect_sensitive_command([priv(0, command)], CONFIG["sensitive_command"])
    assert result.details["techniques"] == [technique]


def test_sensitive_command_session_lists_each_technique_once_in_order():
    events = [priv(0, "/bin/cat /etc/shadow"), priv(10, "/usr/sbin/useradd x"), priv(20, "/bin/cat /etc/shadow")]
    (result,) = detect_sensitive_command(events, CONFIG["sensitive_command"])
    assert result.details["techniques"] == ["T1003.008", "T1136.001"]
    assert classify(result)[0] == "Credential Access"


def test_config_patterns_use_known_techniques():
    assert set(CONFIG["sensitive_command"]["patterns"]) <= set(TECHNIQUES)


def test_unknown_technique_is_rejected():
    with pytest.raises(ValueError):
        classify(alert("sensitive_command", techniques=["T9999"]))


def test_reference_rows_and_urls():
    assert technique_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"
    assert technique_url("T1098") == "https://attack.mitre.org/techniques/T1098/"
    rows = {row[0]: row for row in reference_rows()}
    assert rows["T1548.003"][2:4] == ("TA0004", "Privilege Escalation")
    assert len(rows) == len(TECHNIQUES)
