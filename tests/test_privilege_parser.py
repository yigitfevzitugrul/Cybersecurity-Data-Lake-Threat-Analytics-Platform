"""sudo / su satırlarının ayrıştırılması."""
from dataclasses import replace
from datetime import datetime

import pytest

from src.etl.parser import (
    SU_FAILURE,
    SU_SUCCESS,
    SUDO_AUTH_FAILURE,
    SUDO_COMMAND,
    SUDO_NOT_ALLOWED,
    PrivilegeEvent,
    parse_line,
)
from src.etl.validate import check_event

YEAR = 2026
NOW = datetime(2026, 12, 31)


def sudo(message: str) -> str:
    return f"Oct 14 10:00:00 web01 sudo:    {message}"


def test_sudo_command():
    e = parse_line(sudo("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"), YEAR)
    assert isinstance(e, PrivilegeEvent)
    assert (e.program, e.event_type, e.username, e.target_user) == ("sudo", SUDO_COMMAND, "alice", "root")
    assert (e.tty, e.pwd, e.command, e.attempts) == ("pts/0", "/home/alice", "/usr/bin/apt update", 1)
    assert e.event_time == datetime(2026, 10, 14, 10, 0, 0)
    assert e.pid is None


@pytest.mark.parametrize("message, attempts", [
    ("1 incorrect password attempt", 1),
    ("3 incorrect password attempts", 3),
])
def test_sudo_wrong_password(message, attempts):
    e = parse_line(sudo(f"alice : {message} ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"), YEAR)
    assert (e.event_type, e.attempts, e.command) == (SUDO_AUTH_FAILURE, attempts, "/bin/bash")


@pytest.mark.parametrize("status", ["user NOT in sudoers", "user NOT authorized on host", "command not allowed"])
def test_sudo_not_allowed(status):
    e = parse_line(sudo(f"bob : {status} ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow"), YEAR)
    assert (e.event_type, e.username, e.command) == (SUDO_NOT_ALLOWED, "bob", "/bin/cat /etc/shadow")


def test_sudo_to_other_user_and_newer_fields():
    e = parse_line(sudo("alice : TTY=pts/0 ; PWD=/srv ; USER=postgres ; TSID=000001 ; COMMAND=/usr/bin/psql"), YEAR)
    assert (e.target_user, e.command) == ("postgres", "/usr/bin/psql")


def test_sudo_command_may_contain_separator():
    # Komut, sudo'nun alan ayırıcısını içerebilir; COMMAND'dan sonrası olduğu gibi alınır.
    e = parse_line(sudo("alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c id ; whoami"), YEAR)
    assert e.command == "/bin/sh -c id ; whoami"


@pytest.mark.parametrize("line", [
    "Oct 14 10:00:00 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 "
    "euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice",
    "Oct 14 10:00:00 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
    sudo("alice : a password is required ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls"),
    "Oct 14 10:00:00 web01 sudo: unable to resolve host web01",
    "Oct 14 10:00:00 web01 su[123]: pam_unix(su:session): session opened for user root by alice(uid=1000)",
    "Jun 15 04:06:19 combo su(pam_unix)[21416]: session closed for user cyrus",
    "Jun 15 04:06:19 combo syslogd 1.4.1: restart.",
    "Jun 15 04:06:19 combo kernel: Linux version 2.6.5",
])
def test_irrelevant_privilege_lines(line):
    assert parse_line(line, YEAR) is None


def test_su_util_linux():
    ok = parse_line("Oct 14 10:00:00 web01 su[123]: (to root) alice on pts/0", YEAR)
    failed = parse_line("Oct 14 10:00:05 web01 su[124]: FAILED SU (to root) bob on pts/1", YEAR)
    assert (ok.program, ok.event_type, ok.username, ok.target_user, ok.tty, ok.pid) == (
        "su", SU_SUCCESS, "alice", "root", "pts/0", 123)
    assert (failed.event_type, failed.username) == (SU_FAILURE, "bob")


def test_su_shadow_utils():
    ok = parse_line("Oct 14 10:00:00 web01 su[1]: Successful su for root by alice", YEAR)
    failed = parse_line("Oct 14 10:00:00 web01 su[2]: FAILED su for root by bob", YEAR)
    assert (ok.event_type, ok.username, ok.target_user) == (SU_SUCCESS, "alice", "root")
    assert (failed.event_type, failed.username) == (SU_FAILURE, "bob")


def test_su_legacy_pam_session_from_loghub():
    # Loghub Linux veri setindeki gerçek satır biçimi.
    e = parse_line("Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)", YEAR)
    assert (e.event_type, e.username, e.target_user, e.pid, e.host) == (SU_SUCCESS, "root", "cyrus", 21416, "combo")

    named = parse_line("Jun 15 04:06:18 combo su(pam_unix)[1]: session opened for user root by alice(uid=500)", YEAR)
    assert named.username == "alice"


def test_valid_privilege_event_passes_validation():
    e = parse_line(sudo("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"), YEAR)
    assert check_event(e, NOW) is None


@pytest.mark.parametrize("changes, reason", [
    ({"username": ""}, "missing_field"),
    ({"target_user": " "}, "missing_field"),
    ({"program": "doas"}, "schema_error"),
    ({"event_type": "sudo_maybe"}, "schema_error"),
    ({"attempts": 0}, "schema_error"),
    ({"attempts": "3"}, "schema_error"),
    ({"event_time": datetime(2027, 6, 1)}, "invalid_timestamp"),
])
def test_invalid_privilege_events_are_rejected(changes, reason):
    e = parse_line(sudo("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"), YEAR)
    problem = check_event(replace(e, **changes), NOW)
    assert problem is not None and problem[0] == reason
