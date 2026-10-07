from datetime import datetime

import pytest

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS, ParseError, parse_line

YEAR = 2024


def test_failed_password_valid_user():
    e = parse_line(
        "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2",
        YEAR,
    )
    assert e.event_type == LOGIN_FAILED
    assert e.event_time == datetime(2024, 12, 10, 7, 13, 43)
    assert e.host == "LabSZ"
    assert e.pid == 24227
    assert e.auth_method == "password"
    assert e.username == "root"
    assert e.is_invalid_user is False
    assert e.source_ip == "5.36.59.76"
    assert e.source_port == 42393
    assert e.repeat_count == 1


def test_failed_password_invalid_user():
    e = parse_line(
        "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
        YEAR,
    )
    assert e.event_type == LOGIN_FAILED
    assert e.username == "webmaster"
    assert e.is_invalid_user is True


def test_failed_none_method():
    e = parse_line(
        "Dec 10 09:11:20 LabSZ sshd[24439]: Failed none for invalid user admin from 103.99.0.122 port 59812 ssh2",
        YEAR,
    )
    assert e.event_type == LOGIN_FAILED
    assert e.auth_method == "none"


def test_accepted_password():
    e = parse_line(
        "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2",
        YEAR,
    )
    assert e.event_type == LOGIN_SUCCESS
    assert e.username == "fztu"
    assert e.is_invalid_user is False


def test_accepted_publickey_with_key_suffix():
    e = parse_line(
        "Jan  5 10:00:00 web01 sshd[100]: Accepted publickey for deploy from 10.0.0.5 port 50000 ssh2: RSA SHA256:abcDEF123",
        YEAR,
    )
    assert e.event_type == LOGIN_SUCCESS
    assert e.auth_method == "publickey"
    assert e.event_time == datetime(2024, 1, 5, 10, 0, 0)


def test_message_repeated_keeps_count():
    e = parse_line(
        "Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]",
        YEAR,
    )
    assert e.event_type == LOGIN_FAILED
    assert e.username == "root"
    assert e.repeat_count == 5


def test_username_with_spaces_and_injected_source():
    # Saldırgan kullanıcı adına sahte kaynak gömmeye çalışırsa gerçek (son) kaynak alınmalı.
    e = parse_line(
        "Dec 10 08:00:00 LabSZ sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from 203.0.113.9 port 4444 ssh2",
        YEAR,
    )
    assert e.source_ip == "203.0.113.9"
    assert e.source_port == 4444
    assert e.username == "x from 8.8.8.8 port 1 ssh2"


@pytest.mark.parametrize(
    "line",
    [
        "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
        "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
        "Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]",
        "Dec 10 07:07:45 LabSZ sshd[24206]: Received disconnect from 52.80.34.196: 11: Bye Bye [preauth]",
        "Dec 10 07:00:00 LabSZ CRON[999]: pam_unix(cron:session): session opened for user root by (uid=0)",
    ],
)
def test_irrelevant_lines_return_none(line):
    assert parse_line(line, YEAR) is None


@pytest.mark.parametrize(
    "line",
    [
        "tamamen bozuk bir satir",
        "",
        "Dec 10 LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Feb 30 10:00:00 LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Dec 10 25:61:00 LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
    ],
)
def test_malformed_lines_raise(line):
    with pytest.raises(ParseError):
        parse_line(line, YEAR)

def test_truncated_auth_line_is_malformed_not_irrelevant():
    with pytest.raises(ParseError) as exc:
        parse_line("Dec 10 08:00:00 LabSZ sshd[1]: Failed password for root from", YEAR)
    assert exc.value.reason == "malformed_line"


def test_parse_error_reason_codes():
    with pytest.raises(ParseError) as exc:
        parse_line("tamamen bozuk bir satir", YEAR)
    assert exc.value.reason == "malformed_line"
    with pytest.raises(ParseError) as exc:
        parse_line("Feb 30 10:00:00 LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", YEAR)
    assert exc.value.reason == "invalid_timestamp"
