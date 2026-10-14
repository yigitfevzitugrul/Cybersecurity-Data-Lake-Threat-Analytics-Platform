"""Validate: ayrıştırılmış olaylara veri kalitesi kontrolleri uygular.

Kontroller sırayla çalışır; ilk başarısız kontrol red sebebi olur.
"""
import ipaddress
from datetime import datetime, timedelta
from typing import Optional

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS, PRIVILEGE_EVENT_TYPES, PrivilegeEvent
from src.etl.transform import Event, Rejected, event_hash

MISSING_FIELD = "missing_field"
SCHEMA_ERROR = "schema_error"
INVALID_IP = "invalid_ip"
INVALID_PORT = "invalid_port"
INVALID_TIMESTAMP = "invalid_timestamp"
DUPLICATE = "duplicate"

REQUIRED_TEXT_FIELDS = ("host", "event_type", "auth_method", "username", "source_ip")
EXPECTED_TYPES = {
    "event_time": datetime,
    "host": str,
    "event_type": str,
    "auth_method": str,
    "username": str,
    "is_invalid_user": bool,
    "source_ip": str,
    "source_port": int,
    "repeat_count": int,
}
MIN_YEAR = 2000
# Saat farkı / küçük saat kaymaları için tolerans.
FUTURE_TOLERANCE = timedelta(days=1)


PRIVILEGE_REQUIRED_TEXT_FIELDS = ("host", "program", "event_type", "username", "target_user")
PRIVILEGE_EXPECTED_TYPES = {
    "event_time": datetime,
    "host": str,
    "program": str,
    "event_type": str,
    "username": str,
    "target_user": str,
    "attempts": int,
}


def _missing(event, fields) -> Optional[tuple[str, str]]:
    for field in fields:
        value = getattr(event, field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return MISSING_FIELD, f"{field} boş"
    return None


def _wrong_type(event, expected_types) -> Optional[tuple[str, str]]:
    for field, expected in expected_types.items():
        value = getattr(event, field)
        # bool, int'in alt sınıfıdır; sayı alanlarında kabul edilmez.
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            return SCHEMA_ERROR, f"{field} tipi {type(value).__name__}, beklenen {expected.__name__}"
    if event.pid is not None and not isinstance(event.pid, int):
        return SCHEMA_ERROR, "pid tam sayı değil"
    return None


def _bad_timestamp(event, now: datetime) -> Optional[tuple[str, str]]:
    if event.event_time.year < MIN_YEAR:
        return INVALID_TIMESTAMP, f"yıl çok eski: {event.event_time.year}"
    if event.event_time > now + FUTURE_TOLERANCE:
        return INVALID_TIMESTAMP, f"gelecekte zaman damgası: {event.event_time.isoformat()}"
    return None


def check_privilege_event(event: PrivilegeEvent, now: datetime) -> Optional[tuple[str, str]]:
    problem = _missing(event, PRIVILEGE_REQUIRED_TEXT_FIELDS) or _wrong_type(event, PRIVILEGE_EXPECTED_TYPES)
    if problem:
        return problem
    if event.program not in ("sudo", "su"):
        return SCHEMA_ERROR, f"bilinmeyen program: {event.program}"
    if event.event_type not in PRIVILEGE_EVENT_TYPES:
        return SCHEMA_ERROR, f"bilinmeyen event_type: {event.event_type}"
    if event.attempts < 1:
        return SCHEMA_ERROR, f"attempts {event.attempts}"
    return _bad_timestamp(event, now)


def check_event(event: Event, now: datetime) -> Optional[tuple[str, str]]:
    """Olay geçerliyse None, değilse (sebep, detay) döndürür."""
    if isinstance(event, PrivilegeEvent):
        return check_privilege_event(event, now)
    problem = _missing(event, REQUIRED_TEXT_FIELDS) or _wrong_type(event, EXPECTED_TYPES)
    if problem:
        return problem
    if event.event_type not in (LOGIN_FAILED, LOGIN_SUCCESS):
        return SCHEMA_ERROR, f"bilinmeyen event_type: {event.event_type}"
    if event.repeat_count < 1:
        return SCHEMA_ERROR, f"repeat_count {event.repeat_count}"

    try:
        ipaddress.ip_address(event.source_ip)
    except ValueError:
        return INVALID_IP, f"geçersiz IP: {event.source_ip}"

    if not 1 <= event.source_port <= 65535:
        return INVALID_PORT, f"port aralık dışı: {event.source_port}"

    return _bad_timestamp(event, now)


def validate(
    events: list[tuple[int, Event]], now: Optional[datetime] = None
) -> tuple[list[tuple[int, Event]], list[Rejected]]:
    """(geçerli olaylar, reddedilenler) döndürür. Aynı olayın dosyadaki ilk kopyası tutulur."""
    now = now or datetime.now()
    valid: list[tuple[int, Event]] = []
    rejected: list[Rejected] = []
    seen: dict[str, int] = {}
    for line_no, event in events:
        problem = check_event(event, now)
        if problem is None:
            digest = event_hash(event)
            if digest in seen:
                problem = (DUPLICATE, f"satır {seen[digest]} ile aynı")
            else:
                seen[digest] = line_no
        if problem is None:
            valid.append((line_no, event))
        else:
            rejected.append(Rejected(line_no, event.raw_line, problem[0], problem[1]))
    return valid, rejected
