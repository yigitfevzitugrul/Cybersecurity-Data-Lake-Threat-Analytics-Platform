"""Validate: ayrıştırılmış olaylara veri kalitesi kontrolleri uygular.

Kontroller sırayla çalışır; ilk başarısız kontrol red sebebi olur.
"""
import ipaddress
from datetime import datetime, timedelta
from typing import Optional

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS, AuthEvent
from src.etl.transform import Rejected, event_hash

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


def check_event(event: AuthEvent, now: datetime) -> Optional[tuple[str, str]]:
    """Olay geçerliyse None, değilse (sebep, detay) döndürür."""
    for field in REQUIRED_TEXT_FIELDS:
        value = getattr(event, field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return MISSING_FIELD, f"{field} boş"

    for field, expected in EXPECTED_TYPES.items():
        value = getattr(event, field)
        # bool, int'in alt sınıfıdır; sayı alanlarında kabul edilmez.
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            return SCHEMA_ERROR, f"{field} tipi {type(value).__name__}, beklenen {expected.__name__}"
    if event.pid is not None and not isinstance(event.pid, int):
        return SCHEMA_ERROR, "pid tam sayı değil"
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

    if event.event_time.year < MIN_YEAR:
        return INVALID_TIMESTAMP, f"yıl çok eski: {event.event_time.year}"
    if event.event_time > now + FUTURE_TOLERANCE:
        return INVALID_TIMESTAMP, f"gelecekte zaman damgası: {event.event_time.isoformat()}"

    return None


def validate(
    events: list[tuple[int, AuthEvent]], now: Optional[datetime] = None
) -> tuple[list[tuple[int, AuthEvent]], list[Rejected]]:
    """(geçerli olaylar, reddedilenler) döndürür. Aynı olayın dosyadaki ilk kopyası tutulur."""
    now = now or datetime.now()
    valid: list[tuple[int, AuthEvent]] = []
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
