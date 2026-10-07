"""Transform: ham satırları ayrıştırır ve normalize eder."""
import hashlib
import ipaddress
from dataclasses import dataclass, replace
from typing import Iterable

from src.etl.extract import RawLine
from src.etl.parser import AuthEvent, ParseError, parse_line


@dataclass(frozen=True)
class Rejected:
    """Karantinaya gidecek satır."""
    line_no: int
    raw_line: str
    reason: str
    detail: str


def event_hash(event: AuthEvent) -> str:
    """Olayın kimliği: zaman (yıl dahil) + ham satır. Aynı olay hangi dosyadan gelirse gelsin aynı hash'i alır."""
    key = f"{event.event_time.isoformat()}|{event.raw_line}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def normalize_ip(value: str) -> str:
    """Geçerli IP'yi kanonik biçime çevirir (örn. ::ffff:1.2.3.4 → 1.2.3.4). Geçersizse dokunmaz; validate reddeder."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def transform(
    lines: Iterable[RawLine], year: int
) -> tuple[list[tuple[int, AuthEvent]], list[Rejected], int]:
    """(olaylar, reddedilenler, ilgisiz satır sayısı) döndürür."""
    events: list[tuple[int, AuthEvent]] = []
    rejected: list[Rejected] = []
    irrelevant = 0
    for raw in lines:
        try:
            event = parse_line(raw.text, year)
        except ParseError as exc:
            rejected.append(Rejected(raw.line_no, raw.text, exc.reason, str(exc)))
            continue
        if event is None:
            irrelevant += 1
            continue
        events.append((raw.line_no, replace(event, source_ip=normalize_ip(event.source_ip))))
    return events, rejected, irrelevant
