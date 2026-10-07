"""OpenSSH auth log satırlarını yapılandırılmış olaylara çevirir.

Her satır için üç sonuç mümkündür:
  - AuthEvent : bir kimlik doğrulama denemesi (başarılı / başarısız giriş)
  - None      : geçerli ama bizi ilgilendirmeyen satır (pam, disconnect vb.)
  - ParseError: syslog formatına uymayan bozuk satır (ileride karantinaya gider)
"""
import argparse
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Union

LOGIN_FAILED = "login_failed"
LOGIN_SUCCESS = "login_success"

# Örn: "Dec 10 06:55:48 LabSZ sshd[24200]: <mesaj>"
HEADER_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[\w\-./]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

# Örn: "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
# Kullanıcı adı saldırganın kontrolündedir ve boşluk / sahte " from ... port ..."
# içerebilir. Açgözlü (.*) + satır sonu çapası sayesinde her zaman sshd'nin
# yazdığı SON " from <ip> port <n>" kısmı gerçek kaynak olarak alınır.
AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\S+) for "
    r"(?P<invalid>invalid user )?(?P<username>.*) "
    r"from (?P<ip>\S+) port (?P<port>\d+) ssh2(?:: .*)?$"
)

# Örn: "message repeated 5 times: [ Failed password for root from ... ssh2]"
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[ (?P<inner>.*)\]$")


class ParseError(ValueError):
    """Satır beklenen syslog formatında değil."""


@dataclass(frozen=True)
class AuthEvent:
    event_time: datetime
    host: str
    pid: Optional[int]
    event_type: str
    auth_method: str
    username: str
    is_invalid_user: bool
    source_ip: str
    source_port: int
    repeat_count: int
    raw_line: str


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Tek bir log satırını ayrıştırır. Syslog satırında yıl olmadığı için dışarıdan verilir."""
    line = line.rstrip("\r\n")
    header = HEADER_RE.match(line)
    if header is None:
        raise ParseError("syslog başlığı eşleşmedi")

    try:
        event_time = datetime.strptime(
            f"{year} {header['month']} {header['day']} {header['time']}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError as exc:
        raise ParseError(f"geçersiz zaman damgası: {exc}") from exc

    if header["process"] != "sshd":
        return None

    message = header["message"]
    repeat_count = 1
    repeated = REPEATED_RE.match(message)
    if repeated:
        repeat_count = int(repeated["count"])
        message = repeated["inner"]

    auth = AUTH_RE.match(message)
    if auth is None:
        return None

    return AuthEvent(
        event_time=event_time,
        host=header["host"],
        pid=int(header["pid"]) if header["pid"] else None,
        event_type=LOGIN_SUCCESS if auth["result"] == "Accepted" else LOGIN_FAILED,
        auth_method=auth["method"],
        username=auth["username"],
        is_invalid_user=auth["invalid"] is not None,
        source_ip=auth["ip"],
        source_port=int(auth["port"]),
        repeat_count=repeat_count,
        raw_line=line,
    )


def parse_file(
    path: Union[str, Path], year: int
) -> Iterator[tuple[int, str, Union[AuthEvent, ParseError, None]]]:
    """Dosyayı satır satır okur; (satır_no, ham_satır, sonuç) üretir. Boş satırlar atlanır."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            try:
                yield line_no, line, parse_line(line, year)
            except ParseError as exc:
                yield line_no, line, exc


def main() -> None:
    ap = argparse.ArgumentParser(description="Auth log dosyasını ayrıştırıp özet basar.")
    ap.add_argument("path")
    ap.add_argument("--year", type=int, default=datetime.now().year)
    args = ap.parse_args()

    total = skipped = 0
    errors = []
    by_type = Counter()
    attempts = Counter()
    for line_no, _, result in parse_file(args.path, args.year):
        total += 1
        if result is None:
            skipped += 1
        elif isinstance(result, ParseError):
            errors.append((line_no, str(result)))
        else:
            by_type[result.event_type] += 1
            attempts[result.event_type] += result.repeat_count

    print(f"Toplam satır       : {total}")
    print(f"Auth olayı         : {sum(by_type.values())}")
    for event_type in sorted(by_type):
        print(f"  {event_type:<15}: {by_type[event_type]} satır, {attempts[event_type]} deneme")
    print(f"İlgisiz (atlanan)  : {skipped}")
    print(f"Bozuk satır        : {len(errors)}")
    for line_no, reason in errors[:10]:
        print(f"  satır {line_no}: {reason}")


if __name__ == "__main__":
    main()
