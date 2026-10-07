"""OpenSSH auth log satırlarını yapılandırılmış olaylara çevirir.

Her satır için üç sonuç mümkündür:
  - AuthEvent : bir kimlik doğrulama denemesi (başarılı / başarısız giriş)
  - None      : geçerli ama bizi ilgilendirmeyen satır (pam, disconnect vb.)
  - ParseError: bozuk satır (karantinaya gider)
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

LOGIN_FAILED = "login_failed"
LOGIN_SUCCESS = "login_success"

# ParseError red sebepleri
MALFORMED_LINE = "malformed_line"
INVALID_TIMESTAMP = "invalid_timestamp"

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

# Auth satırı gibi başlayıp AUTH_RE'ye uymayan satır yarım / bozuk demektir.
AUTH_PREFIX_RE = re.compile(r"^(?:Failed|Accepted) \S+ for ")

# Örn: "message repeated 5 times: [ Failed password for root from ... ssh2]"
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[ (?P<inner>.*)\]$")


class ParseError(ValueError):
    """Satır ayrıştırılamadı. `reason` karantinadaki red sebebi kodudur."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


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
        raise ParseError(MALFORMED_LINE, "syslog başlığı eşleşmedi")

    try:
        event_time = datetime.strptime(
            f"{year} {header['month']} {header['day']} {header['time']}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError as exc:
        raise ParseError(INVALID_TIMESTAMP, str(exc)) from exc

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
        if AUTH_PREFIX_RE.match(message):
            raise ParseError(MALFORMED_LINE, "auth satırı eksik veya bozuk")
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
