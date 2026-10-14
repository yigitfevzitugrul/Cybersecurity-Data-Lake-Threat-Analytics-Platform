"""Linux auth log satırlarını yapılandırılmış olaylara çevirir.

Her satır için dört sonuç mümkündür:
  - AuthEvent      : bir SSH kimlik doğrulama denemesi (başarılı / başarısız giriş)
  - PrivilegeEvent : bir yetki yükseltme girişimi (sudo / su)
  - None           : geçerli ama bizi ilgilendirmeyen satır (pam, disconnect vb.)
  - ParseError     : bozuk satır (karantinaya gider)
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union

LOGIN_FAILED = "login_failed"
LOGIN_SUCCESS = "login_success"

# Yetki yükseltme olay tipleri
SUDO_COMMAND = "sudo_command"            # sudo izin verdi, komut çalıştı
SUDO_AUTH_FAILURE = "sudo_auth_failure"  # yanlış sudo parolası
SUDO_NOT_ALLOWED = "sudo_not_allowed"    # kullanıcının sudo yetkisi yok
SU_SUCCESS = "su_success"
SU_FAILURE = "su_failure"
PRIVILEGE_EVENT_TYPES = (SUDO_COMMAND, SUDO_AUTH_FAILURE, SUDO_NOT_ALLOWED, SU_SUCCESS, SU_FAILURE)

# ParseError red sebepleri
MALFORMED_LINE = "malformed_line"
INVALID_TIMESTAMP = "invalid_timestamp"

# Örn: "Dec 10 06:55:48 LabSZ sshd[24200]: <mesaj>"
# Süreç adı eski sistemlerde "su(pam_unix)" ya da "syslogd 1.4.1" gibi parantez ve
# boşluk içerebilir; ilk "[" ya da ":" karakterine kadar alınır.
HEADER_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[^\s\[:][^\[:]*?)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
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

# sudo: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
#       "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
#       "alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
SUDO_FAILED_ATTEMPTS_RE = re.compile(r"^(?P<count>\d+) incorrect password attempts?$")
SUDO_NOT_ALLOWED_MESSAGES = ("user NOT in sudoers", "user NOT authorized on host", "command not allowed")

# su (util-linux): "(to root) alice on pts/0", "FAILED SU (to root) alice on pts/0"
SU_RE = re.compile(r"^(?P<failed>FAILED SU )?\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)$")
# su (shadow-utils): "Successful su for root by alice", "FAILED su for root by alice"
SU_SHADOW_RE = re.compile(r"^(?P<result>Successful|FAILED) su for (?P<target>\S+) by (?P<user>\S+)$")
# Eski sistemler (ör. Loghub Linux): "su(pam_unix)[123]: session opened for user news by (uid=0)"
SU_PAM_SESSION_RE = re.compile(
    r"^session opened for user (?P<target>\S+) by (?P<user>[^\s(]*)\(uid=(?P<uid>\d+)\)$"
)


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


@dataclass(frozen=True)
class PrivilegeEvent:
    event_time: datetime
    host: str
    pid: Optional[int]
    program: str           # sudo | su
    event_type: str        # PRIVILEGE_EVENT_TYPES
    username: str          # yetki isteyen kullanıcı
    target_user: str       # olunmak istenen kullanıcı (çoğunlukla root)
    tty: Optional[str]
    pwd: Optional[str]
    command: Optional[str]
    attempts: int          # sudo'nun bildirdiği yanlış parola sayısı; diğerlerinde 1
    raw_line: str


def _parse_sudo(message: str, base: dict) -> Optional[PrivilegeEvent]:
    match = SUDO_RE.match(message)
    if match is None or message.lstrip().startswith("pam_unix("):
        return None
    status, fields = None, {}
    rest = match["rest"]
    # COMMAND her zaman son alandır ve kendisi " ; " içerebilir: ondan sonrası olduğu gibi alınır.
    head, sep, command = rest.partition(" ; COMMAND=")
    if not sep and rest.startswith("COMMAND="):
        head, command = "", rest[len("COMMAND="):]
    for i, item in enumerate(part for part in head.split(" ; ") if part):
        key, eq, value = item.partition("=")
        if eq and key.isupper():
            fields[key] = value
        elif i == 0:
            status = item
        else:
            return None

    attempts = 1
    if status is None:
        event_type = SUDO_COMMAND
    elif failed := SUDO_FAILED_ATTEMPTS_RE.match(status):
        event_type, attempts = SUDO_AUTH_FAILURE, int(failed["count"])
    elif status in SUDO_NOT_ALLOWED_MESSAGES:
        event_type = SUDO_NOT_ALLOWED
    else:
        return None  # ör. "a password is required" (sudo -n): girişim değil

    return PrivilegeEvent(
        **base, program="sudo", event_type=event_type, username=match["user"],
        target_user=fields.get("USER", "root"), tty=fields.get("TTY"), pwd=fields.get("PWD"),
        command=command or None, attempts=attempts,
    )


def _parse_su(process: str, message: str, base: dict) -> Optional[PrivilegeEvent]:
    if match := SU_RE.match(message):
        event_type = SU_FAILURE if match["failed"] else SU_SUCCESS
        user, target, tty = match["user"], match["target"], match["tty"]
    elif match := SU_SHADOW_RE.match(message):
        event_type = SU_SUCCESS if match["result"] == "Successful" else SU_FAILURE
        user, target, tty = match["user"], match["target"], None
    elif process == "su(pam_unix)" and (match := SU_PAM_SESSION_RE.match(message)):
        # Eski biçimde başka su satırı yoktur; oturum açılması başarılı su demektir.
        uid = int(match["uid"])
        user = match["user"] or ("root" if uid == 0 else f"uid={uid}")
        event_type, target, tty = SU_SUCCESS, match["target"], None
    else:
        return None
    return PrivilegeEvent(
        **base, program="su", event_type=event_type, username=user, target_user=target,
        tty=tty, pwd=None, command=None, attempts=1,
    )


def parse_line(line: str, year: int) -> Optional[Union[AuthEvent, PrivilegeEvent]]:
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

    process = header["process"]
    base = {
        "event_time": event_time,
        "host": header["host"],
        "pid": int(header["pid"]) if header["pid"] else None,
        "raw_line": line,
    }
    if process == "sudo":
        return _parse_sudo(header["message"], base)
    if process in ("su", "su(pam_unix)"):
        return _parse_su(process, header["message"], base)
    if process != "sshd":
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
