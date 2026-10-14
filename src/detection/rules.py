"""Kural tabanlı tehdit tespiti.

Kurallar saf fonksiyonlardır: zamana göre sıralı olay listesi ve eşik
sözlüğü alır, alarm listesi döndürür. Veritabanına dokunmazlar.
"""
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, NamedTuple, Optional

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS, SU_FAILURE, SUDO_AUTH_FAILURE, SUDO_COMMAND, SUDO_NOT_ALLOWED

BRUTE_FORCE = "brute_force"
PASSWORD_SPRAY = "password_spray"
SUSPICIOUS_IP = "suspicious_ip"
AUTH_ANOMALY = "auth_anomaly"
PRIVILEGE_ABUSE = "privilege_abuse"
SENSITIVE_COMMAND = "sensitive_command"
ESCALATION_CHAIN = "escalation_chain"
PRIVILEGE_RULES = (PRIVILEGE_ABUSE, SENSITIVE_COMMAND, ESCALATION_CHAIN)

PRIVILEGE_FAILURE_TYPES = (SUDO_AUTH_FAILURE, SUDO_NOT_ALLOWED, SU_FAILURE)

# auth_anomaly sebepleri
SUCCESS_AFTER_FAILURES = "success_after_failures"
NEW_IP = "new_ip"
OFF_HOURS = "off_hours"


class Event(NamedTuple):
    time: datetime
    host: str
    event_type: str
    username: str
    is_invalid_user: bool
    source_ip: str
    attempts: int  # repeat_count


class PrivEvent(NamedTuple):
    time: datetime
    host: str
    program: str
    event_type: str
    username: str
    target_user: str
    command: Optional[str]
    attempts: int


@dataclass
class Alert:
    rule: str
    severity: str
    source_ip: Optional[str]  # sudo / su alarmlarında kaynak IP yoktur
    username: Optional[str]  # birden çok kullanıcı hedeflendiyse None
    window_start: datetime
    window_end: datetime
    attempt_count: int
    distinct_users: int
    details: dict = field(default_factory=dict)


def _sessions(events: list[Event], gap: timedelta) -> Iterable[list[Event]]:
    """Sıralı olayları, aralarında `gap`ten uzun boşluk olan yerlerden böler."""
    session: list[Event] = []
    for event in events:
        if session and event.time - session[-1].time > gap:
            yield session
            session = []
        session.append(event)
    if session:
        yield session


def _peak_attempts(session: list[Event], window: timedelta) -> int:
    """Herhangi bir `window` uzunluğundaki kayan penceredeki en yüksek deneme sayısı."""
    peak = current = start = 0
    for event in session:
        current += event.attempts
        while event.time - session[start].time > window:
            current -= session[start].attempts
            start += 1
        peak = max(peak, current)
    return peak


def _peak_distinct_users(session: list[Event], window: timedelta) -> int:
    """Herhangi bir `window` uzunluğundaki kayan penceredeki en yüksek farklı kullanıcı sayısı."""
    users: Counter = Counter()
    peak = start = 0
    for event in session:
        users[event.username] += 1
        while event.time - session[start].time > window:
            old = session[start].username
            users[old] -= 1
            if users[old] == 0:
                del users[old]
            start += 1
        peak = max(peak, len(users))
    return peak


def _group_failed(events: Iterable[Event], key) -> dict:
    groups = defaultdict(list)
    for event in events:
        if event.event_type == LOGIN_FAILED:
            groups[key(event)].append(event)
    return groups


def detect_brute_force(events: list[Event], cfg: dict) -> list[Alert]:
    """Aynı IP → aynı kullanıcı, kısa pencerede çok başarısız deneme."""
    window = timedelta(minutes=cfg["window_minutes"])
    alerts = []
    for (ip, username), failed in _group_failed(events, lambda e: (e.source_ip, e.username)).items():
        for session in _sessions(failed, window):
            peak = _peak_attempts(session, window)
            if peak < cfg["min_failed_attempts"]:
                continue
            total = sum(e.attempts for e in session)
            alerts.append(Alert(
                rule=BRUTE_FORCE,
                severity="high" if total >= cfg["high_severity_attempts"] else "medium",
                source_ip=ip,
                username=username,
                window_start=session[0].time,
                window_end=session[-1].time,
                attempt_count=total,
                distinct_users=1,
                details={
                    "peak_attempts_in_window": peak,
                    "window_minutes": cfg["window_minutes"],
                    "is_invalid_user": session[0].is_invalid_user,
                    "hosts": sorted({e.host for e in session}),
                },
            ))
    return alerts


def detect_password_spray(events: list[Event], cfg: dict) -> list[Alert]:
    """Aynı IP → çok farklı kullanıcı, her birine az deneme."""
    window = timedelta(minutes=cfg["window_minutes"])
    alerts = []
    for ip, failed in _group_failed(events, lambda e: e.source_ip).items():
        for session in _sessions(failed, window):
            peak_users = _peak_distinct_users(session, window)
            if peak_users < cfg["min_distinct_users"]:
                continue
            users = {e.username for e in session}
            total = sum(e.attempts for e in session)
            if total / len(users) > cfg["max_avg_attempts_per_user"]:
                continue
            alerts.append(Alert(
                rule=PASSWORD_SPRAY,
                severity="high" if len(users) >= cfg["high_severity_users"] else "medium",
                source_ip=ip,
                username=None,
                window_start=session[0].time,
                window_end=session[-1].time,
                attempt_count=total,
                distinct_users=len(users),
                details={
                    "peak_distinct_users_in_window": peak_users,
                    "window_minutes": cfg["window_minutes"],
                    "valid_users_targeted": sorted({e.username for e in session if not e.is_invalid_user}),
                    "sample_users": sorted(users)[:10],
                    "hosts": sorted({e.host for e in session}),
                },
            ))
    return alerts


def detect_suspicious_ip(events: list[Event], cfg: dict) -> list[Alert]:
    """root ya da var olmayan kullanıcılara yönelik denemeler; çok sunucuyu yoklayan IP'ler."""
    window = timedelta(minutes=cfg["window_minutes"])
    probes = [e for e in events if e.is_invalid_user or e.username == "root"]
    alerts = []
    for ip, failed in _group_failed(probes, lambda e: e.source_ip).items():
        for session in _sessions(failed, window):
            total = sum(e.attempts for e in session)
            hosts = sorted({e.host for e in session})
            many_hosts = len(hosts) >= cfg["min_distinct_hosts"]
            if total < cfg["min_attempts"] and not many_hosts:
                continue
            users = {e.username for e in session}
            alerts.append(Alert(
                rule=SUSPICIOUS_IP,
                severity="medium" if many_hosts else "low",
                source_ip=ip,
                username=None,
                window_start=session[0].time,
                window_end=session[-1].time,
                attempt_count=total,
                distinct_users=len(users),
                details={
                    "root_attempts": sum(e.attempts for e in session if e.username == "root"),
                    "invalid_user_attempts": sum(e.attempts for e in session if e.is_invalid_user),
                    "hosts": hosts,
                },
            ))
    return alerts


def detect_auth_anomaly(events: list[Event], cfg: dict) -> list[Alert]:
    """Olağandışı başarılı girişler: çok başarısızlık sonrası giriş, yeni IP, mesai dışı saat."""
    window = timedelta(minutes=cfg["window_minutes"])
    recent_failures: dict[str, deque] = defaultdict(deque)  # ip → (zaman, deneme)
    login_history: dict[str, Counter] = defaultdict(Counter)  # kullanıcı → IP başına başarılı giriş
    alerts = []
    for event in events:
        if event.event_type == LOGIN_FAILED:
            recent_failures[event.source_ip].append((event.time, event.attempts))
            continue
        if event.event_type != LOGIN_SUCCESS:
            continue

        failures = recent_failures[event.source_ip]
        while failures and event.time - failures[0][0] > window:
            failures.popleft()
        prior_failures = sum(attempts for _, attempts in failures)
        history = login_history[event.username]

        reasons = []
        if prior_failures >= cfg["min_prior_failures"]:
            reasons.append(SUCCESS_AFTER_FAILURES)
        if sum(history.values()) >= cfg["min_history_logins"] and event.source_ip not in history:
            reasons.append(NEW_IP)
        if not cfg["business_hours_start"] <= event.time.hour < cfg["business_hours_end"]:
            reasons.append(OFF_HOURS)

        if reasons:
            if SUCCESS_AFTER_FAILURES in reasons:
                # Kullanıcının zaten bildiğimiz IP'sinden geliyorsa büyük olasılıkla şifresini
                # unutmuştur: alarm yine üretilir ama önem derecesi düşürülür.
                severity = "medium" if event.source_ip in history else "critical"
            elif NEW_IP in reasons:
                severity = "high" if OFF_HOURS in reasons else "medium"
            else:
                severity = "low"
            alerts.append(Alert(
                rule=AUTH_ANOMALY,
                severity=severity,
                source_ip=event.source_ip,
                username=event.username,
                window_start=event.time,
                window_end=event.time,
                attempt_count=prior_failures,
                distinct_users=1,
                details={
                    "reasons": reasons,
                    "prior_failures": prior_failures,
                    "known_ips_for_user": len(history),
                    "host": event.host,
                },
            ))
        # Geçmiş, giriş değerlendirildikten sonra güncellenir. Başarılı girişten önceki
        # başarısızlıklar sonraki girişlere tekrar sayılmaz.
        history[event.source_ip] += 1
        failures.clear()
    return alerts


def detect_privilege_abuse(events: list[PrivEvent], cfg: dict) -> list[Alert]:
    """Aynı kullanıcının kısa sürede art arda başarısız yetki girişimleri (sudo / su)."""
    window = timedelta(minutes=cfg["window_minutes"])
    groups = defaultdict(list)
    for event in events:
        if event.event_type in PRIVILEGE_FAILURE_TYPES:
            groups[event.username].append(event)
    alerts = []
    for username, failures in groups.items():
        for session in _sessions(failures, window):
            total = sum(e.attempts for e in session)
            if total < cfg["min_failures"]:
                continue
            by_type: Counter = Counter()
            for e in session:
                by_type[e.event_type] += e.attempts
            alerts.append(Alert(
                rule=PRIVILEGE_ABUSE,
                severity="high" if total >= cfg["high_severity_failures"] else "medium",
                source_ip=None,
                username=username,
                window_start=session[0].time,
                window_end=session[-1].time,
                attempt_count=total,
                distinct_users=1,
                details={
                    "failures_by_type": dict(by_type),
                    "target_users": sorted({e.target_user for e in session}),
                    "hosts": sorted({e.host for e in session}),
                },
            ))
    return alerts


def detect_sensitive_command(events: list[PrivEvent], cfg: dict) -> list[Alert]:
    """sudo ile çalıştırılan hassas komutlar (parola dosyası, sudoers, kullanıcı yönetimi, setuid).

    Kalıplar ATT&CK tekniğine göre gruplanmıştır; eşleşen teknikler alarmın ayrıntılarına yazılır.
    """
    patterns = [(technique, re.compile(p)) for technique, group in cfg["patterns"].items() for p in group]
    gap = timedelta(minutes=cfg["session_gap_minutes"])
    groups = defaultdict(list)
    matched = {}
    for event in events:
        if event.event_type != SUDO_COMMAND or not event.command:
            continue
        techniques = [t for t, p in patterns if p.search(event.command)]
        if techniques:
            groups[event.username].append(event)
            matched[event] = techniques
    alerts = []
    for username, hits in groups.items():
        for session in _sessions(hits, gap):
            techniques = list(dict.fromkeys(t for e in session for t in matched[e]))
            alerts.append(Alert(
                rule=SENSITIVE_COMMAND,
                severity="high",
                source_ip=None,
                username=username,
                window_start=session[0].time,
                window_end=session[-1].time,
                attempt_count=0,
                distinct_users=1,
                details={
                    "commands": [e.command for e in session][:10],
                    "techniques": techniques,
                    "target_users": sorted({e.target_user for e in session}),
                    "hosts": sorted({e.host for e in session}),
                },
            ))
    return alerts


def detect_escalation_chain(events: list[PrivEvent], auth_alerts: list[Alert], cfg: dict) -> list[Alert]:
    """Şüpheli bir girişin ardından aynı hesapla yapılan yetki etkinliği: saldırı zinciri.

    Tetikleyici, auth_anomaly kuralının high / critical alarmlarıdır: bilinmeyen bir IP'den
    çok başarısızlık sonrası giriş ya da gece yeni bir IP'den giriş. sudo / su kayıtlarında
    IP olmadığı için zincir, hesap adı ve zaman üzerinden kurulur.
    """
    follow = timedelta(minutes=cfg["follow_minutes"])
    by_user = defaultdict(list)
    for event in events:
        by_user[event.username].append(event)
    alerts = []
    for login in auth_alerts:
        if login.rule != AUTH_ANOMALY or login.severity not in ("high", "critical"):
            continue
        after = [e for e in by_user.get(login.username, [])
                 if login.window_end <= e.time <= login.window_end + follow]
        if not after:
            continue
        by_type: Counter = Counter()
        for e in after:
            by_type[e.event_type] += e.attempts
        alerts.append(Alert(
            rule=ESCALATION_CHAIN,
            severity="critical",
            source_ip=login.source_ip,
            username=login.username,
            window_start=login.window_start,
            window_end=after[-1].time,
            attempt_count=sum(e.attempts for e in after if e.event_type in PRIVILEGE_FAILURE_TYPES),
            distinct_users=1,
            details={
                "login_reasons": login.details.get("reasons", []),
                "privilege_events": dict(by_type),
                "commands": [e.command for e in after if e.command][:10],
                "minutes_after_login": round((after[0].time - login.window_end).total_seconds() / 60, 1),
            },
        ))
    return alerts


DETECTORS = {
    BRUTE_FORCE: detect_brute_force,
    PASSWORD_SPRAY: detect_password_spray,
    SUSPICIOUS_IP: detect_suspicious_ip,
    AUTH_ANOMALY: detect_auth_anomaly,
}


def run_rules(events: list[Event], config: dict, privilege_events: Iterable[PrivEvent] = ()) -> list[Alert]:
    """Bütün kuralları çalıştırır. İki olay listesi de zamana göre sıralı olmalıdır."""
    alerts = []
    for rule, detector in DETECTORS.items():
        alerts.extend(detector(events, config[rule]))
    privilege_events = list(privilege_events)
    if privilege_events:
        auth_alerts = list(alerts)
        alerts.extend(detect_privilege_abuse(privilege_events, config[PRIVILEGE_ABUSE]))
        alerts.extend(detect_sensitive_command(privilege_events, config[SENSITIVE_COMMAND]))
        alerts.extend(detect_escalation_chain(privilege_events, auth_alerts, config[ESCALATION_CHAIN]))
    return sorted(alerts, key=lambda a: (a.window_start, a.rule, a.source_ip or "", a.username or ""))
