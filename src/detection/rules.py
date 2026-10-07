"""Kural tabanlı tehdit tespiti.

Kurallar saf fonksiyonlardır: zamana göre sıralı olay listesi ve eşik
sözlüğü alır, alarm listesi döndürür. Veritabanına dokunmazlar.
"""
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, NamedTuple, Optional

from src.etl.parser import LOGIN_FAILED, LOGIN_SUCCESS

BRUTE_FORCE = "brute_force"
PASSWORD_SPRAY = "password_spray"
SUSPICIOUS_IP = "suspicious_ip"
AUTH_ANOMALY = "auth_anomaly"

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


@dataclass
class Alert:
    rule: str
    severity: str
    source_ip: str
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


DETECTORS = {
    BRUTE_FORCE: detect_brute_force,
    PASSWORD_SPRAY: detect_password_spray,
    SUSPICIOUS_IP: detect_suspicious_ip,
    AUTH_ANOMALY: detect_auth_anomaly,
}


def run_rules(events: list[Event], config: dict) -> list[Alert]:
    """Bütün kuralları çalıştırır. `events` zamana göre sıralı olmalıdır."""
    alerts = []
    for rule, detector in DETECTORS.items():
        alerts.extend(detector(events, config[rule]))
    return sorted(alerts, key=lambda a: (a.window_start, a.rule, a.source_ip, a.username or ""))
