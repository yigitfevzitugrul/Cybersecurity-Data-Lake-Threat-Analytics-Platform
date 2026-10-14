"""Tespit motoru: olayları okur, kuralları çalıştırır, alerts tablosuna yazar.

Varsayılan mod artımlıdır: yalnızca son çalıştırmadan beri yüklenen olaylar ve onlardan
önceki geriye bakış penceresi (config: incremental.lookback_hours) değerlendirilir.
Kullanıcıların giriş geçmişi o pencereden öncesi için veritabanında özetlenir.
İlk çalıştırma, --full ve --reset bütün geçmişi değerlendirir.

Kullanım:
    python -m src.detection.engine [--full | --reset]
"""
import argparse
import hashlib
import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union

import yaml
from psycopg2.extras import Json, execute_values

from src.detection.mitre import classify, reference_rows
from src.detection.rules import Alert, Event, PrivEvent, run_rules
from src.utils.db import apply_schema, get_connection

log = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "detection_rules.yaml"

UPSERT_SQL = """
    INSERT INTO alerts (
        alert_hash, rule, severity, source_ip, username, window_start, window_end,
        attempt_count, distinct_users, details, mitre_tactic, mitre_techniques
    ) VALUES %s
    ON CONFLICT (alert_hash) DO UPDATE SET
        severity = EXCLUDED.severity,
        window_end = EXCLUDED.window_end,
        attempt_count = EXCLUDED.attempt_count,
        distinct_users = EXCLUDED.distinct_users,
        details = EXCLUDED.details,
        mitre_tactic = EXCLUDED.mitre_tactic,
        mitre_techniques = EXCLUDED.mitre_techniques,
        last_detected_at = now()
    RETURNING (xmax = 0)
"""


TECHNIQUES_UPSERT_SQL = """
    INSERT INTO attack_techniques (technique_id, name, tactic_id, tactic, url) VALUES %s
    ON CONFLICT (technique_id) DO UPDATE SET
        name = EXCLUDED.name, tactic_id = EXCLUDED.tactic_id, tactic = EXCLUDED.tactic, url = EXCLUDED.url
"""


def load_config(path: Union[str, Path] = CONFIG_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def alert_hash(alert: Alert) -> str:
    key = f"{alert.rule}|{alert.source_ip}|{alert.username or ''}|{alert.window_start.isoformat()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# Zaman filtresi: since NULL ise bütün geçmiş.
SINCE_FILTER = "WHERE %(since)s::timestamp IS NULL OR event_time >= %(since)s"


def fetch_events(conn, since: Optional[datetime] = None) -> list[Event]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT event_time, host, event_type, username, is_invalid_user, host(source_ip), repeat_count "
            f"FROM auth_events {SINCE_FILTER} ORDER BY event_time, event_id",
            {"since": since},
        )
        return [Event(*row) for row in cur.fetchall()]


def fetch_privilege_events(conn, since: Optional[datetime] = None) -> list[PrivEvent]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT event_time, host, program, event_type, username, target_user, command, attempts "
            f"FROM privilege_events {SINCE_FILTER} ORDER BY event_time, event_id",
            {"since": since},
        )
        return [PrivEvent(*row) for row in cur.fetchall()]


def fetch_login_history(conn, before: datetime) -> dict:
    """`before`dan önceki başarılı girişler: {kullanıcı: {ip: giriş sayısı}}."""
    history: dict = defaultdict(dict)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT username, host(source_ip), COUNT(*) FROM auth_events "
            "WHERE event_type = 'login_success' AND event_time < %s GROUP BY 1, 2",
            (before,),
        )
        for user, ip, count in cur.fetchall():
            history[user][ip] = count
    return dict(history)


def current_watermarks(conn) -> tuple[int, int]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT (SELECT COALESCE(MAX(event_id), 0) FROM auth_events), "
            "       (SELECT COALESCE(MAX(event_id), 0) FROM privilege_events)"
        )
        return cur.fetchone()


def last_watermarks(conn) -> Optional[tuple[int, int]]:
    """Son başarılı tespit çalıştırmasının gördüğü olay kimlikleri; hiç çalışmadıysa None."""
    with conn.cursor() as cur:
        cur.execute("SELECT auth_watermark, privilege_watermark FROM detection_runs ORDER BY run_id DESC LIMIT 1")
        return cur.fetchone()


def first_new_event_time(conn, previous: tuple[int, int], current: tuple[int, int]) -> Optional[datetime]:
    """Son çalıştırmadan beri yüklenen olayların en erkeni; yeni olay yoksa None."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT LEAST("
            "  (SELECT MIN(event_time) FROM auth_events WHERE event_id > %s AND event_id <= %s),"
            "  (SELECT MIN(event_time) FROM privilege_events WHERE event_id > %s AND event_id <= %s))",
            (previous[0], current[0], previous[1], current[1]),
        )
        return cur.fetchone()[0]


def save_alerts(conn, alerts: list[Alert]) -> tuple[int, int]:
    """Alarmları yazar (commit etmez); (yeni, güncellenen) sayılarını döndürür."""
    with conn.cursor() as cur:
        execute_values(cur, TECHNIQUES_UPSERT_SQL, reference_rows())
    if not alerts:
        return 0, 0
    # Aynı kimlikli iki alarm tek komutta yazılamaz (ör. aynı saniyede iki giriş); sonuncusu tutulur.
    unique = {alert_hash(a): a for a in alerts}
    rows = [
        (
            digest, a.rule, a.severity, a.source_ip, a.username, a.window_start, a.window_end,
            a.attempt_count, a.distinct_users, Json(a.details), *classify(a),
        )
        for digest, a in unique.items()
    ]
    with conn.cursor() as cur:
        # xmax = 0 → satır bu komutla yeni eklendi; değilse güncellendi.
        result = execute_values(cur, UPSERT_SQL, rows, page_size=1000, fetch=True)
    inserted = sum(1 for (is_new,) in result if is_new)
    return inserted, len(result) - inserted


def run_detection(conn, config: dict, reset: bool = False, full: bool = False) -> dict:
    """Tespiti çalıştırır, alarmları ve çalıştırma kaydını tek transaction'da yazar.

    Artımlı modda yalnızca yeni olaylara dokunabilen alarmlar (window_end, ilk yeni
    olaydan sonra) yazılır; eskileri zaten önceki çalıştırmalarda yazılmıştır. Aynı
    alarm tekrar üretilirse güncellenir. `reset` eşik değişikliklerinden sonra eski
    alarmları silip bütün geçmişi yeniden değerlendirir.
    """
    started_at = datetime.now(timezone.utc)
    clock = time.perf_counter()
    current = current_watermarks(conn)
    previous = None if reset or full else last_watermarks(conn)
    mode = "incremental" if previous else "full"

    eval_start = first_new = history = None
    if mode == "incremental":
        first_new = first_new_event_time(conn, previous, current)
    if mode == "incremental" and first_new is None:
        events, privilege_events, alerts = [], [], []
    else:
        if first_new is not None:
            eval_start = first_new - timedelta(hours=config["incremental"]["lookback_hours"])
            history = fetch_login_history(conn, eval_start)
        events = fetch_events(conn, eval_start)
        privilege_events = fetch_privilege_events(conn, eval_start)
        alerts = run_rules(events, config, privilege_events, history)
        if first_new is not None:
            alerts = [a for a in alerts if a.window_end >= first_new]

    if reset:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts")
    inserted, updated = save_alerts(conn, alerts)
    duration_ms = round((time.perf_counter() - clock) * 1000)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO detection_runs (mode, started_at, duration_ms, eval_start, auth_watermark, "
            "  privilege_watermark, events_evaluated, privilege_events_evaluated, alerts_written, new_alerts) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (mode, started_at, duration_ms, eval_start, current[0], current[1],
             len(events), len(privilege_events), inserted + updated, inserted),
        )
    conn.commit()

    summary = {
        "mode": mode,
        "eval_start": eval_start.isoformat() if eval_start else None,
        "duration_ms": duration_ms,
        "events": len(events),
        "privilege_events": len(privilege_events),
        "alerts": len(alerts),
        "new_alerts": inserted,
        "updated_alerts": updated,
        "by_rule": dict(Counter(a.rule for a in alerts)),
        "by_severity": dict(Counter(a.severity for a in alerts)),
        "by_tactic": dict(Counter(classify(a)[0] or "-" for a in alerts)),
    }
    log.info("tespit bitti: %s", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Tespit kurallarını çalıştırıp alarmları yazar.")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Bütün geçmişi yeniden değerlendir (artımlı değil)")
    mode.add_argument("--reset", action="store_true",
                      help="Önce bütün eski alarmları sil, sonra bütün geçmişi değerlendir (eşik değişikliğinden sonra)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    conn = get_connection()
    try:
        apply_schema(conn)
        summary = run_detection(conn, load_config(), reset=args.reset, full=args.full)
    finally:
        conn.close()

    if summary["eval_start"]:
        window = f"{summary['eval_start']} sonrası"
    else:
        window = "bütün geçmiş" if summary["mode"] == "full" else "yeni olay yok"
    print(f"Mod                 : {summary['mode']} ({window}), {summary['duration_ms']} ms")
    print(f"Değerlendirilen olay: {summary['events']} giriş, {summary['privilege_events']} yetki")
    print(f"Alarm               : {summary['alerts']} ({summary['new_alerts']} yeni, {summary['updated_alerts']} güncellendi)")
    for rule, count in sorted(summary["by_rule"].items()):
        print(f"  {rule:<18}: {count}")
    print("Önem derecesi       : " + ", ".join(f"{k}={v}" for k, v in sorted(summary["by_severity"].items())))
    print("ATT&CK taktiği      : " + ", ".join(f"{k}={v}" for k, v in sorted(summary["by_tactic"].items())))


if __name__ == "__main__":
    main()
