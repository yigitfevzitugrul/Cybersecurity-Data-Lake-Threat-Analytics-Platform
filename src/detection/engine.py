"""Tespit motoru: auth_events'i okur, kuralları çalıştırır, alerts tablosuna yazar.

Kullanım:
    python -m src.detection.engine [--reset]
"""
import argparse
import hashlib
import logging
from collections import Counter
from pathlib import Path
from typing import Union

import yaml
from psycopg2.extras import Json, execute_values

from src.detection.rules import Alert, Event, run_rules
from src.utils.db import apply_schema, get_connection

log = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "detection_rules.yaml"

UPSERT_SQL = """
    INSERT INTO alerts (
        alert_hash, rule, severity, source_ip, username, window_start, window_end,
        attempt_count, distinct_users, details
    ) VALUES %s
    ON CONFLICT (alert_hash) DO UPDATE SET
        severity = EXCLUDED.severity,
        window_end = EXCLUDED.window_end,
        attempt_count = EXCLUDED.attempt_count,
        distinct_users = EXCLUDED.distinct_users,
        details = EXCLUDED.details,
        last_detected_at = now()
    RETURNING (xmax = 0)
"""


def load_config(path: Union[str, Path] = CONFIG_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def alert_hash(alert: Alert) -> str:
    key = f"{alert.rule}|{alert.source_ip}|{alert.username or ''}|{alert.window_start.isoformat()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def fetch_events(conn) -> list[Event]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT event_time, host, event_type, username, is_invalid_user, host(source_ip), repeat_count "
            "FROM auth_events ORDER BY event_time, event_id"
        )
        return [Event(*row) for row in cur.fetchall()]


def save_alerts(conn, alerts: list[Alert]) -> tuple[int, int]:
    """Alarmları yazar; (yeni, güncellenen) sayılarını döndürür."""
    if not alerts:
        conn.commit()
        return 0, 0
    # Aynı kimlikli iki alarm tek komutta yazılamaz (ör. aynı saniyede iki giriş); sonuncusu tutulur.
    unique = {alert_hash(a): a for a in alerts}
    rows = [
        (
            digest, a.rule, a.severity, a.source_ip, a.username, a.window_start, a.window_end,
            a.attempt_count, a.distinct_users, Json(a.details),
        )
        for digest, a in unique.items()
    ]
    with conn.cursor() as cur:
        # xmax = 0 → satır bu komutla yeni eklendi; değilse güncellendi.
        result = execute_values(cur, UPSERT_SQL, rows, page_size=1000, fetch=True)
    conn.commit()
    inserted = sum(1 for (is_new,) in result if is_new)
    return inserted, len(result) - inserted


def run_detection(conn, config: dict, reset: bool = False) -> dict:
    """Bütün olaylar üzerinde tespiti çalıştırır ve özet döndürür.

    Her çalıştırma bütün geçmişi yeniden değerlendirir; aynı alarm tekrar
    üretilirse güncellenir. `reset` eşik değişikliklerinden sonra eski alarmları siler.
    """
    events = fetch_events(conn)
    alerts = run_rules(events, config)
    if reset:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts")
    inserted, updated = save_alerts(conn, alerts)
    summary = {
        "events": len(events),
        "alerts": len(alerts),
        "new_alerts": inserted,
        "updated_alerts": updated,
        "by_rule": dict(Counter(a.rule for a in alerts)),
        "by_severity": dict(Counter(a.severity for a in alerts)),
    }
    log.info("tespit bitti: %s", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Tespit kurallarını çalıştırıp alarmları yazar.")
    ap.add_argument("--reset", action="store_true", help="Önce bütün eski alarmları sil (eşik değişikliğinden sonra)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    conn = get_connection()
    try:
        apply_schema(conn)
        summary = run_detection(conn, load_config(), reset=args.reset)
    finally:
        conn.close()

    print(f"Değerlendirilen olay: {summary['events']}")
    print(f"Alarm               : {summary['alerts']} ({summary['new_alerts']} yeni, {summary['updated_alerts']} güncellendi)")
    for rule, count in sorted(summary["by_rule"].items()):
        print(f"  {rule:<18}: {count}")
    print("Önem derecesi       : " + ", ".join(f"{k}={v}" for k, v in sorted(summary["by_severity"].items())))


if __name__ == "__main__":
    main()
