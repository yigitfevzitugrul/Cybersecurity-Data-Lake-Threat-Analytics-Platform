"""Yerel PostgreSQL ile data lake'in (Athena) aynı veriyi gösterdiğini doğrular.

Her tablo için satır sayısı ve bir kontrol toplamı iki tarafta karşılaştırılır.
Uçtan uca akışın son adımıdır: sync'ten sonra fark çıkarsa veri yolda
kaybolmuş ya da bozulmuş demektir.

Kullanım:
    python -m src.cloud.reconcile
"""
import sys

from src.cloud.athena import run_query
from src.cloud.config import CloudConfig, load_config, pipeline_session
from src.utils.db import get_connection

# (ad, sayılan şey, PostgreSQL sorgusu, Athena sorgusu). İki sorgu da (satır sayısı, toplam) döndürür.
CHECKS = [
    (
        "auth_events", "deneme",
        "SELECT COUNT(*), COALESCE(SUM(repeat_count), 0) FROM auth_events",
        "SELECT COUNT(*), COALESCE(SUM(repeat_count), 0) FROM auth_events",
    ),
    (
        "alerts", "başarısız deneme",
        "SELECT COUNT(*), COALESCE(SUM(attempt_count), 0) FROM alerts",
        "SELECT COUNT(*), COALESCE(SUM(attempt_count), 0) FROM alerts",
    ),
    (
        "daily_ip_summary", "başarısız deneme",
        "SELECT COUNT(*), COALESCE(SUM(failed), 0) FROM ("
        "  SELECT COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_failed'), 0) AS failed"
        "  FROM auth_events GROUP BY event_time::date, source_ip) t",
        "SELECT COUNT(*), COALESCE(SUM(failed_attempts), 0) FROM daily_ip_summary",
    ),
]


def compare(name: str, measure: str, local: tuple[int, int], cloud: tuple[int, int]) -> dict:
    return {
        "table": name,
        "measure": measure,
        "local_rows": local[0], "cloud_rows": cloud[0],
        "local_sum": local[1], "cloud_sum": cloud[1],
        "match": local == cloud,
    }


def reconcile(conn, athena, cfg: CloudConfig) -> list[dict]:
    results = []
    for name, measure, local_sql, cloud_sql in CHECKS:
        with conn.cursor() as cur:
            cur.execute(local_sql)
            local = tuple(int(value) for value in cur.fetchone())
        conn.commit()
        cloud = tuple(int(value) for value in run_query(athena, cfg, cloud_sql)["rows"][0])
        results.append(compare(name, measure, local, cloud))
    return results


def format_results(results: list[dict]) -> str:
    lines = []
    for r in results:
        status = "ok  " if r["match"] else "FARK"
        lines.append(
            f"  {status} {r['table']:<17} satır {r['local_rows']} / {r['cloud_rows']}, "
            f"{r['measure']} {r['local_sum']} / {r['cloud_sum']}  (yerel / bulut)"
        )
    return "\n".join(lines)


def main() -> None:
    cfg = load_config()
    conn = get_connection()
    try:
        results = reconcile(conn, pipeline_session(cfg).client("athena"), cfg)
    finally:
        conn.close()
    print(format_results(results))
    mismatches = [r["table"] for r in results if not r["match"]]
    print("\nYerel veritabanı ve data lake tutarlı." if not mismatches
          else f"\nTutarsız tablolar: {', '.join(mismatches)}")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
