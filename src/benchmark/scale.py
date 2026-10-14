"""Ölçeklenebilirlik testi: veri büyüdükçe ETL ve tespit ne kadar sürüyor?

Sentetik üreteçle çok günlük, yoğun internet gürültülü bir veri seti üretir ve günleri
sırayla yükler (Airflow'un her gün yaptığı gibi). Her günden sonra tespit iki ayrı
şemada çalıştırılır: birinde artımlı, diğerinde bütün geçmiş baştan. Sonunda iki
şemadaki alarmların aynı olduğu doğrulanır ve olaylar Parquet'e çevrilip boyutu
ham logla karşılaştırılır.

Geliştirme verisine dokunmaz: her şey geçici şemalarda çalışır ve sonunda silinir.

Kullanım:
    python -m src.benchmark.scale [--days 60] [--noise 1500] [--seed 7]
"""
import argparse
import json
import tempfile
import time
import uuid
from datetime import date
from itertools import groupby
from pathlib import Path

from src.cloud.catalog import AUTH_EVENTS_COLUMNS
from src.cloud.sync import AUTH_EVENTS_SQL, rows_to_parquet
from src.detection.engine import load_config, run_detection
from src.etl.pipeline import DATA_DIR, run_pipeline
from src.generator.generate import generate
from src.utils.db import apply_schema, get_connection

REPORT_PATH = DATA_DIR / "curated" / "benchmark.json"
ALERTS_SQL = (
    "SELECT alert_hash, severity, window_end, attempt_count, distinct_users, details, mitre_techniques "
    "FROM alerts ORDER BY alert_hash"
)


def open_schema(name: str):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(f"CREATE SCHEMA {name}")
        cur.execute(f"SET search_path TO {name}")
    conn.commit()
    apply_schema(conn)
    return conn


def drop_schema(conn, name: str) -> None:
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute(f"DROP SCHEMA {name} CASCADE")
    conn.commit()
    conn.close()


def split_days(lines: list[str]) -> list[list[str]]:
    """Syslog satırlarını güne göre böler (satır başındaki 'Mar  1' kısmı)."""
    return [list(group) for _, group in groupby(lines, key=lambda line: line[:6])]


def count(conn, sql: str) -> int:
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchone()[0]


def parquet_size(conn) -> tuple[int, int, float]:
    """auth_events'i gün başına bir Parquet dosyasına çevirir: (dosya, bayt, saniye)."""
    clock = time.perf_counter()
    with conn.cursor() as cur:
        cur.execute(AUTH_EVENTS_SQL)
        rows = cur.fetchall()
    files = total = 0
    for _, group in groupby(rows, key=lambda row: row[2].date()):
        files += 1
        total += len(rows_to_parquet(list(group), AUTH_EVENTS_COLUMNS))
    return files, total, time.perf_counter() - clock


def run(days: int, noise: int, seed: int, start: date = date(2026, 1, 1)) -> dict:
    config = load_config()
    clock = time.perf_counter()
    lines, labels = generate(start, days, seed, noise_ips_per_day=noise, hard_cases=True, privilege=True)
    generate_s = time.perf_counter() - clock
    day_lines = split_days(lines)

    suffix = uuid.uuid4().hex[:8]
    names = {"inc": f"bench_inc_{suffix}", "full": f"bench_full_{suffix}"}
    conns = {key: open_schema(name) for key, name in names.items()}
    rows = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw_bytes = 0
            for i, chunk in enumerate(day_lines):
                path = tmp / f"day_{i:03d}.log"
                path.write_text("\n".join(chunk) + "\n", encoding="utf-8", newline="\n")
                raw_bytes += path.stat().st_size

                clock = time.perf_counter()
                stats = run_pipeline(path, start.year, conns["inc"], tmp / "processed")
                etl_s = time.perf_counter() - clock
                run_pipeline(path, start.year, conns["full"], tmp / "processed_full")

                inc = run_detection(conns["inc"], config)
                full = run_detection(conns["full"], config, full=True)
                rows.append({
                    "day": i + 1,
                    "lines": len(chunk),
                    "total_events": count(conns["inc"], "SELECT COUNT(*) FROM auth_events")
                                    + count(conns["inc"], "SELECT COUNT(*) FROM privilege_events"),
                    "etl_ms": round(etl_s * 1000),
                    "etl_lines_per_s": round(len(chunk) / etl_s),
                    "events_loaded": stats.get("events_loaded"),
                    "incremental_ms": inc["duration_ms"],
                    "incremental_events": inc["events"] + inc["privilege_events"],
                    "full_ms": full["duration_ms"],
                    "full_events": full["events"] + full["privilege_events"],
                })
                print(f"gün {i + 1:>3}: {rows[-1]['total_events']:>8} olay | ETL {rows[-1]['etl_ms']:>5} ms | "
                      f"tespit artımlı {inc['duration_ms']:>5} ms ({rows[-1]['incremental_events']} olay), "
                      f"tam {full['duration_ms']:>5} ms ({rows[-1]['full_events']} olay)", flush=True)

        with conns["inc"].cursor() as cur:
            cur.execute(ALERTS_SQL)
            inc_alerts = cur.fetchall()
        with conns["full"].cursor() as cur:
            cur.execute(ALERTS_SQL)
            full_alerts = cur.fetchall()
        files, parquet_bytes, parquet_s = parquet_size(conns["inc"])
    finally:
        for key, name in names.items():
            drop_schema(conns[key], name)

    last = rows[-1]
    return {
        "parameters": {"days": days, "noise_ips_per_day": noise, "seed": seed, "start_date": start.isoformat(),
                       "lookback_hours": config["incremental"]["lookback_hours"]},
        "generate_s": round(generate_s, 2),
        "lines": len(lines),
        "attacks": len(labels["attacks"]),
        "total_events": last["total_events"],
        "alerts": len(inc_alerts),
        "incremental_equals_full": inc_alerts == full_alerts,
        "etl_lines_per_s_median": sorted(r["etl_lines_per_s"] for r in rows)[len(rows) // 2],
        "detection_last_day_ms": {"incremental": last["incremental_ms"], "full": last["full_ms"]},
        "detection_total_ms": {"incremental": sum(r["incremental_ms"] for r in rows),
                               "full": sum(r["full_ms"] for r in rows)},
        "storage": {"raw_log_bytes": raw_bytes, "parquet_bytes": parquet_bytes, "parquet_files": files,
                    "compression_ratio": round(raw_bytes / parquet_bytes, 1), "parquet_write_s": round(parquet_s, 2)},
        "per_day": rows,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="ETL ve tespit için ölçeklenebilirlik testi (geçici şemalarda).")
    ap.add_argument("--days", type=int, default=60)
    ap.add_argument("--noise", type=int, default=1500, help="Günlük internet gürültüsü IP sayısı (varsayılan üreteçte 30)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=REPORT_PATH)
    args = ap.parse_args()

    report = run(args.days, args.noise, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    storage, last, total = report["storage"], report["detection_last_day_ms"], report["detection_total_ms"]
    print()
    print(f"Veri          : {report['lines']} satır, {report['total_events']} olay, {report['alerts']} alarm")
    print(f"ETL           : medyan {report['etl_lines_per_s_median']} satır/sn")
    print(f"Tespit (son gün): artımlı {last['incremental']} ms, tam {last['full']} ms "
          f"(~{last['full'] / max(last['incremental'], 1):.0f} kat)")
    print(f"Tespit (toplam) : artımlı {total['incremental']} ms, tam {total['full']} ms")
    print(f"Artımlı = tam : {report['incremental_equals_full']}")
    print(f"Depolama      : ham log {storage['raw_log_bytes'] / 1e6:.1f} MB → Parquet {storage['parquet_bytes'] / 1e6:.1f} MB "
          f"({storage['compression_ratio']}x, {storage['parquet_files']} dosya)")
    print(f"Rapor         : {args.out}")


if __name__ == "__main__":
    main()
