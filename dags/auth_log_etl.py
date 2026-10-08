"""Günlük auth log ETL'i ve tehdit tespiti.

    generate_daily_log → run_etl ─┬→ quality_gate
                                  └→ detect_threats → sync_to_cloud → reconcile_cloud

generate_daily_log gerçek bir log kaynağını taklit eder: çalıştırmanın mantıksal
günü için sentetik bir log dosyası üretir. run_etl, data/raw altındaki henüz
işlenmemiş tüm *.log dosyalarını pipeline'dan geçirir. detect_threats tespit
kurallarını çalıştırıp alarmları yazar. sync_to_cloud katmanları S3'e gönderir,
reconcile_cloud yerel veritabanı ile Athena'nın aynı sayıları verdiğini doğrular.
Bulut adımları sadece CLOUD_SYNC_ENABLED=true iken çalışır (docker-compose.cloud.yml);
aksi halde atlanır. İş mantığı src/ altında; bu dosya sadece zamanlama ve
sıralamayı tanımlar.
"""
import os
from datetime import date, datetime, timedelta

from airflow.decorators import dag, task
from airflow.exceptions import AirflowFailException, AirflowSkipException

# Bir dosyada reddedilen satır oranı bunu aşarsa DAG başarısız olur.
MAX_REJECT_RATIO = 0.10
SYNTHETIC_BAD_RATIO = 0.02


@dag(
    dag_id="auth_log_etl",
    description="Auth loglarını üretir, ETL'den geçirir, veri kalitesini denetler ve tehditleri tespit eder",
    schedule="@daily",
    start_date=datetime(2026, 10, 1),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 1, "retry_delay": timedelta(minutes=1)},
    tags=["etl", "security", "cloud"],
)
def auth_log_etl():
    @task
    def generate_daily_log(ds=None) -> str:
        from src.etl.pipeline import RAW_DIR
        from src.generator.generate import generate, write_files

        day = date.fromisoformat(ds)
        out = RAW_DIR / f"synthetic_auth_{ds}.log"
        # Seed güne bağlıdır: aynı gün tekrar üretilirse aynı dosya çıkar ve yeniden işlenmez.
        lines, labels = generate(
            day, days=1, seed=day.toordinal(), bad_ratio=SYNTHETIC_BAD_RATIO, hard_cases=True
        )
        write_files(out, lines, labels)
        print(f"{out.name}: {len(lines)} satır, {len(labels['attacks'])} saldırı")
        return out.name

    @task
    def run_etl() -> list[dict]:
        from src.etl.pipeline import process_new_files
        from src.utils.db import apply_schema, get_connection

        conn = get_connection()
        try:
            apply_schema(conn)
            results = process_new_files(conn)
        finally:
            conn.close()
        for stats in results:
            print(stats)
        if not results:
            print("İşlenecek yeni dosya yok.")
        return results

    @task
    def quality_gate(results: list[dict]) -> None:
        problems = []
        for stats in results:
            ratio = stats["lines_rejected"] / max(stats["lines_read"], 1)
            print(f"{stats['source_file']}: red oranı %{100 * ratio:.2f} {stats['reject_reasons']}")
            if ratio > MAX_REJECT_RATIO:
                problems.append(f"{stats['source_file']} red oranı %{100 * ratio:.1f}")
        if problems:
            # Veri sorunu tekrar denemekle düzelmez; retry yapılmaz.
            raise AirflowFailException("Veri kalitesi eşiği aşıldı: " + "; ".join(problems))

    @task
    def detect_threats() -> dict:
        from src.detection.engine import load_config, run_detection
        from src.utils.db import get_connection

        conn = get_connection()
        try:
            summary = run_detection(conn, load_config())
        finally:
            conn.close()
        print(summary)
        return summary

    def require_cloud() -> None:
        if os.environ.get("CLOUD_SYNC_ENABLED", "").lower() != "true":
            raise AirflowSkipException("Bulut senkronu kapalı (CLOUD_SYNC_ENABLED != true).")

    @task
    def sync_to_cloud() -> dict:
        require_cloud()
        from src.cloud.config import load_config
        from src.cloud.sync import sync_all
        from src.utils.db import get_connection

        conn = get_connection()
        try:
            result = sync_all(load_config(), conn)
        finally:
            conn.close()
        print(result)
        return result

    @task
    def reconcile_cloud() -> list[dict]:
        require_cloud()
        from src.cloud.config import load_config, pipeline_session
        from src.cloud.reconcile import format_results, reconcile
        from src.utils.db import get_connection

        cfg = load_config()
        conn = get_connection()
        try:
            results = reconcile(conn, pipeline_session(cfg).client("athena"), cfg)
        finally:
            conn.close()
        print(format_results(results))
        mismatches = [r["table"] for r in results if not r["match"]]
        if mismatches:
            raise AirflowFailException("Yerel veritabanı ve data lake tutarsız: " + ", ".join(mismatches))
        return results

    results = run_etl()
    generate_daily_log() >> results
    quality_gate(results)
    results >> detect_threats() >> sync_to_cloud() >> reconcile_cloud()


auth_log_etl()
