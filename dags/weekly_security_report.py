"""Haftalık güvenlik raporu DAG'i.

    build_report → send_report

Her pazartesi 06:00 (UTC) biten haftanın (önceki pazartesi 00:00 – bu pazartesi 00:00)
raporunu data/curated/reports/ altına HTML ve JSON olarak yazar. send_report, Telegram
ayarlıysa (docker-compose.alerting.yml ile TELEGRAM_BOT_TOKEN ve TELEGRAM_CHAT_ID) raporu
kısa bir özetle birlikte gönderir; ayarlı değilse atlanır. İş mantığı src/reporting/weekly.py'de.
"""
import os
from datetime import datetime, timedelta

from airflow.decorators import dag, task
from airflow.exceptions import AirflowSkipException


@dag(
    dag_id="weekly_security_report",
    description="Biten haftanın güvenlik raporunu üretir ve Telegram'a gönderir",
    schedule="0 6 * * 1",
    start_date=datetime(2026, 10, 1),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 2, "retry_delay": timedelta(minutes=2)},
    tags=["security", "report"],
)
def weekly_security_report():
    @task
    def build_report(data_interval_end=None) -> dict:
        from src.reporting.weekly import last_monday, write_report
        from src.utils.db import apply_schema, get_connection

        # Pazartesi çalışan zamanlanmış koşuda bu, o pazartesidir; elle tetiklenirse son pazartesi.
        week_ending = last_monday(data_interval_end.date())
        conn = get_connection()
        try:
            apply_schema(conn)
            path, report = write_report(conn, week_ending)
        finally:
            conn.close()
        print(f"{path.name}: {report['kpis']}")
        return {"path": str(path), "week_ending": week_ending.isoformat()}

    @task
    def send_report(built: dict) -> None:
        import json
        from pathlib import Path

        from src.reporting.weekly import send_to_telegram

        if not (os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")):
            raise AirflowSkipException("Telegram ayarlı değil (docker-compose.alerting.yml).")
        path = Path(built["path"])
        report = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        send_to_telegram(path, report)
        print(f"{path.name} Telegram'a gönderildi.")

    send_report(build_report())


weekly_security_report()
