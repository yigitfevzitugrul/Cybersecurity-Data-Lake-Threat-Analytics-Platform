"""Yerel veriyi S3 data lake katmanlarına taşır.

    raw/auth_logs/<dosya>.log                              ham log dosyaları
    processed/auth_events/event_date=YYYY-MM-DD/*.parquet  doğrulanmış olaylar (PostgreSQL'den)
    curated/alerts/, curated/daily_ip_summary/             alarmlar ve günlük özet

En az yetkili pipeline rolüyle çalışır. Tekrar çalıştırmak güvenlidir: içeriği
değişmemiş nesneler yeniden yüklenmez.

Kullanım:
    python -m src.cloud.sync
"""
import hashlib
import io
from itertools import groupby
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

from src.cloud.catalog import ALERTS_COLUMNS, AUTH_EVENTS_COLUMNS, DAILY_IP_SUMMARY_COLUMNS, arrow_schema
from src.cloud.config import CURATED_PREFIX, PROCESSED_PREFIX, RAW_PREFIX, CloudConfig, load_config, pipeline_session
from src.etl.pipeline import RAW_DIR
from src.utils.db import get_connection

AUTH_EVENTS_SQL = """
    SELECT event_id, event_hash, event_time, host, pid, event_type, auth_method, username,
           is_invalid_user, host(source_ip), source_port, repeat_count, source_file, line_no
    FROM auth_events
    ORDER BY event_time, event_id
"""

ALERTS_SQL = """
    SELECT alert_hash, rule, severity, host(source_ip), username, window_start, window_end,
           attempt_count, distinct_users, details::text
    FROM alerts
    ORDER BY window_start, alert_hash
"""

DAILY_IP_SUMMARY_SQL = """
    SELECT event_time::date,
           host(source_ip),
           COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_failed'), 0),
           COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_success'), 0),
           COUNT(DISTINCT username),
           COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_failed' AND is_invalid_user), 0)
    FROM auth_events
    GROUP BY 1, 2
    ORDER BY 1, 2
"""


def rows_to_parquet(rows: list[tuple], columns) -> bytes:
    """Satırları, verilen şemayla Parquet baytlarına çevirir."""
    schema = arrow_schema(columns)
    arrays = [pa.array([row[i] for row in rows], type=field.type) for i, field in enumerate(schema)]
    buffer = io.BytesIO()
    pq.write_table(pa.Table.from_arrays(arrays, schema=schema), buffer, compression="snappy")
    return buffer.getvalue()


def partition_key(day) -> str:
    return f"{PROCESSED_PREFIX}/event_date={day.isoformat()}/part-0000.parquet"


def put_if_changed(s3, bucket: str, key: str, body: bytes) -> bool:
    """Nesneyi yükler; aynı içerik zaten oradaysa dokunmaz. Yüklendiyse True döndürür."""
    digest = hashlib.sha256(body).hexdigest()
    try:
        if s3.head_object(Bucket=bucket, Key=key)["Metadata"].get("sha256") == digest:
            return False
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchKey", "NotFound"):
            raise
    s3.put_object(Bucket=bucket, Key=key, Body=body, Metadata={"sha256": digest})
    return True


def _query(conn, sql: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    conn.commit()
    return rows


def sync_raw(s3, cfg: CloudConfig, raw_dir: Path = RAW_DIR) -> dict:
    uploaded = 0
    files = sorted(Path(raw_dir).glob("*.log"))
    for path in files:
        uploaded += put_if_changed(s3, cfg.bucket, f"{RAW_PREFIX}/{path.name}", path.read_bytes())
    return {"objects": len(files), "uploaded": uploaded}


def sync_processed(s3, cfg: CloudConfig, conn) -> dict:
    """auth_events'i güne göre bölümlenmiş Parquet olarak yazar (gün başına bir dosya)."""
    rows = _query(conn, AUTH_EVENTS_SQL)
    partitions = uploaded = 0
    for day, group in groupby(rows, key=lambda row: row[2].date()):
        partitions += 1
        uploaded += put_if_changed(s3, cfg.bucket, partition_key(day), rows_to_parquet(list(group), AUTH_EVENTS_COLUMNS))
    return {"rows": len(rows), "objects": partitions, "uploaded": uploaded}


def sync_curated(s3, cfg: CloudConfig, conn) -> dict:
    alerts = _query(conn, ALERTS_SQL)
    summary = _query(conn, DAILY_IP_SUMMARY_SQL)
    uploaded = put_if_changed(
        s3, cfg.bucket, f"{CURATED_PREFIX}/alerts/alerts.parquet", rows_to_parquet(alerts, ALERTS_COLUMNS)
    )
    uploaded += put_if_changed(
        s3, cfg.bucket, f"{CURATED_PREFIX}/daily_ip_summary/daily_ip_summary.parquet",
        rows_to_parquet(summary, DAILY_IP_SUMMARY_COLUMNS),
    )
    return {"alerts": len(alerts), "summary_rows": len(summary), "objects": 2, "uploaded": uploaded}


def sync_all(cfg: CloudConfig, conn, session=None) -> dict:
    s3 = (session or pipeline_session(cfg)).client("s3")
    return {
        "raw": sync_raw(s3, cfg),
        "processed": sync_processed(s3, cfg, conn),
        "curated": sync_curated(s3, cfg, conn),
    }


def main() -> None:
    cfg = load_config()
    conn = get_connection()
    try:
        result = sync_all(cfg, conn)
    finally:
        conn.close()

    print(f"Hedef: s3://{cfg.bucket}")
    raw, processed, curated = result["raw"], result["processed"], result["curated"]
    print(f"  raw       : {raw['objects']} dosya, {raw['uploaded']} yüklendi")
    print(f"  processed : {processed['rows']} olay, {processed['objects']} günlük bölüm, {processed['uploaded']} yüklendi")
    print(f"  curated   : {curated['alerts']} alarm, {curated['summary_rows']} özet satırı, {curated['uploaded']} yüklendi")


if __name__ == "__main__":
    main()
