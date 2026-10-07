"""Data lake tablolarının şemaları: hem Parquet yazarken hem Glue kataloğunda kullanılır."""
import pyarrow as pa

from src.cloud.config import CURATED_PREFIX, PROCESSED_PREFIX, CloudConfig

# (sütun adı, Athena tipi, pyarrow tipi)
AUTH_EVENTS_COLUMNS = [
    ("event_id", "bigint", pa.int64()),
    ("event_hash", "string", pa.string()),
    ("event_time", "timestamp", pa.timestamp("ms")),
    ("host", "string", pa.string()),
    ("pid", "int", pa.int32()),
    ("event_type", "string", pa.string()),
    ("auth_method", "string", pa.string()),
    ("username", "string", pa.string()),
    ("is_invalid_user", "boolean", pa.bool_()),
    ("source_ip", "string", pa.string()),
    ("source_port", "int", pa.int32()),
    ("repeat_count", "int", pa.int32()),
    ("source_file", "string", pa.string()),
    ("line_no", "int", pa.int32()),
]

ALERTS_COLUMNS = [
    ("alert_hash", "string", pa.string()),
    ("rule", "string", pa.string()),
    ("severity", "string", pa.string()),
    ("source_ip", "string", pa.string()),
    ("username", "string", pa.string()),
    ("window_start", "timestamp", pa.timestamp("ms")),
    ("window_end", "timestamp", pa.timestamp("ms")),
    ("attempt_count", "int", pa.int32()),
    ("distinct_users", "int", pa.int32()),
    ("details", "string", pa.string()),  # JSON metni
]

DAILY_IP_SUMMARY_COLUMNS = [
    ("event_date", "date", pa.date32()),
    ("source_ip", "string", pa.string()),
    ("failed_attempts", "bigint", pa.int64()),
    ("successful_logins", "bigint", pa.int64()),
    ("distinct_users", "bigint", pa.int64()),
    ("invalid_user_attempts", "bigint", pa.int64()),
]


def arrow_schema(columns) -> pa.Schema:
    return pa.schema([(name, arrow_type) for name, _, arrow_type in columns])


def _table_input(name: str, columns, location: str, description: str) -> dict:
    return {
        "Name": name,
        "Description": description,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "parquet", "EXTERNAL": "TRUE"},
        "StorageDescriptor": {
            "Columns": [{"Name": col, "Type": athena_type} for col, athena_type, _ in columns],
            "Location": location,
            "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
            "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"},
        },
    }


def glue_tables(cfg: CloudConfig) -> list[dict]:
    """Glue kataloğuna yazılacak tablo tanımları."""
    base = f"s3://{cfg.bucket}"
    auth_events = _table_input(
        "auth_events", AUTH_EVENTS_COLUMNS, f"{base}/{PROCESSED_PREFIX}/",
        "Processed katmanı: doğrulanmış kimlik doğrulama olayları (güne göre bölümlenmiş)",
    )
    auth_events["PartitionKeys"] = [{"Name": "event_date", "Type": "string"}]
    # Partition projection: bölümler S3 yolundan hesaplanır; crawler ya da
    # MSCK REPAIR gerekmez ve yeni günler kendiliğinden görünür.
    auth_events["Parameters"].update({
        "projection.enabled": "true",
        "projection.event_date.type": "date",
        "projection.event_date.format": "yyyy-MM-dd",
        "projection.event_date.range": "2020-01-01,NOW+1DAYS",
        "storage.location.template": f"{base}/{PROCESSED_PREFIX}/event_date=${{event_date}}/",
    })
    return [
        auth_events,
        _table_input(
            "alerts", ALERTS_COLUMNS, f"{base}/{CURATED_PREFIX}/alerts/",
            "Curated katmanı: tespit kurallarının ürettiği alarmlar",
        ),
        _table_input(
            "daily_ip_summary", DAILY_IP_SUMMARY_COLUMNS, f"{base}/{CURATED_PREFIX}/daily_ip_summary/",
            "Curated katmanı: gün ve kaynak IP bazında özet",
        ),
    ]
