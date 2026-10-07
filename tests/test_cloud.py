"""Bulut modüllerinin AWS'ye bağlanmadan çalışan testleri."""
import io
import json
from datetime import date, datetime

import pyarrow.parquet as pq
from botocore.exceptions import ClientError

from src.cloud.athena import format_table, split_statements
from src.cloud.catalog import ALERTS_COLUMNS, AUTH_EVENTS_COLUMNS, DAILY_IP_SUMMARY_COLUMNS, glue_tables
from src.cloud.config import CloudConfig
from src.cloud.setup import render_pipeline_policy
from src.cloud.sync import partition_key, put_if_changed, rows_to_parquet

CFG = CloudConfig(
    region="eu-central-1",
    bucket="test-bucket",
    glue_database="test_db",
    athena_workgroup="test_wg",
    pipeline_role_name="test-role",
    pipeline_role_arn=None,
)


class FakeS3:
    """put_if_changed'in kullandığı kadarıyla S3."""

    def __init__(self):
        self.objects = {}
        self.puts = 0

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {"Metadata": self.objects[(Bucket, Key)]["Metadata"]}

    def put_object(self, Bucket, Key, Body, Metadata):
        self.puts += 1
        self.objects[(Bucket, Key)] = {"Body": Body, "Metadata": Metadata}


def test_auth_events_parquet_roundtrip():
    rows = [
        (1, "a" * 64, datetime(2026, 9, 1, 10, 0, 0), "srv", 123, "login_failed", "password",
         "root", False, "192.0.2.10", 4000, 1, "auth.log", 7),
        (2, "b" * 64, datetime(2026, 9, 1, 10, 0, 5), "srv", None, "login_success", "publickey",
         "alice", False, "2001:db8::1", 4001, 5, "auth.log", 9),
    ]
    table = pq.read_table(io.BytesIO(rows_to_parquet(rows, AUTH_EVENTS_COLUMNS)))

    assert table.column_names == [name for name, _, _ in AUTH_EVENTS_COLUMNS]
    assert table.num_rows == 2
    assert table.column("event_time").to_pylist() == [rows[0][2], rows[1][2]]
    assert table.column("pid").to_pylist() == [123, None]
    assert str(table.schema.field("event_time").type) == "timestamp[ms]"


def test_curated_parquet_schemas():
    alerts = [("h" * 64, "brute_force", "high", "192.0.2.10", None, datetime(2026, 9, 1), datetime(2026, 9, 1, 0, 5),
               40, 1, json.dumps({"hosts": ["srv"]}))]
    summary = [(date(2026, 9, 1), "192.0.2.10", 40, 0, 1, 0)]

    alerts_table = pq.read_table(io.BytesIO(rows_to_parquet(alerts, ALERTS_COLUMNS)))
    summary_table = pq.read_table(io.BytesIO(rows_to_parquet(summary, DAILY_IP_SUMMARY_COLUMNS)))

    assert alerts_table.column("username").to_pylist() == [None]
    assert json.loads(alerts_table.column("details")[0].as_py()) == {"hosts": ["srv"]}
    assert summary_table.column("event_date").to_pylist() == [date(2026, 9, 1)]


def test_empty_table_is_still_valid_parquet():
    table = pq.read_table(io.BytesIO(rows_to_parquet([], ALERTS_COLUMNS)))
    assert table.num_rows == 0
    assert table.column_names == [name for name, _, _ in ALERTS_COLUMNS]


def test_parquet_output_is_deterministic():
    rows = [(date(2026, 9, 1), "192.0.2.10", 40, 0, 1, 0)]
    assert rows_to_parquet(rows, DAILY_IP_SUMMARY_COLUMNS) == rows_to_parquet(rows, DAILY_IP_SUMMARY_COLUMNS)


def test_partition_key():
    assert partition_key(date(2026, 9, 1)) == "processed/auth_events/event_date=2026-09-01/part-0000.parquet"


def test_put_if_changed_uploads_only_new_content():
    s3 = FakeS3()
    assert put_if_changed(s3, "b", "k", b"one") is True
    assert put_if_changed(s3, "b", "k", b"one") is False
    assert put_if_changed(s3, "b", "k", b"two") is True
    assert s3.puts == 2
    assert s3.objects[("b", "k")]["Body"] == b"two"


def test_glue_tables_match_parquet_schemas_and_locations():
    tables = {t["Name"]: t for t in glue_tables(CFG)}
    assert set(tables) == {"auth_events", "alerts", "daily_ip_summary"}

    auth = tables["auth_events"]
    assert [c["Name"] for c in auth["StorageDescriptor"]["Columns"]] == [n for n, _, _ in AUTH_EVENTS_COLUMNS]
    assert auth["PartitionKeys"] == [{"Name": "event_date", "Type": "string"}]
    assert auth["StorageDescriptor"]["Location"] == "s3://test-bucket/processed/auth_events/"
    assert auth["Parameters"]["storage.location.template"] == (
        "s3://test-bucket/processed/auth_events/event_date=${event_date}/"
    )
    # Bölüm sütunu veri sütunları arasında tekrar etmemeli.
    assert "event_date" not in [c["Name"] for c in auth["StorageDescriptor"]["Columns"]]
    assert tables["alerts"]["StorageDescriptor"]["Location"] == "s3://test-bucket/curated/alerts/"


def test_pipeline_policy_is_scoped_to_project_resources():
    policy = json.loads(render_pipeline_policy(CFG, "111122223333"))
    statements = {s["Sid"]: s for s in policy["Statement"]}
    actions = [a for s in policy["Statement"] for a in s["Action"]]
    resources = [r for s in policy["Statement"]
                 for r in ([s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"])]

    assert "${" not in json.dumps(policy)
    # Joker yetki ya da silme / yönetim yetkisi yok.
    assert not any(a.endswith(":*") or a == "*" for a in actions)
    assert not any("Delete" in a or a.startswith("iam:") for a in actions)
    assert "*" not in resources
    assert all("test-bucket" in r or "test_db" in r or "test_wg" in r or r.endswith(":catalog") for r in resources)
    assert statements["ReadWriteLakeLayers"]["Resource"] == [
        "arn:aws:s3:::test-bucket/raw/*",
        "arn:aws:s3:::test-bucket/processed/*",
        "arn:aws:s3:::test-bucket/curated/*",
    ]
    assert statements["RunAthenaQueriesInWorkgroup"]["Resource"] == (
        "arn:aws:athena:eu-central-1:111122223333:workgroup/test_wg"
    )


def test_split_statements_drops_comments_and_empty_statements():
    sql = "-- başlık\nSELECT 1;\n\n-- ikinci\nSELECT a,\n       b\nFROM t;\n"
    assert split_statements(sql) == ["SELECT 1", "SELECT a,\n       b\nFROM t"]


def test_format_table():
    assert format_table(["ip", "n"], [["192.0.2.10", "5"], [None, "12"]]) == (
        "ip         | n \n"
        "-----------+---\n"
        "192.0.2.10 | 5 \n"
        "           | 12"
    )
