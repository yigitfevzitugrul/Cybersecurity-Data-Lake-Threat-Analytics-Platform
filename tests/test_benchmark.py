"""Ölçeklenebilirlik aracının duman testi (küçük veriyle, geçici şemalarda)."""
import psycopg2
import pytest

from src.benchmark.scale import run, split_days
from src.utils.db import get_connection


def test_split_days_groups_by_syslog_date():
    lines = ["Mar  1 10:00:00 a", "Mar  1 11:00:00 b", "Mar  2 09:00:00 c", "Mar 10 09:00:00 d"]
    assert split_days(lines) == [lines[:2], [lines[2]], [lines[3]]]


def test_benchmark_runs_and_incremental_matches_full():
    try:
        get_connection().close()
    except (psycopg2.OperationalError, KeyError) as exc:
        pytest.skip(f"PostgreSQL'e bağlanılamadı: {exc}")

    report = run(days=3, noise=20, seed=1)
    assert report["incremental_equals_full"] is True
    assert [d["day"] for d in report["per_day"]] == [1, 2, 3]
    assert report["per_day"][-1]["incremental_events"] < report["per_day"][-1]["full_events"]
    assert report["storage"]["parquet_files"] == 3
