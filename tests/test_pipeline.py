"""Pipeline'ın uçtan uca testleri. Çalışan bir PostgreSQL gerektirir (yoksa atlanır)."""
import json
from datetime import date, datetime

import pytest

from src.etl import pipeline
from src.etl.pipeline import run_pipeline
from src.generator.generate import generate

NOW = datetime(2026, 12, 31)

SAMPLE = "\n".join([
    "Mar  1 10:00:00 srv sshd[100]: Failed password for root from 192.0.2.10 port 4000 ssh2",
    "Mar  1 10:00:01 srv sshd[100]: Connection closed by 192.0.2.10 [preauth]",
    "Mar  1 10:00:02 srv sshd[101]: Accepted password for alice from 10.20.0.10 port 4001 ssh2",
    "",
    "bozuk satir",
    "Mar  1 10:00:03 srv sshd[102]: Failed password for root from 999.1.1.1 port 4002 ssh2",
    "Mar  1 10:00:00 srv sshd[100]: Failed password for root from 192.0.2.10 port 4000 ssh2",
]) + "\n"


def _write(tmp_path, content, name="auth.log"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def _count(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0]


def test_pipeline_loads_valid_and_quarantines_bad(db_conn, tmp_path):
    stats = run_pipeline(_write(tmp_path, SAMPLE), 2026, db_conn, tmp_path / "processed", NOW)

    assert stats["lines_read"] == 6
    assert stats["lines_irrelevant"] == 1
    assert stats["events_valid"] == 2
    assert stats["events_loaded"] == 2
    assert stats["events_skipped_existing"] == 0
    assert stats["lines_rejected"] == 3
    assert stats["reject_reasons"] == {"malformed_line": 1, "invalid_ip": 1, "duplicate": 1}

    with db_conn.cursor() as cur:
        cur.execute("SELECT line_no, username, host(source_ip), run_id FROM auth_events ORDER BY line_no")
        assert cur.fetchall() == [
            (1, "root", "192.0.2.10", stats["run_id"]),
            (3, "alice", "10.20.0.10", stats["run_id"]),
        ]
        cur.execute("SELECT line_no, reject_reason, raw_line FROM rejected_events ORDER BY line_no")
        rejected = cur.fetchall()
        assert [(r[0], r[1]) for r in rejected] == [(5, "malformed_line"), (6, "invalid_ip"), (7, "duplicate")]
        assert rejected[0][2] == "bozuk satir"
        cur.execute(
            "SELECT status, finished_at IS NOT NULL, lines_read, lines_irrelevant, lines_rejected, "
            "events_valid, events_loaded, events_skipped_existing, error_message FROM pipeline_runs"
        )
        assert cur.fetchall() == [("success", True, 6, 1, 3, 2, 2, 0, None)]

    processed = (tmp_path / "processed" / "auth.jsonl").read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in processed]
    assert [r["line_no"] for r in records] == [1, 3]
    assert records[0]["event_time"] == "2026-03-01T10:00:00"
    assert records[0]["source_file"] == "auth.log"


def test_pipeline_is_idempotent(db_conn, tmp_path):
    path = _write(tmp_path, SAMPLE)
    run_pipeline(path, 2026, db_conn, tmp_path / "processed", NOW)
    second = run_pipeline(path, 2026, db_conn, tmp_path / "processed", NOW)

    assert second["events_loaded"] == 0
    assert second["events_skipped_existing"] == 2
    assert _count(db_conn, "auth_events") == 2
    assert _count(db_conn, "rejected_events") == 3
    assert _count(db_conn, "pipeline_runs") == 2


def test_overlapping_file_only_adds_new_events(db_conn, tmp_path):
    run_pipeline(_write(tmp_path, SAMPLE), 2026, db_conn, tmp_path / "processed", NOW)
    extra = SAMPLE + "Mar  1 10:05:00 srv sshd[200]: Failed password for bob from 192.0.2.11 port 5000 ssh2\n"
    stats = run_pipeline(_write(tmp_path, extra, "auth_rotated.log"), 2026, db_conn, tmp_path / "processed", NOW)

    assert stats["events_valid"] == 3
    assert stats["events_loaded"] == 1
    assert stats["events_skipped_existing"] == 2
    assert _count(db_conn, "auth_events") == 3


def test_failed_run_is_recorded_and_nothing_is_loaded(db_conn, tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("yükleme patladı")

    monkeypatch.setattr(pipeline, "load_rejected", boom)
    with pytest.raises(RuntimeError):
        run_pipeline(_write(tmp_path, SAMPLE), 2026, db_conn, tmp_path / "processed", NOW)

    assert _count(db_conn, "auth_events") == 0
    assert _count(db_conn, "rejected_events") == 0
    with db_conn.cursor() as cur:
        cur.execute("SELECT status, error_message, finished_at IS NOT NULL FROM pipeline_runs")
        assert cur.fetchall() == [("failed", "RuntimeError: yükleme patladı", True)]


def test_generated_bad_lines_are_all_quarantined(db_conn, tmp_path):
    clean_lines, _ = generate(date(2026, 3, 1), days=2, seed=5)
    lines, labels = generate(date(2026, 3, 1), days=2, seed=5, bad_ratio=0.05)
    injected = labels["injected_bad_lines"]
    assert sum(injected.values()) == round(len(clean_lines) * 0.05) > 0

    clean = run_pipeline(
        _write(tmp_path, "\n".join(clean_lines) + "\n", "clean.log"), 2026, db_conn, tmp_path / "p", NOW
    )
    assert clean["lines_rejected"] == 0

    dirty = run_pipeline(
        _write(tmp_path, "\n".join(lines) + "\n", "dirty.log"), 2026, db_conn, tmp_path / "p", NOW
    )
    assert dirty["reject_reasons"] == injected
    # Bozuk satırlar temiz olayları etkilemez: hepsi zaten yüklü.
    assert dirty["events_valid"] == clean["events_valid"]
    assert dirty["events_loaded"] == 0
    assert dirty["lines_read"] == dirty["lines_irrelevant"] + dirty["lines_rejected"] + dirty["events_valid"]
