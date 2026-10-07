"""Yıl tahmini ve yeni dosya keşfi testleri."""
import os
from datetime import datetime

from src.etl.extract import infer_year
from src.etl.pipeline import find_unprocessed, process_new_files

NOW = datetime(2026, 12, 31)


def _log(tmp_path, name, content, modified=None):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8", newline="\n")
    if modified is not None:
        ts = modified.timestamp()
        os.utime(path, (ts, ts))
    return path


def _line(stamp, port):
    return f"{stamp} srv sshd[1]: Failed password for root from 192.0.2.10 port {port} ssh2\n"


def test_infer_year_same_year(tmp_path):
    path = _log(tmp_path, "a.log", _line("Sep  1 10:00:00", 1), datetime(2026, 10, 7, 12))
    assert infer_year(path) == 2026


def test_infer_year_previous_year_when_log_date_is_after_file_date(tmp_path):
    path = _log(tmp_path, "a.log", _line("Dec 10 06:55:46", 1), datetime(2026, 10, 7, 12))
    assert infer_year(path) == 2025


def test_infer_year_same_day_is_not_treated_as_future(tmp_path):
    # Dosya gün içinde yazılırken günün ilerideki saatlerine ait satırlar olabilir.
    path = _log(tmp_path, "a.log", _line("Oct  7 23:59:00", 1), datetime(2026, 10, 7, 8))
    assert infer_year(path) == 2026


def test_infer_year_skips_undated_and_impossible_lines(tmp_path):
    content = "#### corrupted ####\n" + _line("Feb 30 10:00:00", 1) + _line("Dec 10 10:00:00", 2)
    path = _log(tmp_path, "a.log", content, datetime(2026, 10, 7))
    assert infer_year(path) == 2025


def test_infer_year_falls_back_to_file_year(tmp_path):
    path = _log(tmp_path, "a.log", "tarihsiz satir\n", datetime(2024, 5, 5))
    assert infer_year(path) == 2024


def test_process_new_files_only_handles_unprocessed_logs(db_conn, tmp_path):
    raw, processed = tmp_path / "raw", tmp_path / "processed"
    raw.mkdir()
    modified = datetime(2026, 3, 2)
    _log(raw, "b.log", _line("Mar  1 10:00:01", 2), modified)
    _log(raw, "a.log", _line("Mar  1 10:00:00", 1), modified)
    _log(raw, "labels.json", "{}", modified)

    assert [p.name for p in find_unprocessed(db_conn, raw)] == ["a.log", "b.log"]

    first = process_new_files(db_conn, raw, processed, NOW)
    assert [(s["source_file"], s["events_loaded"]) for s in first] == [("a.log", 1), ("b.log", 1)]
    with db_conn.cursor() as cur:
        cur.execute("SELECT DISTINCT EXTRACT(YEAR FROM event_time)::int FROM auth_events")
        assert cur.fetchall() == [(2026,)]

    assert find_unprocessed(db_conn, raw) == []
    assert process_new_files(db_conn, raw, processed, NOW) == []

    _log(raw, "c.log", _line("Mar  1 10:00:02", 3), modified)
    third = process_new_files(db_conn, raw, processed, NOW)
    assert [s["source_file"] for s in third] == ["c.log"]


def test_changed_file_is_processed_again_without_duplicating_events(db_conn, tmp_path):
    raw, processed = tmp_path / "raw", tmp_path / "processed"
    raw.mkdir()
    modified = datetime(2026, 3, 2)
    _log(raw, "a.log", _line("Mar  1 10:00:00", 1), modified)
    process_new_files(db_conn, raw, processed, NOW)

    # Dosyaya yeni satır eklenir: içerik değiştiği için yeniden işlenir, eski olay atlanır.
    _log(raw, "a.log", _line("Mar  1 10:00:00", 1) + _line("Mar  1 10:00:05", 2), modified)
    again = process_new_files(db_conn, raw, processed, NOW)
    assert [(s["events_loaded"], s["events_skipped_existing"]) for s in again] == [(1, 1)]
