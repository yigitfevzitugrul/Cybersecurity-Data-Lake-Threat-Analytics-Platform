"""Load: geçerli olayları, karantinayı ve çalıştırma kaydını yazar.

`conn` alan fonksiyonlar kendi transaction'ını commit eder; `cur` alanlar
çağıranın transaction'ı içinde çalışır.
"""
import json
from dataclasses import asdict
from pathlib import Path

from psycopg2.extras import execute_values

from src.etl.parser import AuthEvent
from src.etl.transform import Rejected, event_hash

INSERT_EVENTS_SQL = """
    INSERT INTO auth_events (
        event_hash, event_time, host, pid, event_type, auth_method, username,
        is_invalid_user, source_ip, source_port, repeat_count,
        source_file, line_no, raw_line, run_id
    ) VALUES %s
    ON CONFLICT (event_hash) DO NOTHING
    RETURNING 1
"""

INSERT_REJECTED_SQL = """
    INSERT INTO rejected_events (
        run_id, source_file, file_sha256, line_no, raw_line, reject_reason, reject_detail
    ) VALUES %s
    ON CONFLICT (file_sha256, line_no) DO NOTHING
    RETURNING 1
"""


def start_run(conn, source_file: str, file_sha256: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO pipeline_runs (source_file, file_sha256, status) "
            "VALUES (%s, %s, 'running') RETURNING run_id",
            (source_file, file_sha256),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def load_events(cur, events: list[tuple[int, AuthEvent]], source_file: str, run_id: int) -> int:
    """Gerçekten eklenen satır sayısını döndürür; veritabanında zaten olanlar atlanır."""
    rows = [
        (
            event_hash(e), e.event_time, e.host, e.pid, e.event_type, e.auth_method,
            e.username, e.is_invalid_user, e.source_ip, e.source_port, e.repeat_count,
            source_file, line_no, e.raw_line, run_id,
        )
        for line_no, e in events
    ]
    if not rows:
        return 0
    return len(execute_values(cur, INSERT_EVENTS_SQL, rows, page_size=1000, fetch=True))


def load_rejected(cur, rejected: list[Rejected], source_file: str, file_sha256: str, run_id: int) -> int:
    rows = [
        (run_id, source_file, file_sha256, r.line_no, r.raw_line, r.reason, r.detail)
        for r in rejected
    ]
    if not rows:
        return 0
    return len(execute_values(cur, INSERT_REJECTED_SQL, rows, page_size=1000, fetch=True))


def finish_run(cur, run_id: int, stats: dict) -> None:
    cur.execute(
        """
        UPDATE pipeline_runs
        SET status = 'success', finished_at = now(),
            lines_read = %(lines_read)s,
            lines_irrelevant = %(lines_irrelevant)s,
            lines_rejected = %(lines_rejected)s,
            events_valid = %(events_valid)s,
            events_loaded = %(events_loaded)s,
            events_skipped_existing = %(events_skipped_existing)s
        WHERE run_id = %(run_id)s
        """,
        {**stats, "run_id": run_id},
    )


def fail_run(conn, run_id: int, error: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE pipeline_runs SET status = 'failed', finished_at = now(), error_message = %s "
            "WHERE run_id = %s",
            (error[:2000], run_id),
        )
    conn.commit()


def write_processed(path: Path, events: list[tuple[int, AuthEvent]], source_file: str) -> None:
    """Geçerli olayları processed katmanına JSON Lines olarak yazar (dosya her çalıştırmada yeniden üretilir)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for line_no, e in events:
            record = asdict(e)
            record["event_time"] = e.event_time.isoformat()
            record["event_hash"] = event_hash(e)
            record["source_file"] = source_file
            record["line_no"] = line_no
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
