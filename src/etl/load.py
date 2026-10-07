"""Ayrıştırılmış olayları PostgreSQL'deki auth_events tablosuna yükler."""
import argparse
import hashlib
from pathlib import Path

from psycopg2.extras import execute_values

from src.etl.parser import AuthEvent, ParseError, parse_file
from src.utils.db import apply_schema, get_connection

INSERT_SQL = """
    INSERT INTO auth_events (
        event_hash, event_time, host, pid, event_type, auth_method, username,
        is_invalid_user, source_ip, source_port, repeat_count,
        source_file, line_no, raw_line
    ) VALUES %s
    ON CONFLICT (event_hash) DO NOTHING
    RETURNING 1
"""


def event_hash(event: AuthEvent) -> str:
    """Olayın kimliği: zaman (yıl dahil) + ham satır. Aynı olay hangi dosyadan gelirse gelsin aynı hash'i alır."""
    key = f"{event.event_time.isoformat()}|{event.raw_line}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def load_events(conn, events: list[tuple[int, AuthEvent]], source_file: str) -> int:
    """(satır_no, olay) listesini yükler; gerçekten eklenen satır sayısını döndürür."""
    rows = [
        (
            event_hash(e), e.event_time, e.host, e.pid, e.event_type, e.auth_method,
            e.username, e.is_invalid_user, e.source_ip, e.source_port, e.repeat_count,
            source_file, line_no, e.raw_line,
        )
        for line_no, e in events
    ]
    if not rows:
        return 0
    with conn.cursor() as cur:
        inserted = execute_values(cur, INSERT_SQL, rows, page_size=1000, fetch=True)
    conn.commit()
    return len(inserted)


def main() -> None:
    ap = argparse.ArgumentParser(description="Auth log dosyasını ayrıştırıp auth_events'e yükler.")
    ap.add_argument("path")
    ap.add_argument("--year", type=int, required=True, help="Logların ait olduğu yıl (syslog satırında yıl yok)")
    args = ap.parse_args()

    events, skipped, errors = [], 0, 0
    for line_no, _, result in parse_file(args.path, args.year):
        if result is None:
            skipped += 1
        elif isinstance(result, ParseError):
            errors += 1
        else:
            events.append((line_no, result))

    conn = get_connection()
    try:
        apply_schema(conn)
        inserted = load_events(conn, events, Path(args.path).name)
    finally:
        conn.close()

    print(f"Ayrıştırılan olay  : {len(events)}")
    print(f"Yeni eklenen       : {inserted}")
    print(f"Zaten var (atlandı): {len(events) - inserted}")
    print(f"İlgisiz satır      : {skipped}")
    print(f"Bozuk satır        : {errors}")


if __name__ == "__main__":
    main()
