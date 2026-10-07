"""ETL pipeline: extract → transform → validate → load.

Kullanım:
    python -m src.etl.pipeline data/raw/OpenSSH_2k.log [--year 2025]
"""
import argparse
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from src.etl.extract import file_sha256, infer_year, read_lines
from src.etl.load import fail_run, finish_run, load_events, load_rejected, start_run, write_processed
from src.etl.transform import transform
from src.etl.validate import validate
from src.utils.db import apply_schema, get_connection

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"


def run_pipeline(
    path: Union[str, Path],
    year: int,
    conn,
    processed_dir: Path = PROCESSED_DIR,
    now: Optional[datetime] = None,
) -> dict:
    """Dosyayı uçtan uca işler ve istatistik sözlüğü döndürür.

    Olaylar, karantina ve çalıştırma kaydı tek transaction'da yazılır: hata
    olursa hiçbiri yazılmaz, çalıştırma 'failed' olarak işaretlenir ve hata
    yeniden fırlatılır.
    """
    path = Path(path)
    source_file = path.name
    sha = file_sha256(path)
    run_id = start_run(conn, source_file, sha)
    log.info("run_id=%s başladı: %s (sha256=%s…)", run_id, source_file, sha[:12])

    try:
        lines = list(read_lines(path))
        events, parse_rejected, irrelevant = transform(lines, year)
        valid, quality_rejected = validate(events, now)
        rejected = sorted(parse_rejected + quality_rejected, key=lambda r: r.line_no)
        log.info(
            "okunan=%d olay=%d geçerli=%d reddedilen=%d ilgisiz=%d",
            len(lines), len(events), len(valid), len(rejected), irrelevant,
        )

        write_processed(processed_dir / f"{path.stem}.jsonl", valid, source_file)

        with conn.cursor() as cur:
            loaded = load_events(cur, valid, source_file, run_id)
            load_rejected(cur, rejected, source_file, sha, run_id)
            stats = {
                "lines_read": len(lines),
                "lines_irrelevant": irrelevant,
                "lines_rejected": len(rejected),
                "events_valid": len(valid),
                "events_loaded": loaded,
                "events_skipped_existing": len(valid) - loaded,
            }
            finish_run(cur, run_id, stats)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        fail_run(conn, run_id, f"{type(exc).__name__}: {exc}")
        log.exception("run_id=%s başarısız", run_id)
        raise

    stats["run_id"] = run_id
    stats["reject_reasons"] = dict(Counter(r.reason for r in rejected))
    log.info("run_id=%s bitti: yüklenen=%d zaten_var=%d", run_id, loaded, len(valid) - loaded)
    return stats


def find_unprocessed(conn, raw_dir: Path = RAW_DIR) -> list[Path]:
    """raw_dir altındaki, içeriği daha önce başarıyla işlenmemiş *.log dosyalarını isim sırasıyla döndürür."""
    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT file_sha256 FROM pipeline_runs WHERE status = 'success'")
        done = {row[0] for row in cur.fetchall()}
    conn.commit()
    return [path for path in sorted(Path(raw_dir).glob("*.log")) if file_sha256(path) not in done]


def process_new_files(
    conn, raw_dir: Path = RAW_DIR, processed_dir: Path = PROCESSED_DIR, now: Optional[datetime] = None
) -> list[dict]:
    """Yeni dosyaların her birini pipeline'dan geçirir; dosya başına istatistik listesi döndürür."""
    results = []
    for path in find_unprocessed(conn, raw_dir):
        stats = run_pipeline(path, infer_year(path), conn, processed_dir, now)
        stats["source_file"] = path.name
        results.append(stats)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Auth log dosyasını ETL pipeline'ından geçirir.")
    ap.add_argument("path")
    ap.add_argument(
        "--year", type=int,
        help="Logların ait olduğu yıl (syslog satırında yıl yok). Verilmezse dosya tarihinden tahmin edilir.",
    )
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    year = args.year or infer_year(args.path)
    conn = get_connection()
    try:
        apply_schema(conn)
        stats = run_pipeline(args.path, year, conn)
    finally:
        conn.close()

    print(f"Yıl                : {year}" + ("" if args.year else " (tahmin)"))
    print(f"Çalıştırma no      : {stats['run_id']}")
    print(f"Okunan satır       : {stats['lines_read']}")
    print(f"İlgisiz satır      : {stats['lines_irrelevant']}")
    print(f"Geçerli olay       : {stats['events_valid']}")
    print(f"  yeni yüklenen    : {stats['events_loaded']}")
    print(f"  zaten var        : {stats['events_skipped_existing']}")
    print(f"Reddedilen satır   : {stats['lines_rejected']}")
    for reason, count in sorted(stats["reject_reasons"].items()):
        print(f"  {reason:<17}: {count}")


if __name__ == "__main__":
    main()
