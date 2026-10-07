"""Athena üzerinde sorgu çalıştırır.

Kullanım:
    python -m src.cloud.athena sql/athena/01_lake_analysis.sql
"""
import argparse
import time
from pathlib import Path

from src.cloud.config import CloudConfig, load_config, pipeline_session


def split_statements(sql_text: str) -> list[str]:
    """Bir .sql dosyasını ';' ile ayrılmış sorgulara böler; '--' yorum satırlarını atar."""
    lines = [line for line in sql_text.splitlines() if not line.strip().startswith("--")]
    return [statement.strip() for statement in "\n".join(lines).split(";") if statement.strip()]


def run_query(athena, cfg: CloudConfig, sql: str, timeout_seconds: int = 120) -> dict:
    """Sorguyu çalıştırır; sütunları, satırları ve taranan veri miktarını döndürür."""
    query_id = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": cfg.glue_database},
        WorkGroup=cfg.athena_workgroup,
    )["QueryExecutionId"]

    deadline = time.monotonic() + timeout_seconds
    while True:
        execution = athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        if time.monotonic() > deadline:
            athena.stop_query_execution(QueryExecutionId=query_id)
            raise TimeoutError(f"Athena sorgusu {timeout_seconds} saniyede bitmedi: {query_id}")
        time.sleep(1)
    if state != "SUCCEEDED":
        raise RuntimeError(f"Athena sorgusu {state}: {execution['Status'].get('StateChangeReason', '')}")

    columns, rows = [], []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=query_id):
        if not columns:
            columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
        rows.extend([cell.get("VarCharValue") for cell in row["Data"]] for row in page["ResultSet"]["Rows"])
    # SELECT sonuçlarının ilk satırı başlıktır.
    if rows and rows[0] == columns:
        rows = rows[1:]
    stats = execution.get("Statistics", {})
    return {
        "columns": columns,
        "rows": rows,
        "bytes_scanned": stats.get("DataScannedInBytes", 0),
        "millis": stats.get("TotalExecutionTimeInMillis", 0),
    }


def format_table(columns: list[str], rows: list[list]) -> str:
    cells = [columns] + [["" if value is None else str(value) for value in row] for row in rows]
    widths = [max(len(row[i]) for row in cells) for i in range(len(columns))]
    lines = [" | ".join(value.ljust(width) for value, width in zip(row, widths)) for row in cells]
    lines.insert(1, "-+-".join("-" * width for width in widths))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Bir .sql dosyasındaki sorguları Athena'da çalıştırır.")
    ap.add_argument("path", type=Path)
    args = ap.parse_args()

    cfg = load_config()
    athena = pipeline_session(cfg).client("athena")
    total_bytes = 0
    for number, sql in enumerate(split_statements(args.path.read_text(encoding="utf-8")), start=1):
        result = run_query(athena, cfg, sql)
        total_bytes += result["bytes_scanned"]
        print(f"\n[{number}] {sql.splitlines()[0][:80]}")
        print(format_table(result["columns"], result["rows"]))
        print(f"({len(result['rows'])} satır, {result['bytes_scanned'] / 1024:.1f} KB tarandı, {result['millis']} ms)")
    print(f"\nToplam taranan veri: {total_bytes / 1024:.1f} KB")


if __name__ == "__main__":
    main()
