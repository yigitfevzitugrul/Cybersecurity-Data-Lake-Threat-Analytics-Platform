"""Yerel–bulut tutarlılık kontrolünün testleri (Athena taklit edilir)."""
from datetime import datetime

from src.cloud import reconcile as reconcile_module
from src.cloud.reconcile import compare, format_results, reconcile
from src.detection.engine import load_config, run_detection
from src.etl.pipeline import run_pipeline

NOW = datetime(2026, 12, 31)

LOG = "\n".join(
    [f"Mar  1 10:00:{i:02d} srv sshd[{100 + i}]: Failed password for root from 192.0.2.10 port {4000 + i} ssh2"
     for i in range(12)]
    + ["Mar  1 10:00:30 srv sshd[200]: message repeated 3 times: [ Failed password for root from 192.0.2.11 port 5000 ssh2]",
       "Mar  2 09:00:00 srv sshd[300]: Accepted password for alice from 10.20.0.10 port 6000 ssh2"]
) + "\n"


def test_compare_flags_any_difference():
    assert compare("t", "deneme", (10, 25), (10, 25))["match"] is True
    assert compare("t", "deneme", (10, 25), (9, 25))["match"] is False
    assert compare("t", "deneme", (10, 25), (10, 24))["match"] is False


def test_format_results_marks_mismatches():
    text = format_results([
        compare("auth_events", "deneme", (10, 25), (10, 25)),
        compare("alerts", "başarısız deneme", (3, 40), (2, 28)),
    ])
    ok_line, diff_line = text.splitlines()
    assert ok_line.strip().startswith("ok") and "satır 10 / 10" in ok_line
    assert diff_line.strip().startswith("FARK") and "satır 3 / 2" in diff_line


def test_reconcile_compares_local_counts_with_athena(db_conn, tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text(LOG, encoding="utf-8", newline="\n")
    run_pipeline(log, 2026, db_conn, tmp_path / "processed", NOW)
    run_detection(db_conn, load_config())

    # 14 olay; "message repeated 3 times" yüzünden 16 deneme. İki günde üç farklı (gün, IP) çifti.
    cloud_answers = {"auth_events": ["14", "16"], "daily_ip_summary": ["3", "15"]}
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*), COALESCE(SUM(attempt_count), 0) FROM alerts")
        cloud_answers["alerts"] = [str(value) for value in cur.fetchone()]
    assert int(cloud_answers["alerts"][0]) > 0

    def fake_run_query(athena, cfg, sql):
        table = next(name for name in ("daily_ip_summary", "auth_events", "alerts") if f"FROM {name}" in sql)
        return {"rows": [cloud_answers[table]]}

    monkeypatch.setattr(reconcile_module, "run_query", fake_run_query)
    results = reconcile(db_conn, athena=None, cfg=None)
    assert [(r["table"], r["match"]) for r in results] == [
        ("auth_events", True), ("alerts", True), ("daily_ip_summary", True),
    ]

    # Bulutta bir satır eksikse fark yakalanır.
    cloud_answers["auth_events"] = ["13", "15"]
    results = reconcile(db_conn, athena=None, cfg=None)
    assert [r["match"] for r in results] == [False, True, True]
