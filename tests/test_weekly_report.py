"""Haftalık güvenlik raporu testleri."""
from datetime import date, datetime

from src.detection.engine import load_config, run_detection
from src.etl.pipeline import run_pipeline
from src.generator.generate import generate, write_files
from src.reporting import weekly
from src.reporting.weekly import collect, last_monday, nice_axis, render_html, summary_text, week_bounds

NOW = datetime(2026, 12, 31)


def test_week_helpers():
    assert last_monday(date(2026, 10, 15)) == date(2026, 10, 12)   # perşembe → o haftanın pazartesisi
    assert last_monday(date(2026, 10, 12)) == date(2026, 10, 12)   # pazartesi → bugün
    assert week_bounds(date(2026, 10, 12)) == (datetime(2026, 10, 5), datetime(2026, 10, 12))
    assert nice_axis(0) == (1, 1)
    assert nice_axis(298) == (100, 300)
    assert nice_axis(1515) == (500, 2000)


def _load(db_conn, tmp_path):
    lines, labels = generate(date(2026, 3, 2), days=7, seed=5, bad_ratio=0.02, hard_cases=True, privilege=True)
    log = tmp_path / "week.log"
    write_files(log, lines, labels)
    run_pipeline(log, 2026, db_conn, tmp_path / "processed", NOW)
    run_detection(db_conn, load_config())
    return labels


def test_collect_matches_database(db_conn, tmp_path):
    labels = _load(db_conn, tmp_path)
    report = collect(db_conn, date(2026, 3, 9))  # 2026-03-02 pazartesi .. 03-08 pazar

    with db_conn.cursor() as cur:
        cur.execute("SELECT SUM(repeat_count) FROM auth_events WHERE event_type = 'login_failed'")
        failed = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*), COUNT(*) FILTER (WHERE severity = 'critical') FROM alerts")
        alerts, critical = cur.fetchone()
        cur.execute("SELECT SUM(lines_read), SUM(lines_rejected) FROM pipeline_runs")
        lines_read, lines_rejected = cur.fetchone()

    k = report["kpis"]
    assert (k["failed_attempts"], k["alerts"], k["critical_alerts"]) == (failed, alerts, critical)
    assert report["previous_kpis"]["failed_attempts"] == 0
    assert [d["date"] for d in report["daily"]] == [f"2026-03-{d:02d}" for d in range(2, 9)]
    assert sum(d["failed_attempts"] for d in report["daily"]) == failed
    assert sum(report["alerts_by_severity"].values()) == alerts
    assert len(report["critical_alerts"]) == critical > 0
    assert report["attack_techniques"] and report["sensitive_commands"]
    assert report["top_attacking_ips"][0]["failed_attempts"] >= report["top_attacking_ips"][-1]["failed_attempts"]
    q = report["data_quality"]
    assert (q["lines_read"], q["lines_rejected"]) == (lines_read, lines_rejected)
    assert sum(q["reject_reasons"].values()) == lines_rejected
    assert sum(labels["injected_bad_lines"].values()) == lines_rejected

    # Bir sonraki haftada bu veri "önceki hafta" olarak görünür.
    following = collect(db_conn, date(2026, 3, 16))
    assert following["kpis"]["failed_attempts"] == 0
    assert following["previous_kpis"]["failed_attempts"] == failed


def test_html_escapes_values_from_logs(db_conn, tmp_path):
    _load(db_conn, tmp_path)
    report = collect(db_conn, date(2026, 3, 9))
    # Kullanıcı adları saldırganın kontrolündedir; rapora ham HTML olarak girmemeli.
    report["top_targeted_usernames"][0]["username"] = "<script>alert(1)</script>"
    html = render_html(report)
    assert "<script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Haftalık güvenlik raporu" in html and "<svg" in html
    assert "Haftalık güvenlik raporu 2026-03-02 – 2026-03-08" in summary_text(report)


def test_empty_week_renders(db_conn):
    report = collect(db_conn, date(2026, 3, 9))
    assert report["kpis"]["failed_attempts"] == 0
    html = render_html(report)
    assert "Bu hafta kritik alarm yok." in html


def test_telegram_is_optional(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("src.utils.telegram.send_document",
                        lambda token, chat, path, caption="": sent.append((token, chat, path.name, caption)))
    path = tmp_path / "weekly.html"
    path.write_text("<html></html>", encoding="utf-8")
    report = {"week_start": "2026-03-02", "week_end": "2026-03-08", "top_attacking_ips": [],
              "kpis": {"failed_attempts": 1, "attacking_ips": 1, "alerts": 0, "critical_alerts": 0,
                       "high_alerts": 0, "privilege_failures": 0}}

    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert weekly.send_to_telegram(path, report) is False and sent == []

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
    assert weekly.send_to_telegram(path, report) is True
    assert sent[0][:3] == ("t", "42", "weekly.html") and "2026-03-02" in sent[0][3]
