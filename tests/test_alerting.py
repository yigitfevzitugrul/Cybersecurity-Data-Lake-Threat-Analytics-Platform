"""Grafana Telegram bildirim kuralının testleri (Grafana'ya bağlanmaz)."""
from datetime import datetime
from pathlib import Path

import yaml

from src.detection.engine import save_alerts
from src.detection.rules import Alert
from src.utils.telegram_setup import render_contact_point

ALERTING = yaml.safe_load(
    (Path(__file__).resolve().parents[1] / "grafana" / "alerting" / "critical_alerts.yaml").read_text(encoding="utf-8")
)
RULE = ALERTING["groups"][0]["rules"][0]
QUERY = next(d for d in RULE["data"] if d["refId"] == "A")["model"]["rawSql"]


def test_rule_wiring():
    refs = {d["refId"]: d for d in RULE["data"]}
    assert RULE["condition"] == "C" and set(refs) == {"A", "B", "C"}
    assert refs["A"]["datasourceUid"] == "secdl-postgres"
    assert refs["B"]["model"]["expression"] == "A" and refs["C"]["model"]["expression"] == "B"
    assert RULE["noDataState"] == "OK"
    assert "contactPoints" not in ALERTING  # kanal yerel dosyada (telegram_setup)
    template = ALERTING["templates"][0]["template"]
    for label in ("rule", "source_ip", "username", "techniques", "window_start"):
        assert f".Labels.{label}" in template


def test_query_returns_only_recently_written_critical_alerts(db_conn):
    old_attack = datetime(2025, 12, 10, 3, 0)
    save_alerts(db_conn, [
        Alert("auth_anomaly", "critical", "203.0.113.9", "dave", old_attack, old_attack, 12, 1,
              {"reasons": ["success_after_failures"]}),
        Alert("brute_force", "high", "203.0.113.9", "dave", old_attack, old_attack, 12, 1),
        Alert("privilege_abuse", "critical", None, "erin", old_attack, old_attack, 6, 1,
              {"failures_by_type": {"su_failure": 6}}),
    ])
    with db_conn.cursor() as cur:
        cur.execute(QUERY)
        rows = sorted(cur.fetchall())
        assert rows == [
            ("auth_anomaly", "203.0.113.9", "dave", "T1078.003, T1110.001", "2025-12-10 03:00", 1),
            ("privilege_abuse", "-", "erin", "T1110.001", "2025-12-10 03:00", 1),
        ]
        # Beş dakikadan önce yazılmış alarmlar tekrar bildirilmez.
        cur.execute("UPDATE alerts SET first_detected_at = now() - interval '6 minutes'")
        cur.execute(QUERY)
        assert cur.fetchall() == []


def test_generated_contact_point_matches_policy_and_keeps_token_out():
    contact = yaml.safe_load(render_contact_point(8481866838))["contactPoints"][0]
    receiver = contact["receivers"][0]
    assert contact["name"] == ALERTING["policies"][0]["receiver"]
    # Chat id metin olarak yazılır (Grafana ortam değişkenindeki sayıyı sayıya çevirir).
    assert receiver["settings"]["chatid"] == "8481866838"
    # Token dosyaya yazılmaz; Grafana onu ortam değişkeninden okur.
    assert receiver["settings"]["bottoken"] == "$TELEGRAM_BOT_TOKEN"
    assert receiver["settings"]["message"] == '{{ template "secdl.message" . }}'
