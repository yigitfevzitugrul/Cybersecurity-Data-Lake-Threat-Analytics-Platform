"""Tespit motoru ve doğruluk ölçümü testleri."""
import json
from datetime import date, datetime

from src.detection.engine import load_config, run_detection
from src.detection.evaluate import evaluate, fetch_alerts, load_labels
from src.detection.rules import Alert
from src.etl.pipeline import run_pipeline
from src.generator.generate import generate, write_files

NOW = datetime(2026, 12, 31)
DAY = datetime(2026, 3, 1)


def _alert(rule, ip, start, end=None, severity="high"):
    return Alert(rule, severity, ip, None, start, end or start, 10, 1)


def _attack(attack_type, ip, start, end):
    return {"attack_type": attack_type, "source_ip": ip, "start": start, "end": end}


def test_evaluate_counts_recall_precision_and_scope():
    scopes = [(DAY, datetime(2026, 3, 2))]
    attacks = [
        _attack("brute_force", "203.0.113.1", DAY.replace(hour=1), DAY.replace(hour=1, minute=5)),
        _attack("password_spray", "203.0.113.2", DAY.replace(hour=2), DAY.replace(hour=2, minute=5)),
        _attack("slow_brute_force", "203.0.113.3", DAY.replace(hour=3), DAY.replace(hour=6)),
    ]
    alerts = [
        _alert("brute_force", "203.0.113.1", DAY.replace(hour=1), DAY.replace(hour=1, minute=5)),
        # Doğru IP ama yanlış kural: saldırı "bir kuralla" yakalanmış sayılır, beklenen kuralla değil.
        _alert("suspicious_ip", "203.0.113.2", DAY.replace(hour=2), severity="low"),
        # Etiketli saldırıyla eşleşmeyen alarm: yanlış alarm.
        _alert("brute_force", "10.20.0.10", DAY.replace(hour=9), severity="medium"),
        # Aynı IP ama saldırıdan saatler sonra: eşleşmez.
        _alert("brute_force", "203.0.113.1", DAY.replace(hour=20), severity="medium"),
        # Kapsam dışı (etiketi olmayan gün): ölçüme girmez.
        _alert("brute_force", "198.51.100.9", datetime(2025, 12, 10, 10)),
    ]
    report = evaluate(attacks, scopes, alerts)

    assert report["attacks"] == 3
    assert report["alerts_in_scope"] == 4
    assert report["recall_by_attack_type"] == {
        "brute_force": {"attacks": 1, "detected": 1, "recall": 1.0},
        "password_spray": {"attacks": 1, "detected": 0, "recall": 0.0},
        "slow_brute_force": {"attacks": 1, "detected": 0, "recall": 0.0},
    }
    assert report["precision_by_rule"] == {
        "brute_force": {"alerts": 3, "true_positive": 1, "false_positive": 2, "precision": 0.3333},
        "suspicious_ip": {"alerts": 1, "true_positive": 1, "false_positive": 0, "precision": 1.0},
    }
    assert report["overall"]["recall"] == 0.3333
    assert report["overall"]["detected_by_any_rule"] == 0.6667
    assert report["overall"]["precision"] == 0.5
    assert (report["overall"]["high_critical_alerts"], report["overall"]["high_critical_precision"]) == (1, 1.0)
    assert len(report["missed_attacks"]) == 2
    assert [fp["source_ip"] for fp in report["false_positives"]] == ["10.20.0.10", "203.0.113.1"]


def test_evaluate_without_data_does_not_divide_by_zero():
    report = evaluate([], [], [])
    assert report["overall"] == {
        "recall": None, "detected_by_any_rule": None, "precision": None,
        "high_critical_alerts": 0, "high_critical_precision": None,
    }


def test_load_labels_merges_files_and_deduplicates(tmp_path):
    for name in ("a_labels.json", "b_labels.json"):
        _, labels = generate(date(2026, 3, 1), days=2, seed=3)
        (tmp_path / name).write_text(json.dumps(labels), encoding="utf-8")
    attacks, scopes = load_labels(tmp_path.glob("*_labels.json"))
    assert len(attacks) == 8
    assert scopes == [(datetime(2026, 3, 1), datetime(2026, 3, 3))] * 2


def _load_synthetic(db_conn, tmp_path, **kwargs):
    lines, labels = generate(date(2026, 3, 1), **kwargs)
    log = tmp_path / "synthetic.log"
    write_files(log, lines, labels)
    run_pipeline(log, 2026, db_conn, tmp_path / "processed", NOW)
    return load_labels(tmp_path.glob("*_labels.json"))


def test_detection_is_idempotent_and_reset_clears_alerts(db_conn, tmp_path):
    _load_synthetic(db_conn, tmp_path, days=2, seed=11)
    config = load_config()

    first = run_detection(db_conn, config)
    assert first["mode"] == "full"  # ilk çalıştırma bütün geçmişi değerlendirir
    assert first["alerts"] > 0
    assert (first["new_alerts"], first["updated_alerts"]) == (first["alerts"], 0)

    # Yeni olay yoksa artımlı çalıştırma hiçbir şey okumaz ve yazmaz.
    idle = run_detection(db_conn, config)
    assert (idle["mode"], idle["events"], idle["alerts"]) == ("incremental", 0, 0)

    second = run_detection(db_conn, config, full=True)
    assert (second["new_alerts"], second["updated_alerts"]) == (0, first["alerts"])
    assert len(fetch_alerts(db_conn)) == first["alerts"]

    # Eşik yükseltilince eski alarmlar ancak --reset ile temizlenir.
    strict = {**config, "brute_force": {**config["brute_force"], "min_failed_attempts": 10_000}}
    run_detection(db_conn, strict)
    assert any(a.rule == "brute_force" for a in fetch_alerts(db_conn))
    run_detection(db_conn, strict, reset=True)
    assert not any(a.rule == "brute_force" for a in fetch_alerts(db_conn))


def test_end_to_end_detects_every_embedded_attack(db_conn, tmp_path):
    attacks, scopes = _load_synthetic(db_conn, tmp_path, days=5, seed=21, bad_ratio=0.03)
    run_detection(db_conn, load_config())
    report = evaluate(attacks, scopes, fetch_alerts(db_conn))

    assert report["attacks"] == 20
    assert report["overall"]["recall"] == 1.0
    assert report["overall"]["precision"] == 1.0
    assert report["missed_attacks"] == [] and report["false_positives"] == []


def test_end_to_end_hard_cases_expose_rule_limits(db_conn, tmp_path):
    attacks, scopes = _load_synthetic(db_conn, tmp_path, days=5, seed=21, hard_cases=True)
    run_detection(db_conn, load_config())
    report = evaluate(attacks, scopes, fetch_alerts(db_conn))
    recall = report["recall_by_attack_type"]

    # Temel saldırılar yine yakalanır.
    for attack_type in ("brute_force", "password_spray", "success_after_failures", "off_hours_new_ip_login"):
        assert recall[attack_type]["recall"] == 1.0
    # Yavaş brute force eşiğin altında kalır.
    assert recall["slow_brute_force"] == {"attacks": 5, "detected": 0, "recall": 0.0}
    # Şifresini unutan kullanıcı brute_force kuralında yanlış alarm üretir.
    assert report["precision_by_rule"]["brute_force"]["false_positive"] == 5
    assert report["precision_by_rule"]["password_spray"]["precision"] == 1.0


def test_evaluate_matches_privilege_attacks_by_username():
    scopes = [(DAY, datetime(2026, 3, 2))]
    attack = {"attack_type": "su_bruteforce", "source_ip": None, "username": "dave",
              "start": DAY.replace(hour=3), "end": DAY.replace(hour=3, minute=2)}
    abuse = Alert("privilege_abuse", "high", None, "dave", DAY.replace(hour=3), DAY.replace(hour=3, minute=2), 8, 1)
    other_user = Alert("privilege_abuse", "high", None, "erin", DAY.replace(hour=3), DAY.replace(hour=3, minute=2), 8, 1)
    # Aynı hesap ve zaman olsa da SSH kuralının alarmı yetki saldırısıyla eşleşmez.
    ssh_rule = Alert("brute_force", "high", "203.0.113.1", "dave", DAY.replace(hour=3), DAY.replace(hour=3, minute=1), 40, 1)

    report = evaluate([attack], scopes, [abuse, other_user, ssh_rule])
    assert report["recall_by_attack_type"]["su_bruteforce"]["recall"] == 1.0
    assert report["precision_by_rule"]["privilege_abuse"] == {
        "alerts": 2, "true_positive": 1, "false_positive": 1, "precision": 0.5}
    assert report["precision_by_rule"]["brute_force"]["false_positive"] == 1


def test_end_to_end_privilege_escalation_is_detected(db_conn, tmp_path):
    attacks, scopes = _load_synthetic(db_conn, tmp_path, days=5, seed=42, privilege=True)
    summary = run_detection(db_conn, load_config())
    report = evaluate(attacks, scopes, fetch_alerts(db_conn))
    recall = report["recall_by_attack_type"]

    assert summary["privilege_events"] > 0
    assert recall["privilege_escalation"] == {"attacks": 5, "detected": 5, "recall": 1.0}
    assert recall["su_bruteforce"] == {"attacks": 5, "detected": 5, "recall": 1.0}
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts WHERE rule = 'escalation_chain' AND severity = 'critical'")
        assert cur.fetchone()[0] >= 5


def test_alerts_are_tagged_with_attack_techniques(db_conn, tmp_path):
    _load_synthetic(db_conn, tmp_path, days=5, seed=42, privilege=True)
    run_detection(db_conn, load_config())
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts WHERE mitre_tactic IS NULL OR cardinality(mitre_techniques) = 0")
        assert cur.fetchone()[0] == 0
        # Her teknik başvuru tablosunda adıyla bulunur (Grafana bu birleştirmeyle okur).
        cur.execute(
            "SELECT DISTINCT t FROM alerts, unnest(mitre_techniques) t "
            "WHERE t NOT IN (SELECT technique_id FROM attack_techniques)"
        )
        assert cur.fetchall() == []
        cur.execute("SELECT mitre_techniques FROM alerts WHERE rule = 'sensitive_command'")
        assert {t for (techniques,) in cur.fetchall() for t in techniques} >= {"T1003.008", "T1136.001"}


def _alert_rows(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT alert_hash, severity, window_end, attempt_count, distinct_users, details, mitre_techniques "
            "FROM alerts ORDER BY alert_hash"
        )
        return cur.fetchall()


def test_incremental_detection_matches_full_detection(db_conn, tmp_path):
    """Günlük yüklemelerden sonra artımlı tespit, bütün geçmişin tek seferde değerlendirilmesiyle aynı alarmları üretir.

    Bir gün sıradan geç gelir (geriye dönük yükleme); kimlik tabanlı filigran onu da yakalamalı.
    """
    lines, _ = generate(date(2026, 3, 1), days=6, seed=21, hard_cases=True, privilege=True)
    days: dict = {}
    for line in lines:
        days.setdefault(line[:6], []).append(line)
    order = list(days)
    order[2], order[3] = order[3], order[2]

    modes = []
    for i, day in enumerate(order):
        path = tmp_path / f"day_{i}.log"
        path.write_text("\n".join(days[day]) + "\n", encoding="utf-8", newline="\n")
        run_pipeline(path, 2026, db_conn, tmp_path / "processed", NOW)
        summary = run_detection(db_conn, load_config())
        modes.append(summary["mode"])
        if i:
            # Artımlı çalıştırma bütün geçmişi değil, yeni günü ve öncesindeki pencereyi okur.
            assert summary["events"] < sum(len(days[d]) for d in order[:i + 1])

    incremental = _alert_rows(db_conn)
    run_detection(db_conn, load_config(), reset=True)
    full = _alert_rows(db_conn)

    assert modes == ["full"] + ["incremental"] * (len(order) - 1)
    assert len(full) > 30
    assert incremental == full
