"""Tespit doğruluğunu sentetik üretecin etiketlerine (ground truth) karşı ölçer.

Tanımlar:
  - Kapsam     : etiket dosyalarının kapsadığı günler. Etiketi olmayan veriye
                 (ör. Loghub) ait alarmlar ölçüme girmez.
  - Eşleşme    : alarm ile saldırının kaynak IP'si aynı ve zaman aralıkları kesişiyor.
  - Recall     : (saldırı tipi başına) beklenen kuralla yakalanan saldırı oranı.
  - Precision  : (kural başına) etiketli bir saldırıyla eşleşen alarm oranı.

Kullanım:
    python -m src.detection.evaluate
"""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from src.detection.rules import AUTH_ANOMALY, BRUTE_FORCE, PASSWORD_SPRAY, Alert
from src.utils.db import get_connection

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
RAW_DIR = DATA_DIR / "raw"
REPORT_PATH = DATA_DIR / "curated" / "detection_evaluation.json"

# Her saldırı tipini yakalaması beklenen kural.
EXPECTED_RULE = {
    "brute_force": BRUTE_FORCE,
    "password_spray": PASSWORD_SPRAY,
    "success_after_failures": AUTH_ANOMALY,
    "off_hours_new_ip_login": AUTH_ANOMALY,
    "slow_brute_force": BRUTE_FORCE,
}
MATCH_TOLERANCE = timedelta(seconds=60)


def load_labels(paths: Iterable[Path]) -> tuple[list[dict], list[tuple[datetime, datetime]]]:
    """(saldırılar, kapsam aralıkları) döndürür. Aynı saldırı birden çok dosyada varsa bir kez sayılır."""
    attacks: dict[tuple, dict] = {}
    scopes = []
    for path in sorted(paths):
        labels = json.loads(Path(path).read_text(encoding="utf-8"))
        start = datetime.fromisoformat(labels["start_date"])
        scopes.append((start, start + timedelta(days=labels["days"])))
        for attack in labels["attacks"]:
            record = {
                "attack_type": attack["attack_type"],
                "source_ip": attack["source_ip"],
                "start": datetime.fromisoformat(attack["start_time"]),
                "end": datetime.fromisoformat(attack["end_time"]),
            }
            attacks[(record["attack_type"], record["source_ip"], record["start"])] = record
    return list(attacks.values()), scopes


def _matches(alert: Alert, attack: dict) -> bool:
    return (
        alert.source_ip == attack["source_ip"]
        and alert.window_start <= attack["end"] + MATCH_TOLERANCE
        and alert.window_end >= attack["start"] - MATCH_TOLERANCE
    )


def _ratio(part: int, whole: int):
    return round(part / whole, 4) if whole else None


def evaluate(attacks: list[dict], scopes: list[tuple[datetime, datetime]], alerts: list[Alert]) -> dict:
    in_scope = [a for a in alerts if any(start <= a.window_start < end for start, end in scopes)]

    recall = defaultdict(lambda: {"attacks": 0, "detected": 0})
    missed = []
    detected_by_any_rule = 0
    for attack in attacks:
        matching = [a for a in in_scope if _matches(a, attack)]
        detected_by_any_rule += bool(matching)
        row = recall[attack["attack_type"]]
        row["attacks"] += 1
        if any(a.rule == EXPECTED_RULE[attack["attack_type"]] for a in matching):
            row["detected"] += 1
        else:
            missed.append({
                "attack_type": attack["attack_type"],
                "source_ip": attack["source_ip"],
                "start": attack["start"].isoformat(),
            })
    for row in recall.values():
        row["recall"] = _ratio(row["detected"], row["attacks"])

    precision = defaultdict(lambda: {"alerts": 0, "true_positive": 0, "false_positive": 0})
    false_positives = []
    for alert in in_scope:
        row = precision[alert.rule]
        row["alerts"] += 1
        if any(_matches(alert, attack) for attack in attacks):
            row["true_positive"] += 1
        else:
            row["false_positive"] += 1
            false_positives.append({
                "rule": alert.rule,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "username": alert.username,
                "window_start": alert.window_start.isoformat(),
            })
    for row in precision.values():
        row["precision"] = _ratio(row["true_positive"], row["alerts"])

    total_detected = sum(row["detected"] for row in recall.values())
    total_tp = sum(row["true_positive"] for row in precision.values())
    urgent = [a for a in in_scope if a.severity in ("high", "critical")]
    urgent_tp = sum(1 for a in urgent if any(_matches(a, attack) for attack in attacks))
    return {
        "scope_days": sum((end - start).days for start, end in scopes),
        "attacks": len(attacks),
        "alerts_in_scope": len(in_scope),
        "overall": {
            "recall": _ratio(total_detected, len(attacks)),
            "detected_by_any_rule": _ratio(detected_by_any_rule, len(attacks)),
            "precision": _ratio(total_tp, len(in_scope)),
            # Sadece high / critical alarmlar: bir analistin ilk bakacağı alarmlar.
            "high_critical_alerts": len(urgent),
            "high_critical_precision": _ratio(urgent_tp, len(urgent)),
        },
        "recall_by_attack_type": {k: dict(v) for k, v in sorted(recall.items())},
        "precision_by_rule": {k: dict(v) for k, v in sorted(precision.items())},
        "missed_attacks": missed,
        "false_positives": false_positives,
    }


def fetch_alerts(conn) -> list[Alert]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT rule, severity, host(source_ip), username, window_start, window_end, "
            "attempt_count, distinct_users, details FROM alerts ORDER BY window_start, alert_id"
        )
        alerts = [Alert(*row) for row in cur.fetchall()]
    conn.commit()
    return alerts


def _pct(value) -> str:
    return "—" if value is None else f"%{100 * value:.1f}"


def print_report(report: dict) -> None:
    print(f"Kapsam: {report['scope_days']} gün, {report['attacks']} etiketli saldırı, "
          f"{report['alerts_in_scope']} alarm")
    print("\nRecall (saldırı tipi → beklenen kural)")
    for attack_type, row in report["recall_by_attack_type"].items():
        print(f"  {attack_type:<24} → {EXPECTED_RULE[attack_type]:<15} "
              f"{row['detected']:>3}/{row['attacks']:<3} {_pct(row['recall'])}")
    print("\nPrecision (kural başına)")
    for rule, row in report["precision_by_rule"].items():
        print(f"  {rule:<15} {row['true_positive']:>3}/{row['alerts']:<3} {_pct(row['precision'])}"
              f"   (yanlış alarm: {row['false_positive']})")
    overall = report["overall"]
    print(f"\nGenel: recall {_pct(overall['recall'])}, precision {_pct(overall['precision'])}, "
          f"herhangi bir kuralla yakalanan {_pct(overall['detected_by_any_rule'])}")
    print(f"       high/critical alarmlarda precision {_pct(overall['high_critical_precision'])} "
          f"({overall['high_critical_alerts']} alarm)")
    for title, items in (("Kaçan saldırılar", report["missed_attacks"]),
                         ("Yanlış alarmlar", report["false_positives"])):
        if items:
            print(f"\n{title}: {len(items)} (tam liste raporda)")
            for item in items[:3]:
                print("  " + ", ".join(f"{k}={v}" for k, v in item.items()))


def main() -> None:
    ap = argparse.ArgumentParser(description="Alarmları sentetik etiketlere karşı değerlendirir.")
    ap.add_argument("--labels-dir", type=Path, default=RAW_DIR)
    ap.add_argument("--out", type=Path, default=REPORT_PATH)
    args = ap.parse_args()

    attacks, scopes = load_labels(args.labels_dir.glob("*_labels.json"))
    conn = get_connection()
    try:
        alerts = fetch_alerts(conn)
    finally:
        conn.close()

    report = evaluate(attacks, scopes, alerts)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print_report(report)
    print(f"\nRapor: {args.out}")


if __name__ == "__main__":
    main()
