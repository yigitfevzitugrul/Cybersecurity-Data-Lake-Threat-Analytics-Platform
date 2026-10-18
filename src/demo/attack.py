"""Sunum için tek komutla saldırı senaryosu: log üret → ETL → tespit → Grafana'yı aç.

    python -m src.demo.attack            # bugünün tarihiyle
    python -m src.demo.attack --no-open  # tarayıcıyı açma

Her çalıştırma yeni bir seed ve dosya adı kullanır; böylece olaylar her seferinde
yenidir, yeni alarmlar oluşur ve critical olanlar (alerting eklentisi açıksa) Telegram'a gider.
"""

import argparse
import subprocess
import sys
import webbrowser
from datetime import datetime

DASHBOARD_URL = "http://localhost:3000/d/secdl-security-overview?from=now%2Fd&to=now%2Fd"


def _run(title: str, args: list[str]) -> None:
    print(f"\n=== {title} ===", flush=True)
    result = subprocess.run([sys.executable, "-m", *args])
    if result.returncode != 0:
        sys.exit(f"\n'{title}' adımı başarısız oldu (çıkış kodu {result.returncode}).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-open", action="store_true", help="Grafana'yı tarayıcıda açma")
    args = ap.parse_args()

    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    seed = int(now.strftime("%H%M%S"))
    out = f"data/raw/demo_{stamp}.log"

    _run("1/3 Saldırı içeren log üretiliyor", [
        "src.generator.generate", "--start-date", now.strftime("%Y-%m-%d"), "--days", "1",
        "--seed", str(seed), "--bad-ratio", "0.02", "--hard-cases", "--privilege", "--out", out,
    ])
    _run("2/3 ETL (extract → transform → validate → load)", ["src.etl.pipeline", out])
    _run("3/3 Tehdit tespiti", ["src.detection.engine"])

    print("\nBitti. Critical alarmlar 1-2 dakika içinde Telegram'a düşer (alerting eklentisi açıksa).")
    print("Not: günün ileri saatlerine düşen saldırılar o saat gelince Grafana'da görünür.")
    if not args.no_open:
        webbrowser.open(DASHBOARD_URL)


if __name__ == "__main__":
    main()
