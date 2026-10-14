"""DB-IP "IP to City Lite" veritabanını indirir (ücretsiz, hesap gerektirmez).

Lisans: Creative Commons Attribution 4.0. Veriyi gösteren her yerde
"IP Geolocation by DB-IP" (https://db-ip.com) atfı bulunmalıdır.

Kullanım:
    python -m src.enrichment.download_geoip
"""
import gzip
import json
import shutil
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

REFERENCE_DIR = Path(__file__).resolve().parents[2] / "data" / "reference"
DB_PATH = REFERENCE_DIR / "dbip-city-lite.mmdb"
INFO_PATH = REFERENCE_DIR / "dbip-city-lite.json"
URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"


def candidate_months(today: date) -> list[str]:
    """Bu ay ve önceki ay: yeni ayın dosyası ilk günlerde henüz yayımlanmamış olabilir."""
    previous = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    return [f"{today:%Y-%m}", f"{previous:%Y-%m}"]


def download(today: date = None) -> dict:
    REFERENCE_DIR.mkdir(parents=True, exist_ok=True)
    errors = []
    for month in candidate_months(today or date.today()):
        url = URL.format(month=month)
        tmp = DB_PATH.with_suffix(".mmdb.part")
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "secdl-geoip-download"})
            with urllib.request.urlopen(request, timeout=120) as response, \
                    gzip.GzipFile(fileobj=response) as compressed, open(tmp, "wb") as out:
                shutil.copyfileobj(compressed, out, length=1024 * 1024)
        except (urllib.error.URLError, OSError) as exc:
            errors.append(f"{month}: {exc}")
            tmp.unlink(missing_ok=True)
            continue
        tmp.replace(DB_PATH)
        info = {"source": url, "version": month, "attribution": ATTRIBUTION, "downloaded": date.today().isoformat()}
        INFO_PATH.write_text(json.dumps(info, indent=2), encoding="utf-8")
        return info
    raise RuntimeError("DB-IP veritabanı indirilemedi: " + "; ".join(errors))


def main() -> None:
    info = download()
    size_mb = DB_PATH.stat().st_size / 1024 / 1024
    print(f"İndirildi: {DB_PATH} ({size_mb:.0f} MB, sürüm {info['version']})")
    print(f"Atıf     : {ATTRIBUTION}")


if __name__ == "__main__":
    main()
