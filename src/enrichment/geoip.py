"""Kaynak IP'leri ülke, şehir ve koordinatla eşleştirir (DB-IP Lite, çevrimdışı).

IP'ler dışarıdaki bir servise gönderilmez; yerel veritabanı dosyasından okunur.
Her IP bir kez çözülür; --refresh veritabanı güncellendiğinde hepsini yeniden çözer.

Kullanım:
    python -m src.enrichment.download_geoip   # bir kez: veritabanını indir
    python -m src.enrichment.geoip [--refresh]
"""
import argparse
import ipaddress
import json
import sys
from dataclasses import astuple, dataclass
from pathlib import Path
from typing import Optional

from psycopg2.extras import execute_values

from src.enrichment.download_geoip import ATTRIBUTION, DB_PATH, INFO_PATH
from src.utils.db import apply_schema, get_connection

PENDING_SQL = """
    SELECT DISTINCT host(ip) FROM (
        SELECT source_ip AS ip FROM auth_events
        UNION
        SELECT source_ip FROM alerts WHERE source_ip IS NOT NULL
    ) ips
    WHERE %(refresh)s OR NOT EXISTS (SELECT 1 FROM ip_geolocation g WHERE g.ip = ips.ip)
    ORDER BY 1
"""

UPSERT_SQL = """
    INSERT INTO ip_geolocation (ip, is_global, country_code, country_name, city, latitude, longitude, db_version)
    VALUES %s
    ON CONFLICT (ip) DO UPDATE SET
        is_global = EXCLUDED.is_global, country_code = EXCLUDED.country_code,
        country_name = EXCLUDED.country_name, city = EXCLUDED.city,
        latitude = EXCLUDED.latitude, longitude = EXCLUDED.longitude,
        db_version = EXCLUDED.db_version, looked_up_at = now()
"""


@dataclass(frozen=True)
class GeoRecord:
    ip: str
    is_global: bool
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


def to_record(ip: str, raw: Optional[dict]) -> GeoRecord:
    """Veritabanı kaydını (GeoIP2 City yapısı) düz bir kayda çevirir."""
    if not raw:
        return GeoRecord(ip, True)
    country = raw.get("country") or {}
    location = raw.get("location") or {}
    return GeoRecord(
        ip=ip,
        is_global=True,
        country_code=country.get("iso_code"),
        country_name=(country.get("names") or {}).get("en"),
        city=((raw.get("city") or {}).get("names") or {}).get("en"),
        latitude=location.get("latitude"),
        longitude=location.get("longitude"),
    )


def lookup(reader, ip: str) -> GeoRecord:
    """`reader`: .get(ip) → dict | None sunan herhangi bir nesne (maxminddb okuyucusu)."""
    if not ipaddress.ip_address(ip).is_global:
        return GeoRecord(ip, False)
    return to_record(ip, reader.get(ip))


def enrich(conn, reader, db_version: str, refresh: bool = False) -> dict:
    with conn.cursor() as cur:
        cur.execute(PENDING_SQL, {"refresh": refresh})
        ips = [row[0] for row in cur.fetchall()]
    records = [lookup(reader, ip) for ip in ips]
    if records:
        with conn.cursor() as cur:
            execute_values(cur, UPSERT_SQL, [astuple(r) + (db_version,) for r in records], page_size=1000)
    conn.commit()
    return {
        "looked_up": len(records),
        "located": sum(1 for r in records if r.country_code),
        "not_global": sum(1 for r in records if not r.is_global),
        "unknown": sum(1 for r in records if r.is_global and not r.country_code),
    }


def open_reader(path: Path = DB_PATH):
    import maxminddb

    version = json.loads(INFO_PATH.read_text(encoding="utf-8"))["version"] if INFO_PATH.exists() else "unknown"
    return maxminddb.open_database(str(path)), version


def main() -> None:
    ap = argparse.ArgumentParser(description="Kaynak IP'leri coğrafi konumla eşleştirir.")
    ap.add_argument("--refresh", action="store_true", help="Daha önce çözülmüş IP'leri de yeniden çöz")
    args = ap.parse_args()
    if not DB_PATH.exists():
        print(f"{DB_PATH} yok. Önce: python -m src.enrichment.download_geoip")
        sys.exit(1)

    reader, version = open_reader()
    conn = get_connection()
    try:
        apply_schema(conn)
        result = enrich(conn, reader, version, args.refresh)
    finally:
        conn.close()
        reader.close()
    print(f"Çözülen IP: {result['looked_up']} (konumu bulunan {result['located']}, "
          f"özel/ayrılmış {result['not_global']}, bilinmeyen {result['unknown']})")
    print(f"Kaynak    : {ATTRIBUTION}, sürüm {version}")


if __name__ == "__main__":
    main()
