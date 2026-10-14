"""IP konum zenginleştirmesi; gerçek veritabanı yerine sahte bir okuyucu kullanılır."""
from datetime import date, datetime

from src.enrichment.download_geoip import candidate_months
from src.enrichment.geoip import GeoRecord, enrich, lookup, to_record
from src.etl.pipeline import run_pipeline

BEIJING = {
    "city": {"names": {"en": "Beijing"}},
    "country": {"iso_code": "CN", "names": {"en": "China", "de": "China, Volksrepublik"}},
    "location": {"latitude": 39.9042, "longitude": 116.407},
}


class FakeReader:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def get(self, ip):
        self.calls.append(ip)
        return self.records.get(ip)


def test_to_record_reads_city_database_structure():
    assert to_record("183.62.140.253", BEIJING) == GeoRecord(
        "183.62.140.253", True, "CN", "China", "Beijing", 39.9042, 116.407)


def test_partial_and_missing_records():
    assert to_record("1.1.1.1", None) == GeoRecord("1.1.1.1", True)
    assert to_record("1.1.1.1", {"country": {"iso_code": "AU"}}) == GeoRecord("1.1.1.1", True, "AU")


def test_private_and_reserved_addresses_are_not_looked_up():
    reader = FakeReader({})
    for ip in ("10.20.0.10", "192.0.2.10", "198.51.100.7", "203.0.113.9", "100.64.0.5", "127.0.0.1", "fe80::1"):
        assert lookup(reader, ip) == GeoRecord(ip, False)
    assert reader.calls == []


def test_candidate_months_falls_back_to_previous_month():
    assert candidate_months(date(2026, 10, 2)) == ["2026-10", "2026-09"]
    assert candidate_months(date(2027, 1, 3)) == ["2027-01", "2026-12"]


LOG = "\n".join([
    "Mar  1 10:00:00 srv sshd[1]: Failed password for root from 183.62.140.253 port 4000 ssh2",
    "Mar  1 10:00:05 srv sshd[2]: Failed password for root from 183.62.140.253 port 4001 ssh2",
    "Mar  1 10:01:00 srv sshd[3]: Failed password for admin from 192.0.2.10 port 4002 ssh2",
    "Mar  1 10:02:00 srv sshd[4]: Accepted password for alice from 10.20.0.10 port 4003 ssh2",
    "Mar  1 10:03:00 srv sshd[5]: Failed password for root from 8.8.4.4 port 4004 ssh2",
]) + "\n"


def test_enrich_resolves_each_ip_once(db_conn, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(LOG, encoding="utf-8", newline="\n")
    run_pipeline(log, 2026, db_conn, tmp_path / "processed", datetime(2026, 12, 31))
    reader = FakeReader({"183.62.140.253": BEIJING})

    first = enrich(db_conn, reader, "2026-10")
    assert first == {"looked_up": 4, "located": 1, "not_global": 2, "unknown": 1}
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT host(ip), is_global, country_code, city, latitude, db_version FROM ip_geolocation ORDER BY ip"
        )
        assert cur.fetchall() == [
            ("8.8.4.4", True, None, None, None, "2026-10"),
            ("10.20.0.10", False, None, None, None, "2026-10"),
            ("183.62.140.253", True, "CN", "Beijing", 39.9042, "2026-10"),
            ("192.0.2.10", False, None, None, None, "2026-10"),
        ]

    assert enrich(db_conn, reader, "2026-10")["looked_up"] == 0
    reader.records["8.8.4.4"] = {"country": {"iso_code": "US", "names": {"en": "United States"}}}
    refreshed = enrich(db_conn, reader, "2026-11", refresh=True)
    assert (refreshed["looked_up"], refreshed["located"]) == (4, 2)
    with db_conn.cursor() as cur:
        cur.execute("SELECT country_code, db_version FROM ip_geolocation WHERE ip = '8.8.4.4'")
        assert cur.fetchone() == ("US", "2026-11")
