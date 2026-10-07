"""PostgreSQL bağlantı yardımcıları. Ayarlar .env dosyasından okunur."""
import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "sql" / "schema"


def get_connection():
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=os.environ["POSTGRES_PORT"],
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def apply_schema(conn) -> list[str]:
    """sql/schema altındaki dosyaları isim sırasıyla çalıştırır. Tekrar çalıştırmak güvenlidir."""
    applied = []
    with conn.cursor() as cur:
        for path in sorted(SCHEMA_DIR.glob("*.sql")):
            cur.execute(path.read_text(encoding="utf-8"))
            applied.append(path.name)
    conn.commit()
    return applied


if __name__ == "__main__":
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            print("Bağlantı başarılı:", cur.fetchone()[0])
        print("Şema uygulandı:", ", ".join(apply_schema(conn)))
    finally:
        conn.close()
