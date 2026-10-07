"""PostgreSQL bağlantı yardımcıları. Ayarlar .env dosyasından okunur."""
import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=os.environ["POSTGRES_PORT"],
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


if __name__ == "__main__":
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT version()")
        print("Bağlantı başarılı:", cur.fetchone()[0])
