import uuid

import psycopg2
import pytest

from src.utils.db import apply_schema, get_connection


@pytest.fixture
def db_conn():
    """Geçici bir şemada boş tablolarla bağlantı verir; test bitince şema silinir.

    Geliştirme verisine dokunmaz. Veritabanına ulaşılamıyorsa test atlanır.
    """
    try:
        conn = get_connection()
    except (psycopg2.OperationalError, KeyError) as exc:
        pytest.skip(f"PostgreSQL'e bağlanılamadı: {exc}")

    schema = f"test_{uuid.uuid4().hex[:12]}"
    with conn.cursor() as cur:
        cur.execute(f"CREATE SCHEMA {schema}")
        cur.execute(f"SET search_path TO {schema}")
    conn.commit()
    apply_schema(conn)
    try:
        yield conn
    finally:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(f"DROP SCHEMA {schema} CASCADE")
        conn.commit()
        conn.close()
