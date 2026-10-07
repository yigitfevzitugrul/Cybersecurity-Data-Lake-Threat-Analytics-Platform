-- Ayrıştırılmış kimlik doğrulama olayları (başarılı / başarısız SSH girişleri).
CREATE TABLE IF NOT EXISTS auth_events (
    event_id        BIGSERIAL PRIMARY KEY,
    -- Aynı olayın tekrar yüklenmesini engeller (idempotent yükleme anahtarı).
    event_hash      CHAR(64)    NOT NULL UNIQUE,
    event_time      TIMESTAMP   NOT NULL,
    host            TEXT        NOT NULL,
    pid             INTEGER,
    event_type      TEXT        NOT NULL CHECK (event_type IN ('login_failed', 'login_success')),
    auth_method     TEXT        NOT NULL,
    username        TEXT        NOT NULL,
    is_invalid_user BOOLEAN     NOT NULL,
    source_ip       INET        NOT NULL,
    source_port     INTEGER     NOT NULL CHECK (source_port BETWEEN 0 AND 65535),
    -- syslog "message repeated N times" satırları tek olay + deneme sayısı olarak tutulur.
    repeat_count    INTEGER     NOT NULL DEFAULT 1 CHECK (repeat_count >= 1),
    source_file     TEXT        NOT NULL,
    line_no         INTEGER     NOT NULL,
    raw_line        TEXT        NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_events_time ON auth_events (event_time);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_time ON auth_events (source_ip, event_time);
