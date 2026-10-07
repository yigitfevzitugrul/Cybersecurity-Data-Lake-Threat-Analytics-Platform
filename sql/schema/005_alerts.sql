-- Tespit kurallarının ürettiği alarmlar.
CREATE TABLE IF NOT EXISTS alerts (
    alert_id          BIGSERIAL PRIMARY KEY,
    -- Alarmın kimliği: kural + IP + kullanıcı + pencere başlangıcı. Tespit tekrar
    -- çalıştığında aynı alarm yeniden eklenmez, güncellenir.
    alert_hash        CHAR(64)    NOT NULL UNIQUE,
    rule              TEXT        NOT NULL
                      CHECK (rule IN ('brute_force', 'password_spray', 'suspicious_ip', 'auth_anomaly')),
    severity          TEXT        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source_ip         INET        NOT NULL,
    username          TEXT,       -- birden çok kullanıcı hedeflendiyse NULL
    window_start      TIMESTAMP   NOT NULL,
    window_end        TIMESTAMP   NOT NULL,
    attempt_count     INTEGER     NOT NULL,
    distinct_users    INTEGER     NOT NULL,
    details           JSONB       NOT NULL DEFAULT '{}',
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_window_start ON alerts (window_start);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
