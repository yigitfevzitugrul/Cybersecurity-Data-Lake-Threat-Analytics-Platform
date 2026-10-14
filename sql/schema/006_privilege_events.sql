-- Yetki yükseltme girişimleri: sudo ve su kayıtları.
CREATE TABLE IF NOT EXISTS privilege_events (
    event_id     BIGSERIAL PRIMARY KEY,
    -- auth_events ile aynı kimlik: zaman (yıl dahil) + ham satır.
    event_hash   CHAR(64)    NOT NULL UNIQUE,
    event_time   TIMESTAMP   NOT NULL,
    host         TEXT        NOT NULL,
    pid          INTEGER,
    program      TEXT        NOT NULL CHECK (program IN ('sudo', 'su')),
    event_type   TEXT        NOT NULL CHECK (event_type IN (
                     'sudo_command', 'sudo_auth_failure', 'sudo_not_allowed', 'su_success', 'su_failure')),
    username     TEXT        NOT NULL,  -- yetki isteyen kullanıcı
    target_user  TEXT        NOT NULL,  -- olunmak istenen kullanıcı
    tty          TEXT,
    pwd          TEXT,
    command      TEXT,
    -- sudo'nun tek satırda bildirdiği yanlış parola sayısı; diğer olaylarda 1.
    attempts     INTEGER     NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    source_file  TEXT        NOT NULL,
    line_no      INTEGER     NOT NULL,
    raw_line     TEXT        NOT NULL,
    run_id       BIGINT      REFERENCES pipeline_runs (run_id),
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_privilege_events_time ON privilege_events (event_time);
CREATE INDEX IF NOT EXISTS idx_privilege_events_user_time ON privilege_events (username, event_time);
