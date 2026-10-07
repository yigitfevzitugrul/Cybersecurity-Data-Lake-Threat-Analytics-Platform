-- Her pipeline çalıştırmasının denetim (audit) kaydı.
-- Başarılı bir çalıştırmada:
--   lines_read    = lines_irrelevant + lines_rejected + events_valid
--   events_valid  = events_loaded + events_skipped_existing
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id                  BIGSERIAL PRIMARY KEY,
    source_file             TEXT        NOT NULL,
    file_sha256             CHAR(64)    NOT NULL,
    status                  TEXT        NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at             TIMESTAMPTZ,
    lines_read              INTEGER,
    lines_irrelevant        INTEGER,
    lines_rejected          INTEGER,
    events_valid            INTEGER,
    events_loaded           INTEGER,
    events_skipped_existing INTEGER,
    error_message           TEXT
);
