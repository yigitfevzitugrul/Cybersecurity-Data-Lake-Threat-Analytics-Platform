-- Karantina: veri kalitesi kontrollerinden geçemeyen satırlar ve red sebepleri.
CREATE TABLE IF NOT EXISTS rejected_events (
    rejected_id   BIGSERIAL PRIMARY KEY,
    run_id        BIGINT      NOT NULL REFERENCES pipeline_runs (run_id),
    source_file   TEXT        NOT NULL,
    file_sha256   CHAR(64)    NOT NULL,
    line_no       INTEGER     NOT NULL,
    raw_line      TEXT        NOT NULL,
    reject_reason TEXT        NOT NULL,
    reject_detail TEXT,
    rejected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Aynı dosya tekrar işlenirse aynı satır karantinaya ikinci kez yazılmaz.
    UNIQUE (file_sha256, line_no)
);

CREATE INDEX IF NOT EXISTS idx_rejected_events_reason ON rejected_events (reject_reason);
