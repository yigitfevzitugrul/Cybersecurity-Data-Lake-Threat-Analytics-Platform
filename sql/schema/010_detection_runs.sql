-- Tespit motorunun her çalıştırması: denetim kaydı ve artımlı tespitin kaldığı yer.
-- Bir çalıştırma alarmlarla aynı transaction'da yazılır; satırın varlığı başarılı olduğunu gösterir.
-- Tekrar çalıştırmak güvenlidir.
CREATE TABLE IF NOT EXISTS detection_runs (
    run_id                     BIGSERIAL PRIMARY KEY,
    mode                       TEXT        NOT NULL CHECK (mode IN ('full', 'incremental')),
    started_at                 TIMESTAMPTZ NOT NULL,
    finished_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms                INTEGER     NOT NULL,
    -- Değerlendirilen en eski olay zamanı; tam tespitte NULL (bütün geçmiş).
    eval_start                 TIMESTAMP,
    -- Bu çalıştırmanın gördüğü en büyük olay kimlikleri. Sonraki artımlı çalıştırma
    -- bunlardan büyük kimlikli olayları "yeni" sayar.
    auth_watermark             BIGINT      NOT NULL,
    privilege_watermark        BIGINT      NOT NULL,
    events_evaluated           INTEGER     NOT NULL,
    privilege_events_evaluated INTEGER     NOT NULL,
    alerts_written             INTEGER     NOT NULL,
    new_alerts                 INTEGER     NOT NULL
);
