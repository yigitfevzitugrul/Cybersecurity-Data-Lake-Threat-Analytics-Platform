-- Her olayı, onu ilk yükleyen pipeline çalıştırmasına bağlar (lineage).
-- Seviye 1'de pipeline_runs olmadan yüklenen eski kayıtlarda NULL kalır.
ALTER TABLE auth_events
    ADD COLUMN IF NOT EXISTS run_id BIGINT REFERENCES pipeline_runs (run_id);
