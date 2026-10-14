-- MITRE ATT&CK eşlemesi: her alarmın taktiği ve teknikleri, tekniklerin adları için başvuru tablosu.
-- Eşleme src/detection/mitre.py içindedir; tespit motoru her çalıştırmada ikisini de günceller.
-- Tekrar çalıştırmak güvenlidir.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_alerts_mitre_techniques ON alerts USING GIN (mitre_techniques);

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id TEXT PRIMARY KEY,   -- ör. T1110.001
    name         TEXT NOT NULL,
    tactic_id    TEXT NOT NULL,      -- ör. TA0006
    tactic       TEXT NOT NULL,      -- bu projedeki bağlamına uyan taktik
    url          TEXT NOT NULL
);
