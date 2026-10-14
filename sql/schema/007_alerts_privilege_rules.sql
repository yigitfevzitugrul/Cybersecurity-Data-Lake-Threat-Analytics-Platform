-- Yetki yükseltme kuralları için alerts tablosu: sudo / su alarmlarında kaynak IP yoktur
-- ve kural listesi genişler. Tekrar çalıştırmak güvenlidir.
ALTER TABLE alerts ALTER COLUMN source_ip DROP NOT NULL;

ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_rule_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_rule_check CHECK (rule IN (
    'brute_force', 'password_spray', 'suspicious_ip', 'auth_anomaly',
    'privilege_abuse', 'sensitive_command', 'escalation_chain'
));

CREATE INDEX IF NOT EXISTS idx_alerts_username ON alerts (username);
