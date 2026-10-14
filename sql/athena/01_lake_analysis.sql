-- Data lake üzerinde Athena analiz sorguları.
-- Çalıştırmak için: python -m src.cloud.athena sql/athena/01_lake_analysis.sql

-- Günlük olay ve deneme sayıları (processed katmanı)
SELECT event_date,
       COUNT(*) AS olay,
       SUM(repeat_count) AS deneme,
       COUNT(DISTINCT source_ip) AS farkli_ip
FROM auth_events
GROUP BY event_date
ORDER BY event_date;

-- Tek bir günün sorgusu: bölümleme sayesinde sadece o günün dosyası taranır
SELECT event_type, COUNT(*) AS olay, SUM(repeat_count) AS deneme
FROM auth_events
WHERE event_date = '2026-09-01'
GROUP BY event_type
ORDER BY event_type;

-- En çok başarısız deneme yapan IP'ler (curated katmanı)
SELECT source_ip,
       SUM(failed_attempts) AS basarisiz_deneme,
       SUM(successful_logins) AS basarili_giris,
       COUNT(*) AS aktif_gun
FROM daily_ip_summary
GROUP BY source_ip
ORDER BY basarisiz_deneme DESC
LIMIT 10;

-- Kural ve önem derecesine göre alarmlar (curated katmanı)
SELECT rule, severity, COUNT(*) AS alarm
FROM alerts
GROUP BY rule, severity
ORDER BY rule, severity;

-- Critical alarmlar ve o IP'nin aynı günkü toplam etkinliği (iki curated tablonun birleşimi)
SELECT a.window_start, a.rule, a.source_ip, a.username, a.attempt_count,
       s.failed_attempts AS gunluk_basarisiz, s.distinct_users AS gunluk_farkli_kullanici
FROM alerts a
JOIN daily_ip_summary s
  ON s.source_ip = a.source_ip AND s.event_date = CAST(a.window_start AS date)
WHERE a.severity = 'critical'
ORDER BY a.window_start DESC
LIMIT 10;

-- Yetki yükseltme girişimleri: kullanıcı ve olay türüne göre (processed katmanı)
SELECT username, event_type, COUNT(*) AS olay, SUM(attempts) AS deneme
FROM privilege_events
GROUP BY username, event_type
ORDER BY deneme DESC
LIMIT 20;

-- sudo ile çalıştırılan hassas komutlar ve aynı hesabın o gün aldığı alarmlar
-- (processed ve curated katmanlarının birleşimi)
SELECT p.event_time, p.username, p.command, a.rule, a.severity
FROM privilege_events p
JOIN alerts a
  ON a.username = p.username AND CAST(a.window_start AS date) = CAST(p.event_time AS date)
WHERE p.event_type = 'sudo_command'
  AND regexp_like(p.command, '/etc/shadow|/etc/sudoers|useradd|adduser')
ORDER BY p.event_time DESC
LIMIT 20;
