-- Seviye 1 temel analiz sorguları. Deneme sayıları repeat_count üzerinden toplanır.

\echo '1) Olay tipine gore ozet'
SELECT event_type,
       COUNT(*)          AS satir,
       SUM(repeat_count) AS deneme,
       MIN(event_time)   AS ilk,
       MAX(event_time)   AS son
FROM auth_events
GROUP BY event_type
ORDER BY deneme DESC;

\echo '2) En cok basarisiz deneme yapan 10 IP'
SELECT source_ip,
       SUM(repeat_count)        AS deneme,
       COUNT(DISTINCT username) AS farkli_kullanici,
       MIN(event_time)          AS ilk,
       MAX(event_time)          AS son
FROM auth_events
WHERE event_type = 'login_failed'
GROUP BY source_ip
ORDER BY deneme DESC
LIMIT 10;

\echo '3) En cok hedeflenen 10 kullanici adi'
SELECT username,
       is_invalid_user,
       SUM(repeat_count)         AS deneme,
       COUNT(DISTINCT source_ip) AS farkli_ip
FROM auth_events
WHERE event_type = 'login_failed'
GROUP BY username, is_invalid_user
ORDER BY deneme DESC
LIMIT 10;

\echo '4) Gecerli / gecersiz kullanici dagilimi (basarisiz denemeler)'
SELECT is_invalid_user,
       SUM(repeat_count) AS deneme,
       ROUND(100.0 * SUM(repeat_count) / SUM(SUM(repeat_count)) OVER (), 1) AS yuzde
FROM auth_events
WHERE event_type = 'login_failed'
GROUP BY is_invalid_user;

\echo '5) Saatlik basarisiz deneme dagilimi'
SELECT date_trunc('hour', event_time) AS saat,
       SUM(repeat_count)              AS deneme,
       COUNT(DISTINCT source_ip)      AS farkli_ip
FROM auth_events
WHERE event_type = 'login_failed'
GROUP BY saat
ORDER BY saat;

\echo '6) Basarili girisler ve ayni IP''den onceki basarisiz deneme sayisi'
SELECT s.event_time, s.username, s.source_ip, s.auth_method,
       COALESCE((SELECT SUM(f.repeat_count)
                 FROM auth_events f
                 WHERE f.event_type = 'login_failed'
                   AND f.source_ip = s.source_ip
                   AND f.event_time < s.event_time), 0) AS onceki_basarisiz
FROM auth_events s
WHERE s.event_type = 'login_success'
ORDER BY s.event_time;
