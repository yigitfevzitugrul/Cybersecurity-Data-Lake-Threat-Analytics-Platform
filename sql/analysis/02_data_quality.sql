-- Seviye 2 veri kalitesi ve pipeline denetim sorguları.

\echo '1) Pipeline calistirmalari'
SELECT run_id, source_file, status,
       ROUND(EXTRACT(EPOCH FROM finished_at - started_at)::numeric, 2) AS sure_sn,
       lines_read, lines_irrelevant, lines_rejected,
       events_valid, events_loaded, events_skipped_existing
FROM pipeline_runs
ORDER BY run_id;

\echo '2) Sayim tutarliligi (her basarili calistirmada tutarli = t olmali)'
SELECT run_id,
       lines_read = lines_irrelevant + lines_rejected + events_valid
           AND events_valid = events_loaded + events_skipped_existing AS tutarli
FROM pipeline_runs
WHERE status = 'success'
ORDER BY run_id;

\echo '3) Dosya bazinda red orani (dosyanin en son basarili calistirmasi)'
SELECT DISTINCT ON (source_file)
       source_file, lines_read, lines_rejected,
       ROUND(100.0 * lines_rejected / NULLIF(lines_read, 0), 2) AS red_yuzde
FROM pipeline_runs
WHERE status = 'success'
ORDER BY source_file, run_id DESC;

\echo '4) Red sebeplerine gore karantina'
SELECT source_file, reject_reason, COUNT(*) AS adet
FROM rejected_events
GROUP BY source_file, reject_reason
ORDER BY source_file, adet DESC, reject_reason;

\echo '5) Her red sebebinden ornek satir'
SELECT DISTINCT ON (reject_reason)
       reject_reason, reject_detail, LEFT(raw_line, 90) AS ornek
FROM rejected_events
ORDER BY reject_reason, rejected_id;

\echo '6) Yuklenen olaylarda kalite kontrolu (hepsi 0 olmali)'
SELECT COUNT(*) FILTER (WHERE username = '')                     AS bos_kullanici,
       COUNT(*) FILTER (WHERE source_port NOT BETWEEN 1 AND 65535) AS gecersiz_port,
       COUNT(*) FILTER (WHERE event_time > now() + interval '1 day') AS gelecek_zaman,
       COUNT(*) - COUNT(DISTINCT event_hash)                     AS tekrar_eden
FROM auth_events;
