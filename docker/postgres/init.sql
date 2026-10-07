-- db-init servisi her `docker compose up` çalıştırmasında bunu uygular; tekrar çalıştırmak güvenlidir.
-- Değişkenler (grafana_user, grafana_password, app_db) psql -v ile verilir.

-- Airflow'un kendi metadata veritabanı (uygulama verisinden ayrı).
SELECT 'CREATE DATABASE airflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'airflow') \gexec

-- Grafana için salt-okunur rol (en az yetki): sadece SELECT.
SELECT format('CREATE ROLE %I LOGIN', :'grafana_user')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'grafana_user') \gexec

ALTER ROLE :"grafana_user" PASSWORD :'grafana_password';
GRANT CONNECT ON DATABASE :"app_db" TO :"grafana_user";
GRANT USAGE ON SCHEMA public TO :"grafana_user";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"grafana_user";
-- Sonradan oluşturulacak tablolar için de geçerli olsun.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO :"grafana_user";
