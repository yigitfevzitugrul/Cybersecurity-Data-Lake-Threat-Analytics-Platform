# Cybersecurity Data Lake & Threat Analytics Platform

Bu dosya Claude Code'un her oturum başında okuduğu proje hafızasıdır. Kararlar değiştikçe güncellenir.

## Proje bağlamı
- Bilişim Sistemleri Mühendisliği 4. sınıf bitirme projesi + GitHub portföy projesi.
- Hedef kariyer: Data Engineering + Cloud. Geliştiricinin ~3 yıl cybersecurity/red team geçmişi var.
- Amaç: Security/auth loglarını toplayan, ETL'den geçiren, veri kalitesini kontrol eden, AWS Data Lake'te depolayan, tehditleri tespit edip Grafana'da görselleştiren platform.
- Konuşma dili: Türkçe.

## Çalışma kuralları (önemli)
- Projeyi tek seferde yazma. Küçük, çalışan parçalar halinde ilerle.
- Her adımdan sonra geliştiricinin kendi makinesinde çalıştırıp doğrulamasını bekle, sonra sonraki adıma geç.
- Gereksiz teknoloji/karmaşıklık ekleme (Kubernetes, ileri ML yok; Kafka/Terraform sadece zaman kalırsa).
- Öncelik sırası: 1) çalışan sistem 2) tamamlanma 3) sunulabilirlik 4) akademik rapor 5) GitHub portföyü 6) öğrenme.
- Ortam: Windows + Docker Desktop (WSL2). Şifreler `.env`'de, git'e girmez.

## Mimari kararlar
- Yerel `data/raw`, `data/processed`, `data/curated` katmanları ilk günden; 5. haftada aynı mantık S3 prefix'lerine taşınır.
- PostgreSQL 1. haftadan Docker'da çalışır (Windows'a native kurulum yok). Airflow + Grafana 3. haftada compose'a eklenir.
- Veri kaynağı: Loghub OpenSSH gerçek logları + kendi sentetik log üretecimiz (gömülü saldırılarla; tespit doğruluğu ölçülebilsin diye).
- Tablolar: `auth_events`, `rejected_events` (karantina + red sebebi), `pipeline_runs` (audit), `alerts`.
- Tespit kuralları rule-based, eşikler `config/detection_rules.yaml`'da:
  - Brute Force: aynı IP → aynı kullanıcı, kısa pencerede çok başarısız deneme
  - Password Spraying: aynı IP → çok farklı kullanıcı, her birine az deneme
  - Suspicious IP: invalid user / root denemeleri, çok host
  - Auth Anomaly: olağandışı saat, kullanıcı için yeni IP, çok başarısızlık sonrası başarılı giriş
- Data quality: duplicate, null/missing, invalid IP, timestamp, schema validation, error handling, logging.

## Seviyeler
1. Temel: Linux auth logları → Python parser → PostgreSQL → SQL analiz
2. ETL: extract / transform / validate / load, karantina, idempotent yükleme, pytest
3. Docker Compose + Airflow DAG + Grafana
4. Security analytics: 4 tespit kuralı, `alerts`, güvenlik dashboard'u, doğruluk ölçümü (MVP)
5. AWS: S3 raw/processed/curated (Parquet), IAM en az yetki, Glue, Athena, Budgets alarmı
6. Opsiyonel: PySpark

## Klasör yapısı
```
README.md, docker-compose.yml, .env.example, requirements.txt, .gitignore
config/detection_rules.yaml
data/{raw,processed,curated}/      (git'e girmez)
src/generator/  src/etl/{extract,parser,transform,validate,load}.py
src/detection/  src/cloud/  src/utils/
sql/schema/  sql/analysis/
dags/  grafana/  tests/  docs/
```

## Takvim (6 hafta + 2 hafta tampon)
- H1: Seviye 1 (ortam, veri, parser, Postgres, SQL analiz, sentetik üretecin ilk sürümü)
- H2: Seviye 2 ETL + testler
- H3: Docker Compose + Airflow + Grafana
- H4: Tespit kuralları + güvenlik dashboard'u → MVP
- H5: AWS S3 / IAM / Glue / Athena
- H6: Uçtan uca bulut akışı, opsiyonel PySpark, README, kod dondurma
- H7–8: Tampon, rapor, sunum, demo videosu

## Mevcut durum
- 2026-10-07: Seviye 1 / Aşama 1–2 tamamlandı ve doğrulandı: klasör iskeleti, `.venv`, `requirements.txt` (sabit sürümler), `docker-compose.yml` (postgres:16, konteyner `secdl-postgres`), `src/utils/db.py` bağlantı testi başarılı.
- Ortam: Python 3.12.4, Docker 29.6.1 + Compose v5.1.4, Git 2.45.2, WSL2.
- Makinede 5432'de yerel bir PostgreSQL çalışıyor; proje konteyneri host'ta **5433** portunu kullanır.
- Veri kaynağı planı (Loghub OpenSSH + sentetik üreteç) onaylandı.
- Git: 2026-10-07'den itibaren commit ve push'ları Claude yapar (`origin master`, repo: github.com/yigitfevzitugrul/Cybersecurity-Data-Lake-Threat-Analytics-Platform). Commit mesajları İngilizce. Kritik durumlar dışında soru sorulmaz; indirmeler dahil her şey sormadan yapılıp doğrulanır.
- 2026-10-07: Seviye 1 / Aşama 3–4 tamamlandı ve doğrulandı:
  - `data/raw/OpenSSH_2k.log` indirildi (Loghub, 2000 satır, tamamı "Dec 10"; yıl bilinmediği için `--year 2025` ile yüklendi).
  - `src/etl/parser.py`: satır → `AuthEvent` | `None` (ilgisiz) | `ParseError` (bozuk). Sadece `Failed/Accepted <method> for ...` satırları olay sayılır; pam/Invalid user/disconnect satırları aynı denemenin tekrarı olduğu için atlanır.
  - "message repeated N times" tek olay + `repeat_count=N`. **Deneme sayan her sorgu `SUM(repeat_count)` kullanmalı, `COUNT(*)` değil.**
  - `auth_events` şeması `sql/schema/001_auth_events.sql`; idempotency anahtarı `event_hash` = sha256(event_time + ham satır), `ON CONFLICT DO NOTHING`.
  - `src/etl/load.py` (`python -m src.etl.load <dosya> --year <yıl>`), `sql/analysis/01_basic_analysis.sql`, 20 pytest testi geçiyor.
  - Sonuç: 2000 satır → 525 olay (524 başarısız / 532 deneme, 1 başarılı), 0 bozuk; ikinci yüklemede 0 yeni kayıt.
- 2026-10-07: Seviye 1 / Aşama 5 tamamlandı → **Seviye 1 bitti.**
  - `src/generator/generate.py` (`python -m src.generator.generate --start-date YYYY-MM-DD --days N --seed S`): normal trafik (8 kullanıcı, `10.20.0.x`, mesai saatleri) + gürültü + her güne 4 saldırı: `brute_force`, `password_spray`, `success_after_failures`, `off_hours_new_ip_login`.
  - Dış IP'ler RFC 5737 bloklarından; saldırgan IP'leri gürültü havuzundan ayrı. Ground truth: `data/raw/synthetic_auth_labels.json`.
  - 7 günlük örnek (2026-09-01, seed 42) üretildi ve yüklendi: 3589 satır → 1500 olay, 28 etiketli saldırı. Toplam 25 test geçiyor.
  - H4 notu: `success_after_failures` saldırıları brute force kuralını da tetikler; doğruluk ölçümünde bu beklenen eşleşme sayılmalı.
- 2026-10-07: **Seviye 2 bitti** ve doğrulandı:
  - `python -m src.etl.pipeline <dosya> --year <yıl>`: `extract.py` → `transform.py` (+`parser.py`) → `validate.py` → `load.py`. Eski `python -m src.etl.load` ve `python -m src.etl.parser` CLI'ları kaldırıldı.
  - Şema: `002_pipeline_runs.sql`, `003_rejected_events.sql`, `004_auth_events_run_id.sql` (`auth_events.run_id` lineage).
  - Red sebepleri: `malformed_line`, `invalid_timestamp`, `missing_field`, `schema_error`, `invalid_ip`, `invalid_port`, `duplicate`. Auth satırı gibi başlayıp yarım kalan satır artık "ilgisiz" değil `malformed_line`.
  - Dosya içi kopyalar `duplicate` olarak karantinaya gider; veritabanında zaten olan olaylar reddedilmez, `events_skipped_existing` olarak sayılır.
  - Olaylar + karantina + çalıştırma kaydı tek transaction; hata olursa hiçbiri yazılmaz, run `failed` olur.
  - Değişmez: `lines_read = lines_irrelevant + lines_rejected + events_valid`, `events_valid = events_loaded + events_skipped_existing`.
  - Processed katmanı: `data/processed/<dosya>.jsonl` (H5'te Parquet/S3'e taşınacak).
  - Üreteç: `--bad-ratio` ile 6 türde bozuk satır ekler; temiz satırlar ve saldırı etiketleri değişmez. Etiket dosyasında `injected_bad_lines`.
  - Testler: 56 test geçiyor. DB testleri `tests/conftest.py` içindeki `db_conn` fixture'ı ile geçici şemada çalışır.
  - Geliştirme DB'si sıfırlanıp pipeline ile yeniden yüklendi: Loghub 525 olay / 0 red; sentetik (7 gün, seed 42, bad-ratio 0.02) 1500 olay / 72 red.
- Commit mesajlarına `Co-Authored-By: Claude` satırı eklenmez (geliştirici tercihi). Geçmişi yeniden yazma / force push Claude tarafından yapılamıyor; gerekirse komut geliştiriciye verilir.
- 2026-10-07: **Seviye 3 bitti** ve doğrulandı:
  - `docker compose up -d --build --wait` → `postgres`, `db-init` (tek seferlik: `airflow` veritabanı + salt-okunur `grafana_ro` rolü, `docker/postgres/init.sql`), `airflow-init`, `airflow-scheduler`, `airflow-webserver` (:8080), `grafana` (:3000). Parolalar `.env`'de (`AIRFLOW_ADMIN_PASSWORD`, `GRAFANA_ADMIN_PASSWORD` vb.).
  - Airflow 2.10.5 (LocalExecutor), imaj `docker/airflow/Dockerfile`. Metadata aynı Postgres'te ayrı `airflow` veritabanında. `src/`, `sql/`, `config/`, `data/` konteynere `/opt/airflow/project` altına bağlanır (`PYTHONPATH`).
  - DAG `dags/auth_log_etl.py` (@daily, UTC): `generate_daily_log` (o günün sentetik logu, seed = tarih, %2 bozuk satır) → `run_etl` (`process_new_files`: `data/raw/*.log` içinden SHA-256'sı başarıyla işlenmemiş olanlar) → `quality_gate` (red oranı > %10 ise fail).
  - Airflow saat dilimi UTC bırakıldı: Europe/Istanbul iken `ds` bir gün geri kayıyordu.
  - `--year` artık opsiyonel: `infer_year` yılı dosyanın değişiklik tarihinden tahmin eder (Loghub → 2025). Bir yıldan eski veya yıl sınırını aşan dosyada elle verilmeli.
  - Grafana 11.6.0, provisioning `grafana/provisioning/`, dashboard `grafana/dashboards/pipeline_overview.json` ("Pipeline ve Veri Kalitesi", 10 panel). `grafana_ro` ile yazma denemesi "permission denied" veriyor (doğrulandı).
  - Testler: 63 test geçiyor. DAG, konteynerde elle ve zamanlanmış olarak çalıştırıldı; 3 task da success.
  - Manuel tetiklenen DAG o günün logunu üretir; günün ileri saatlerine ait olaylar Grafana'da "now"dan sonra kaldığı için gün bitene kadar görünmez (beklenen davranış).
- Sıradaki: Seviye 4 (H4) — `config/detection_rules.yaml`, 4 tespit kuralı (`src/detection/`), `alerts` tablosu, DAG'e tespit adımı, güvenlik dashboard'u, etiketlere karşı doğruluk ölçümü (precision/recall) → MVP.
