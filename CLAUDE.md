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
- Git: commit/push'ları geliştirici manuel yapar. Claude git komutu çalıştırmaz, sadece commit noktalarında komut önerir. Git dışındaki her şeyi (indirmeler dahil) sormadan yapıp kendisi doğrular; sadece kritik durumlarda sorar.
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
- Sıradaki: Seviye 2 (H2) — pipeline'ı `extract / transform / validate / load` adımlarına ayır, `rejected_events` + `pipeline_runs` tabloları, veri kalitesi kontrolleri (duplicate, null, invalid IP, timestamp, şema), üretece bozuk satır enjeksiyonu.
