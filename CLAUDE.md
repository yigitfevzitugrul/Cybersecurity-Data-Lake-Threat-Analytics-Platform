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
- Git: commit/push'ları geliştirici manuel yapar. Claude git komutu çalıştırmaz, sadece commit noktalarında komut önerir. Git dışındaki her şeyi sormadan yapıp kendisi doğrular.
- Sıradaki: Seviye 1 / Aşama 3 (Loghub OpenSSH logunu `data/raw`'a indir, `src/etl/parser.py` + testleri).
