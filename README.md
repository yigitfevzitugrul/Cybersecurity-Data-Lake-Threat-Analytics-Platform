# Cybersecurity Data Lake & Threat Analytics Platform

Security/auth loglarını toplayan, ETL'den geçiren, veri kalitesini kontrol eden, AWS Data Lake'te depolayan ve tehditleri tespit edip Grafana'da görselleştiren platform.

> Durum: geliştirme aşamasında (Seviye 1 — temel pipeline).

## Kurulum

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # POSTGRES_PASSWORD değerini değiştir
docker compose up -d --wait
python -m src.utils.db        # bağlantıyı test eder, şemayı uygular
```

## Kullanım

Örnek veri: [Loghub OpenSSH_2k.log](https://github.com/logpai/loghub/tree/master/OpenSSH) dosyasını `data/raw/` altına koy.

```powershell
python -m src.etl.parser data/raw/OpenSSH_2k.log            # sadece ayrıştırma özeti
python -m src.etl.load data/raw/OpenSSH_2k.log --year 2025   # PostgreSQL'e yükle (tekrar çalıştırmak güvenli)
cmd /c "docker compose exec -T postgres psql -U secdl -d security_lake < sql\analysis\01_basic_analysis.sql"
python -m pytest -q
```

Gömülü saldırılar içeren sentetik log (etiketler `data/raw/synthetic_auth_labels.json` dosyasına yazılır):

```powershell
python -m src.generator.generate --start-date 2026-09-01 --days 7 --seed 42
python -m src.etl.load data/raw/synthetic_auth.log --year 2026
```
