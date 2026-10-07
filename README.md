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
python -m src.utils.db        # "Bağlantı başarılı" yazmalı
```
