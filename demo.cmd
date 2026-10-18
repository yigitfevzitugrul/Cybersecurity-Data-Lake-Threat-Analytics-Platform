@echo off
rem Sunum demosu: saldiri uret -> ETL -> tespit -> Grafana. Kullanim: demo
cd /d "%~dp0"
".venv\Scripts\python.exe" -m src.demo.attack %*
