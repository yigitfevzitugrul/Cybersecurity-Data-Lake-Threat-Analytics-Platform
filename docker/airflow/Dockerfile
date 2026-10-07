FROM apache/airflow:2.10.5-python3.12

# Proje kodunun (src/) ihtiyaç duyduğu, Airflow imajında garanti olmayan paketler.
# psycopg2 imajda zaten var.
RUN pip install --no-cache-dir python-dotenv PyYAML
