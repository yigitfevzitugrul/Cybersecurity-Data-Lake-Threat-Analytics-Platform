"""Pipeline rolünün en az yetkiyle çalıştığını canlı olarak doğrular.

İzin verilmesi gereken işlemler başarılı, verilmemesi gerekenler AccessDenied
olmalıdır. Yasak işlemler var olmayan hedeflerle denenir; rol yanlışlıkla
fazla yetkili olsa bile hiçbir veri silinmez.

Kullanım:
    python -m src.cloud.verify_access
"""
import sys

from botocore.exceptions import ClientError

from src.cloud.config import CURATED_PREFIX, RAW_PREFIX, load_config, pipeline_session

DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "403"}


def main() -> None:
    cfg = load_config()
    session = pipeline_session(cfg)
    s3, glue, iam, athena = (session.client(name) for name in ("s3", "glue", "iam", "athena"))
    alerts_key = f"{CURATED_PREFIX}/alerts/alerts.parquet"
    missing = "__does_not_exist__"

    checks = [
        # (açıklama, izin verilmeli mi, işlem)
        ("raw katmanını listele", True, lambda: s3.list_objects_v2(Bucket=cfg.bucket, Prefix=RAW_PREFIX, MaxKeys=1)),
        ("curated nesnesini oku", True, lambda: s3.head_object(Bucket=cfg.bucket, Key=alerts_key)),
        ("Glue tablosunu oku", True, lambda: glue.get_table(DatabaseName=cfg.glue_database, Name="auth_events")),
        ("kendi workgroup'unu oku", True, lambda: athena.get_work_group(WorkGroup=cfg.athena_workgroup)),
        ("nesne sil", False, lambda: s3.delete_object(Bucket=cfg.bucket, Key=f"{RAW_PREFIX}/{missing}")),
        ("katman dışına yaz", False, lambda: s3.put_object(Bucket=cfg.bucket, Key=f"other/{missing}", Body=b"")),
        ("bucket politikasını oku", False, lambda: s3.get_bucket_policy(Bucket=cfg.bucket)),
        ("hesaptaki bucket'ları listele", False, lambda: s3.list_buckets()),
        ("Glue tablosu sil", False, lambda: glue.delete_table(DatabaseName=cfg.glue_database, Name=missing)),
        ("varsayılan workgroup'ta sorgu çalıştır", False,
         lambda: athena.start_query_execution(QueryString="SELECT 1", WorkGroup="primary")),
        ("IAM kullanıcılarını listele", False, lambda: iam.list_users()),
    ]

    failures = 0
    for description, should_be_allowed, action in checks:
        try:
            action()
            allowed = True
        except ClientError as exc:
            # Yetki hatası dışındaki bir hata (ör. "bulunamadı"), isteğin yetki kontrolünü geçtiğini gösterir.
            allowed = exc.response["Error"]["Code"] not in DENIED_CODES
        ok = allowed == should_be_allowed
        failures += not ok
        print(f"  {'ok  ' if ok else 'HATA'} {description:<40} {'izin verildi' if allowed else 'reddedildi'}")

    print("\nRol en az yetkiyle çalışıyor." if not failures else f"\n{failures} beklenmeyen sonuç!")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
