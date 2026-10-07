"""AWS altyapısını kurar. Tekrar çalıştırmak güvenlidir; var olan kaynaklar güncellenir.

Yönetici yetkili varsayılan AWS kimliğiyle çalışır ve şunları oluşturur:
  - S3 bucket (herkese açık erişim kapalı, şifreli, sadece TLS, Athena sonuçları 7 günde silinir)
  - Glue veritabanı ve tabloları
  - Athena workgroup (sorgu başına taranan veri sınırıyla)
  - En az yetkili pipeline IAM rolü
  - Aylık maliyet bütçesi ve e-posta uyarısı (BUDGET_ALERT_EMAIL tanımlıysa)

Kullanım:
    python -m src.cloud.setup
"""
import json
import os
from pathlib import Path
from string import Template

from botocore.exceptions import ClientError

from src.cloud.catalog import glue_tables
from src.cloud.config import ATHENA_RESULTS_PREFIX, CloudConfig, admin_session, load_config

POLICY_TEMPLATE = Path(__file__).resolve().parents[2] / "infra" / "iam" / "pipeline_policy.json"
BUDGET_NAME = "secdl-monthly"
# Athena: tek sorgunun tarayabileceği en fazla veri (maliyet koruması).
QUERY_SCAN_LIMIT_BYTES = 100 * 1024 * 1024
TAGS = [{"Key": "project", "Value": "secdl"}]


def _error_code(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


def ensure_bucket(session, cfg: CloudConfig) -> None:
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=cfg.bucket)
        print(f"S3 bucket var        : {cfg.bucket}")
    except ClientError as exc:
        if _error_code(exc) not in ("404", "NoSuchBucket"):
            raise
        s3.create_bucket(Bucket=cfg.bucket, CreateBucketConfiguration={"LocationConstraint": cfg.region})
        print(f"S3 bucket oluşturuldu: {cfg.bucket}")

    s3.put_public_access_block(
        Bucket=cfg.bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=cfg.bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_policy(Bucket=cfg.bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{cfg.bucket}", f"arn:aws:s3:::{cfg.bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }))
    s3.put_bucket_lifecycle_configuration(
        Bucket=cfg.bucket,
        LifecycleConfiguration={"Rules": [
            {
                "ID": "expire-athena-results",
                "Status": "Enabled",
                "Filter": {"Prefix": f"{ATHENA_RESULTS_PREFIX}/"},
                "Expiration": {"Days": 7},
            },
            {
                "ID": "abort-incomplete-uploads",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
            },
        ]},
    )
    s3.put_bucket_tagging(Bucket=cfg.bucket, Tagging={"TagSet": TAGS})


def ensure_glue(session, cfg: CloudConfig) -> None:
    glue = session.client("glue")
    try:
        glue.create_database(DatabaseInput={
            "Name": cfg.glue_database,
            "Description": "Cybersecurity Data Lake: auth olayları ve alarmlar",
        })
        print(f"Glue veritabanı oluşturuldu: {cfg.glue_database}")
    except ClientError as exc:
        if _error_code(exc) != "AlreadyExistsException":
            raise
        print(f"Glue veritabanı var  : {cfg.glue_database}")

    for table in glue_tables(cfg):
        try:
            glue.create_table(DatabaseName=cfg.glue_database, TableInput=table)
            print(f"  tablo oluşturuldu  : {table['Name']}")
        except ClientError as exc:
            if _error_code(exc) != "AlreadyExistsException":
                raise
            glue.update_table(DatabaseName=cfg.glue_database, TableInput=table)
            print(f"  tablo güncellendi  : {table['Name']}")


def ensure_athena_workgroup(session, cfg: CloudConfig) -> None:
    athena = session.client("athena")
    configuration = {
        "ResultConfiguration": {
            "OutputLocation": f"s3://{cfg.bucket}/{ATHENA_RESULTS_PREFIX}/",
            "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"},
        },
        "EnforceWorkGroupConfiguration": True,
        "PublishCloudWatchMetricsEnabled": False,
        "BytesScannedCutoffPerQuery": QUERY_SCAN_LIMIT_BYTES,
    }
    try:
        athena.create_work_group(
            Name=cfg.athena_workgroup,
            Configuration=configuration,
            Description="Cybersecurity Data Lake sorguları",
            Tags=TAGS,
        )
        print(f"Athena workgroup oluşturuldu: {cfg.athena_workgroup}")
    except ClientError as exc:
        if _error_code(exc) != "InvalidRequestException" or "already" not in str(exc):
            raise
        update = {k: v for k, v in configuration.items() if k != "ResultConfiguration"}
        update["ResultConfigurationUpdates"] = configuration["ResultConfiguration"]
        athena.update_work_group(WorkGroup=cfg.athena_workgroup, ConfigurationUpdates=update)
        print(f"Athena workgroup var : {cfg.athena_workgroup}")


def render_pipeline_policy(cfg: CloudConfig, account_id: str) -> str:
    return Template(POLICY_TEMPLATE.read_text(encoding="utf-8")).substitute(
        BUCKET=cfg.bucket,
        REGION=cfg.region,
        ACCOUNT_ID=account_id,
        GLUE_DATABASE=cfg.glue_database,
        ATHENA_WORKGROUP=cfg.athena_workgroup,
    )


def ensure_pipeline_role(session, cfg: CloudConfig, account_id: str, caller_arn: str) -> str:
    """Pipeline'ın üstleneceği rolü oluşturur. Uzun ömürlü erişim anahtarı üretilmez."""
    iam = session.client("iam")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": caller_arn},
            "Action": "sts:AssumeRole",
        }],
    })
    try:
        role = iam.create_role(
            RoleName=cfg.pipeline_role_name,
            AssumeRolePolicyDocument=trust,
            Description="Cybersecurity Data Lake pipeline (en az yetki)",
            MaxSessionDuration=3600,
            Tags=TAGS,
        )["Role"]
        print(f"IAM rolü oluşturuldu : {cfg.pipeline_role_name}")
    except ClientError as exc:
        if _error_code(exc) != "EntityAlreadyExists":
            raise
        role = iam.get_role(RoleName=cfg.pipeline_role_name)["Role"]
        iam.update_assume_role_policy(RoleName=cfg.pipeline_role_name, PolicyDocument=trust)
        print(f"IAM rolü var         : {cfg.pipeline_role_name}")
    iam.put_role_policy(
        RoleName=cfg.pipeline_role_name,
        PolicyName="secdl-pipeline-access",
        PolicyDocument=render_pipeline_policy(cfg, account_id),
    )
    return role["Arn"]


def ensure_budget(session, account_id: str, email: str, limit_usd: str) -> None:
    budgets = session.client("budgets", region_name="us-east-1")
    subscribers = [{"SubscriptionType": "EMAIL", "Address": email}]
    try:
        budgets.create_budget(
            AccountId=account_id,
            Budget={
                "BudgetName": BUDGET_NAME,
                "BudgetLimit": {"Amount": limit_usd, "Unit": "USD"},
                "TimeUnit": "MONTHLY",
                "BudgetType": "COST",
            },
            NotificationsWithSubscribers=[
                {
                    "Notification": {
                        "NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
                        "Threshold": 80.0, "ThresholdType": "PERCENTAGE",
                    },
                    "Subscribers": subscribers,
                },
                {
                    "Notification": {
                        "NotificationType": "FORECASTED", "ComparisonOperator": "GREATER_THAN",
                        "Threshold": 100.0, "ThresholdType": "PERCENTAGE",
                    },
                    "Subscribers": subscribers,
                },
            ],
        )
        print(f"Bütçe oluşturuldu    : {BUDGET_NAME} (aylık {limit_usd} USD)")
    except ClientError as exc:
        if _error_code(exc) != "DuplicateRecordException":
            raise
        print(f"Bütçe var            : {BUDGET_NAME}")


def main() -> None:
    cfg = load_config()
    session = admin_session(cfg)
    identity = session.client("sts").get_caller_identity()
    account_id, caller_arn = identity["Account"], identity["Arn"]
    print(f"Hesap {account_id}, bölge {cfg.region}, kimlik {caller_arn.split('/')[-1]}")

    ensure_bucket(session, cfg)
    ensure_glue(session, cfg)
    ensure_athena_workgroup(session, cfg)
    role_arn = ensure_pipeline_role(session, cfg, account_id, caller_arn)

    email = os.environ.get("BUDGET_ALERT_EMAIL")
    if email:
        ensure_budget(session, account_id, email, os.environ.get("BUDGET_LIMIT_USD", "5"))
    else:
        print("Bütçe atlandı        : BUDGET_ALERT_EMAIL tanımlı değil")

    print(f"\n.env dosyasına ekle  : AWS_PIPELINE_ROLE_ARN={role_arn}")


if __name__ == "__main__":
    main()
