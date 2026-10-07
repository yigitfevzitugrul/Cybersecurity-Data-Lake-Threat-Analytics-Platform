"""AWS ayarları (.env) ve oturum oluşturma."""
import os
from dataclasses import dataclass
from typing import Optional

import boto3
from dotenv import load_dotenv

load_dotenv()

RAW_PREFIX = "raw/auth_logs"
PROCESSED_PREFIX = "processed/auth_events"
CURATED_PREFIX = "curated"
ATHENA_RESULTS_PREFIX = "athena-results"


@dataclass(frozen=True)
class CloudConfig:
    region: str
    bucket: str
    glue_database: str
    athena_workgroup: str
    pipeline_role_name: str
    # Kurulumdan sonra .env'e yazılır; pipeline bu rolü üstlenerek çalışır.
    pipeline_role_arn: Optional[str]


def load_config() -> CloudConfig:
    return CloudConfig(
        region=os.environ["AWS_REGION"],
        bucket=os.environ["S3_BUCKET"],
        glue_database=os.environ.get("GLUE_DATABASE", "security_lake"),
        athena_workgroup=os.environ.get("ATHENA_WORKGROUP", "secdl"),
        pipeline_role_name=os.environ.get("AWS_PIPELINE_ROLE_NAME", "secdl-pipeline"),
        pipeline_role_arn=os.environ.get("AWS_PIPELINE_ROLE_ARN") or None,
    )


def admin_session(cfg: CloudConfig) -> boto3.Session:
    """Makinedeki varsayılan AWS kimliği. Sadece altyapı kurulumu (setup) için kullanılır."""
    return boto3.Session(region_name=cfg.region)


def pipeline_session(cfg: CloudConfig) -> boto3.Session:
    """En az yetkili pipeline rolünü üstlenir; geçici (1 saatlik) kimlik bilgileriyle oturum döndürür."""
    if not cfg.pipeline_role_arn:
        raise RuntimeError("AWS_PIPELINE_ROLE_ARN tanımlı değil. Önce: python -m src.cloud.setup")
    sts = boto3.Session(region_name=cfg.region).client("sts")
    creds = sts.assume_role(RoleArn=cfg.pipeline_role_arn, RoleSessionName="secdl-pipeline")["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=cfg.region,
    )
