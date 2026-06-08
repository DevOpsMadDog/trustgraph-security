from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Auth
    jwt_secret: str = Field("change-me", alias="JWT_SECRET")
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    jwt_expires_min: int = Field(1440, alias="JWT_EXPIRES_MIN")
    admin_email: str = Field("admin@trustgraph.local", alias="ADMIN_EMAIL")
    admin_password: str = Field("change-me", alias="ADMIN_PASSWORD")

    # TrustGraph
    tg_api_url: str = Field("http://trustgraph:8088", alias="TG_API_URL")
    tg_api_key: str = Field("change-me", alias="TG_API_KEY")
    tg_knowledge_core: str = Field("trustgraph-security", alias="TG_KNOWLEDGE_CORE")
    tg_collection: str = Field("default", alias="TG_COLLECTION")
    tg_flow_id: str = Field("security-rag", alias="TG_FLOW_ID")

    # Celery / Redis
    redis_url: str = Field("redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field("redis://redis:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field("redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")

    # CAI pentest agent
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field("", alias="ANTHROPIC_API_KEY")
    cai_model: str = Field("anthropic/claude-sonnet-4-5", alias="CAI_MODEL")
    cai_max_turns: int = Field(25, alias="CAI_MAX_TURNS")
    cai_timeout_sec: int = Field(600, alias="CAI_TIMEOUT_SEC")

    # GitHub
    github_app_id: str = Field("", alias="GITHUB_APP_ID")
    github_app_private_key_path: str = Field("", alias="GITHUB_APP_PRIVATE_KEY_PATH")
    github_webhook_secret: str = Field("", alias="GITHUB_WEBHOOK_SECRET")

    # Scanners
    semgrep_rules: str = Field("p/default", alias="SEMGREP_RULES")
    trivy_severity: str = Field("HIGH,CRITICAL", alias="TRIVY_SEVERITY")
    nuclei_templates: str = Field("cves,exposures,misconfiguration", alias="NUCLEI_TEMPLATES")

    # Feeds
    feed_local_path: str = Field("/data/feeds", alias="FEED_LOCAL_PATH")
    feed_s3_bucket: str = Field("", alias="FEED_S3_BUCKET")


@lru_cache
def get_settings() -> Settings:
    return Settings()
