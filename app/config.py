from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://iam:iam_dev_password@localhost/netskope_iam"
    secret_key: str = "dev-secret-key-change-in-production"
    access_token_expire_minutes: int = 60
    netskope_tenant: str = ""
    netskope_scim_token: str = ""

    model_config = {"env_file": ".env"}


settings = Settings()
