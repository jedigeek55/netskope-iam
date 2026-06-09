from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://iam:iam_dev_password@localhost/netskope_iam"
    secret_key: str = "dev-secret-key-change-in-production"
    access_token_expire_minutes: int = 60

    # SCIM server — token Netskope (or any SP) must send when calling our /scim/v2/ endpoints
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    scim_bearer_token: str = ""

    # Netskope SCIM client — our credentials for calling Netskope's SCIM API
    netskope_tenant: str = ""       # e.g. yourtenant.goskope.com
    netskope_scim_token: str = ""   # from Netskope: Settings > Tools > Directory Tools > SCIM INTEGRATION
    netskope_verify_ssl: bool = True  # set False only for local dev with SSL inspection

    model_config = {"env_file": ".env"}


settings = Settings()
