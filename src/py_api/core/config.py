from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr


def _package_version() -> str:
    try:
        return version("py_api")
    except PackageNotFoundError:
        return "0.0.0"


class Settings(BaseSettings):
    """Application settings, loaded from environment variables (prefix ``PY_API_``) or a ``.env`` file."""

    model_config = SettingsConfigDict(
        env_prefix="PY_API_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    app_name: str = "Py API"
    version: str = _package_version()
    environment: str = "local"
    debug: bool = False
    database_url: str | None = None
    redis_url: SecretStr | None = None
    cognito_issuer: str | None = None
    cognito_domain: str | None = None
    cognito_client_id: str | None = None
    cognito_client_secret: SecretStr | None = None
    cognito_audience: str | None = None
    cognito_admin_group: str | None = None
    cognito_scope: str = "openid"
    auth_redirect_uri: str | None = None
    frontend_origin: str | None = None
    frontend_redirect_url: str | None = None
    refresh_cookie_max_age: int = 2592000
    cognito_refresh_token_lifetime: int | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
