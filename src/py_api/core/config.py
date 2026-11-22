from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

from pydantic_settings import BaseSettings, SettingsConfigDict


def _package_version() -> str:
    try:
        return version("py_api")
    except PackageNotFoundError:
        return "0.0.0"


class Settings(BaseSettings):
    """Application settings, loaded from environment variables (prefix ``PY_API_``) or a ``.env`` file."""

    model_config = SettingsConfigDict(env_prefix="PY_API_", env_file=".env", extra="ignore")

    app_name: str = "Py API"
    version: str = _package_version()
    environment: str = "local"
    debug: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
