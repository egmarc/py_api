from collections.abc import Iterator
from functools import lru_cache

from fastapi import HTTPException, status
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session

from py_api.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    database_url = get_settings().database_url
    if not database_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not configured",
        )
    if make_url(database_url).drivername not in {"postgresql", "postgresql+psycopg"}:
        raise RuntimeError("PY_API_DATABASE_URL must use PostgreSQL with the psycopg driver")
    # Explicitly select psycopg 3 even when the URL uses the generic PostgreSQL scheme.
    url = make_url(database_url).set(drivername="postgresql+psycopg")
    return create_engine(url, pool_pre_ping=True)


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session
