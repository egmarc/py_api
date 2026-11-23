import hashlib
import logging

from fastapi import HTTPException
from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from py_api.core.revocations import get_redis
from py_api.schemas.users import UserRead

logger = logging.getLogger(__name__)
PROFILE_TTL_SECONDS = 60


def _digest(user_id: str) -> bytes:
    return hashlib.sha256(user_id.encode("utf-8")).digest()


def profile_key(user_id: str) -> str:
    return f"py_api:profile:v1:{_digest(user_id).hex()}"


def lock_profile(session: Session, user_id: str, *, write: bool) -> None:
    lock_id = int.from_bytes(_digest(user_id)[:8], byteorder="big", signed=True)
    function = "pg_advisory_xact_lock" if write else "pg_advisory_xact_lock_shared"
    session.execute(text(f"SELECT {function}(:lock_id)"), {"lock_id": lock_id})


def get_cached_profile(user_id: str) -> UserRead | None:
    try:
        value = get_redis().get(profile_key(user_id))
        if value is None:
            return None
        profile = UserRead.model_validate_json(value)
        if profile.id != user_id:
            raise ValueError("Cached profile ID does not match")
        return profile
    except (RedisError, ValidationError, ValueError) as exc:
        logger.error("Could not read profile cache: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Profile cache unavailable") from exc


def cache_profile(profile: UserRead) -> None:
    try:
        get_redis().set(profile_key(profile.id), profile.model_dump_json(), ex=PROFILE_TTL_SECONDS)
    except RedisError as exc:
        logger.error("Could not write profile cache: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Profile cache unavailable") from exc


def invalidate_profile(user_id: str) -> None:
    try:
        get_redis().delete(profile_key(user_id))
    except RedisError as exc:
        logger.error("Could not invalidate profile cache: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Profile cache unavailable") from exc
