import hashlib
import json
import logging
import time
from functools import lru_cache

from fastapi import HTTPException
from redis import Redis
from redis.exceptions import RedisError

from py_api.core.config import get_settings

logger = logging.getLogger(__name__)
MAX_ACCESS_LIFETIME = 86400
CLOCK_SKEW = 30


@lru_cache
def get_redis() -> Redis:
    url = get_settings().redis_url
    if not url or not url.get_secret_value():
        raise HTTPException(status_code=503, detail="Session revocation service is not configured")
    if not url.get_secret_value().startswith(("redis://", "rediss://")):
        raise HTTPException(status_code=503, detail="Invalid Redis configuration")
    try:
        return Redis.from_url(
            url.get_secret_value(), socket_connect_timeout=3, socket_timeout=3,
            health_check_interval=30,
        )
    except (ValueError, RedisError) as exc:
        raise HTTPException(status_code=503, detail="Invalid Redis configuration") from exc


def key_for(kind: str, issuer: str, client_id: str, identifier: str) -> str:
    data = json.dumps([issuer, client_id, identifier], ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(data.encode()).hexdigest()
    return f"py_api:revoked:{kind}:{digest}"


def is_revoked(issuer: str, client_id: str, session_id: str, token_id: str | None = None) -> bool:
    keys = [key_for("session", issuer, client_id, session_id)]
    if token_id is not None:
        keys.append(key_for("token", issuer, client_id, token_id))
    try:
        return bool(get_redis().exists(*keys))
    except RedisError as exc:
        logger.error("Could not check session revocation: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Session revocation service unavailable") from exc


def revoke(
    issuer: str, client_id: str, session_id: str, token_id: str,
    token_exp: int, session_deadline: int,
) -> None:
    try:
        with get_redis().pipeline(transaction=True) as pipe:
            pipe.set(key_for("session", issuer, client_id, session_id), "1", exat=session_deadline)
            if token_exp > time.time():
                pipe.set(key_for("token", issuer, client_id, token_id), "1", exat=token_exp)
            pipe.execute()
    except RedisError as exc:
        logger.error("Could not persist session revocation: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Session revocation service unavailable") from exc
