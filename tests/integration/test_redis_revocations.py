import os
import time
from uuid import uuid4

import fakeredis
import pytest
from redis import Redis

from py_api.core import revocations


def exercise_revocation(cache, monkeypatch):
    issuer, client = "https://issuer.example", "client"
    session_id, token_id = str(uuid4()), str(uuid4())
    token_key = revocations.key_for("token", issuer, client, token_id)
    session_key = revocations.key_for("session", issuer, client, session_id)
    monkeypatch.setattr(revocations, "get_redis", lambda: cache)
    now = int(time.time())
    try:
        assert not revocations.is_revoked(issuer, client, session_id, token_id)
        revocations.revoke(issuer, client, session_id, token_id, now + 20, now + 120)
        assert revocations.is_revoked(issuer, client, session_id, "another-token")
        assert revocations.is_revoked(issuer, client, "another-session", token_id)
        assert not revocations.is_revoked(issuer, client, "another-session", "another-token")
        assert 18 <= cache.ttl(token_key) <= 20
        assert 118 <= cache.ttl(session_key) <= 120
        revocations.revoke(issuer, client, session_id, token_id, now + 20, now + 120)
        assert cache.ttl(token_key) <= 20
    finally:
        cache.delete(token_key, session_key)


def test_revocation_keys_and_ttl(monkeypatch):
    with fakeredis.FakeRedis() as cache:
        exercise_revocation(cache, monkeypatch)


def test_expired_token_does_not_create_jti_key(monkeypatch):
    cache = fakeredis.FakeRedis()
    monkeypatch.setattr(revocations, "get_redis", lambda: cache)
    now = int(time.time())
    revocations.revoke("issuer", "client", "sid", "jti", now - 1, now + 60)
    assert not cache.exists(revocations.key_for("token", "issuer", "client", "jti"))
    assert revocations.is_revoked("issuer", "client", "sid")


@pytest.mark.skipif(not os.getenv("PY_API_TEST_REDIS_URL"), reason="Requires a dedicated Redis instance")
def test_real_redis_revocations(monkeypatch):
    with Redis.from_url(os.environ["PY_API_TEST_REDIS_URL"], socket_timeout=3) as cache:
        exercise_revocation(cache, monkeypatch)
        monkeypatch.setattr(revocations, "get_redis", lambda: cache)
        session_id, token_id = str(uuid4()), str(uuid4())
        now = int(time.time())
        token_key = revocations.key_for("token", "issuer", "client", token_id)
        session_key = revocations.key_for("session", "issuer", "client", session_id)
        try:
            revocations.revoke("issuer", "client", session_id, token_id, now + 2, now + 30)
            time.sleep(2.1)
            assert not cache.exists(token_key)
            assert cache.exists(session_key)
        finally:
            cache.delete(token_key, session_key)
