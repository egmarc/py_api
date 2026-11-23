import json
import time
import hashlib
import base64
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import fakeredis
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jwt import PyJWK
from pydantic import SecretStr

from py_api.api.routes import auth
from py_api.api.security import ACCESS_COOKIE, REFRESH_COOKIE, SESSION_COOKIE, STATE_COOKIE, JWKSCache, jwks_cache
from py_api.core.config import Settings, get_settings
from py_api.main import create_app


@pytest.fixture
def auth_env(monkeypatch):
    settings = Settings(
        cognito_issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
        cognito_domain="https://example.auth.us-east-1.amazoncognito.com",
        cognito_client_id="client",
        cognito_client_secret=SecretStr("test-secret"),
        cognito_audience="https://api.example.com",
        cognito_admin_group="admins",
        auth_redirect_uri="https://api.example.com/api/auth/callback",
        frontend_origin="https://app.example.com",
        frontend_redirect_url="https://app.example.com/home",
        cognito_refresh_token_lifetime=2592000,
    )
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "key1", "alg": "RS256", "use": "sig"})
    monkeypatch.setattr(jwks_cache, "get_key", lambda issuer, kid: PyJWK.from_dict(public) if kid == "key1" else _bad_key())
    cache = fakeredis.FakeRedis()
    monkeypatch.setattr("py_api.core.revocations.get_redis", lambda: cache)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, base_url="https://api.example.com", follow_redirects=False) as client:
        yield settings, private, client
    cache.close()


def _bad_key():
    from py_api.api.security import invalid_token
    raise invalid_token()


def make_token(settings, private, claims=None, headers=None):
    now = int(time.time())
    payload = {
        "iss": settings.cognito_issuer, "aud": settings.cognito_audience,
        "client_id": settings.cognito_client_id, "token_use": "access",
        "sub": "alice", "username": "alice", "sid": "session-1", "jti": "token-1",
        "iat": now, "exp": now + 300,
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, private, algorithm="RS256", headers={"kid": "key1", **(headers or {})})


def session_cookie(settings, sid="session-1", token_exp=None):
    now = int(time.time())
    return jwt.encode({
        "sid": sid, "jti": "token-1", "token_exp": token_exp or now + 300,
        "exp": now + 600, "revoke_until": now + 90000,
    }, auth.state_key(settings), algorithm="HS256")


def test_missing_or_malformed_credentials_and_openapi(auth_env):
    _, _, client = auth_env
    for header in (None, "Basic abc", "Bearer one.two", "Bearer a.b.c", "Bearer " + "x" * 17000):
        response = client.get("/users/alice", headers={"Authorization": header} if header else {})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    settings, private, _ = auth_env
    token = make_token(settings, private)
    spec = client.get("/openapi.json", headers={"Authorization": f"Bearer {token}"}).json()
    assert spec["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert spec["components"]["securitySchemes"]["APIKeyCookie"]["name"] == ACCESS_COOKIE


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://evil.example.com"}, {"aud": "https://elsewhere.example.com"},
        {"aud": ["https://api.example.com"]}, {"client_id": "other"},
        {"token_use": "id"}, {"sub": ""}, {"sub": "client"},
        {"username": None}, {"cognito:groups": "admins"},
        {"sid": None}, {"sid": ""}, {"jti": None}, {"jti": ""},
        {"exp": 0}, {"exp": "9999999999"}, {"iat": int(time.time()) + 3600},
        {"exp": int(time.time()) + 90000},
        {"nbf": int(time.time()) + 3600}, {"nbf": None},
    ],
)
def test_invalid_claims(auth_env, changes):
    settings, private, client = auth_env
    token = make_token(settings, private, changes)
    assert client.get("/users/alice", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_headers_signature_and_authorization(auth_env):
    settings, private, client = auth_env
    for headers in ({"typ": "JWE"}, {"kid": "other"}, {"crit": ["x"]}, {"b64": False}):
        token = make_token(settings, private, headers=headers) if "b64" not in headers else "e30.e30.YQ"
        assert client.get("/users/alice", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(settings, other_private)
    assert client.get("/users/alice", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    token = jwt.encode({"sub": "alice"}, "a" * 32, algorithm="HS256", headers={"kid": "key1"})
    assert client.get("/users/alice", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    token = make_token(settings, private, headers={"typ": None, "jku": "https://evil.example/jwks"})
    assert client.get("/users/bob", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    admin = make_token(settings, private, {"cognito:groups": ["admins"]}, {"typ": "at+jwt"})
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {admin}"}).status_code == 503


def test_missing_jti_is_rejected(auth_env):
    settings, private, client = auth_env
    claims = {
        "iss": settings.cognito_issuer, "aud": settings.cognito_audience,
        "client_id": settings.cognito_client_id, "token_use": "access",
        "sub": "alice", "username": "alice", "sid": "session-1",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
    }
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key1"})
    assert client.get("/users/alice", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_clock_skew_and_expiry(auth_env, monkeypatch):
    settings, private, client = auth_env
    now = int(time.time())
    monkeypatch.setattr("py_api.api.security.time.time", lambda: now)
    accepted = make_token(settings, private, {"iat": now + 30, "nbf": now + 30, "exp": now + 1})
    assert client.get("/users/bob", headers={"Authorization": f"Bearer {accepted}"}).status_code == 403
    for changes in ({"exp": now}, {"iat": now + 31}, {"nbf": now + 31}):
        token = make_token(settings, private, changes)
        assert client.get("/users/bob", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_login_callback_refresh_logout(auth_env, monkeypatch):
    settings, private, client = auth_env
    access = make_token(settings, private)
    calls = []

    def mock_post(url, *, data, auth, timeout, follow_redirects):
        calls.append((url, data, auth))
        if url.endswith("/oauth2/revoke"):
            return httpx.Response(200)
        return httpx.Response(200, json={
            "access_token": access, "token_type": "Bearer", "expires_in": 300,
            "refresh_token": "initial-refresh" if data["grant_type"] == "authorization_code" else "rotated-refresh",
        })

    monkeypatch.setattr(auth.httpx, "post", mock_post)
    login = client.get("/api/auth/login")
    assert login.status_code == 302
    params = parse_qs(urlsplit(login.headers["location"]).query)
    assert params["resource"] == [settings.cognito_audience]
    assert params["code_challenge_method"] == ["S256"]
    assert "SameSite=lax" in login.headers["set-cookie"]
    assert client.get("/api/auth/callback", params={"state": "wrong", "code": "code"}).status_code == 400
    callback = client.get("/api/auth/callback", params={"state": params["state"][0], "code": "code"})
    assert callback.status_code == 303
    assert callback.headers["location"] == settings.frontend_redirect_url
    assert "code_verifier" in calls[0][1]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(calls[0][1]["code_verifier"].encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == params["code_challenge"][0]
    assert client.cookies[ACCESS_COOKIE] == access
    assert client.cookies[REFRESH_COOKIE] == "initial-refresh"
    assert STATE_COOKIE not in client.cookies
    assert client.get("/api/auth/session").json() == {"user_id": "alice", "is_admin": False}
    original_session = jwt.decode(client.cookies[SESSION_COOKIE], auth.state_key(settings), algorithms=["HS256"])
    assert client.get("/api/auth/callback", params={"state": params["state"][0], "code": "code"}).status_code == 400
    cookies = callback.headers.get_list("set-cookie")
    assert any("HttpOnly" in c and "Secure" in c and "SameSite=strict" in c for c in cookies if c.startswith(ACCESS_COOKIE))
    assert client.patch("/users/alice", json={"first_name": "A"}).status_code == 403
    assert client.post("/api/auth/refresh").status_code == 403
    origin = {"Origin": settings.frontend_origin}
    assert client.post("/api/auth/refresh", headers={"Origin": "https://evil.example.com"}).status_code == 403
    assert client.post("/api/auth/refresh", headers=origin).json() == {"status": "refreshed"}
    refreshed_session = jwt.decode(client.cookies[SESSION_COOKIE], auth.state_key(settings), algorithms=["HS256"])
    assert refreshed_session["exp"] == original_session["exp"]
    assert refreshed_session["revoke_until"] == original_session["revoke_until"]
    assert client.cookies[REFRESH_COOKIE] == "rotated-refresh"
    assert calls[-1][1]["refresh_token"] == "initial-refresh"
    logout = client.post("/api/auth/logout", headers=origin)
    assert logout.status_code == 200
    assert urlsplit(logout.json()["logout_url"]).path == "/logout"
    assert parse_qs(urlsplit(logout.json()["logout_url"]).query)["logout_uri"] == [settings.frontend_redirect_url]
    assert calls[-1][1] == {"token": "rotated-refresh", "revoke_associated_sessions": "LINKED"}
    assert ACCESS_COOKIE not in client.cookies and REFRESH_COOKIE not in client.cookies and SESSION_COOKIE not in client.cookies
    assert client.get("/api/auth/session").status_code == 401
    assert client.get("/api/auth/session", headers={"Authorization": f"Bearer {access}"}).status_code == 401
    earlier_token = make_token(settings, private, {"jti": "earlier-token"})
    assert client.get("/api/auth/session", headers={"Authorization": f"Bearer {earlier_token}"}).status_code == 401


def test_no_cookie_fallback_for_bad_bearer(auth_env):
    settings, private, client = auth_env
    client.cookies.set(ACCESS_COOKIE, make_token(settings, private), domain="api.example.com", path="/")
    assert client.get("/users/bob").status_code == 403
    assert client.get("/users/bob", headers={"Authorization": "Bearer broken"}).status_code == 401


def test_jwks_cache_rotation_and_outage(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "first", "alg": "RS256", "use": "sig"})
    calls = []
    now = [1000.0]
    monkeypatch.setattr("py_api.api.security.time.monotonic", lambda: now[0])

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, json={"keys": [public]})

    original_client = httpx.Client
    monkeypatch.setattr("py_api.api.security.httpx.Client", lambda **kwargs: original_client(transport=httpx.MockTransport(handler)))
    cache = JWKSCache()
    issuer = "https://issuer.example"
    assert cache.get_key(issuer, "first").key_id == "first"
    assert cache.get_key(issuer, "first").key_id == "first"
    with pytest.raises(HTTPException) as err:
        cache.get_key(issuer, "missing")
    assert err.value.status_code == 401 and len(calls) == 1
    now[0] += 31
    public["kid"] = "second"
    assert cache.get_key(issuer, "second").key_id == "second"
    assert len(calls) == 2


def test_refresh_without_rotation_and_provider_errors(auth_env, monkeypatch):
    settings, private, client = auth_env
    client.cookies.set(REFRESH_COOKIE, "refresh", domain="api.example.com", path="/")
    client.cookies.set(
        SESSION_COOKIE,
        session_cookie(settings),
        domain="api.example.com", path="/",
    )
    origin = {"Origin": settings.frontend_origin}
    response_data = {
        "access_token": make_token(settings, private), "token_type": "Bearer", "expires_in": 300
    }

    def mock_post(url, **kwargs):
        return httpx.Response(200, json=response_data)

    monkeypatch.setattr(auth.httpx, "post", mock_post)
    assert client.post("/api/auth/refresh", headers=origin).status_code == 200
    assert client.cookies[REFRESH_COOKIE] == "refresh"
    response_data["access_token"] = "invalid"
    assert client.post("/api/auth/refresh", headers=origin).status_code == 503
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: httpx.Response(400))
    assert client.post("/api/auth/refresh", headers=origin).status_code == 401
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: httpx.Response(500))
    assert client.post("/api/auth/refresh", headers=origin).status_code == 503


def test_jwks_outage_fails_closed(monkeypatch):
    original_client = httpx.Client
    def handler(request):
        return httpx.Response(503)
    monkeypatch.setattr(
        "py_api.api.security.httpx.Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler)),
    )
    cache = JWKSCache()
    with pytest.raises(HTTPException) as err:
        cache.get_key("https://issuer.example", "first")
    assert err.value.status_code == 503
    with pytest.raises(HTTPException) as err:
        cache.get_key("https://issuer.example", "first")
    assert err.value.status_code == 503


def test_cors_is_restricted_to_frontend(monkeypatch):
    monkeypatch.setenv("PY_API_FRONTEND_ORIGIN", "https://app.example.com")
    get_settings.cache_clear()
    try:
        with TestClient(create_app(), base_url="https://api.example.com") as client:
            headers = {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            }
            response = client.options("/api/auth/refresh", headers=headers)
            assert response.status_code == 200
            assert response.headers["access-control-allow-origin"] == "https://app.example.com"
            assert response.headers["access-control-allow-credentials"] == "true"
            headers["Origin"] = "https://evil.example.com"
            assert client.options("/api/auth/refresh", headers=headers).status_code == 400
    finally:
        get_settings.cache_clear()


def test_logout_with_expired_access_and_failed_revoke_is_retryable(auth_env, monkeypatch):
    settings, private, client = auth_env
    access = make_token(settings, private)
    client.cookies.set(SESSION_COOKIE, session_cookie(settings, token_exp=int(time.time()) - 1), domain="api.example.com", path="/")
    client.cookies.set(REFRESH_COOKIE, "refresh", domain="api.example.com", path="/")
    origin = {"Origin": settings.frontend_origin}
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: httpx.Response(500))
    assert client.post("/api/auth/logout", headers=origin).status_code == 503
    assert REFRESH_COOKIE in client.cookies and SESSION_COOKIE in client.cookies
    assert client.get("/api/auth/session", headers={"Authorization": f"Bearer {access}"}).status_code == 401
    assert client.post("/api/auth/refresh", headers=origin).status_code == 401
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: httpx.Response(200))
    assert client.post("/api/auth/logout", headers=origin).status_code == 200
    assert REFRESH_COOKIE not in client.cookies and SESSION_COOKIE not in client.cookies
    other = make_token(settings, private, {"sid": "session-2"})
    assert client.get("/users/bob", headers={"Authorization": f"Bearer {other}"}).status_code == 403


def test_logout_rejects_tampered_session_and_origin(auth_env, monkeypatch):
    settings, private, client = auth_env
    client.cookies.set(REFRESH_COOKIE, "refresh", domain="api.example.com", path="/")
    client.cookies.set(SESSION_COOKIE, "invalid", domain="api.example.com", path="/")
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: pytest.fail("unexpected revocation"))
    assert client.post("/api/auth/logout", headers={"Origin": settings.frontend_origin}).status_code == 401
    assert client.post("/api/auth/logout", headers={"Origin": "https://evil.example.com"}).status_code == 403
    valid = make_token(settings, private)
    assert client.get("/users/bob", headers={"Authorization": f"Bearer {valid}"}).status_code == 403


def test_refresh_rejects_different_session(auth_env, monkeypatch):
    settings, private, client = auth_env
    client.cookies.set(REFRESH_COOKIE, "refresh", domain="api.example.com", path="/")
    signed = session_cookie(settings)
    client.cookies.set(SESSION_COOKIE, signed, domain="api.example.com", path="/")
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: httpx.Response(200, json={
        "access_token": make_token(settings, private, {"sid": "session-2"}),
        "token_type": "Bearer", "expires_in": 300,
    }))
    assert client.post("/api/auth/refresh", headers={"Origin": settings.frontend_origin}).status_code == 503


def test_revocation_redis_failure_fails_closed(auth_env, monkeypatch):
    from redis.exceptions import ConnectionError

    settings, private, client = auth_env
    def broken():
        raise ConnectionError("unavailable")
    monkeypatch.setattr("py_api.core.revocations.get_redis", broken)
    token = make_token(settings, private)
    assert client.get("/api/auth/session", headers={"Authorization": f"Bearer {token}"}).status_code == 503
    signed = session_cookie(settings)
    client.cookies.set(SESSION_COOKIE, signed, domain="api.example.com", path="/")
    client.cookies.set(REFRESH_COOKIE, "refresh", domain="api.example.com", path="/")
    assert client.post("/api/auth/logout", headers={"Origin": settings.frontend_origin}).status_code == 503
    assert SESSION_COOKIE in client.cookies and REFRESH_COOKIE in client.cookies


def test_missing_refresh_still_revokes_local_session(auth_env, monkeypatch):
    settings, private, client = auth_env
    signed = session_cookie(settings)
    client.cookies.set(SESSION_COOKIE, signed, domain="api.example.com", path="/")
    monkeypatch.setattr(auth.httpx, "post", lambda *args, **kwargs: pytest.fail("unexpected revocation"))
    assert client.post("/api/auth/logout", headers={"Origin": settings.frontend_origin}).status_code == 401
    token = make_token(settings, private)
    assert client.get("/api/auth/session", headers={"Authorization": f"Bearer {token}"}).status_code == 401
