import base64
import json
import re
import threading
import time
from typing import Annotated
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyCookie, HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWK
from pydantic import BaseModel

from py_api.core.config import Settings, get_settings
from py_api.core.revocations import MAX_ACCESS_LIFETIME, is_revoked

ACCESS_COOKIE = "__Host-access"
REFRESH_COOKIE = "__Host-refresh"
STATE_COOKIE = "__Host-oauth-state"
SESSION_COOKIE = "__Host-session"
bearer = HTTPBearer(auto_error=False)
access_cookie = APIKeyCookie(name=ACCESS_COOKIE, auto_error=False)


class Principal(BaseModel):
    user_id: str
    is_admin: bool = False


class VerifiedAccess(BaseModel):
    principal: Principal
    session_id: str
    token_id: str
    expires_at: int


def unavailable(detail: str = "Authentication is not configured") -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)


def invalid_token() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def https_url(value: str | None, *, origin_only: bool = False) -> bool:
    if not value:
        return False
    try:
        url = urlsplit(value)
        if (
            url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.port is not None and not 1 <= url.port <= 65535
        ):
            return False
        return not origin_only or not url.path
    except ValueError:
        return False


def validate_api_config(settings: Settings) -> None:
    if (
        not https_url(settings.cognito_issuer)
        or settings.cognito_issuer.endswith("/")
        or not settings.cognito_client_id
        or not settings.cognito_audience
        or not settings.cognito_admin_group
    ):
        raise unavailable()


def require_origin(request: Request, settings: Settings) -> None:
    if not https_url(settings.frontend_origin, origin_only=True):
        raise unavailable()
    if request.headers.get("origin") != settings.frontend_origin:
        raise HTTPException(status_code=403, detail="Invalid request origin")


class JWKSCache:
    """Cache trusted pool keys and rate-limit refreshes for unknown key IDs."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.issuer: str | None = None
        self.keys: dict[str, PyJWK] = {}
        self.expires = 0.0
        self.next_refresh = 0.0

    def get_key(self, issuer: str, kid: str) -> PyJWK:
        with self.lock:
            now = time.monotonic()
            if self.issuer != issuer:
                self.issuer, self.keys, self.expires, self.next_refresh = issuer, {}, 0, 0
            if now < self.expires and kid in self.keys:
                return self.keys[kid]
            if now < self.next_refresh:
                if now >= self.expires:
                    raise unavailable("Signing keys temporarily unavailable")
                raise invalid_token()
            self.next_refresh = now + 30
            try:
                with httpx.Client(timeout=5.0, follow_redirects=False) as client:
                    with client.stream("GET", f"{issuer}/.well-known/jwks.json") as response:
                        response.raise_for_status()
                        data = bytearray()
                        for chunk in response.iter_bytes():
                            data.extend(chunk)
                            if len(data) > 1024 * 1024:
                                raise ValueError("JWKS exceeds size limit")
                document = json.loads(data)
                if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
                    raise ValueError("Invalid JWKS")
                keys: dict[str, PyJWK] = {}
                for item in document["keys"]:
                    if not isinstance(item, dict):
                        raise ValueError("Invalid key")
                    key_id = item.get("kid")
                    if not isinstance(key_id, str) or not key_id or key_id in keys:
                        raise ValueError("Invalid key identifier")
                    if item.get("kty") == "RSA" and item.get("use", "sig") == "sig" and item.get("alg", "RS256") == "RS256":
                        keys[key_id] = PyJWK.from_dict(item, algorithm="RS256")
                if not keys:
                    raise ValueError("No usable signing keys")
            except (httpx.HTTPError, ValueError, TypeError, jwt.PyJWTError) as exc:
                raise unavailable("Signing keys temporarily unavailable") from exc
            self.keys = keys
            self.expires = now + 300
            if kid not in keys:
                raise invalid_token()
            return keys[kid]


jwks_cache = JWKSCache()
_segment = re.compile(r"^[A-Za-z0-9_-]+$")


def _decode_segment(segment: str) -> bytes:
    if not _segment.fullmatch(segment) or len(segment) % 4 == 1:
        raise ValueError("Invalid base64url")
    return base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)


def verify_access_token(token: str, settings: Settings) -> VerifiedAccess:
    validate_api_config(settings)
    if len(token) > 16384:
        raise invalid_token()
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT structure")
        header = json.loads(_decode_segment(parts[0]))
        payload = json.loads(_decode_segment(parts[1]))
        _decode_segment(parts[2])
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("Invalid JWT")
        if (header.get("alg") != "RS256" or header.get("typ", "JWT") not in {"JWT", "at+jwt"}
                or not isinstance(header.get("kid"), str) or not header["kid"] or len(header["kid"]) > 256
                or "crit" in header or "b64" in header):
            raise ValueError("Invalid JWT header")
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise invalid_token() from exc

    key = jwks_cache.get_key(settings.cognito_issuer, header["kid"])
    try:
        claims = jwt.decode(
            token, key.key, algorithms=["RS256"], issuer=settings.cognito_issuer,
            audience=settings.cognito_audience,
            options={
                "require": ["iss", "aud", "exp", "iat", "sub", "client_id", "token_use", "sid", "jti"],
                "verify_exp": False, "verify_iat": False, "verify_nbf": False,
                "strict_aud": True,
            },
        )
        now = time.time()
        for name in ("exp", "iat", "nbf"):
            if name in claims and (type(claims[name]) is not int):
                raise ValueError("Invalid timestamp")
        if (claims["exp"] <= now or claims["iat"] > now + 30
                or claims["exp"] - claims["iat"] > MAX_ACCESS_LIFETIME
                or ("nbf" in claims and claims["nbf"] > now + 30)
                or claims["client_id"] != settings.cognito_client_id or claims["token_use"] != "access"
                or not isinstance(claims["sub"], str) or not claims["sub"]
                or claims["sub"] == claims["client_id"]
                or not isinstance(claims["sid"], str) or not 1 <= len(claims["sid"]) <= 256
                or not isinstance(claims["jti"], str) or not 1 <= len(claims["jti"]) <= 256
                or not isinstance(claims.get("username"), str) or not claims["username"]):
            raise ValueError("Invalid claims")
        groups = claims.get("cognito:groups", [])
        if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
            raise ValueError("Invalid groups")
        verified = VerifiedAccess(
            principal=Principal(user_id=claims["sub"], is_admin=settings.cognito_admin_group in groups),
            session_id=claims["sid"],
            token_id=claims["jti"],
            expires_at=claims["exp"],
        )
    except (InvalidTokenError, ValueError, TypeError) as exc:
        raise invalid_token() from exc
    if is_revoked(settings.cognito_issuer, settings.cognito_client_id, verified.session_id, verified.token_id):
        raise invalid_token()
    return verified


def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    cookie: Annotated[str | None, Depends(access_cookie)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    validate_api_config(settings)
    if request.headers.get("authorization") is not None:
        if not credentials:
            raise invalid_token()
        token = credentials.credentials
    else:
        token = cookie
        if not token:
            raise invalid_token()
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            require_origin(request, settings)
    return verify_access_token(token, settings).principal
