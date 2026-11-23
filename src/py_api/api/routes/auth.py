import base64
import hashlib
import hmac
import secrets
import time
from typing import Annotated
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from py_api.api.security import (
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    SESSION_COOKIE,
    STATE_COOKIE,
    Principal,
    VerifiedAccess,
    get_principal,
    https_url,
    require_origin,
    unavailable,
    validate_api_config,
    verify_access_token,
)
from py_api.core.config import Settings, get_settings
from py_api.core.revocations import CLOCK_SKEW, MAX_ACCESS_LIFETIME, is_revoked, revoke

router = APIRouter(prefix="/api/auth", tags=["authentication"])
SettingsDep = Annotated[Settings, Depends(get_settings)]


class TokenResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    access_token: str = Field(min_length=1, max_length=3800)
    token_type: str
    expires_in: int = Field(gt=0, le=86400)
    refresh_token: str | None = Field(default=None, min_length=1, max_length=3800)


class AuthStatus(BaseModel):
    status: str


class LogoutResponse(AuthStatus):
    logout_url: str


class BrowserSession(BaseModel):
    model_config = ConfigDict(strict=True)
    sid: str = Field(min_length=1, max_length=256)
    jti: str = Field(min_length=1, max_length=256)
    token_exp: int
    exp: int
    revoke_until: int


def bff_config(settings: Settings) -> None:
    validate_api_config(settings)
    if (
        not https_url(settings.cognito_domain, origin_only=True)
        or not https_url(settings.auth_redirect_uri)
        or not https_url(settings.frontend_origin, origin_only=True)
        or not https_url(settings.frontend_redirect_url)
        or not settings.cognito_client_secret
        or not settings.cognito_client_secret.get_secret_value()
        or not settings.cognito_scope.strip()
        or not 1 <= settings.refresh_cookie_max_age <= 315360000
        or settings.cognito_refresh_token_lifetime is None
        or not settings.refresh_cookie_max_age <= settings.cognito_refresh_token_lifetime <= 315360000
    ):
        raise unavailable()
    redirect = urlsplit(settings.frontend_redirect_url)
    if f"{redirect.scheme}://{redirect.netloc}" != settings.frontend_origin:
        raise unavailable("Invalid authentication configuration")


def state_key(settings: Settings) -> bytes:
    return hmac.digest(settings.cognito_client_secret.get_secret_value().encode(), b"py-api-oauth-state-v1", "sha256")


def token_request(settings: Settings, data: dict[str, str], expected_session: str | None = None) -> tuple[TokenResponse, VerifiedAccess]:
    try:
        response = httpx.post(
            f"{settings.cognito_domain}/oauth2/token",
            data=data,
            auth=(settings.cognito_client_id, settings.cognito_client_secret.get_secret_value()),
            timeout=10.0,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise unavailable("Identity provider unavailable") from exc
    if response.status_code in {400, 401}:
        raise HTTPException(status_code=401, detail="Authentication could not be completed")
    if response.status_code != 200:
        raise unavailable("Identity provider unavailable")
    try:
        tokens = TokenResponse.model_validate(response.json())
        if tokens.token_type.lower() != "bearer":
            raise ValueError("Invalid token type")
    except (ValueError, ValidationError) as exc:
        raise unavailable("Identity provider returned an invalid response") from exc
    try:
        verified = verify_access_token(tokens.access_token, settings)
        if expected_session is not None and verified.session_id != expected_session:
            raise HTTPException(status_code=401, detail="Invalid session")
    except HTTPException as exc:
        if exc.status_code == 401:
            raise unavailable("Identity provider returned an invalid access token") from exc
        raise
    return tokens, verified


def set_cookies(
    response: Response, tokens: TokenResponse, settings: Settings, verified: VerifiedAccess,
    previous_session: BrowserSession | None = None,
) -> None:
    now = int(time.time())
    expires = previous_session.exp if previous_session else now + settings.refresh_cookie_max_age
    revoke_until = previous_session.revoke_until if previous_session else (
        now + settings.cognito_refresh_token_lifetime + MAX_ACCESS_LIFETIME + CLOCK_SKEW
    )
    max_age = max(1, expires - now)
    response.set_cookie(
        ACCESS_COOKIE, tokens.access_token, max_age=tokens.expires_in,
        secure=True, httponly=True, samesite="strict", path="/",
    )
    if tokens.refresh_token:
        response.set_cookie(
            REFRESH_COOKIE, tokens.refresh_token, max_age=max_age,
            secure=True, httponly=True, samesite="strict", path="/",
        )
    session_token = jwt.encode(
        {"sid": verified.session_id, "jti": verified.token_id, "token_exp": verified.expires_at,
         "exp": expires, "revoke_until": revoke_until},
        state_key(settings), algorithm="HS256",
    )
    response.set_cookie(
        SESSION_COOKIE, session_token, max_age=max_age,
        secure=True, httponly=True, samesite="strict", path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.get("/login", response_class=RedirectResponse, status_code=302)
def login(settings: SettingsDep) -> RedirectResponse:
    bff_config(settings)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state_token = jwt.encode(
        {"state": state, "verifier": verifier, "exp": int(time.time()) + 600},
        state_key(settings), algorithm="HS256",
    )
    params = urlencode({
        "response_type": "code", "client_id": settings.cognito_client_id,
        "redirect_uri": settings.auth_redirect_uri, "scope": settings.cognito_scope,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": settings.cognito_audience,
    })
    response = RedirectResponse(f"{settings.cognito_domain}/oauth2/authorize?{params}", status_code=302)
    response.set_cookie(STATE_COOKIE, state_token, max_age=600, secure=True, httponly=True, samesite="lax", path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/callback", response_class=RedirectResponse, status_code=303)
def callback(request: Request, settings: SettingsDep) -> RedirectResponse:
    bff_config(settings)
    query = request.query_params
    try:
        if (len(query.getlist("code")) != 1 or len(query.getlist("state")) != 1
                or not 1 <= len(query["code"]) <= 4096 or not 1 <= len(query["state"]) <= 128):
            raise ValueError("Invalid authorization response")
        state_token = request.cookies.get(STATE_COOKIE, "")
        if len(state_token) > 4096:
            raise ValueError("Invalid authorization state")
        saved = jwt.decode(state_token, state_key(settings), algorithms=["HS256"], options={"require": ["state", "verifier", "exp"]})
        if (not isinstance(saved["state"], str) or not isinstance(saved["verifier"], str)
                or not secrets.compare_digest(saved["state"], query["state"])):
            raise ValueError("Invalid state")
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid authorization response") from exc
    tokens, verified = token_request(settings, {
        "grant_type": "authorization_code", "code": query["code"],
        "redirect_uri": settings.auth_redirect_uri, "code_verifier": saved["verifier"],
    })
    if not tokens.refresh_token:
        raise unavailable("Identity provider returned no refresh token")
    response = RedirectResponse(settings.frontend_redirect_url, status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.headers["Referrer-Policy"] = "no-referrer"
    set_cookies(response, tokens, settings, verified)
    return response


@router.post("/refresh", response_model=AuthStatus)
def refresh(request: Request, response: Response, settings: SettingsDep) -> AuthStatus:
    bff_config(settings)
    require_origin(request, settings)
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not refresh_token or len(refresh_token) > 3800:
        raise HTTPException(status_code=401, detail="Refresh session is unavailable")
    session = read_session_cookie(request, settings)
    if is_revoked(settings.cognito_issuer, settings.cognito_client_id, session.sid):
        raise HTTPException(status_code=401, detail="Refresh session is unavailable")
    tokens, verified = token_request(
        settings, {"grant_type": "refresh_token", "refresh_token": refresh_token}, session.sid
    )
    set_cookies(response, tokens, settings, verified, session)
    return AuthStatus(status="refreshed")


@router.get("/session", response_model=Principal)
def session(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    return principal


def read_session_cookie(request: Request, settings: Settings) -> BrowserSession:
    value = request.cookies.get(SESSION_COOKIE, "")
    try:
        if not value or len(value) > 4096:
            raise ValueError("Invalid session cookie")
        claims = jwt.decode(
            value, state_key(settings), algorithms=["HS256"],
            options={"require": ["sid", "jti", "token_exp", "exp", "revoke_until"]},
        )
        session = BrowserSession.model_validate(claims)
        if session.revoke_until <= time.time():
            raise ValueError("Invalid session cookie")
        return session
    except (jwt.PyJWTError, ValueError, TypeError, ValidationError) as exc:
        raise HTTPException(status_code=401, detail="Session is unavailable") from exc


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request, response: Response, settings: SettingsDep,
) -> LogoutResponse:
    bff_config(settings)
    require_origin(request, settings)
    session = read_session_cookie(request, settings)
    revoke(
        settings.cognito_issuer, settings.cognito_client_id, session.sid,
        session.jti, session.token_exp, session.revoke_until,
    )
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not refresh_token or len(refresh_token) > 3800:
        raise HTTPException(status_code=401, detail="Refresh session is unavailable; local session revoked")
    try:
        result = httpx.post(
            f"{settings.cognito_domain}/oauth2/revoke",
            data={"token": refresh_token, "revoke_associated_sessions": "LINKED"},
            auth=(settings.cognito_client_id, settings.cognito_client_secret.get_secret_value()),
            timeout=10.0, follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise unavailable("Identity provider revocation unavailable; retry logout") from exc
    if result.status_code != 200:
        raise unavailable("Identity provider revocation failed; retry logout")
    for cookie in (ACCESS_COOKIE, REFRESH_COOKIE, SESSION_COOKIE, STATE_COOKIE):
        response.delete_cookie(cookie, path="/", secure=True, httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    params = urlencode({"client_id": settings.cognito_client_id, "logout_uri": settings.frontend_redirect_url})
    return LogoutResponse(status="logged_out", logout_url=f"{settings.cognito_domain}/logout?{params}")
