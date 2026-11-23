# Py API
REST API written in Python using the FastAPI framework.

## Project structure

```
src/py_api/
├── main.py              # App factory (create_app) and ASGI `app`
├── core/config.py       # Settings (pydantic-settings, env prefix PY_API_)
├── api/router.py        # Aggregates all route modules
├── api/routes/health.py # GET /health-check
└── schemas/health.py    # Response models
tests/integration/       # Integration tests (pytest)
```

## Configuration

Settings are read from environment variables (or a `.env` file). See `.env.example`.

| Variable             | Default  |
|----------------------|----------|
| `PY_API_APP_NAME`    | `Py API` |
| `PY_API_ENVIRONMENT` | `local`  |
| `PY_API_DEBUG`       | `false`  |
| `PY_API_DATABASE_URL` | unset   |
| `PY_API_REDIS_URL` | unset |

`PY_API_DATABASE_URL` is a SQLAlchemy PostgreSQL URL, for example
`postgresql+psycopg://user:password@host:5432/py_api?sslmode=verify-full`.
SQLAlchemy connects to AWS RDS for PostgreSQL through the psycopg driver. Configure
network access, credentials, and the RDS CA certificate separately; do not commit secrets.
The database role needs the necessary permissions on the three user-data tables and
the identity sequences. Do not use the restricted deletion-worker role for these routes.
The database schema must already exist: the application does not create or migrate tables.
`src/migrations/001_init.sql` is the current reference schema.

## User data API

The customer routes use `/users` and the staff/admin routes use `/admin/users`.
Both support creating a profile (`POST /users`), reading it (`GET /users/{user_id}`),
and partially updating it (`PATCH /users/{user_id}`). Admins can list profiles
(`GET /admin/users`); there is no customer profile collection GET. Nested `/users/{user_id}/addresses` and
`/users/{user_id}/contact-methods` collections support POST and paginated GET, and
their `/{id}` resources support GET, PATCH and DELETE. Prefix each with `/admin`
for staff routes. Address and contact lists accept `limit` (1–100, default 50) and
`offset` (default 0).
Request and response models are documented in `/docs` and `/openapi.json`. IDs and
ownership cannot be changed through updates. Profile status is read-only; updates to
user data are restricted to active profiles.

Customer routes allow access only to the authenticated user's Cognito `sub`; admin
routes require membership in the configured Cognito group. Profile DELETE returns 503
until the deletion workflow (including stored-object deletion) exists; it must not be
replaced with a direct database delete.

`GET /admin/users` accepts `status` (`ACTIVE`, `DISABLED`, or `PENDING_DELETION`),
`first_name`, and `last_name` filters. Name matching is case-insensitive and exact;
filters are combined with AND. The response is `{"items": [...], "next_cursor": ...}`.
Results are ordered by user ID and limited by `limit` (1–100, default 50). Pass
`next_cursor` as the `cursor` query parameter for the next page, keeping the filters
unchanged. A null cursor means there is no next page. Pages are not a database
snapshot; concurrent changes can change later results.

After authorization, customer and admin profile GETs share a Redis cache entry keyed
by a hash of the user ID, not the bearer token. Entries expire after 60 seconds.
Profile creation and PATCH invalidate that entry before committing. PostgreSQL
transaction-scoped advisory locks coordinate reads and writes across API instances,
preventing an older cache fill from racing with an API update. A Redis failure returns
503 rather than silently serving stale data or committing an uninvalidated update.
Profile DELETE is still disabled. Any future deletion workflow or other writer that
changes profile data must acquire the same exclusive advisory lock and invalidate the
same cache key before committing; writes outside that protocol may be stale for up to
60 seconds. Redis holds personal data, so restrict access and protect its transport,
backups and persistence accordingly.

## Cognito authentication

Configure the values shown in `.env.example`. The user pool app client must have a
secret, authorization-code grant and token revocation enabled, the configured callback
and sign-out URL registered, and the requested scopes enabled. Enable Cognito user-pool
session tracking (requires the Essentials or Plus plan); access tokens without `sid`
are rejected. Tokens issued before enabling session tracking require a new login.
Set `PY_API_COGNITO_ISSUER` to the exact user-pool issuer,
`PY_API_COGNITO_DOMAIN` to its hosted-login domain (no trailing slash), and
`PY_API_COGNITO_AUDIENCE` to the HTTPS API resource URL. The login request passes
that URL as Cognito's `resource` parameter. Access tokens must contain an exact
matching `aud`, `client_id`, `iss`, `token_use=access`, user `sub`, `username`, `sid`,
and `jti`; the access-token lifetime (`exp - iat`) must not exceed 24 hours;
standard non-resource-bound Cognito access tokens and ID tokens are not accepted.
If custom scopes are needed, set `PY_API_COGNITO_SCOPE` to the space-separated
scopes enabled for the app client. The signing key is resolved only from the
configured issuer's JWKS endpoint; keys are cached and unknown-key refreshes
are rate-limited. Only RS256 is accepted. `typ`, if present, must be `JWT` or
`at+jwt` (Cognito may omit it). Expiration is strict; `iat` and `nbf` allow at
most 30 seconds of clock skew.

API clients can send `Authorization: Bearer <access-token>`. Browser clients use
the BFF flow instead:

1. Navigate to `GET /api/auth/login` to start Cognito managed login with PKCE and state.
2. Cognito redirects to `GET /api/auth/callback`. The backend exchanges the code and
   sets host-only Secure, HttpOnly, SameSite=Strict access, refresh, and signed session cookies.
   The short-lived login-state cookie uses SameSite=Lax for the cross-site callback.
   The BFF rejects token values over 3,800 characters to avoid oversized cookies.
3. Use `GET /api/auth/session` to obtain the current user ID and admin flag. Send
   requests with credentials enabled. On an expired access token, send
   `POST /api/auth/refresh` with credentials and retry the request. The browser never
   receives tokens in a response body. Rotated refresh tokens replace the old cookie;
   the frontend must serialize refresh attempts and wait for any refresh to finish
   before logout to avoid rotation races.
4. Send `POST /api/auth/logout` with credentials and the frontend origin, even if the
   access token has expired. On success, the response contains `logout_url`: navigate
   the browser to that URL to clear Cognito's managed-login cookie and complete sign-out.
   Register `PY_API_FRONTEND_REDIRECT_URL` as an allowed Cognito sign-out URL. The
   backend first records the session as revoked, then revokes the refresh token and
   linked SSO session at Cognito, and clears local cookies. If Cognito is unavailable,
   logout returns 503 and retains the cookies for a retry; the API session is already
   revoked. If the refresh cookie is missing, logout returns 401 after locally revoking
   the session; Cognito sign-out must still be completed separately. A session created
   before this change must log in again to obtain the signed session cookie.

Browser and API hosts must be HTTPS and same-site for Strict cookies to work.
Set `PY_API_FRONTEND_ORIGIN` to the exact HTTPS origin of the browser app and
`PY_API_FRONTEND_REDIRECT_URL` to a URL on that origin. Cookie-authenticated
mutations, refresh, and logout require a matching `Origin` header; credentialed
CORS permits only this origin. Cross-site deployments require a different cookie
and CSRF design. Configure `PY_API_REFRESH_COOKIE_MAX_AGE` to match or be shorter
than the Cognito app client's refresh-token lifetime; Cognito enforces expiry.
Set `PY_API_COGNITO_REFRESH_TOKEN_LIFETIME` to at least the app client's actual
refresh-token validity in seconds (at most ten years), and never less than
`PY_API_REFRESH_COOKIE_MAX_AGE`. Do not decrease it until every session issued under
the longer Cognito lifetime has expired. Session cookies created before Redis support
require a new login. Do not log authorization codes, tokens, cookies, or client secrets.

All API instances must use the same `PY_API_REDIS_URL`. Use a TLS-protected `rediss://`
endpoint in production and a non-cluster-mode Redis deployment; configure access
controls, persistence and high availability appropriate for security data. Use a
dedicated instance with `noeviction`: eviction, data loss, a stale failover replica,
or changing the Redis database can restore revoked sessions. Redis and API hosts
must have synchronized clocks. Every access token is checked against Redis for both
its session ID and `jti`. Logout atomically stores hashed identifiers: the `jti`
key expires at the JWT's `exp`, and the session key expires after the maximum possible
refresh-token lifetime plus 24 hours and 30 seconds for the last access token.
This keeps other tokens from the same session blocked even when Cognito revocation
fails or a token refresh races with logout. Cookies retain their original session
expiration across refreshes. Requests already authorized can still complete.
Redis failures cause authentication and logout to fail closed with 503.
Revocations performed outside this API and Cognito group changes are not automatically
reflected in this table; use short-lived access tokens or add a separate synchronization
mechanism when immediate enforcement of those events is required. Cognito sign-out
does not necessarily sign users out of their external social or OIDC identity provider.

The health check, login, callback, refresh and logout are public (refresh and logout
require session cookies and origin); CORS preflights are also unauthenticated. All other application routes,
including `/docs`, `/redoc`, and `/openapi.json`, require an access token. If Cognito
is not configured, protected routes return 503. JWT or refresh credential failures
return 401; signing-key and identity-provider outages return 503.

## Running locally

```bash
poetry install
poetry run fastapi dev src/py_api/main.py
```

API: http://localhost:8000 — docs: http://localhost:8000/docs (authentication required).
The browser BFF flow requires HTTPS, including for local development.

## Running with Docker

```bash
docker compose up --build
```

Set `API_PORT` to change the host port (default `8000`).
Set `PY_API_DATABASE_URL` in the environment or Compose `.env` to pass it to the API container.

## Testing

```bash
# In-process (no server needed)
poetry run pytest

# Against a running server, e.g. the Docker container
docker compose up -d --build --wait
API_BASE_URL=http://localhost:8000 poetry run pytest -m integration
docker compose down
```

The optional PostgreSQL integration test requires a **dedicated test database** with
the reference schema applied. Set `PY_API_TEST_DATABASE_URL` to its psycopg connection
URL when running `poetry run pytest tests/integration/test_postgres_users.py`.
Set `PY_API_TEST_REDIS_URL` to a dedicated Redis instance to run the real-Redis
integration test in `tests/integration/test_redis_revocations.py`.

## CI

`.github/workflows/integration-tests.yml` builds the Docker image and runs the integration
tests against the container on every pull request targeting `main` and every push/merge to `main`.
