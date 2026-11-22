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

## Running locally

```bash
poetry install
poetry run fastapi dev src/py_api/main.py
```

API: http://localhost:8000 — docs: http://localhost:8000/docs

## Running with Docker

```bash
docker compose up --build
```

Set `API_PORT` to change the host port (default `8000`).

## Testing

```bash
# In-process (no server needed)
poetry run pytest

# Against a running server, e.g. the Docker container
docker compose up -d --build --wait
API_BASE_URL=http://localhost:8000 poetry run pytest -m integration
docker compose down
```

## CI

`.github/workflows/integration-tests.yml` builds the Docker image and runs the integration
tests against the container on every pull request targeting `main` and every push/merge to `main`.
