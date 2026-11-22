from datetime import datetime

import httpx
import pytest

pytestmark = pytest.mark.integration


def test_health_check_returns_ok(client: httpx.Client) -> None:
    response = client.get("/health-check")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["environment"]
    assert datetime.fromisoformat(body["timestamp"]).tzinfo is not None


def test_health_check_rejects_unsupported_method(client: httpx.Client) -> None:
    response = client.post("/health-check")

    assert response.status_code == 405


def test_openapi_schema_exposes_health_check(client: httpx.Client) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/health-check" in response.json()["paths"]
