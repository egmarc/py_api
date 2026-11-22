import os
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from py_api.main import create_app


@pytest.fixture(scope="session")
def client() -> Iterator[httpx.Client]:
    """HTTP client for integration tests.

    If ``API_BASE_URL`` is set (e.g. ``http://localhost:8000``), tests run against that live
    server (such as the Docker container). Otherwise the app is served in-process.
    """
    base_url = os.getenv("API_BASE_URL")
    if base_url:
        with httpx.Client(base_url=base_url, timeout=10.0) as live_client:
            yield live_client
    else:
        with TestClient(create_app()) as test_client:
            yield test_client
