import os
import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from py_api.api.routes import users
from py_api.api.security import Principal, get_principal
from py_api.core.config import get_settings
from py_api.db.session import get_engine, get_session
from py_api.main import create_app


@pytest.mark.skipif(
    not os.getenv("PY_API_TEST_DATABASE_URL"),
    reason="Requires a dedicated PostgreSQL database initialized with the reference schema",
)
def test_postgres_schema_and_triggers(monkeypatch):
    engine = create_engine(os.environ["PY_API_TEST_DATABASE_URL"])
    user_id = f"test-{uuid4()}"
    monkeypatch.setenv("PY_API_DATABASE_URL", os.environ["PY_API_TEST_DATABASE_URL"])
    cache = fakeredis.FakeRedis()
    monkeypatch.setattr("py_api.core.profile_cache.get_redis", lambda: cache)
    get_settings.cache_clear()
    get_engine.cache_clear()
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(user_id=user_id)
    try:
        with TestClient(app) as client:
            assert client.post("/users", json={"id": user_id, "first_name": "A", "last_name": "B"}).status_code == 201
            address = client.post(
                f"/users/{user_id}/addresses",
                json={"address_line_1": "1 Main", "city": "Town", "state": "CA", "zip_code": "12345"},
            )
            assert address.status_code == 201, address.text
            assert address.json()["id"] > 0
            contact = client.post(f"/users/{user_id}/contact-methods", json={"type": "SMS", "value": "123"})
            assert contact.status_code == 201, contact.text
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE user_profiles SET status = 'PENDING_DELETION' WHERE id = :id"), {"id": user_id}
                )
            assert client.patch(
                f"/users/{user_id}/addresses/{address.json()['id']}", json={"city": "New"}
            ).status_code == 409
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(
                    text("UPDATE contact_methods SET value = '456' WHERE id = :id"),
                    {"id": contact.json()["id"]},
                )
            assert client.delete(f"/users/{user_id}").status_code == 503
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM addresses WHERE user_id = :id"), {"id": user_id})
            connection.execute(text("DELETE FROM contact_methods WHERE user_id = :id"), {"id": user_id})
            connection.execute(text("DELETE FROM user_profiles WHERE id = :id"), {"id": user_id})
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        engine.dispose()
        cache.close()


@pytest.mark.skipif(
    not os.getenv("PY_API_TEST_DATABASE_URL"),
    reason="Requires a dedicated PostgreSQL database initialized with the reference schema",
)
def test_profile_cache_fill_and_update_are_serialized(monkeypatch):
    engine = create_engine(os.environ["PY_API_TEST_DATABASE_URL"])
    user_id = f"test-{uuid4()}"
    cache = fakeredis.FakeRedis()
    monkeypatch.setattr("py_api.core.profile_cache.get_redis", lambda: cache)
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(user_id=user_id)

    def db_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = db_session
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO user_profiles(id, first_name, last_name) VALUES (:id, 'Old', 'Name')"),
            {"id": user_id},
        )
    fill_started = threading.Event()
    release_fill = threading.Event()
    original_cache_profile = users.cache_profile

    def delayed_cache(value):
        fill_started.set()
        assert release_fill.wait(timeout=10)
        original_cache_profile(value)

    monkeypatch.setattr(users, "cache_profile", delayed_cache)
    try:
        with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as pool:
            reader = pool.submit(client.get, f"/users/{user_id}")
            assert fill_started.wait(timeout=10)
            writer = pool.submit(client.patch, f"/users/{user_id}", json={"first_name": "New"})
            with pytest.raises(TimeoutError):
                writer.result(timeout=0.3)
            release_fill.set()
            assert reader.result(timeout=10).json()["first_name"] == "Old"
            assert writer.result(timeout=10).json()["first_name"] == "New"
            assert client.get(f"/users/{user_id}").json()["first_name"] == "New"
    finally:
        release_fill.set()
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM user_profiles WHERE id = :id"), {"id": user_id})
        engine.dispose()
        cache.close()


@pytest.mark.skipif(
    not os.getenv("PY_API_TEST_DATABASE_URL"),
    reason="Requires a dedicated PostgreSQL database initialized with the reference schema",
)
def test_admin_user_filters_and_cursor_on_postgres():
    engine = create_engine(os.environ["PY_API_TEST_DATABASE_URL"])
    prefix = f"test-{uuid4()}"
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(user_id="staff", is_admin=True)

    def db_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = db_session
    with engine.begin() as connection:
        for suffix, state in (("a", "ACTIVE"), ("b", "ACTIVE"), ("c", "DISABLED")):
            connection.execute(
                text("INSERT INTO user_profiles(id, first_name, last_name, status) "
                     "VALUES (:id, :first, 'Jones', :state)"),
                {"id": prefix + suffix, "first": prefix.upper(), "state": state},
            )
    try:
        with TestClient(app) as client:
            params = {"first_name": prefix, "last_name": "jones", "status": "ACTIVE", "limit": 1}
            page = client.get("/admin/users", params=params).json()
            assert [item["id"] for item in page["items"]] == [prefix + "a"]
            assert page["next_cursor"] == prefix + "a"
            page = client.get("/admin/users", params={**params, "cursor": page["next_cursor"]}).json()
            assert [item["id"] for item in page["items"]] == [prefix + "b"]
            assert page["next_cursor"] is None
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM user_profiles WHERE id IN (:a, :b, :c)"),
                {"a": prefix + "a", "b": prefix + "b", "c": prefix + "c"},
            )
        engine.dispose()
