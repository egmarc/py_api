from collections.abc import Iterator

import pytest
import fakeredis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from py_api.api.security import Principal, get_principal
from py_api.db.models import Base, UserProfile
from py_api.db.session import get_session
from py_api.main import create_app


@pytest.fixture
def api(monkeypatch) -> Iterator[tuple[TestClient, Session]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    cache = fakeredis.FakeRedis()
    monkeypatch.setattr("py_api.core.profile_cache.get_redis", lambda: cache)
    monkeypatch.setattr("py_api.api.routes.users.lock_profile", lambda session, user_id, *, write: None)
    with Session(engine, expire_on_commit=False) as session:
        app = create_app()
        app.dependency_overrides[get_principal] = lambda: Principal(user_id="alice")
        app.dependency_overrides[get_session] = lambda: session
        with TestClient(app) as client:
            yield client, session
    engine.dispose()
    cache.close()


def create_user(client: TestClient, user_id: str = "alice") -> dict:
    response = client.post(
        "/users", json={"id": user_id, "first_name": "Alice", "last_name": "Smith"}
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_authentication_fails_closed():
    with TestClient(create_app()) as client:
        for path in ("/users/alice", "/admin/users/alice", "/users/alice/addresses"):
            response = client.get(path)
            assert response.status_code == 503
            assert response.json()["detail"] == "Authentication is not configured"
        assert client.post("/users", json={"id": "alice", "first_name": "A", "last_name": "B"}).status_code == 503
        assert client.delete("/users/alice").status_code == 503


def test_authorization_precedes_database_access():
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(user_id="alice")
    with TestClient(app) as client:
        assert client.get("/users/bob").status_code == 403
        assert client.get("/admin/users").status_code == 403


def test_profile_contract_and_authorization(api):
    client, session = api
    assert create_user(client)["status"] == "ACTIVE"
    assert client.post("/users", json={"id": "bob", "first_name": "B", "last_name": "C"}).status_code == 403
    assert client.get("/users/bob").status_code == 403
    assert client.get("/admin/users").status_code == 403
    assert client.post("/users", json={"id": "alice", "first_name": "A", "last_name": "B"}).status_code == 409
    assert client.patch("/users/alice", json={"first_name": None}).status_code == 422
    assert client.patch("/users/alice", json={"status": "PENDING_DELETION"}).status_code == 422
    response = client.patch("/users/alice", json={"middle_name": "M", "first_name": "A"})
    assert response.status_code == 200
    assert response.json()["middle_name"] == "M"
    assert client.patch("/users/alice", json={"middle_name": None}).json()["middle_name"] is None
    assert client.delete("/users/alice").status_code == 503
    assert session.get(UserProfile, "alice") is not None
    session.get(UserProfile, "alice").status = "PENDING_DELETION"
    session.commit()
    assert client.patch("/users/alice", json={"first_name": "B"}).status_code == 409


@pytest.mark.parametrize(
    ("collection", "payload", "updated"),
    [
        ("addresses", {"address_line_1": "1 Main", "city": "Town", "state": "CA", "zip_code": "12345"},
         {"city": "City", "address_line_2": "Apt 1"}),
        ("contact-methods", {"type": "EMAIL", "value": "a@example.com"}, {"value": "b@example.com"}),
    ],
)
def test_child_crud_and_ownership(api, collection, payload, updated):
    client, session = api
    create_user(client)
    session.add(UserProfile(id="bob", first_name="Bob", last_name="Jones"))
    session.commit()
    path = f"/users/alice/{collection}"
    response = client.post(path, json=payload)
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["user_id"] == "alice"
    item_path = f"{path}/{item['id']}"
    assert client.get(item_path).json() == item
    assert client.get(path).json() == [item]
    assert client.get(path, params={"limit": 1, "offset": 1}).json() == []
    assert client.get(path, params={"limit": 101}).status_code == 422
    assert client.patch(item_path, json=updated).status_code == 200
    assert client.patch(item_path, json={"user_id": "bob"}).status_code == 422
    assert client.patch(item_path, json={next(iter(payload)): None}).status_code == 422
    assert client.get(item_path.replace("alice", "bob")).status_code == 403
    client.app.dependency_overrides[get_principal] = lambda: Principal(user_id="staff", is_admin=True)
    assert client.get(item_path.replace("/users/alice", "/admin/users/bob")).status_code == 404
    admin_item_path = item_path.replace("/users", "/admin/users")
    assert client.delete(admin_item_path).status_code == 204
    assert client.get(admin_item_path).status_code == 404


def test_admin_access_and_inactive_user(api):
    client, session = api
    client.app.dependency_overrides[get_principal] = lambda: Principal(user_id="staff", is_admin=True)
    response = client.post(
        "/admin/users", json={"id": "bob", "first_name": "Bob", "last_name": "Jones"}
    )
    assert response.status_code == 201
    assert client.get("/admin/users").json()["items"][0]["id"] == "bob"
    assert client.get("/users/bob").status_code == 403
    assert client.get("/admin/users/bob").status_code == 200
    session.get(UserProfile, "bob").status = "DISABLED"
    session.commit()
    assert client.post(
        "/admin/users/bob/contact-methods", json={"type": "PHONE", "value": "123"}
    ).status_code == 409
    assert client.delete("/admin/users/bob").status_code == 503


def test_openapi_contracts():
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(user_id="alice")
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()
    for path in ("/users/{user_id}", "/admin/users/{user_id}",
                 "/users/{user_id}/addresses", "/admin/users/{user_id}/contact-methods"):
        assert path in spec["paths"]
    assert "UserCreate" in spec["components"]["schemas"]
    assert "AddressRead" in spec["components"]["schemas"]
    assert "ContactRead" in spec["components"]["schemas"]
    user_update = spec["components"]["schemas"]["UserUpdate"]["properties"]
    assert user_update["first_name"]["type"] == "string"
    assert any(option.get("type") == "null" for option in user_update["middle_name"]["anyOf"])
    assert set(spec["components"]["schemas"]["AddressRead"]["required"]) == {
        "id", "user_id", "address_line_1", "address_line_2", "city", "state", "zip_code", "active", "type"
    }
    assert "get" not in spec["paths"]["/users"]
    assert "UserPage" in spec["components"]["schemas"]


def test_admin_filters_and_keyset_pagination(api):
    client, session = api
    session.add_all([
        UserProfile(id="a", first_name="Alice", last_name="Smith", status="ACTIVE"),
        UserProfile(id="b", first_name="ALICE", last_name="SMITH", status="ACTIVE"),
        UserProfile(id="c", first_name="Alice", last_name="Smith", status="DISABLED"),
        UserProfile(id="d", first_name="Alicia", last_name="Smith", status="ACTIVE"),
    ])
    session.commit()
    client.app.dependency_overrides[get_principal] = lambda: Principal(user_id="staff", is_admin=True)
    params = {"first_name": "alice", "last_name": "smith", "status": "ACTIVE", "limit": 1}
    first = client.get("/admin/users", params=params)
    assert first.status_code == 200
    assert [item["id"] for item in first.json()["items"]] == ["a"]
    assert first.json()["next_cursor"] == "a"
    second = client.get("/admin/users", params={**params, "cursor": first.json()["next_cursor"]})
    assert [item["id"] for item in second.json()["items"]] == ["b"]
    assert second.json()["next_cursor"] is None
    assert client.get("/admin/users", params={"status": "INVALID"}).status_code == 422
    assert client.get("/admin/users", params={"limit": 0}).status_code == 422
    assert client.get("/admin/users", params={"first_name": ""}).status_code == 422
    assert client.get("/admin/users", params={"cursor": "z"}).json() == {"items": [], "next_cursor": None}
    assert client.get("/users").status_code == 405


def test_profile_cache_shared_and_invalidated_after_patch(api):
    from py_api.core.profile_cache import get_redis, profile_key

    client, session = api
    create_user(client)
    assert client.get("/users/alice").json()["first_name"] == "Alice"
    key = profile_key("alice")
    cache = get_redis()
    assert cache.ttl(key) > 0
    client.app.dependency_overrides[get_principal] = lambda: Principal(user_id="staff", is_admin=True)
    assert client.get("/admin/users/alice").json()["first_name"] == "Alice"
    assert client.patch("/admin/users/alice", json={"first_name": "New"}).status_code == 200
    assert cache.get(key) is None
    client.app.dependency_overrides[get_principal] = lambda: Principal(user_id="alice")
    assert client.get("/users/alice").json()["first_name"] == "New"
    assert client.get("/users/bob").status_code == 403
    assert cache.get(profile_key("bob")) is None


def test_cache_failure_rejects_profile_update(api, monkeypatch):
    from redis.exceptions import ConnectionError

    client, session = api
    create_user(client)

    class BrokenCache:
        def delete(self, key):
            raise ConnectionError("unavailable")

    monkeypatch.setattr("py_api.core.profile_cache.get_redis", lambda: BrokenCache())
    assert client.patch("/users/alice", json={"first_name": "New"}).status_code == 503
    session.rollback()
    assert session.get(UserProfile, "alice").first_name == "Alice"
