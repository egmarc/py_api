from typing import Annotated, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from py_api.api.security import Principal, get_principal
from py_api.core.profile_cache import cache_profile, get_cached_profile, invalidate_profile, lock_profile
from py_api.db.models import Address, ContactMethod, UserProfile
from py_api.db.session import get_session
from py_api.schemas.users import (
    AddressCreate,
    AddressRead,
    AddressUpdate,
    ContactCreate,
    ContactRead,
    ContactUpdate,
    ErrorResponse,
    ProfileStatus,
    UserCreate,
    UserPage,
    UserRead,
    UserUpdate,
)

SessionDep = Annotated[Session, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]
Model = TypeVar("Model", Address, ContactMethod)


def authorize(principal: Principal, user_id: str, admin: bool) -> None:
    if (admin and not principal.is_admin) or (not admin and principal.user_id != user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def profile(session: Session, user_id: str, *, lock: bool = False) -> UserProfile:
    query = select(UserProfile).where(UserProfile.id == user_id)
    if lock:
        query = query.with_for_update()
    user = session.scalar(query)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if lock and user.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is not active")
    return user


def child(session: Session, model: type[Model], user_id: str, item_id: int) -> Model:
    item = session.scalar(select(model).where(model.user_id == user_id, model.id == item_id))
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return item


def commit(session: Session) -> None:
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Resource conflicts with existing data"
        ) from exc


def build_router(*, admin: bool) -> APIRouter:
    def authorized_principal(request: Request, principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        user_id = request.path_params.get("user_id")
        if admin or user_id is not None:
            authorize(principal, user_id or principal.user_id, admin)
        return principal

    auth = Annotated[Principal, Depends(authorized_principal)]
    router = APIRouter(
        tags=["admin users" if admin else "users"],
        responses={
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            503: {"model": ErrorResponse},
        },
    )

    if admin:
        @router.get("/users", response_model=UserPage)
        def list_users(
            principal: auth,
            session: SessionDep,
            status: ProfileStatus | None = None,
            first_name: Annotated[str | None, Query(min_length=1)] = None,
            last_name: Annotated[str | None, Query(min_length=1)] = None,
            limit: Limit = 50,
            cursor: Annotated[str | None, Query(min_length=1)] = None,
        ) -> UserPage:
            query = select(UserProfile)
            if status is not None:
                query = query.where(UserProfile.status == status.value)
            if first_name is not None:
                query = query.where(func.lower(UserProfile.first_name) == func.lower(first_name))
            if last_name is not None:
                query = query.where(func.lower(UserProfile.last_name) == func.lower(last_name))
            if cursor is not None:
                query = query.where(UserProfile.id > cursor)
            users = list(session.scalars(query.order_by(UserProfile.id).limit(limit + 1)))
            return UserPage(
                items=[UserRead.model_validate(user) for user in users[:limit]],
                next_cursor=users[limit - 1].id if len(users) > limit else None,
            )

    @router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
    def create_user(body: UserCreate, principal: auth, session: SessionDep) -> UserProfile:
        authorize(principal, body.id, admin)
        lock_profile(session, body.id, write=True)
        user = UserProfile(**body.model_dump())
        session.add(user)
        invalidate_profile(body.id)
        commit(session)
        session.refresh(user)
        return user

    @router.get("/users/{user_id}", response_model=UserRead)
    def get_user(user_id: str, principal: auth, session: SessionDep) -> UserRead:
        lock_profile(session, user_id, write=False)
        cached = get_cached_profile(user_id)
        if cached is not None:
            return cached
        user = UserRead.model_validate(profile(session, user_id))
        cache_profile(user)
        return user

    @router.patch("/users/{user_id}", response_model=UserRead)
    def update_user(
        user_id: str, body: UserUpdate, principal: auth, session: SessionDep
    ) -> UserProfile:
        lock_profile(session, user_id, write=True)
        user = profile(session, user_id, lock=True)
        for key, value in body.model_dump(exclude_unset=True).items():
            setattr(user, key, value)
        invalidate_profile(user_id)
        commit(session)
        session.refresh(user)
        return user

    @router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_user(user_id: str, principal: auth) -> Response:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User deletion workflow is not configured",
        )

    @router.get("/users/{user_id}/addresses", response_model=list[AddressRead])
    def list_addresses(
        user_id: str, principal: auth, session: SessionDep, limit: Limit = 50, offset: Offset = 0
    ) -> list[Address]:
        profile(session, user_id)
        return list(session.scalars(
            select(Address).where(Address.user_id == user_id).order_by(Address.id).limit(limit).offset(offset)
        ))

    @router.post("/users/{user_id}/addresses", response_model=AddressRead, status_code=status.HTTP_201_CREATED)
    def create_address(
        user_id: str, body: AddressCreate, principal: auth, session: SessionDep
    ) -> Address:
        profile(session, user_id, lock=True)
        item = Address(user_id=user_id, **body.model_dump())
        session.add(item)
        commit(session)
        session.refresh(item)
        return item

    @router.get("/users/{user_id}/addresses/{item_id}", response_model=AddressRead)
    def get_address(user_id: str, item_id: int, principal: auth, session: SessionDep) -> Address:
        return child(session, Address, user_id, item_id)

    @router.patch("/users/{user_id}/addresses/{item_id}", response_model=AddressRead)
    def update_address(
        user_id: str, item_id: int, body: AddressUpdate, principal: auth, session: SessionDep
    ) -> Address:
        profile(session, user_id, lock=True)
        item = child(session, Address, user_id, item_id)
        for key, value in body.model_dump(exclude_unset=True).items():
            setattr(item, key, value)
        commit(session)
        session.refresh(item)
        return item

    @router.delete("/users/{user_id}/addresses/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_address(user_id: str, item_id: int, principal: auth, session: SessionDep) -> Response:
        profile(session, user_id, lock=True)
        session.delete(child(session, Address, user_id, item_id))
        commit(session)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/users/{user_id}/contact-methods", response_model=list[ContactRead])
    def list_contacts(
        user_id: str, principal: auth, session: SessionDep, limit: Limit = 50, offset: Offset = 0
    ) -> list[ContactMethod]:
        profile(session, user_id)
        return list(session.scalars(
            select(ContactMethod).where(ContactMethod.user_id == user_id)
            .order_by(ContactMethod.id).limit(limit).offset(offset)
        ))

    @router.post(
        "/users/{user_id}/contact-methods", response_model=ContactRead, status_code=status.HTTP_201_CREATED
    )
    def create_contact(
        user_id: str, body: ContactCreate, principal: auth, session: SessionDep
    ) -> ContactMethod:
        profile(session, user_id, lock=True)
        item = ContactMethod(user_id=user_id, **body.model_dump())
        session.add(item)
        commit(session)
        session.refresh(item)
        return item

    @router.get("/users/{user_id}/contact-methods/{item_id}", response_model=ContactRead)
    def get_contact(user_id: str, item_id: int, principal: auth, session: SessionDep) -> ContactMethod:
        return child(session, ContactMethod, user_id, item_id)

    @router.patch("/users/{user_id}/contact-methods/{item_id}", response_model=ContactRead)
    def update_contact(
        user_id: str, item_id: int, body: ContactUpdate, principal: auth, session: SessionDep
    ) -> ContactMethod:
        profile(session, user_id, lock=True)
        item = child(session, ContactMethod, user_id, item_id)
        for key, value in body.model_dump(exclude_unset=True).items():
            setattr(item, key, value)
        commit(session)
        session.refresh(item)
        return item

    @router.delete("/users/{user_id}/contact-methods/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_contact(user_id: str, item_id: int, principal: auth, session: SessionDep) -> Response:
        profile(session, user_id, lock=True)
        session.delete(child(session, ContactMethod, user_id, item_id))
        commit(session)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
