from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

NonEmpty = Annotated[str, Field(min_length=1)]


class ProfileStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PENDING_DELETION = "PENDING_DELETION"
    DISABLED = "DISABLED"


class AddressType(StrEnum):
    HOME = "HOME"
    WORK = "WORK"
    MAILING = "MAILING"
    BILLING = "BILLING"


class ContactType(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SMS = "SMS"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class PatchContract(Contract):
    @model_validator(mode="after")
    def reject_null_required_fields(self) -> Self:
        for name in self.model_fields_set - self.nullable_fields():
            if getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self

    @classmethod
    def nullable_fields(cls) -> set[str]:
        return set()


class UserCreate(Contract):
    id: NonEmpty
    first_name: NonEmpty
    last_name: NonEmpty
    middle_name: str | None = None


class UserUpdate(PatchContract):
    first_name: NonEmpty | SkipJsonSchema[None] = None
    last_name: NonEmpty | SkipJsonSchema[None] = None
    middle_name: str | None = None

    @classmethod
    def nullable_fields(cls) -> set[str]:
        return {"middle_name"}


class UserRead(Contract):
    id: str
    status: ProfileStatus
    first_name: str
    last_name: str
    middle_name: str | None


class UserPage(Contract):
    items: list[UserRead]
    next_cursor: str | None


class AddressCreate(Contract):
    address_line_1: NonEmpty
    address_line_2: str | None = None
    city: NonEmpty
    state: NonEmpty
    zip_code: NonEmpty
    active: bool = True
    type: AddressType = AddressType.HOME


class AddressUpdate(PatchContract):
    address_line_1: NonEmpty | SkipJsonSchema[None] = None
    address_line_2: str | None = None
    city: NonEmpty | SkipJsonSchema[None] = None
    state: NonEmpty | SkipJsonSchema[None] = None
    zip_code: NonEmpty | SkipJsonSchema[None] = None
    active: bool | SkipJsonSchema[None] = None
    type: AddressType | SkipJsonSchema[None] = None

    @classmethod
    def nullable_fields(cls) -> set[str]:
        return {"address_line_2"}


class AddressRead(Contract):
    id: int
    user_id: str
    address_line_1: str
    address_line_2: str | None
    city: str
    state: str
    zip_code: str
    active: bool
    type: AddressType


class ContactCreate(Contract):
    type: ContactType
    value: str


class ContactUpdate(PatchContract):
    type: ContactType | SkipJsonSchema[None] = None
    value: str | SkipJsonSchema[None] = None


class ContactRead(Contract):
    id: int
    user_id: str
    type: ContactType
    value: str


class ErrorResponse(BaseModel):
    detail: str
