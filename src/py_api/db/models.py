from sqlalchemy import BigInteger, Boolean, ForeignKey, Identity, Integer, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, server_default=text("'ACTIVE'"))
    first_name: Mapped[str] = mapped_column(Text)
    last_name: Mapped[str] = mapped_column(Text)
    middle_name: Mapped[str | None] = mapped_column(Text)


class Address(Base):
    __tablename__ = "addresses"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), Identity(always=True), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("user_profiles.id"))
    address_line_1: Mapped[str] = mapped_column(Text)
    address_line_2: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    zip_code: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    type: Mapped[str] = mapped_column(Text, server_default=text("'HOME'"))


class ContactMethod(Base):
    __tablename__ = "contact_methods"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), Identity(always=True), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("user_profiles.id"))
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
