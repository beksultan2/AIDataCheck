import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base


def utcnow():
    return datetime.now(timezone.utc)


class UserStatus(str, enum.Enum):
    basic = "basic"
    pro = "pro"


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.basic, nullable=False)
    registered_date = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("user_profiles.id"), nullable=False)
    token = Column(String(512), unique=True, index=True, nullable=False)
    created_date = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("UserProfile", back_populates="tokens")
