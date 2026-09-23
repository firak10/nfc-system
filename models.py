import uuid
from sqlalchemy import Column, String, Boolean, Date, DateTime, ForeignKey, BigInteger, func
from sqlalchemy.dialects.postgresql import UUID
from database import Base

class Company(Base):
    __tablename__ = "companies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    document = Column(String(30), nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.id", ondelete="SET NULL"), nullable=True)
    full_name = Column(String(255), nullable=False)
    document = Column(String(50), nullable=True)
    photo_url = Column(String, nullable=True)
    status = Column(String(20), default="active")  # 'active', 'inactive', 'suspended'
    expires_at = Column(Date, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(BigInteger, primary_key=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    read_at = Column(DateTime(timezone=True), server_default=func.now())
    user_agent = Column(String, nullable=True)
    ip_address = Column(String(45), nullable=True)