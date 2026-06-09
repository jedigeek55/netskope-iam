import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base

NAME_ID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAME_ID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAME_ID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"


class ServiceProvider(Base):
    __tablename__ = "service_providers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    acs_url: Mapped[str] = mapped_column(String(500), nullable=False)
    slo_url: Mapped[str | None] = mapped_column(String(500))
    name_id_format: Mapped[str] = mapped_column(String(255), nullable=False, default=NAME_ID_EMAIL)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sp_cert: Mapped[str | None] = mapped_column(Text)  # PEM cert for verifying signed AuthnRequests
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
