from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class NetskopeConfig(Base):
    """Singleton row (id=1) holding Netskope SCIM client settings entered via the UI.

    When present (tenant is set), overrides the NETSKOPE_TENANT / NETSKOPE_SCIM_TOKEN /
    NETSKOPE_VERIFY_SSL values from .env.
    """

    __tablename__ = "netskope_config"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    tenant: Mapped[str | None] = mapped_column(String(255))
    scim_token: Mapped[str | None] = mapped_column(String(500))
    verify_ssl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
