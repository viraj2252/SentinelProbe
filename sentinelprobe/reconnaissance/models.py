"""Models for the Reconnaissance module."""

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from sqlalchemy import JSON, DateTime
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelprobe.core.db import Base


class TargetStatus(enum.Enum):
    """Target status enum."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class PortStatus(enum.Enum):
    """Port status enum."""

    CLOSED = "closed"
    OPEN = "open"
    FILTERED = "filtered"


class ServiceType(enum.Enum):
    """Service type enum."""

    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    TELNET = "telnet"
    POP3 = "pop3"
    RPC = "rpc"
    NTP = "ntp"
    MSRPC = "msrpc"
    NETBIOS = "netbios"
    IMAP = "imap"
    SNMP = "snmp"
    LDAP = "ldap"
    SMB = "smb"
    SMTPS = "smtps"
    IPP = "ipp"
    IMAPS = "imaps"
    POP3S = "pop3s"
    MSSQL = "mssql"
    ORACLE = "oracle"
    PPTP = "pptp"
    MYSQL = "mysql"
    RDP = "rdp"
    POSTGRESQL = "postgresql"
    VNC = "vnc"
    REDIS = "redis"
    HTTP_PROXY = "http_proxy"
    ELASTICSEARCH = "elasticsearch"
    GIT = "git"
    MONGODB = "mongodb"
    UNKNOWN = "unknown"
    OTHER = "other"


class Target(Base):
    """Target model for reconnaissance."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    status: Mapped[TargetStatus] = mapped_column(
        SQLAEnum(TargetStatus), nullable=False, default=TargetStatus.PENDING
    )
    target_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    ports: Mapped[List["Port"]] = relationship(
        "Port", back_populates="target", cascade="all, delete-orphan"
    )


class Port(Base):
    """Port model for reconnaissance."""

    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[PortStatus] = mapped_column(
        SQLAEnum(PortStatus), nullable=False, default=PortStatus.CLOSED
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    # Relationships
    target: Mapped[Target] = relationship("Target", back_populates="ports")
    service: Mapped[Optional["Service"]] = relationship(
        "Service", back_populates="port", uselist=False, cascade="all, delete-orphan"
    )


class Service(Base):
    """Service model for reconnaissance."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"), nullable=False)
    service_type: Mapped[ServiceType] = mapped_column(
        SQLAEnum(ServiceType), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    service_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    # Relationships
    port: Mapped[Port] = relationship("Port", back_populates="service")


# Pydantic models for API
class TargetCreate(BaseModel):
    """Target creation model."""

    job_id: int
    hostname: str
    ip_address: Optional[str] = None
    target_metadata: Dict[str, Any] = {}


class TargetUpdate(BaseModel):
    """Target update model."""

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[TargetStatus] = None
    target_metadata: Optional[Dict[str, Any]] = None


class PortCreate(BaseModel):
    """Port creation model."""

    target_id: int
    port_number: int
    protocol: str
    status: PortStatus


class PortUpdate(BaseModel):
    """Port update model."""

    port_number: Optional[int] = None
    protocol: Optional[str] = None
    status: Optional[PortStatus] = None


class ServiceCreate(BaseModel):
    """Service creation model."""

    port_id: int
    service_type: ServiceType
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    service_metadata: Dict[str, Any] = {}


class ServiceUpdate(BaseModel):
    """Service update model."""

    service_type: Optional[ServiceType] = None
    name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    service_metadata: Optional[Dict[str, Any]] = None


class TargetResponse(BaseModel):
    """Target response model."""

    id: int
    job_id: int
    hostname: str
    ip_address: Optional[str]
    status: TargetStatus
    target_metadata: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class PortResponse(BaseModel):
    """Port response model."""

    id: int
    target_id: int
    port_number: int
    protocol: str
    status: PortStatus
    created_at: datetime


class ServiceResponse(BaseModel):
    """Service response model."""

    id: int
    port_id: int
    service_type: ServiceType
    name: str
    version: Optional[str]
    banner: Optional[str]
    service_metadata: Dict[str, Any]
    created_at: datetime
