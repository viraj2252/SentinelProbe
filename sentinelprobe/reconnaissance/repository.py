"""Repository implementations for the Reconnaissance module."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.reconnaissance.models import (
    Port,
    PortStatus,
    Service,
    ServiceType,
    Target,
    TargetStatus,
)


class TargetRepository:
    """Repository for Target model."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session."""
        self.session = session

    async def create_target(
        self,
        job_id: int,
        hostname: str,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Target:
        """
        Create a new target.

        Args:
            job_id: ID of the associated job
            hostname: Target hostname
            ip_address: Target IP address (optional)
            metadata: Additional metadata (optional)

        Returns:
            Target: Created target
        """
        target = Target(
            job_id=job_id,
            hostname=hostname,
            ip_address=ip_address,
            status=TargetStatus.PENDING,
            target_metadata=metadata or {},
        )

        self.session.add(target)
        await self.session.commit()
        await self.session.refresh(target)

        return target

    async def get_target(self, target_id: int) -> Optional[Target]:
        """
        Get a target by ID.

        Args:
            target_id: Target ID

        Returns:
            Optional[Target]: Found target or None
        """
        query = select(Target).where(Target.id == target_id)
        result = await self.session.execute(query)
        target: Optional[Target] = result.scalars().first()
        return target

    async def get_targets_by_job(self, job_id: int) -> List[Target]:
        """
        Get targets for a job.

        Args:
            job_id: Job ID

        Returns:
            List[Target]: List of targets
        """
        query = select(Target).where(Target.job_id == job_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_target(
        self,
        target_id: int,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        status: Optional[TargetStatus] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Target]:
        """
        Update a target.

        Args:
            target_id: Target ID
            hostname: New hostname
            ip_address: New IP address
            status: New status
            metadata: Updated metadata

        Returns:
            Optional[Target]: Updated target or None
        """
        target = await self.get_target(target_id)
        if not target:
            return None

        if hostname is not None:
            target.hostname = hostname
        if ip_address is not None:
            target.ip_address = ip_address
        if status is not None:
            target.status = status
            # Update timestamps based on status
            if status == TargetStatus.SCANNING and not target.started_at:
                target.started_at = datetime.utcnow()
            elif status in (TargetStatus.COMPLETED, TargetStatus.FAILED):
                target.completed_at = datetime.utcnow()
        if metadata is not None:
            target.target_metadata = metadata

        await self.session.commit()
        await self.session.refresh(target)
        return target

    async def delete_target(self, target_id: int) -> bool:
        """
        Delete a target.

        Args:
            target_id: Target ID

        Returns:
            bool: True if deleted, False if not found
        """
        target = await self.get_target(target_id)
        if not target:
            return False

        await self.session.delete(target)
        await self.session.commit()
        return True


class PortRepository:
    """Repository for Port model."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session."""
        self.session = session

    async def create_port(
        self,
        target_id: int,
        port_number: int,
        protocol: str,
        status: PortStatus,
    ) -> Port:
        """
        Create a new port.

        Args:
            target_id: Target ID
            port_number: Port number
            protocol: Protocol (e.g., 'tcp', 'udp')
            status: Port status

        Returns:
            Port: Created port
        """
        port = Port(
            target_id=target_id,
            port_number=port_number,
            protocol=protocol,
            status=status,
        )

        self.session.add(port)
        await self.session.commit()
        await self.session.refresh(port)

        return port

    async def get_port(self, port_id: int) -> Optional[Port]:
        """
        Get a port by ID.

        Args:
            port_id: Port ID

        Returns:
            Optional[Port]: Found port or None
        """
        query = select(Port).where(Port.id == port_id)
        result = await self.session.execute(query)
        port: Optional[Port] = result.scalars().first()
        return port

    async def get_port_by_number(
        self, target_id: int, port_number: int, protocol: str
    ) -> Optional[Port]:
        """
        Get a port by number and protocol.

        Args:
            target_id: Target ID
            port_number: Port number
            protocol: Protocol

        Returns:
            Optional[Port]: Found port or None
        """
        query = select(Port).where(
            Port.target_id == target_id,
            Port.port_number == port_number,
            Port.protocol == protocol,
        )
        result = await self.session.execute(query)
        port: Optional[Port] = result.scalars().first()
        return port

    async def get_ports_by_target(self, target_id: int) -> List[Port]:
        """
        Get ports for a target.

        Args:
            target_id: Target ID

        Returns:
            List[Port]: List of ports
        """
        query = select(Port).where(Port.target_id == target_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_port(
        self,
        port_id: int,
        port_number: Optional[int] = None,
        protocol: Optional[str] = None,
        status: Optional[PortStatus] = None,
    ) -> Optional[Port]:
        """
        Update a port.

        Args:
            port_id: Port ID
            port_number: New port number
            protocol: New protocol
            status: New status

        Returns:
            Optional[Port]: Updated port or None
        """
        port = await self.get_port(port_id)
        if not port:
            return None

        if port_number is not None:
            port.port_number = port_number
        if protocol is not None:
            port.protocol = protocol
        if status is not None:
            port.status = status

        await self.session.commit()
        await self.session.refresh(port)
        return port

    async def delete_port(self, port_id: int) -> bool:
        """
        Delete a port.

        Args:
            port_id: Port ID

        Returns:
            bool: True if deleted, False if not found
        """
        port = await self.get_port(port_id)
        if not port:
            return False

        await self.session.delete(port)
        await self.session.commit()
        return True


class ServiceRepository:
    """Repository for Service model."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session."""
        self.session = session

    async def create_service(
        self,
        port_id: int,
        service_type: ServiceType,
        name: str,
        version: Optional[str] = None,
        banner: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Service:
        """
        Create a new service.

        Args:
            port_id: Port ID
            service_type: Service type
            name: Service name
            version: Service version (optional)
            banner: Service banner (optional)
            metadata: Additional metadata (optional)

        Returns:
            Service: Created service
        """
        service = Service(
            port_id=port_id,
            service_type=service_type,
            name=name,
            version=version,
            banner=banner,
            service_metadata=metadata or {},
        )

        self.session.add(service)
        await self.session.commit()
        await self.session.refresh(service)

        return service

    async def get_service(self, service_id: int) -> Optional[Service]:
        """
        Get a service by ID.

        Args:
            service_id: Service ID

        Returns:
            Optional[Service]: Found service or None
        """
        query = select(Service).where(Service.id == service_id)
        result = await self.session.execute(query)
        service: Optional[Service] = result.scalars().first()
        return service

    async def get_service_by_port(self, port_id: int) -> Optional[Service]:
        """
        Get a service by port ID.

        Args:
            port_id: Port ID

        Returns:
            Optional[Service]: Found service or None
        """
        query = select(Service).where(Service.port_id == port_id)
        result = await self.session.execute(query)
        service: Optional[Service] = result.scalars().first()
        return service

    async def update_service(
        self,
        service_id: int,
        service_type: Optional[ServiceType] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Service]:
        """
        Update a service.

        Args:
            service_id: Service ID
            service_type: New service type
            name: New service name
            version: New service version
            banner: New service banner
            metadata: Updated metadata

        Returns:
            Optional[Service]: Updated service or None
        """
        service = await self.get_service(service_id)
        if not service:
            return None

        if service_type is not None:
            service.service_type = service_type
        if name is not None:
            service.name = name
        if version is not None:
            service.version = version
        if banner is not None:
            service.banner = banner
        if metadata is not None:
            service.service_metadata = metadata

        await self.session.commit()
        await self.session.refresh(service)
        return service

    async def delete_service(self, service_id: int) -> bool:
        """
        Delete a service.

        Args:
            service_id: Service ID

        Returns:
            bool: True if deleted, False if not found
        """
        service = await self.get_service(service_id)
        if not service:
            return False

        await self.session.delete(service)
        await self.session.commit()
        return True
