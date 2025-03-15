"""Service layer for the Reconnaissance module."""

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.reconnaissance.models import (
    Port,
    PortCreate,
    PortResponse,
    PortUpdate,
    Service,
    ServiceCreate,
    ServiceResponse,
    ServiceUpdate,
    Target,
    TargetCreate,
    TargetResponse,
    TargetUpdate,
)
from sentinelprobe.reconnaissance.repository import (
    PortRepository,
    ServiceRepository,
    TargetRepository,
)
from sentinelprobe.reconnaissance.scanner import PortScannerService


class ReconnaissanceService:
    """Service for reconnaissance operations."""

    def __init__(self, session: AsyncSession):
        """Initialize with database session."""
        self.session = session
        self.target_repository = TargetRepository(session)
        self.port_repository = PortRepository(session)
        self.service_repository = ServiceRepository(session)
        self.scanner_service = PortScannerService(
            self.target_repository, self.port_repository, self.service_repository
        )

    async def create_target(self, target_data: TargetCreate) -> TargetResponse:
        """
        Create a new target.

        Args:
            target_data: Target creation data

        Returns:
            TargetResponse: Created target
        """
        target = await self.target_repository.create_target(
            job_id=target_data.job_id,
            hostname=target_data.hostname,
            ip_address=target_data.ip_address,
            metadata=target_data.target_metadata,
        )
        return self._target_to_response(target)

    async def get_target(self, target_id: int) -> Optional[TargetResponse]:
        """
        Get a target by ID.

        Args:
            target_id: Target ID

        Returns:
            Optional[TargetResponse]: Found target or None
        """
        target = await self.target_repository.get_target(target_id)
        if not target:
            return None
        return self._target_to_response(target)

    async def get_targets_by_job(self, job_id: int) -> List[TargetResponse]:
        """
        Get targets for a job.

        Args:
            job_id: Job ID

        Returns:
            List[TargetResponse]: List of targets
        """
        targets = await self.target_repository.get_targets_by_job(job_id)
        return [self._target_to_response(target) for target in targets]

    async def update_target(
        self, target_id: int, target_data: TargetUpdate
    ) -> Optional[TargetResponse]:
        """
        Update a target.

        Args:
            target_id: Target ID
            target_data: Target update data

        Returns:
            Optional[TargetResponse]: Updated target or None
        """
        target = await self.target_repository.update_target(
            target_id=target_id,
            hostname=target_data.hostname,
            ip_address=target_data.ip_address,
            status=target_data.status,
            metadata=target_data.target_metadata,
        )
        if not target:
            return None
        return self._target_to_response(target)

    async def delete_target(self, target_id: int) -> bool:
        """
        Delete a target.

        Args:
            target_id: Target ID

        Returns:
            bool: True if deleted, False if not found
        """
        return await self.target_repository.delete_target(target_id)

    async def scan_target(
        self, target_id: int, ports: Optional[List[int]] = None
    ) -> TargetResponse:
        """
        Scan a target for open ports and services.

        Args:
            target_id: Target ID
            ports: List of ports to scan (optional)

        Returns:
            TargetResponse: Updated target with scan results
        """
        target = await self.scanner_service.scan_target(target_id, ports)
        return self._target_to_response(target)

    async def create_port(self, port_data: PortCreate) -> PortResponse:
        """
        Create a new port.

        Args:
            port_data: Port creation data

        Returns:
            PortResponse: Created port
        """
        port = await self.port_repository.create_port(
            target_id=port_data.target_id,
            port_number=port_data.port_number,
            protocol=port_data.protocol,
            status=port_data.status,
        )
        return self._port_to_response(port)

    async def get_port(self, port_id: int) -> Optional[PortResponse]:
        """
        Get a port by ID.

        Args:
            port_id: Port ID

        Returns:
            Optional[PortResponse]: Found port or None
        """
        port = await self.port_repository.get_port(port_id)
        if not port:
            return None
        return self._port_to_response(port)

    async def get_ports_by_target(self, target_id: int) -> List[PortResponse]:
        """
        Get ports for a target.

        Args:
            target_id: Target ID

        Returns:
            List[PortResponse]: List of ports
        """
        ports = await self.port_repository.get_ports_by_target(target_id)
        return [self._port_to_response(port) for port in ports]

    async def update_port(
        self, port_id: int, port_data: PortUpdate
    ) -> Optional[PortResponse]:
        """
        Update a port.

        Args:
            port_id: Port ID
            port_data: Port update data

        Returns:
            Optional[PortResponse]: Updated port or None
        """
        port = await self.port_repository.update_port(
            port_id=port_id,
            port_number=port_data.port_number,
            protocol=port_data.protocol,
            status=port_data.status,
        )
        if not port:
            return None
        return self._port_to_response(port)

    async def create_service(self, service_data: ServiceCreate) -> ServiceResponse:
        """
        Create a new service.

        Args:
            service_data: Service creation data

        Returns:
            ServiceResponse: Created service
        """
        service = await self.service_repository.create_service(
            port_id=service_data.port_id,
            service_type=service_data.service_type,
            name=service_data.name,
            version=service_data.version,
            banner=service_data.banner,
            metadata=service_data.service_metadata,
        )
        return self._service_to_response(service)

    async def get_service(self, service_id: int) -> Optional[ServiceResponse]:
        """
        Get a service by ID.

        Args:
            service_id: Service ID

        Returns:
            Optional[ServiceResponse]: Found service or None
        """
        service = await self.service_repository.get_service(service_id)
        if not service:
            return None
        return self._service_to_response(service)

    async def get_service_by_port(self, port_id: int) -> Optional[ServiceResponse]:
        """
        Get a service by port ID.

        Args:
            port_id: Port ID

        Returns:
            Optional[ServiceResponse]: Found service or None
        """
        service = await self.service_repository.get_service_by_port(port_id)
        if not service:
            return None
        return self._service_to_response(service)

    async def update_service(
        self, service_id: int, service_data: ServiceUpdate
    ) -> Optional[ServiceResponse]:
        """
        Update a service.

        Args:
            service_id: Service ID
            service_data: Service update data

        Returns:
            Optional[ServiceResponse]: Updated service or None
        """
        service = await self.service_repository.update_service(
            service_id=service_id,
            service_type=service_data.service_type,
            name=service_data.name,
            version=service_data.version,
            banner=service_data.banner,
            metadata=service_data.service_metadata,
        )
        if not service:
            return None
        return self._service_to_response(service)

    def _target_to_response(self, target: Target) -> TargetResponse:
        """Convert Target model to TargetResponse."""
        return TargetResponse(
            id=target.id,
            job_id=target.job_id,
            hostname=target.hostname,
            ip_address=target.ip_address,
            status=target.status,
            target_metadata=target.target_metadata,
            created_at=target.created_at,
            started_at=target.started_at,
            completed_at=target.completed_at,
        )

    def _port_to_response(self, port: Port) -> PortResponse:
        """Convert Port model to PortResponse."""
        return PortResponse(
            id=port.id,
            target_id=port.target_id,
            port_number=port.port_number,
            protocol=port.protocol,
            status=port.status,
            created_at=port.created_at,
        )

    def _service_to_response(self, service: Service) -> ServiceResponse:
        """Convert Service model to ServiceResponse."""
        return ServiceResponse(
            id=service.id,
            port_id=service.port_id,
            service_type=service.service_type,
            name=service.name,
            version=service.version,
            banner=service.banner,
            service_metadata=service.service_metadata,
            created_at=service.created_at,
        )
