"""API interface for the Reconnaissance module."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelprobe.core.db import get_db_session
from sentinelprobe.core.logging import get_logger
from sentinelprobe.reconnaissance.models import (
    PortCreate,
    PortResponse,
    ServiceCreate,
    ServiceResponse,
    TargetCreate,
    TargetResponse,
)
from sentinelprobe.reconnaissance.service import ReconnaissanceService

logger = get_logger(__name__)

router = APIRouter(prefix="/reconnaissance", tags=["reconnaissance"])


@router.post(
    "/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Target",
)
async def create_target(
    target_data: TargetCreate, session: AsyncSession = Depends(get_db_session)
) -> TargetResponse:
    """
    Create a new target for reconnaissance.

    Args:
        target_data: Target creation data
        session: Database session

    Returns:
        Created target
    """
    service = ReconnaissanceService(session)
    try:
        return await service.create_target(target_data)
    except Exception as e:
        logger.error(f"Error creating target: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating target: {str(e)}",
        )


@router.get(
    "/targets",
    response_model=List[TargetResponse],
    summary="List Targets",
)
async def list_targets(
    job_id: Optional[int] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_db_session),
) -> List[TargetResponse]:
    """
    List targets with optional filtering.

    Args:
        job_id: Filter by job ID (optional)
        session: Database session

    Returns:
        List of targets
    """
    service = ReconnaissanceService(session)
    try:
        if job_id:
            return await service.get_targets_by_job(job_id)
        return await service.get_all_targets()
    except Exception as e:
        logger.error(f"Error listing targets: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing targets: {str(e)}",
        )


@router.get(
    "/targets/{target_id}",
    response_model=TargetResponse,
    summary="Get Target",
)
async def get_target(
    target_id: int = Path(..., description="Target ID"),
    session: AsyncSession = Depends(get_db_session),
) -> TargetResponse:
    """
    Get target details.

    Args:
        target_id: Target ID
        session: Database session

    Returns:
        Target details
    """
    service = ReconnaissanceService(session)
    try:
        target = await service.get_target(target_id)
        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target with ID {target_id} not found",
            )
        return target
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting target: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting target: {str(e)}",
        )


@router.post(
    "/targets/{target_id}/scan",
    response_model=TargetResponse,
    summary="Scan Target",
)
async def scan_target(
    target_id: int = Path(..., description="Target ID"),
    ports: Optional[List[int]] = Query(None, description="Specific ports to scan"),
    start_port: Optional[int] = Query(None, description="Start of port range to scan"),
    end_port: Optional[int] = Query(None, description="End of port range to scan"),
    scan_rate: Optional[float] = Query(
        None, description="Scan rate (ports per second)"
    ),
    aggressive_mode: Optional[bool] = Query(
        None, description="Use aggressive scanning mode"
    ),
    session: AsyncSession = Depends(get_db_session),
) -> TargetResponse:
    """
    Scan a target for open ports.

    Args:
        target_id: Target ID
        ports: Optional list of specific ports to scan
        start_port: Optional start of port range to scan
        end_port: Optional end of port range to scan
        scan_rate: Optional scan rate (ports per second)
        aggressive_mode: Optional flag to enable aggressive scanning
        session: Database session

    Returns:
        Updated target with scan results
    """
    service = ReconnaissanceService(session)
    try:
        # Determine if we're using a port range
        port_range = None
        if start_port is not None and end_port is not None:
            if start_port > end_port:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Start port must be less than or equal to end port",
                )
            port_range = (start_port, end_port)

        # Execute the scan
        target = await service.scan_target(
            target_id=target_id,
            ports=ports,
            port_range=port_range,
            scan_rate=scan_rate,
            aggressive_mode=aggressive_mode,
        )

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target with ID {target_id} not found",
            )
        return target
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning target: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error scanning target: {str(e)}",
        )


@router.get(
    "/targets/{target_id}/ports",
    response_model=List[PortResponse],
    summary="Get Target Ports",
)
async def get_target_ports(
    target_id: int = Path(..., description="Target ID"),
    session: AsyncSession = Depends(get_db_session),
) -> List[PortResponse]:
    """
    Get ports for a specific target.

    Args:
        target_id: Target ID
        session: Database session

    Returns:
        List of ports
    """
    service = ReconnaissanceService(session)
    try:
        # First check if target exists
        target = await service.get_target(target_id)
        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target with ID {target_id} not found",
            )

        return await service.get_ports_by_target(target_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting target ports: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting target ports: {str(e)}",
        )


@router.post(
    "/ports",
    response_model=PortResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Port",
)
async def create_port(
    port_data: PortCreate, session: AsyncSession = Depends(get_db_session)
) -> PortResponse:
    """
    Create a new port record.

    Args:
        port_data: Port creation data
        session: Database session

    Returns:
        Created port
    """
    service = ReconnaissanceService(session)
    try:
        return await service.create_port(port_data)
    except Exception as e:
        logger.error(f"Error creating port: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating port: {str(e)}",
        )


@router.post(
    "/services",
    response_model=ServiceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Service",
)
async def create_service(
    service_data: ServiceCreate, session: AsyncSession = Depends(get_db_session)
) -> ServiceResponse:
    """
    Create a new service record.

    Args:
        service_data: Service creation data
        session: Database session

    Returns:
        Created service
    """
    service = ReconnaissanceService(session)
    try:
        return await service.create_service(service_data)
    except Exception as e:
        logger.error(f"Error creating service: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating service: {str(e)}",
        )


@router.post(
    "/targets/{target_id}/full-scan",
    response_model=TargetResponse,
    summary="Full Port Scan",
)
async def full_scan_target(
    target_id: int = Path(..., description="Target ID"),
    scan_type: str = Query(
        "common", description="Scan type: 'common', 'web', 'db', 'full', 'custom'"
    ),
    custom_start: Optional[int] = Query(
        None, description="Start port for custom range"
    ),
    custom_end: Optional[int] = Query(None, description="End port for custom range"),
    scan_rate: Optional[float] = Query(0.5, description="Scan rate (ports per second)"),
    aggressive_mode: Optional[bool] = Query(
        False, description="Use aggressive scanning"
    ),
    session: AsyncSession = Depends(get_db_session),
) -> TargetResponse:
    """
    Perform a comprehensive port scan using predefined ranges.

    Args:
        target_id: Target ID
        scan_type: Type of scan to perform:
          - common: Scan common ports (default)
          - web: Scan common web application ports
          - db: Scan database ports
          - full: Scan all TCP ports (1-65535)
          - custom: Scan a custom range (requires custom_start and custom_end)
        custom_start: Start port for custom range
        custom_end: End port for custom range
        scan_rate: Scan rate in ports per second
        aggressive_mode: Use aggressive scanning mode
        session: Database session

    Returns:
        Updated target with scan results
    """
    service = ReconnaissanceService(session)

    try:
        # Define port ranges based on scan type
        port_range = None
        ports = None

        if scan_type == "common":
            # Use the default common ports
            pass
        elif scan_type == "web":
            # Common web application ports
            ports = [80, 443, 3000, 3001, 4200, 5000, 8000, 8080, 8443, 8888, 9000]
        elif scan_type == "db":
            # Common database ports
            ports = [1433, 1521, 3306, 5432, 6379, 9200, 27017, 27018, 27019, 28017]
        elif scan_type == "full":
            # Scan all ports (use cautiously)
            port_range = (1, 65535)
        elif scan_type == "custom":
            # Custom port range
            if custom_start is None or custom_end is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Custom scan requires both custom_start and custom_end parameters",
                )
            if custom_start > custom_end:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Start port must be less than or equal to end port",
                )
            port_range = (custom_start, custom_end)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan_type: {scan_type}",
            )

        # Execute the scan
        target = await service.scan_target(
            target_id=target_id,
            ports=ports,
            port_range=port_range,
            scan_rate=scan_rate,
            aggressive_mode=aggressive_mode,
        )

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target with ID {target_id} not found",
            )
        return target
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning target: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error scanning target: {str(e)}",
        )
