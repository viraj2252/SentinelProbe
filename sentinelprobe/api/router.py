"""Main API router for SentinelProbe."""

from fastapi import APIRouter

from sentinelprobe.core.config import get_settings
from sentinelprobe.reporting.api import router as reports_router
from sentinelprobe.vulnerability_scanner.api import router as vulnerability_router
from sentinelprobe.vulnerability_scanner.attack_pattern_api import (
    router as attack_pattern_router,
)

settings = get_settings()

# Create main API router
api_router = APIRouter(prefix=settings.API_PREFIX)

# Include all module routers
api_router.include_router(reports_router)
api_router.include_router(vulnerability_router)
api_router.include_router(attack_pattern_router)

# Add more routers as they are implemented
# api_router.include_router(reconnaissance_router)
# api_router.include_router(ai_decision_router)
