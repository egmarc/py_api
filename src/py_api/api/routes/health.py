from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status

from py_api.core.config import Settings, get_settings
from py_api.schemas.health import HealthCheck

router = APIRouter(tags=["health"])


@router.get(
    "/health-check",
    response_model=HealthCheck,
    status_code=status.HTTP_200_OK,
    summary="Service health check",
)
async def health_check(settings: Annotated[Settings, Depends(get_settings)]) -> HealthCheck:
    return HealthCheck(
        version=settings.version,
        environment=settings.environment,
        timestamp=datetime.now(UTC),
    )
