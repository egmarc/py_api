from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class HealthCheck(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    environment: str
    timestamp: datetime
