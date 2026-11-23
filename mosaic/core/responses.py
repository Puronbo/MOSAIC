"""Stable response envelope."""
from pydantic import BaseModel
from mosaic.core.types import Status

class MathResponse(BaseModel):
    schema_version: str = "1.0"
    status: Status
    operation: str
    result: str | None = None
    certificate: dict | None = None
    explanation: str
