"""Versioned API request model."""
from pydantic import BaseModel, ConfigDict, Field
from mosaic.core.types import Operation

class MathRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    operation: Operation
    expression: str = Field(min_length=1, max_length=2000)
    variable: str = Field(default="x", min_length=1, max_length=32)
    rhs: str | None = Field(default=None, max_length=2000)
