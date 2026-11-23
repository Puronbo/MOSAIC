"""Small synchronous Python client for a running MOSAIC HTTP service."""
from typing import Any

import httpx

from mosaic.core.requests import MathRequest
from mosaic.verification.task_bound import TaskBoundCheck


class MosaicClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, operation: str, expression: str, *, variable: str = "x",
                rhs: str | None = None) -> dict[str, Any]:
        payload = {"schema_version": "1.0", "operation": operation,
                   "expression": expression, "variable": variable, "rhs": rhs}
        response = httpx.post(f"{self.base_url}/v1/math", json=payload, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def verify_model_candidate(
        self,
        request: MathRequest,
        candidate: str,
        *,
        provider_id: str = "external",
        model_id: str = "unspecified",
    ) -> dict[str, Any]:
        """Submit an AI proposal for task-bound and optional Lean verification."""
        payload = {
            "request": request.model_dump(mode="json"),
            "candidate": candidate,
            "provider_id": provider_id,
            "model_id": model_id,
        }
        response = httpx.post(
            f"{self.base_url}/v1/ai/candidate",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def verify_candidate(self, request: MathRequest, candidate: str) -> dict[str, Any]:
        """Submit an untrusted candidate for request-bound checking."""
        payload = {"request": request.model_dump(mode="json"), "candidate": candidate}
        response = httpx.post(
            f"{self.base_url}/v1/verify/task-bound",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
