"""FastAPI adapter for the initial MOSAIC operation set."""
from fastapi import FastAPI, HTTPException
from mosaic.core.requests import MathRequest
from mosaic.core.responses import MathResponse
from mosaic.core.types import Status
from mosaic.engines.algebra import ExpressionError, run_algebra
from mosaic.verification.exact_checker import verify_identity

app = FastAPI(title="MOSAIC API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok", "service": "mosaic", "version": "0.1.0"}

@app.post("/v1/math", response_model=MathResponse)
def math_operation(request: MathRequest):
    operation = request.operation.value
    try:
        if operation == "verify_identity":
            if request.rhs is None:
                raise HTTPException(status_code=422, detail="rhs is required for verify_identity.")
            checked = verify_identity(request.expression, request.rhs)
            return MathResponse(status=Status(checked["status"]), operation=operation,
                                result=str(checked["equal"]), certificate=checked["certificate"],
                                explanation=checked["explanation"])
        if operation in {"simplify", "expand", "factor", "differentiate", "integrate"}:
            result = run_algebra(operation, request.expression, request.variable)
            return MathResponse(status=Status.EXPERIMENTAL, operation=operation, result=str(result),
                                explanation="Computed by the SymPy-backed prototype; this is not a formal proof.")
        return MathResponse(status=Status.UNSUPPORTED, operation=operation, result=None,
                            explanation="This operation is registered but not implemented in the initial prototype.")
    except ExpressionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
