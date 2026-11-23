from fastapi.testclient import TestClient
from mosaic.api import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_expand_endpoint():
    response = client.post("/v1/math", json={
        "operation": "expand", "expression": "(x+1)**2"
    })
    assert response.status_code == 200
    assert response.json()["result"] == "x**2 + 2*x + 1"
    assert response.json()["status"] == "EXPERIMENTAL"

def test_identity_requires_rhs():
    response = client.post("/v1/math", json={
        "operation": "verify_identity", "expression": "x+1"
    })
    assert response.status_code == 422
