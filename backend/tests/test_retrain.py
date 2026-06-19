"""
P1-2: Test that POST /model/retrain endpoint works.

Tests are fast — the actual retrain run is mocked to avoid timeout.
"""
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _noop_bg_task():
    """Mock background retrain to no-op (prevents timeout from long-running retrain)."""
    import app.routers.modeling as rm
    original = rm.asyncio.create_task
    rm.asyncio.create_task = lambda c, *a, **kw: None
    yield
    rm.asyncio.create_task = original


class TestRetrainEndpoint:
    """Tests for model retrain endpoint (P1-2)."""

    def test_retrain_endpoint_exists(self, client):
        """POST /api/model/retrain should return 202 Accepted with job_id."""
        response = client.post("/api/model/retrain?type=ip")
        assert response.status_code == 202, f"Expected 202, got {response.status_code}"

        data = response.json()
        assert "job_id" in data, f"Response missing 'job_id'. Keys: {list(data.keys())}"
        assert data["status"] == "accepted", f"Expected status 'accepted', got {data.get('status')}"

    def test_retrain_returns_job_status(self, client):
        """GET /api/model/retrain/status/{job_id} should return job progress."""
        start_resp = client.post("/api/model/retrain?type=ip")
        assert start_resp.status_code == 202
        job_id = start_resp.json()["job_id"]

        status_resp = client.get(f"/api/model/retrain/status/{job_id}")
        assert status_resp.status_code == 200, f"Expected 200, got {status_resp.status_code}"

        data = status_resp.json()
        assert data["job_id"] == job_id
        assert data["status"] in ("pending", "running", "completed", "failed")
        assert "progress" in data
        assert "message" in data

    def test_retrain_status_404(self, client):
        """GET /api/model/retrain/status/{nonexistent} should return 404."""
        response = client.get("/api/model/retrain/status/nonexistent123")
        assert response.status_code == 404

    def test_retrain_all_model_types_accepted(self, client):
        """POST /api/model/retrain should accept ip, domain, cve, otx, all."""
        for model_type in ("ip", "domain", "cve", "otx", "all"):
            response = client.post(f"/api/model/retrain?type={model_type}")
            assert response.status_code == 202, (
                f"Expected 202 for type={model_type}, got {response.status_code}"
            )
