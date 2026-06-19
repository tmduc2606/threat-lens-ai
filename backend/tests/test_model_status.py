"""
P0-2: Test that GET /api/model/status includes model_version per model.

RED phase: This test should FAIL before implementation.
GREEN phase: After adding version.json and updating get_model_status(), it should PASS.
"""
import json
import os
import sys

# Add backend app to path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import get_settings


@pytest.fixture
def client():
    return TestClient(app)


class TestModelStatusVersion:
    """Tests for model_version field in /api/model/status response."""

    def test_model_status_includes_version_field(self, client):
        """GET /api/model/status should include model_version for each loaded model."""
        response = client.get("/api/model/status")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        data = response.json()
        assert "models" in data, f"Response missing 'models' key. Keys: {list(data.keys())}"

        models = data["models"]
        # At minimum, these models should be present
        expected_models = [
            "cve_tfidf_logreg",
            "domain_model",
            "ip_xgb_model",
            "ip_logreg_model",
            "otx_minilm_logreg",
        ]

        for model_name in expected_models:
            assert model_name in models, f"Model '{model_name}' not found in status. Present: {list(models.keys())}"
            model_info = models[model_name]
            assert "model_version" in model_info, (
                f"Model '{model_name}' missing 'model_version' field. "
                f"Present fields: {list(model_info.keys())}"
            )
            assert model_info["model_version"] is not None, (
                f"Model '{model_name}' has null model_version"
            )
            # Version should follow semver pattern (e.g., "v1.0.0")
            version = model_info["model_version"]
            assert isinstance(version, str), f"model_version should be string, got {type(version)}"
            assert version.startswith("v"), f"model_version should start with 'v', got '{version}'"

    def test_model_version_readable_from_file(self, client):
        """model_version should match what's in models/version.json."""
        response = client.get("/api/model/status")
        assert response.status_code == 200
        data = response.json()

        # Use the config's models_path as source of truth
        settings = get_settings()
        version_file = settings.models_path / "version.json"
        assert version_file.is_file(), f"version.json not found at {version_file}"

        with open(str(version_file)) as f:
            versions = json.load(f)

        models = data["models"]
        for model_name, expected_version in versions.items():
            if model_name in models:
                actual_version = models[model_name].get("model_version")
                assert actual_version == expected_version, (
                    f"Model '{model_name}': API returns '{actual_version}' "
                    f"but version.json has '{expected_version}'"
                )
