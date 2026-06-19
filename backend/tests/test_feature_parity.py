"""
P2-2: Test that backend feature engineering matches training-time features.

RED phase: tests may FAIL if drift exists.
GREEN phase: after refactoring to shared features module, they should PASS.
"""
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

import pytest
import pandas as pd
import numpy as np
from app.services.modeling_service import (
    build_domain_features,
    build_ip_features,
    _build_domain_df_local,
    _build_ip_df_local,
)


class TestFeatureParity:
    """Tests that backend features match training-time features (P2-2)."""

    def test_ip_feature_columns(self):
        """build_ip_features output should have expected structure."""
        sample = {
            "malicious_votes": 5,
            "suspicious_votes": 2,
            "harmless_votes": 10,
            "undetected_votes": 1,
            "total_reports": 18,
            "reputation_score": -1.5,
            "times_submitted": 3,
            "tor_node": False,
            "country": "US",
            "continent": "NA",
            "asn": "15169",
            "owner": "Google LLC",
            "network": "8.8.8.0/24",
            "threat_label": "clean",
            "threat_category": "unrated",
            "regional_registry": "ARIN",
            "last_analysis_date": "2026-01-15",
        }
        df = build_ip_features(sample)
        assert isinstance(df, pd.DataFrame)
        assert df.shape[0] == 1, "Should produce exactly 1 row"
        # Key numeric columns must be present
        for col in ("Malicious_Votes", "Reputation_Score", "malicious_ratio", "tor_flag"):
            assert col in df.columns, f"Missing column: {col}"
        # Key categorical columns must be present
        for col in ("Country", "Continent", "ASN", "Network"):
            assert col in df.columns, f"Missing column: {col}"

    def test_domain_feature_columns(self):
        """build_domain_features output should include is_randomized_domain."""
        sample = {
            "domain": "test-example-login-secure.com",
            "tld": "com",
            "domain_length": 30,
            "has_numbers": True,
            "has_hyphen": True,
            "reputation": 0.5,
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 3,
            "undetected_votes": 0,
            "total_engines": 3,
            "registrar": "Unknown",
            "categories": "{}",
            "popularity_rank": 1000,
            "data_source": "lexical_heuristics",
            "threat_severity": "Low",
            "creation_date": "",
            "last_update_date": "",
            "whois_summary": "",
            "domain_age_days": 0,
        }
        df = build_domain_features(sample)
        assert isinstance(df, pd.DataFrame)
        assert df.shape[0] == 1
        # Check is_randomized_domain is present
        assert "is_randomized_domain" in df.columns, (
            f"Missing is_randomized_domain. Columns: {list(df.columns)}"
        )

    def test_domain_feature_parity_with_local_fallback(self):
        """Shared module and local fallback should produce same features."""
        sample = {
            "domain": "google.com",
            "tld": "com",
            "domain_length": 10,
            "has_numbers": False,
            "has_hyphen": False,
            "reputation": 8.0,
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 100,
            "undetected_votes": 0,
            "total_engines": 100,
            "registrar": "MarkMonitor Inc.",
            "categories": "{}",
            "popularity_rank": 1,
            "data_source": "api",
            "threat_severity": "clean",
            "domain_age_days": 3650,
        }
        df_shared = build_domain_features(sample)
        df_local = _build_domain_df_local(sample)

        shared_cols = set(df_shared.columns)
        local_cols = set(df_local.columns)
        assert shared_cols == local_cols, (
            f"Column mismatch. Shared extra: {shared_cols - local_cols}. "
            f"Local extra: {local_cols - shared_cols}"
        )

    def test_ip_feature_parity_with_local_fallback(self):
        """Shared module and local fallback should produce same IP features."""
        sample = {
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 5,
            "undetected_votes": 0,
            "total_reports": 0,
            "reputation_score": 10.0,
            "times_submitted": 1,
            "tor_node": False,
            "country": "US",
            "continent": "NA",
            "asn": "15169",
            "owner": "Google LLC",
            "network": "8.8.8.0/24",
            "threat_label": "clean",
            "threat_category": "unrated",
            "regional_registry": "ARIN",
            "last_analysis_date": None,
        }
        df_shared = build_ip_features(sample)
        df_local = _build_ip_df_local(sample)

        shared_cols = set(df_shared.columns)
        local_cols = set(df_local.columns)
        assert shared_cols == local_cols, (
            f"Column mismatch. Shared extra: {shared_cols - local_cols}. "
            f"Local extra: {local_cols - shared_cols}"
        )
