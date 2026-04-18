"""Tests for DeFi Risk Analyzer"""

import pytest
from fastapi.testclient import TestClient
from decimal import Decimal

from src.main import app, RiskAnalyzer, ProtocolMetrics, ImpermanentLossCalculator, RiskScore

client = TestClient(app)


class TestHealth:
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_info(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "DeFi Risk Analyzer" in response.json()["name"]


class TestRiskAnalyzer:
    def test_liquidity_risk_low_tvl(self):
        score = RiskAnalyzer.calculate_liquidity_risk(
            Decimal("5000000"),  # $5M TVL
            Decimal("5"),  # 5% change
            Decimal("10")  # 10% 7d change
        )
        assert score > 40  # High risk due to low TVL

    def test_liquidity_risk_high_tvl(self):
        score = RiskAnalyzer.calculate_liquidity_risk(
            Decimal("1000000000"),  # $1B TVL
            Decimal("2"),  # 2% change
            Decimal("5")  # 5% 7d change
        )
        assert score < 30  # Lower risk

    def test_smart_contract_risk_no_audits(self):
        score = RiskAnalyzer.calculate_smart_contract_risk([], [])
        assert score >= 40  # High risk without audits

    def test_smart_contract_risk_with_audits(self):
        score = RiskAnalyzer.calculate_smart_contract_risk(
            ["trail_of_bits", "openzeppelin"],
            []
        )
        assert score < 25  # Lower risk with good audits

    def test_calculate_il_2x(self):
        il = ImpermanentLossCalculator.calculate_il(2.0)
        assert abs(il - 0.057) < 0.001  # ~5.7% IL at 2x price

    def test_calculate_il_half(self):
        il = ImpermanentLossCalculator.calculate_il(0.5)
        assert abs(il - 0.057) < 0.001  # Same IL at 0.5x


class TestAPIEndpoints:
    def test_calculate_il_endpoint(self):
        response = client.get("/calculate/impermanent-loss?price_ratio=2.0")
        assert response.status_code == 200
        data = response.json()
        assert data["price_ratio"] == 2.0
        assert "impermanent_loss_percent" in data

    def test_calculate_lp_position(self):
        response = client.post("/calculate/lp-position", params={
            "initial_price_a": 100,
            "initial_price_b": 1,
            "initial_amount_a": 1,
            "initial_amount_b": 100,
            "final_price_a": 150,
            "final_price_b": 1
        })
        assert response.status_code == 200
        data = response.json()
        assert "impermanent_loss" in data
        assert "initial_value" in data
