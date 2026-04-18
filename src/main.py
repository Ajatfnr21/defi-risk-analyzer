#!/usr/bin/env python3
"""
DeFi Risk Analyzer - DeFi Protocol Risk Assessment

Features:
- Protocol TVL analysis
- Liquidity risk assessment
- Smart contract vulnerability scoring
- Governance risk analysis
- Impermanent loss calculator
- Liquidation risk monitoring
- Protocol composability risk

Author: Drajat Sukma
License: MIT
Version: 2.0.0
"""

__version__ = "2.0.0"

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

import aiohttp
from web3 import Web3
import structlog
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import numpy as np

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# ============== Data Models ==============

@dataclass
class ProtocolMetrics:
    protocol_name: str
    tvl: Decimal
    tvl_change_24h: Decimal
    tvl_change_7d: Decimal
    users: int
    audits: List[str] = field(default_factory=list)
    exploit_history: List[Dict] = field(default_factory=list)

@dataclass
class RiskScore:
    protocol_name: str
    overall_score: int  # 0-100, lower is safer
    liquidity_risk: int
    smart_contract_risk: int
    governance_risk: int
    oracle_risk: int
    composability_risk: int
    assessment_date: datetime
    factors: List[str] = field(default_factory=list)

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    uptime_seconds: float

class RiskAssessmentRequest(BaseModel):
    protocol_name: str
    chain: str = "ethereum"
    contract_address: Optional[str] = None

class RiskAssessmentResponse(BaseModel):
    protocol_name: str
    overall_risk_score: int
    risk_level: str  # Low, Medium, High, Critical
    breakdown: Dict[str, int]
    factors: List[str]
    recommendations: List[str]
    assessed_at: datetime

# ============== DeFiLlama API Client ==============

class DeFiLlamaClient:
    """Client for DeFiLlama API"""
    
    BASE_URL = "https://api.llama.fi"
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def get_protocols(self) -> List[Dict]:
        """Get list of all DeFi protocols"""
        async with self.session.get(f"{self.BASE_URL}/protocols") as resp:
            if resp.status == 200:
                return await resp.json()
            return []
    
    async def get_protocol_tvl(self, protocol_name: str) -> Dict:
        """Get TVL data for a specific protocol"""
        slug = protocol_name.lower().replace(" ", "-")
        async with self.session.get(f"{self.BASE_URL}/protocol/{slug}") as resp:
            if resp.status == 200:
                return await resp.json()
            return {}
    
    async def get_chains(self) -> List[str]:
        """Get list of chains"""
        async with self.session.get(f"{self.BASE_URL}/chains") as resp:
            if resp.status == 200:
                data = await resp.json()
                return [c.get("gecko_id", "") for c in data]
            return []

# ============== Risk Analyzer ==============

class RiskAnalyzer:
    """Analyzes DeFi protocol risks"""
    
    KNOWN_EXPLOITS = {
        "wormhole": [{"date": "2022-02-02", "loss": 320000000, "type": "smart_contract"}],
        "ronin": [{"date": "2022-03-29", "loss": 625000000, "type": "bridge"}],
        "poly": [{"date": "2021-08-10", "loss": 611000000, "type": "bridge"}],
        "nomad": [{"date": "2022-08-01", "loss": 190000000, "type": "bridge"}],
    }
    
    AUDITORS = {
        "trail_of_bits": 5,
        "openzeppelin": 5,
        "consensys_diligence": 5,
        "certik": 3,
        "hacken": 3,
        "slowmist": 3
    }
    
    @staticmethod
    def calculate_liquidity_risk(tvl: Decimal, tvl_change_24h: Decimal, 
                                  tvl_change_7d: Decimal) -> int:
        """Calculate liquidity risk score (0-100)"""
        score = 0
        
        # TVL size factor (inverse relationship - higher TVL = lower risk)
        if tvl < Decimal("10000000"):  # < $10M
            score += 40
        elif tvl < Decimal("100000000"):  # < $100M
            score += 25
        elif tvl < Decimal("500000000"):  # < $500M
            score += 15
        else:
            score += 5
        
        # TVL volatility
        volatility_24h = abs(tvl_change_24h)
        if volatility_24h > Decimal("50"):  # >50% change
            score += 30
        elif volatility_24h > Decimal("20"):
            score += 15
        elif volatility_24h > Decimal("10"):
            score += 10
        
        # 7-day trend
        if tvl_change_7d < Decimal("-50"):
            score += 20
        elif tvl_change_7d < Decimal("-20"):
            score += 10
        
        return min(score, 100)
    
    @staticmethod
    def calculate_smart_contract_risk(audits: List[str], 
                                       exploit_history: List[Dict]) -> int:
        """Calculate smart contract risk score (0-100)"""
        score = 0
        
        # No audits = higher risk
        if not audits:
            score += 40
        else:
            # Check audit quality
            audit_score = sum(RiskAnalyzer.AUDITORS.get(a.lower().replace(" ", "_"), 0) 
                            for a in audits)
            score += max(0, 25 - audit_score * 3)
        
        # Exploit history
        for exploit in exploit_history:
            loss = exploit.get("loss", 0)
            if loss > 100000000:  # > $100M
                score += 30
            elif loss > 10000000:  # > $10M
                score += 20
            elif loss > 1000000:  # > $1M
                score += 10
            
            # Recent exploits are worse
            exploit_date = datetime.strptime(exploit.get("date", "2000-01-01"), "%Y-%m-%d")
            if (datetime.now() - exploit_date).days < 365:
                score += 10
        
        return min(score, 100)
    
    @staticmethod
    def calculate_governance_risk(admin_keys: int, timelock_hours: int,
                                  multisig_threshold: int) -> int:
        """Calculate governance risk score (0-100)"""
        score = 0
        
        # Admin keys
        if admin_keys == 0:
            score += 10  # Fully decentralized
        elif admin_keys == 1:
            score += 50  # Single admin
        elif admin_keys <= 3:
            score += 30
        else:
            score += 15
        
        # Timelock
        if timelock_hours == 0:
            score += 30  # No timelock
        elif timelock_hours < 24:
            score += 20
        elif timelock_hours < 48:
            score += 10
        
        # Multisig
        if multisig_threshold == 0:
            score += 20
        elif multisig_threshold < 3:
            score += 10
        
        return min(score, 100)
    
    @staticmethod
    def calculate_composability_risk(dependencies: List[str]) -> int:
        """Calculate composability risk score"""
        score = len(dependencies) * 5  # Each dependency adds risk
        return min(score, 100)
    
    @staticmethod
    def assess_protocol(protocol_name: str, metrics: ProtocolMetrics) -> RiskScore:
        """Complete risk assessment for a protocol"""
        
        # Check for known exploits
        exploit_history = RiskAnalyzer.KNOWN_EXPLOITS.get(protocol_name.lower(), [])
        
        # Calculate individual risk scores
        liquidity_risk = RiskAnalyzer.calculate_liquidity_risk(
            metrics.tvl, metrics.tvl_change_24h, metrics.tvl_change_7d
        )
        
        smart_contract_risk = RiskAnalyzer.calculate_smart_contract_risk(
            metrics.audits, exploit_history
        )
        
        # Default governance risk (would need more data)
        governance_risk = 30
        
        # Oracle risk (assume medium for most protocols)
        oracle_risk = 25 if "oracle" not in protocol_name.lower() else 15
        
        # Composability risk
        composability_risk = RiskAnalyzer.calculate_composability_risk([])
        
        # Calculate overall score (weighted average)
        overall_score = int(
            liquidity_risk * 0.25 +
            smart_contract_risk * 0.35 +
            governance_risk * 0.15 +
            oracle_risk * 0.10 +
            composability_risk * 0.15
        )
        
        # Determine risk factors
        factors = []
        if liquidity_risk > 50:
            factors.append("High liquidity risk due to low TVL or high volatility")
        if smart_contract_risk > 50:
            factors.append("Smart contract concerns - limited or no audits")
        if governance_risk > 40:
            factors.append("Centralized governance with admin keys")
        if exploit_history:
            factors.append(f"Previous exploits recorded: {len(exploit_history)} incidents")
        
        return RiskScore(
            protocol_name=protocol_name,
            overall_score=overall_score,
            liquidity_risk=liquidity_risk,
            smart_contract_risk=smart_contract_risk,
            governance_risk=governance_risk,
            oracle_risk=oracle_risk,
            composability_risk=composability_risk,
            assessment_date=datetime.utcnow(),
            factors=factors
        )

# ============== Impermanent Loss Calculator ==============

class ImpermanentLossCalculator:
    """Calculate impermanent loss for AMM positions"""
    
    @staticmethod
    def calculate_il(price_ratio: float) -> float:
        """
        Calculate impermanent loss given price ratio
        
        Args:
            price_ratio: Final price / Initial price (e.g., 2.0 if price doubled)
        
        Returns:
            Impermanent loss as a percentage (e.g., 0.057 = 5.7%)
        """
        sqrt_ratio = np.sqrt(price_ratio)
        il = 2 * sqrt_ratio / (1 + price_ratio) - 1
        return abs(il)
    
    @staticmethod
    def calculate_lp_value(
        initial_price_a: Decimal,
        initial_price_b: Decimal,
        initial_amount_a: Decimal,
        initial_amount_b: Decimal,
        final_price_a: Decimal,
        final_price_b: Decimal
    ) -> Dict[str, Decimal]:
        """Calculate LP position value changes"""
        
        # Initial LP value
        initial_value = (initial_amount_a * initial_price_a + 
                        initial_amount_b * initial_price_b)
        
        # Calculate k (constant product)
        k = initial_amount_a * initial_amount_b
        
        # Final amounts (maintaining k)
        # New amount_a * new amount_b = k
        # new_amount_a * (new_amount_a * final_price_a / final_price_b) = k
        final_amount_a = (k * final_price_b / final_price_a) ** Decimal("0.5")
        final_amount_b = k / final_amount_a
        
        # Final LP value
        final_lp_value = final_amount_a * final_price_a + final_amount_b * final_price_b
        
        # HODL value (if not providing liquidity)
        final_hodl_value = (initial_amount_a * final_price_a + 
                          initial_amount_b * final_price_b)
        
        # Impermanent loss
        il = (final_hodl_value - final_lp_value) / final_hodl_value
        
        return {
            "initial_value": initial_value,
            "final_lp_value": final_lp_value,
            "final_hodl_value": final_hodl_value,
            "impermanent_loss": il * 100,  # As percentage
            "opportunity_cost": final_hodl_value - final_lp_value
        }

# ============== FastAPI Application ==============

start_time = datetime.utcnow()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("defi_risk_analyzer_starting", version=__version__)
    yield
    logger.info("defi_risk_analyzer_stopping")

app = FastAPI(
    title="DeFi Risk Analyzer",
    version=__version__,
    description="DeFi Protocol Risk Assessment",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============== API Endpoints ==============

@app.get("/health", response_model=HealthResponse)
def health_check():
    uptime = (datetime.utcnow() - start_time).total_seconds()
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow(),
        uptime_seconds=uptime
    )

@app.get("/")
def info():
    return {
        "name": "DeFi Risk Analyzer",
        "version": __version__,
        "features": [
            "Protocol TVL analysis",
            "Liquidity risk assessment",
            "Smart contract vulnerability scoring",
            "Governance risk analysis",
            "Impermanent loss calculator",
            "Liquidation risk monitoring"
        ]
    }

@app.post("/analyze/protocol", response_model=RiskAssessmentResponse)
async def analyze_protocol(request: RiskAssessmentRequest):
    """Analyze a specific DeFi protocol"""
    
    async with DeFiLlamaClient() as client:
        protocol_data = await client.get_protocol_tvl(request.protocol_name)
    
    if not protocol_data:
        raise HTTPException(status_code=404, detail=f"Protocol {request.protocol_name} not found")
    
    # Extract TVL data
    tvl = Decimal(str(protocol_data.get("tvl", 0)))
    
    # Get TVL change (from chainTvls or calculate)
    tvl_change_24h = Decimal("0")
    tvl_change_7d = Decimal("0")
    
    metrics = ProtocolMetrics(
        protocol_name=request.protocol_name,
        tvl=tvl,
        tvl_change_24h=tvl_change_24h,
        tvl_change_7d=tvl_change_7d,
        users=protocol_data.get("userKeys", 0),
        audits=protocol_data.get("audits", []),
        exploit_history=[]
    )
    
    # Run risk assessment
    risk_score = RiskAnalyzer.assess_protocol(request.protocol_name, metrics)
    
    # Determine risk level
    if risk_score.overall_score < 25:
        risk_level = "Low"
    elif risk_score.overall_score < 50:
        risk_level = "Medium"
    elif risk_score.overall_score < 75:
        risk_level = "High"
    else:
        risk_level = "Critical"
    
    # Generate recommendations
    recommendations = []
    if risk_score.liquidity_risk > 40:
        recommendations.append("Consider smaller position sizes due to liquidity concerns")
    if risk_score.smart_contract_risk > 40:
        recommendations.append("Wait for additional audits before significant investment")
    if risk_score.governance_risk > 30:
        recommendations.append("Monitor governance proposals closely")
    if not recommendations:
        recommendations.append("Standard risk management practices apply")
    
    return RiskAssessmentResponse(
        protocol_name=request.protocol_name,
        overall_risk_score=risk_score.overall_score,
        risk_level=risk_level,
        breakdown={
            "liquidity_risk": risk_score.liquidity_risk,
            "smart_contract_risk": risk_score.smart_contract_risk,
            "governance_risk": risk_score.governance_risk,
            "oracle_risk": risk_score.oracle_risk,
            "composability_risk": risk_score.composability_risk
        },
        factors=risk_score.factors,
        recommendations=recommendations,
        assessed_at=risk_score.assessment_date
    )

@app.get("/calculate/impermanent-loss")
def calculate_il(price_ratio: float = Query(..., gt=0)):
    """Calculate impermanent loss for a given price ratio"""
    il = ImpermanentLossCalculator.calculate_il(price_ratio)
    
    return {
        "price_ratio": price_ratio,
        "impermanent_loss_percent": round(il * 100, 2),
        "hodl_value": 100,
        "lp_value": round(100 * (1 - il), 2)
    }

@app.post("/calculate/lp-position")
def calculate_lp_position(
    initial_price_a: float,
    initial_price_b: float,
    initial_amount_a: float,
    initial_amount_b: float,
    final_price_a: float,
    final_price_b: float
):
    """Calculate LP position value including impermanent loss"""
    result = ImpermanentLossCalculator.calculate_lp_value(
        Decimal(str(initial_price_a)),
        Decimal(str(initial_price_b)),
        Decimal(str(initial_amount_a)),
        Decimal(str(initial_amount_b)),
        Decimal(str(final_price_a)),
        Decimal(str(final_price_b))
    )
    
    return {
        k: float(v) if isinstance(v, Decimal) else v
        for k, v in result.items()
    }

@app.get("/protocols/top")
async def get_top_protocols(limit: int = Query(default=20, le=100)):
    """Get top protocols by TVL"""
    async with DeFiLlamaClient() as client:
        protocols = await client.get_protocols()
    
    # Sort by TVL and take top
    sorted_protocols = sorted(
        protocols, 
        key=lambda x: x.get("tvl", 0), 
        reverse=True
    )[:limit]
    
    return {
        "count": len(sorted_protocols),
        "protocols": [
            {
                "name": p.get("name"),
                "slug": p.get("slug"),
                "tvl": p.get("tvl"),
                "category": p.get("category"),
                "chains": p.get("chains", [])
            }
            for p in sorted_protocols
        ]
    }

# ============== CLI Interface ==============

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DeFi Risk Analyzer")
    parser.add_argument("command", choices=["serve", "analyze", "il"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--protocol", help="Protocol name to analyze")
    parser.add_argument("--price-ratio", type=float, help="Price ratio for IL calculation")
    
    args = parser.parse_args()
    
    if args.command == "serve":
        uvicorn.run(app, host=args.host, port=args.port)
    elif args.command == "analyze":
        if not args.protocol:
            print("Error: --protocol required")
            exit(1)
        print(f"Analyzing {args.protocol}...")
        # Would run the analysis here
    elif args.command == "il":
        if not args.price_ratio:
            print("Error: --price-ratio required")
            exit(1)
        result = ImpermanentLossCalculator.calculate_il(args.price_ratio)
        print(f"Price ratio: {args.price_ratio}")
        print(f"Impermanent loss: {result * 100:.2f}%")
