<div align="center">

# 💰 DeFi Risk Analyzer

**DeFi protocol risk analyzer with TVL tracking, impermanent loss calculator, and smart contract vulnerability scanner**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![DeFi](https://img.shields.io/badge/DeFi-Finance-00A3E0?style=flat)](https://ethereum.org/en/defi/)

</div>

---

## 🚀 Overview

DeFi Risk Analyzer provides comprehensive risk assessment for decentralized finance protocols. Monitor Total Value Locked (TVL), calculate impermanent loss, and detect smart contract vulnerabilities in real-time.

### Features

- 💰 **TVL Tracking**: Real-time total value locked monitoring
- 📉 **IL Calculator**: Impermanent loss prediction and analysis
- 🔒 **Contract Audit**: Automated vulnerability scanning
- 📊 **APY Analytics**: Yield farming risk/reward analysis
- 🚨 **Risk Alerts**: Early warning system for exploits

---

## 📈 Supported Protocols

| Protocol | TVL Tracking | Risk Score | Status |
|----------|--------------|------------|--------|
| Uniswap V3 | ✅ | ✅ | Live |
| Aave V3 | ✅ | ✅ | Live |
| Compound | ✅ | ✅ | Live |
| Curve | ✅ | ✅ | Live |
| Convex | ✅ | 🚧 | Beta |

---

## 🛠️ Quick Start

```bash
pip install defi-risk-analyzer
```

```python
from defi_risk_analyzer import RiskAnalyzer

analyzer = RiskAnalyzer()
risk_report = analyzer.analyze_protocol("uniswap-v3")
print(f"Risk Score: {risk_report.score}/100")
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ by [Drajat Sukma](https://github.com/Ajatfnr21)**

</div>
