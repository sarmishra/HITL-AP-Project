# HITL-AP: Human-in-the-Loop Agentic Pipeline 🛡️

**Reference Implementation for "Trustworthy Agentic AI Pipelines: Human-in-the-Loop Oversight Architectures for Secure Enterprise Deployment"**

This repository contains the reference implementation of the **HITL-AP framework** and its core enforcement component, the **Agentic Oversight Control Plane (AOCP)**. It demonstrates how to secure autonomous LangGraph/multi-agent workflows using cryptographic audit logging, OPA-based policy enforcement, and risk-triggered human-in-the-loop (HITL) escalation.

## Architecture Overview
The AOCP acts as a vertical cross-cutting middleware across the agent's execution layers:
1. **Policy Engine:** Evaluates actions against Open Policy Agent (OPA) rules.
2. **Risk Analyzer:** A low-latency FastAPI service that scores payloads.
3. **Escalation Manager:** Routes high-risk actions to a RabbitMQ queue for human review.
4. **Audit Logger:** Maintains a tamper-evident, hash-chained PostgreSQL ledger (achieving 100% ACS).

## Repository Structure
```text
.
├── aocp/
│   ├── audit_logger.py       # PostgreSQL + Hash Chain logging
│   ├── escalation_manager.py # RabbitMQ human review routing
│   ├── policy_engine.py      # OPA integration
│   └── risk_analyzer.py      # FastAPI enforcement endpoint
├── pipeline/
│   └── financial_agent.py    # LangGraph agent (Retrieval -> Transform -> Report)
├── requirements.txt
└── README.md
```

## Setup & Execution (Prototype)
1. **Install Dependencies**
```text
pip install -r requirements.txt
```

2. **Start the AOCP Risk Analyzer (Middleware)**
```text
uvicorn aocp.risk_analyzer:app --reload --port 8000
```

3. **Run the Agentic Pipeline**
In a separate terminal, execute the financial agent to simulate the prompt injection case study:
```text
python pipeline/financial_agent.py
```

