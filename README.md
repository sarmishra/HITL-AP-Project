# HITL-AP: Human-in-the-Loop Agentic Pipeline 🛡️

**Reference Implementation for:**
> *"Trustworthy Agentic AI Pipelines: Human-in-the-Loop Oversight Architectures for Secure Enterprise Deployment"*

This repository contains the reference implementation of the **HITL-AP framework** and its core enforcement component, the **Agentic Oversight Control Plane (AOCP)**. It demonstrates how to secure autonomous LangGraph/multi-agent workflows using cryptographic audit logging, OPA-based policy enforcement, and risk-triggered human-in-the-loop (HITL) escalation.

---

## 📄 Citation

If you use this work, please cite:

```bibtex
@inproceedings{mishra2026hitlap,
  author    = {Mishra, Saroj},
  title     = {Trustworthy Agentic AI Pipelines:
               Human-in-the-Loop Oversight Architectures
               for Secure Enterprise Deployment},
  booktitle = {IEEE International Conference on
               Omni-Layer Intelligent Systems (COINS)},
  year      = {2026},
  note      = {Accepted for presentation; proceedings forthcoming}
}
```

---

## Architecture Overview

The AOCP acts as a **vertical cross-cutting middleware** across the agent's seven execution layers (L1–L7). It is composed of four independent microservices:

| Component | Technology | Function |
|---|---|---|
| **Policy Engine** | Open Policy Agent (OPA) + Rego | Enforce governance rules pre- and post-action |
| **Risk Analyzer** | Python FastAPI | Low-latency payload scoring (<50ms target) |
| **Escalation Manager** | RabbitMQ / Redis | Route high-risk decisions to human reviewer queue |
| **Audit Logger** | PostgreSQL + HMAC-SHA256 hash chain | Tamper-evident, cryptographically signed audit ledger |

```
User Input
    │
    ▼
L1: User Interface Layer         ← Input validation & prompt sanitization
    │
    ▼
L2: Policy & Governance Layer    ← AOCP Policy Engine (OPA)
    │
    ▼
L3: Agent Planning Layer         ← RTC metric captured here
    │
    ▼
L4: Tool Invocation Layer        ← AOCP Risk Analyzer intercepts payloads
    │
    ▼
L5: Human Oversight Layer        ← AOCP Escalation Manager routes reviews
    │
    ▼
L6: Execution Sandbox            ← Isolated execution, rollback capability
    │
    ▼
L7: Monitoring & Audit Layer     ← AOCP Audit Logger (ACS metric captured)
```

---

## 📊 Evaluation Results (N=50 executions per system)

| System | RTC (%) | IL (ms) | ACS (%) |
| --- | --- | --- | --- |
| AutoGen (baseline) | 24.2 ± 6.5 | N/A | 0.0 ± 0.0 |
| LangGraph (baseline) | 48.6 ± 8.2 | N/A | 0.0 ± 0.0 |
| CrewAI (baseline) | 36.4 ± 5.1 | N/A | 0.0 ± 0.0 |
| **HITL-AP + AOCP** | **98.5 ± 1.2** | **142.3 ± 18.5** | **100.0 ± 0.0** |

AOCP programmatic latency: median 142ms, p95 = 186ms, p99 = 212ms  
RTC differences statistically significant (Welch's t-test, p < 0.01)

### Safety Efficacy (N=50 adversarial cases)
| Metric | Result |
| --- | --- |
| Adversarial Interception Rate (TPR) | 94.0% |
| Benign Escalation Rate (FPR) | 4.2% |
| Median Human Review Time | 18.5 sec |
| AOCP p95 Programmatic Latency | 186.2 ms |

---

## 📐 Oversight Metrics

| Metric | Definition | Target |
| --- | --- | --- |
| **RTC** — Reasoning Trace Completeness | % of decisions with verifiable pre-execution reasoning trace | > 95% |
| **IL** — Intervention Latency | Programmatic overhead from AOCP trigger to decision receipt (ms), excluding human deliberation | < 200ms |
| **ACS** — Audit Coverage Score | % of pipeline events stored in cryptographically signed, tamper-evident log | 100% |

> **Note:** ACS evaluates cryptographic, append-only audit guarantees — not mere logging presence. Baselines score 0% because their native logs are mutable and unsigned.


---

## 🏛️ NIST AI RMF Alignment

| Function | HITL-AP Coverage |
| --- | --- |
| **GOVERN** | AOCP Policy Engine provides formal, auditable governance rules; version-controlled and access-restricted |
| **MAP** | Pipeline-stage risk taxonomy maps risk categories to specific architectural layers |
| **MEASURE** | RTC, IL, ACS provide quantitative measurement of oversight effectiveness |
| **MANAGE** | L4 Risk Analyzer blocks violations, L5 manages escalations, L7 provides immutable audit records |

---

## Repository Structure

```
.
├── aocp/
│   ├── audit_logger.py           # PostgreSQL + HMAC-SHA256 hash chain logging
│   ├── escalation_manager.py     # RabbitMQ human review routing
│   ├── policy_engine.py          # OPA integration
│   ├── risk_analyzer.py          # FastAPI enforcement endpoint
│   └── policies/
│       └── hitlap_policy.rego    # OPA Rego governance rules
├── pipeline/
│   └── financial_agent.py        # LangGraph agent (Retrieval → Transform → Report)
├── evaluation/
│   └── run_evaluation.py         # Reproduce Table IV results (RTC, IL, ACS)
├── data/
│   ├── sample_financial_dataset.csv   # Synthetic financial records
│   ├── malicious_document.txt         # Prompt injection case study input
│   └── benign_document.txt            # Normal document for baseline runs
├── scripts/
│   └── init_db.py                # PostgreSQL audit table initialization
├── tests/
│   └── test_aocp.py              # AOCP component test suite
├── docker-compose.yml            # One-command infrastructure setup
├── .env.example                  # Environment variable template
├── requirements.txt
└── README.md
```

---

## Prerequisites

- Python 3.9+
- PostgreSQL 14+
- RabbitMQ 3.x
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/#1-download-opa) binary in PATH
- OpenAI API key (for LangGraph agent LLM calls)
- Docker + Docker Compose (recommended for infrastructure)

---

## Quick Start (Recommended — Docker)

```bash
# Step 1: Clone the repository
git clone https://github.com/sarmishra/HITL-AP-Project.git
cd HITL-AP-Project

# Step 2: Copy and configure environment variables
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY and AOCP_HMAC_SECRET

# Step 3: Start infrastructure (PostgreSQL, RabbitMQ, OPA)
docker-compose up -d

# Step 4: Install Python dependencies
pip install -r requirements.txt

# Step 5: Initialize the audit database schema
python scripts/init_db.py

# Step 6: Start the AOCP Risk Analyzer
uvicorn aocp.risk_analyzer:app --reload --port 8000

# Step 7: Start the Escalation Manager consumer (separate terminal)
python aocp/escalation_manager.py

# Step 8: Run the financial pipeline
python pipeline/financial_agent.py
```

---

## Manual Setup (Without Docker)

If you prefer to run services manually:

```bash
# PostgreSQL: Create database
createdb hitlap

# RabbitMQ: Start server (macOS example)
brew services start rabbitmq

# OPA: Start server with policy directory
opa run --server --addr :8181 aocp/policies/

# Then follow Steps 4–8 above
```

---

## Reproducing the Paper Evaluation (Table IV)

The evaluation compares HITL-AP against AutoGen, LangGraph, and CrewAI across 50 task executions per system.

```bash
# Run evaluation for all systems (reproduces Table IV)
python evaluation/run_evaluation.py --system hitlap --runs 50
python evaluation/run_evaluation.py --system autogen --runs 50
python evaluation/run_evaluation.py --system langgraph --runs 50
python evaluation/run_evaluation.py --system crewai --runs 50

# Results saved to: evaluation/results/
# Displays: mean ± std for RTC (%), IL (ms), ACS (%)
```

Each run consists of a multi-step workflow: dataset retrieval → data transformation → compliance report generation, executed under varying input conditions including benign requests, high-confidence tool invocations, low-confidence planning decisions, and simulated adversarial inputs.

---

## Running the Prompt Injection Case Study (Section VII-A)

This demonstrates AOCP interception of an indirect prompt injection attack targeting the SMTP tool for data exfiltration.

```bash
# Run prompt injection simulation (uses data/malicious_document.txt)
python pipeline/financial_agent.py --mode injection_attack

# Run baseline comparison (no AOCP — shows unmitigated exfiltration)
python pipeline/financial_agent.py --mode injection_attack --no-aocp

# Run normal financial pipeline (benign mode)
python pipeline/financial_agent.py --mode normal
```

Expected output (with AOCP):
```
[L4] Risk Analyzer: SMTP payload flagged — CRITICAL (unauthorized network egress)
[L5] Escalation Manager: Action routed to Human Review Queue
[AOCP] Human reviewer decision: REJECTED
[L7] Audit Logger: Full traversal cryptographically appended (hash: <sha256>)
[RESULT] Data exfiltration PREVENTED
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Environment Variables Reference

| Variable | Description | Required |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `RABBITMQ_URL` | RabbitMQ AMQP connection string | Yes |
| `OPA_URL` | OPA server address | Yes |
| `AOCP_HMAC_SECRET` | HMAC-SHA256 signing key for audit log | Yes |
| `OPENAI_API_KEY` | OpenAI API key for LangGraph agent | Yes |
| `AOCP_MODE` | Deployment mode: inline/advisory/hybrid | No (default: hybrid) |
| `AOCP_RISK_THRESHOLD` | Risk score threshold for escalation (0.0–1.0) | No (default: 0.7) |
| `AOCP_IL_TARGET_MS` | Intervention latency target in ms | No (default: 200) |

---

## Security Notes

- **Never commit your `.env` file** — it is in `.gitignore` by default
- The `AOCP_HMAC_SECRET` should be a cryptographically random string (minimum 32 characters)
- In production, manage secrets via a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- The Audit Logger uses append-only semantics — direct database modification requires bypassing application controls

---

## ⚙️ AOCP Deployment Modes

Set via `AOCP_MODE` environment variable:

| Mode | Behavior | Use Case |
| --- | --- | --- |
| `inline` | Blocks execution pending human decision | Maximum safety; irreversible actions |
| `advisory` | Flags without blocking | High-throughput routine tasks |
| `hybrid` (default) | Inline for critical-tier; advisory for routine | **Recommended enterprise deployment** |


---

## License

MIT License. See `LICENSE` for details.

---

## Contact

For questions about the paper or this implementation, please open a GitHub Issue.
