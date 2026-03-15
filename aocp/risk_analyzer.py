from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from aocp.policy_engine import PolicyEngine
from aocp.escalation_manager import EscalationManager
from aocp.audit_logger import AuditLogger

app = FastAPI(title="AOCP Risk Analyzer", version="1.0.0")

# Initialize AOCP Sub-components
policy_engine = PolicyEngine()
escalation_mgr = EscalationManager()
audit_logger = AuditLogger()

class AgentAction(BaseModel):
    agent_id: str
    tool_name: str
    payload: dict
    reasoning_trace: str  # Required for the RTC metric

@app.post("/analyze")
async def analyze_action(action: AgentAction):
    """
    AOCP Component 2: Risk Analyzer
    Intercepts agent tool payloads before execution.
    """
    # 1. Log the incoming event (Pipeline Event for ACS)
    audit_logger.log_event("ACTION_PROPOSED", action.dict())

    # 2. Evaluate against OPA Policy Engine
    evaluation = policy_engine.evaluate_action(action.agent_id, action.tool_name, action.payload)

    # 3. Handle Escalation (Hybrid Mode: Inline block for Critical, Advisory for Low)
    if evaluation["risk_score"] > 80:
        audit_logger.log_event("ESCALATION_TRIGGERED", evaluation)
        
        # Route to RabbitMQ for Human Review
        human_decision = escalation_mgr.route_to_human(action.dict(), evaluation)
        
        audit_logger.log_event("HUMAN_DECISION_RECORDED", {"decision": human_decision})
        
        if human_decision == "REJECTED":
            raise HTTPException(status_code=403, detail="Action blocked by Human Reviewer.")
            
    # 4. Safe to execute
    audit_logger.log_event("ACTION_APPROVED", {"tool": action.tool_name})
    return {"status": "approved", "intervention_latency_ms": 42} # Simulated IL
