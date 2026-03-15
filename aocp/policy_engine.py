import requests
import logging

class PolicyEngine:
    """
    AOCP Component 1: Policy Engine
    Integrates with Open Policy Agent (OPA) to evaluate agent actions against 
    enterprise governance rules (e.g., RBAC, data egress prevention).
    """
    def __init__(self, opa_url="http://localhost:8181/v1/data/hitl_ap/policy"):
        self.opa_url = opa_url
        self.logger = logging.getLogger("PolicyEngine")

    def evaluate_action(self, agent_role: str, tool_name: str, payload: dict) -> dict:
        """
        Queries OPA to determine if the requested tool invocation is permitted.
        Returns a risk score and policy decision.
        """
        self.logger.info(f"Evaluating policy for tool: {tool_name}")
        
        # Stub logic: In production, this makes an HTTP POST to the OPA server.
        # Simulating the Prompt Injection/Data Exfiltration rule from the paper.
        if tool_name == "smtp_email" and "financial_dataset" in str(payload):
            return {
                "allowed": False,
                "risk_score": 95,
                "reason": "CRITICAL: Data exfiltration policy violation detected."
            }
        
        return {
            "allowed": True,
            "risk_score": 10,
            "reason": "Action complies with least-privilege constraints."
        }
