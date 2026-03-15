import json

class EscalationManager:
    """
    AOCP Component 3: Human Escalation Manager
    Routes high-risk actions to human reviewer queues via RabbitMQ/Redis.
    """
    def __init__(self):
        # Stub for pika.BlockingConnection parameters
        self.queue_name = "hitl_review_queue"

    def route_to_human(self, action_data: dict, risk_eval: dict) -> str:
        """
        Publishes the action to the message broker and awaits a human response.
        Enforces SLA timeouts to prevent agent deadlock.
        """
        print(f"\n[ESCALATION MANAGER] Routing action to human review queue...")
        print(f"--> Tool: {action_data['tool_name']}")
        print(f"--> Reason: {risk_eval['reason']}")
        
        # Simulating the Human Reviewer's action from the Prompt Injection Case Study
        return self._simulate_human_dashboard_response(action_data)

    def _simulate_human_dashboard_response(self, action_data: dict) -> str:
        """Stub to simulate a human clicking 'Reject' on the dashboard."""
        if action_data['tool_name'] == "smtp_email":
            print("[HUMAN REVIEWER] Decision: REJECTED (Data Exfiltration Prevented)")
            return "REJECTED"
        return "APPROVED"
