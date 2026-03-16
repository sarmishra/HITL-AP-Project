package hitlap

# ============================================================
# HITL-AP Governance Policy Rules
# Open Policy Agent (OPA) — Rego Language
#
# Paper: "Trustworthy Agentic AI Pipelines: Human-in-the-Loop
#         Oversight Architectures for Secure Enterprise Deployment"
#
# This policy file is evaluated by the AOCP Policy Engine
# at L2 (Policy & Governance Layer) and L4 (Tool Invocation Layer).
# All deny rules produce a human-readable message that is
# captured in the Audit Logger for compliance reporting.
# ============================================================

default allow = false
default risk_level = "LOW"

# ============================================================
# SECTION 1 — ALLOW RULE
# An action is allowed only if no deny rules fire.
# ============================================================

allow {
    count(deny) == 0
}

# ============================================================
# SECTION 2 — CRITICAL DENY RULES
# These trigger immediate hard block + HITL escalation.
# ============================================================

# Block all unauthorized network egress (exfiltration risk)
deny[msg] {
    input.action == "smtp"
    not input.authorized_egress == true
    msg := "CRITICAL: Unauthorized SMTP network egress detected. Possible data exfiltration attempt."
}

deny[msg] {
    input.action == "http_post"
    not input.destination_allowlisted == true
    msg := "CRITICAL: HTTP POST to non-allowlisted destination is not permitted."
}

# Block all destructive database operations
deny[msg] {
    input.action == "sql"
    input.query_type == "DROP"
    msg := "CRITICAL: SQL DROP commands are not permitted. Destructive schema operations require explicit DBA approval."
}

deny[msg] {
    input.action == "sql"
    input.query_type == "TRUNCATE"
    msg := "CRITICAL: SQL TRUNCATE commands are not permitted without explicit DBA approval."
}

deny[msg] {
    input.action == "sql"
    input.query_type == "DELETE"
    not input.delete_approved == true
    msg := "CRITICAL: SQL DELETE requires explicit approval. Use SELECT to preview affected rows first."
}

# Block access to restricted financial datasets without approval
deny[msg] {
    input.action == "database_read"
    input.dataset == "Q4Earnings"
    not input.manager_approved == true
    msg := "CRITICAL: Q4Earnings dataset requires explicit Manager approval before access."
}

deny[msg] {
    input.action == "database_read"
    input.dataset == "SalaryData"
    not input.hr_approved == true
    msg := "CRITICAL: SalaryData dataset requires HR approval before access."
}

deny[msg] {
    input.action == "database_read"
    input.dataset == "MergerDocuments"
    not input.legal_approved == true
    msg := "CRITICAL: MergerDocuments dataset requires Legal approval before access."
}

# Block file system writes outside approved directories
deny[msg] {
    input.action == "file_write"
    not startswith(input.path, "/approved/output/")
    msg := "CRITICAL: File writes are only permitted within /approved/output/ directory."
}

# ============================================================
# SECTION 3 — HIGH SEVERITY DENY RULES
# These trigger risk-based escalation to human reviewer queue.
# ============================================================

# Block privilege escalation attempts
deny[msg] {
    input.action == "execute_code"
    input.privilege_level == "root"
    msg := "HIGH: Root-level code execution is not permitted without explicit security approval."
}

deny[msg] {
    input.action == "api_call"
    input.scope_requested != input.scope_granted
    msg := "HIGH: Requested API scope exceeds granted permissions. Privilege escalation detected."
}

# Block access to PII outside compliance context
deny[msg] {
    input.action == "database_read"
    input.contains_pii == true
    not input.gdpr_justified == true
    msg := "HIGH: Access to PII-containing records requires GDPR justification."
}

# Block multi-agent tool calls that exceed budget
deny[msg] {
    input.action == "api_call"
    input.estimated_cost_usd > 10.0
    not input.budget_approved == true
    msg := "HIGH: Estimated API call cost exceeds $10.00 threshold. Budget approval required."
}

# ============================================================
# SECTION 4 — MEDIUM SEVERITY RULES
# These trigger asynchronous audit review (advisory mode).
# ============================================================

# Flag external API calls for audit
warn[msg] {
    input.action == "api_call"
    input.external == true
    msg := "MEDIUM: External API call flagged for post-execution audit review."
}

# Flag large data retrievals
warn[msg] {
    input.action == "database_read"
    input.row_count_estimated > 10000
    msg := "MEDIUM: Large dataset retrieval (>10,000 rows) flagged for audit review."
}

# ============================================================
# SECTION 5 — RISK LEVEL ASSIGNMENT
# Used by the Risk Analyzer to determine AOCP routing mode.
# ============================================================

risk_level = "CRITICAL" {
    input.action == "smtp"
}

risk_level = "CRITICAL" {
    input.action == "sql"
    input.query_type == "DROP"
}

risk_level = "CRITICAL" {
    input.action == "sql"
    input.query_type == "TRUNCATE"
}

risk_level = "HIGH" {
    input.action == "execute_code"
    input.privilege_level == "root"
}

risk_level = "HIGH" {
    input.action == "database_read"
    input.dataset == "Q4Earnings"
}

risk_level = "MEDIUM" {
    input.action == "api_call"
    input.external == true
}

risk_level = "LOW" {
    input.action == "database_read"
    not input.contains_pii
    not input.dataset == "Q4Earnings"
}
