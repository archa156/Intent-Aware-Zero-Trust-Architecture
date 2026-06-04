INTENT_MAP = {
    "finance_report_generation": {
        "allowed":   ["/reports", "/read_data", "/summary", "/export_own"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/user_lookup"]
    },
    "system_administration": {
        "allowed":   ["/admin", "/system_status", "/user_lookup", "/logs"],
        "forbidden": ["/export_all", "/delete_user", "/billing"]
    },
    "debugging_logs": {
        "allowed":   ["/logs", "/system_status", "/read_data"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing", "/user_management"]
    },
    "user_management": {
        "allowed":   ["/user_lookup", "/user_management", "/read_data"],
        "forbidden": ["/export_all", "/billing", "/delete_user"]
    },
    "data_export_compliance": {
        "allowed":   ["/export_all", "/export_own", "/reports", "/summary"],
        "forbidden": ["/admin", "/delete_user", "/user_management"]
    },
    "routine_check": {
        "allowed":   ["/system_status", "/logs", "/summary"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing"]
    },
    "billing_operations": {
        "allowed":   ["/billing", "/reports", "/export_own"],
        "forbidden": ["/admin", "/delete_user", "/user_management", "/export_all"]
    },
    "read_access_only": {
        "allowed":   ["/read_data", "/summary", "/reports"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/export_own", "/billing"]
    },
    "audit_access": {
        "allowed":   ["/logs", "/reports", "/read_data", "/summary", "/user_lookup"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing", "/user_management"]
    },
    "compliance_review": {
        "allowed":   ["/reports", "/export_own", "/summary", "/read_data", "/logs"],
        "forbidden": ["/admin", "/delete_user", "/user_management", "/export_all"]
    },
    "incident_response": {
        "allowed":   ["/logs", "/system_status", "/user_lookup", "/read_data", "/admin", "/reports"],
        "forbidden": ["/delete_user", "/billing", "/export_all"]
    },
    "data_analytics": {
        "allowed":   ["/read_data", "/summary", "/reports", "/export_own"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing", "/user_management"]
    },
    "onboarding_operations": {
        "allowed":   ["/user_management", "/user_lookup", "/read_data", "/summary"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing", "/logs"]
    },
    "security_monitoring": {
        "allowed":   ["/logs", "/system_status", "/read_data", "/user_lookup", "/summary"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/billing", "/user_management"]
    },
    "reporting_only": {
        "allowed":   ["/reports", "/summary"],
        "forbidden": ["/admin", "/delete_user", "/export_all", "/export_own",
                      "/billing", "/read_data", "/user_management", "/user_lookup", "/logs"]
    },
}

INTENT_KEYWORDS = {
    "finance_report_generation": ["finance", "report", "monthly", "quarterly", "revenue", "financial", "audit", "summary report"],
    "system_administration": ["admin", "system", "administration", "sysadmin", "server", "infrastructure", "manage system"],
    "debugging_logs": ["debug", "log", "debugging", "error", "trace", "troubleshoot", "diagnose"],
    "user_management": ["user", "account", "manage user", "user account", "create user", "update user", "profile"],
    "data_export_compliance": ["export", "data export", "regulatory", "audit export", "download data", "bulk export"],
    "routine_check": ["routine", "check", "monitoring", "status check", "health check", "verify", "daily check"],
    "billing_operations": ["billing", "payment", "invoice", "subscription", "charge", "transaction", "financial ops"],
    "read_access_only": ["read", "view", "browse", "look", "check data", "read only", "view data"],
    "audit_access": ["audit", "audit trail", "access log", "review access", "activity log", "who accessed", "audit review"],
    "compliance_review": ["compliance review", "gdpr", "hipaa", "sox", "regulatory review", "compliance check", "policy review", "data protection", "hipaa review", "sox review"],
    "incident_response": ["incident", "breach", "investigation", "security incident", "respond", "forensic", "compromised", "attack response"],
    "data_analytics": ["analytics", "analysis", "dashboard", "insight", "trend", "data science", "query", "visualise", "visualize"],
    "onboarding_operations": ["onboard", "new employee", "create account", "provision", "setup user", "new user", "employee setup", "access setup"],
    "security_monitoring": ["security", "threat", "soc", "monitor", "watchdog", "intrusion", "anomaly", "surveillance", "siem"],
    "reporting_only": ["reporting", "executive", "summary only", "board report", "management report", "kpi", "dashboard report", "metrics report"],
}

def resolve_intent(text: str) -> str:
    text_lower = text.lower()
    score_map  = {}
    for intent_category, keywords in INTENT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                score_map[intent_category] = score_map.get(intent_category, 0) + 1
    if not score_map:
        return "read_access_only"
    return max(score_map, key=score_map.get)

def get_rules(intent_category: str) -> dict:
    return INTENT_MAP.get(intent_category, INTENT_MAP["read_access_only"])
