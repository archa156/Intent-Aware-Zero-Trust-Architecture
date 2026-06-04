DEFAULT_BASELINE = {
    "avg_calls_per_session": 20,
    "avg_hour":              10,
    "session_count":         30
}


def scenario_normal(user_id="user_normal"):
    return {
        "user_id":          user_id,
        "declared_intent":  "Running monthly finance reports",
        "api_calls":        ["/reports", "/read_data", "/summary",
                             "/reports", "/export_own"],
        "hour":             10,
        "calls_per_minute": 8
    }


def scenario_suspicious(user_id="user_suspicious"):
    return {
        "user_id":          user_id,
        "declared_intent":  "Read access only",
        "api_calls":        ["/read_data", "/admin", "/export_all",
                             "/read_data", "/admin", "/summary",
                             "/export_all", "/admin", "/read_data", "/admin"],
        "hour":             23,
        "calls_per_minute": 15
    }


def scenario_attacker(user_id="user_attacker"):
    return {
        "user_id":          user_id,
        "declared_intent":  "Routine check",
        "api_calls":        ["/delete_user"] * 8 + ["/export_all"] * 4,
        "hour":             2,
        "calls_per_minute": 20
    }
