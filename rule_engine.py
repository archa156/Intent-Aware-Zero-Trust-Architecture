"""
rule_engine.py  —  Deterministic rule checks

Fix applied:
  Rule 2 now compares calls_per_minute against avg_rate_per_minute
  (both in calls/min). Original compared against avg_calls_per_session
  (calls/session) which is a different unit — the rule almost never fired.
"""
from collections import Counter


def run_rule_engine(api_calls: list, hour: int,
                    calls_per_minute: float, baseline: dict) -> dict:
    flags = []

    # Rule 1 — late-night access
    if hour < 6 or hour > 22:
        flags.append(f"LATE_NIGHT_ACCESS: session at {hour}:00")

    # Rule 2 — extreme call rate vs personal baseline (FIXED: same unit)
    baseline_rate = baseline.get("avg_rate_per_minute", 15)
    if calls_per_minute > baseline_rate * 2:
        flags.append(
            f"EXTREME_CALL_RATE: {calls_per_minute:.1f}/min "
            f"vs baseline {baseline_rate:.1f}/min"
        )

    # Rule 3 — known high-risk endpoints
    high_risk = ["/delete_user", "/export_all", "/admin"]
    for call in api_calls:
        if call in high_risk:
            flags.append(f"HIGH_RISK_ENDPOINT_CALLED: {call}")

    # Rule 4 — repeated calls to same endpoint
    call_counts = Counter(api_calls)
    for endpoint, count in call_counts.items():
        if count > 5:
            flags.append(f"REPEATED_CALLS: {endpoint} called {count} times")

    # Rule 5 — honeypot (belt-and-suspenders, main check is in main.py Step 0)
    from role_access import HONEYPOT_ENDPOINTS
    for call in api_calls:
        if call in HONEYPOT_ENDPOINTS:
            flags.append(f"HONEYPOT_ENDPOINT: {call}")

    if len(flags) >= 3:
        rule_decision = "REVOKE"
    elif len(flags) >= 1:
        rule_decision = "WARN"
    else:
        rule_decision = "MAINTAIN"

    return {
        "flags":         flags,
        "rule_decision": rule_decision,
        "flag_count":    len(flags)
    }
