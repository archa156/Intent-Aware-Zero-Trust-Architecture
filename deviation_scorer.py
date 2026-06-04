from intent_map import resolve_intent, get_rules

# ── Weight Justification ──────────────────────────────────────────────────────
# SCOPE_DEVIATION  (0.35) — calling APIs outside declared scope is the
#                           primary signal of intent mismatch
# FORBIDDEN_HITS   (0.35) — explicitly forbidden endpoints are highest risk,
#                           equal weight to scope deviation
# TIME_ANOMALY     (0.20) — off-hours access is a strong secondary indicator
# SEQUENCE_ANOMALY (0.10) — repeated forbidden calls add signal but are
#                           already partially captured by forbidden_hits
# Total = 1.0
# ─────────────────────────────────────────────────────────────────────────────
WEIGHTS = {
    "scope_deviation":   0.35,
    "forbidden_hits":    0.35,
    "time_anomaly":      0.20,
    "sequence_anomaly":  0.10
}


def compute_deviation(api_calls: list, intent_category: str,
                      hour: int, baseline: dict) -> dict:
    rules          = get_rules(intent_category)
    allowed        = rules["allowed"]
    forbidden      = rules["forbidden"]

    if not api_calls:
        return {
            "score": 0.0, "outside": [], "inside": [],
            "forbidden_hits": [], "total_calls": 0, "factors": {}
        }

    outside        = [c for c in api_calls if c not in allowed]
    inside         = [c for c in api_calls if c in allowed]
    forbidden_hits = [c for c in api_calls if c in forbidden]

    # Factor 1 — scope deviation
    f1 = len(outside) / len(api_calls)

    # Factor 2 — forbidden endpoint ratio
    f2 = len(forbidden_hits) / len(api_calls)

    # Factor 3 — time anomaly vs personal baseline
    baseline_hour = baseline.get("avg_hour", 10)
    time_diff     = abs(hour - baseline_hour)
    f3            = min(time_diff / 12.0, 1.0)

    # Factor 4 — repeated forbidden calls (sequence anomaly)
    from collections import Counter
    call_counts        = Counter(api_calls)
    repeated_forbidden = sum(
        count for ep, count in call_counts.items()
        if ep in forbidden and count > 2
    )
    f4 = min(repeated_forbidden / max(len(api_calls), 1), 1.0)

    score = (
        WEIGHTS["scope_deviation"]   * f1 +
        WEIGHTS["forbidden_hits"]    * f2 +
        WEIGHTS["time_anomaly"]      * f3 +
        WEIGHTS["sequence_anomaly"]  * f4
    )

    return {
        "score":          round(score, 3),
        "outside":        outside,
        "inside":         inside,
        "forbidden_hits": forbidden_hits,
        "total_calls":    len(api_calls),
        "factors": {
            "scope_deviation":      round(f1, 3),
            "forbidden_hits_ratio": round(f2, 3),
            "time_anomaly":         round(f3, 3),
            "sequence_anomaly":     round(f4, 3)
        }
    }


def get_decision(score: float) -> str:
    if score < 0.30:
        return "MAINTAIN"
    elif score < 0.65:
        return "WARN"
    else:
        return "REVOKE"


def evaluate_session(user_id: str, declared_intent: str,
                     api_calls: list, hour: int, baseline: dict) -> dict:
    intent_category = resolve_intent(declared_intent)
    result          = compute_deviation(api_calls, intent_category, hour, baseline)
    decision        = get_decision(result["score"])

    return {
        "user_id":         user_id,
        "declared_intent": declared_intent,
        "intent_category": intent_category,
        "api_calls":       api_calls,
        "hour":            hour,
        "deviation_score": result["score"],
        "outside_calls":   result["outside"],
        "forbidden_hits":  result["forbidden_hits"],
        "inside_calls":    result["inside"],
        "total_calls":     result["total_calls"],
        "factors":         result["factors"],
        "decision":        decision
    }
