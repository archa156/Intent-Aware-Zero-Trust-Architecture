def generate_explanation(session: dict, rules: dict) -> dict:
    """
    Generates a human-readable explanation based entirely on
    what actually happened in the session.
    Fully deterministic — no API, no cost, no hallucination.
    """
    score     = session["deviation_score"]
    outside   = session["outside_calls"]
    forbidden = session["forbidden_hits"]
    intent    = session["declared_intent"]
    hour      = session["hour"]
    total     = session["total_calls"]
    factors   = session["factors"]

    parts = []

    if forbidden:
        unique_forbidden = list(set(forbidden))
        parts.append(
            f"User called forbidden endpoints {unique_forbidden} "
            f"despite declaring '{intent}'"
        )

    if outside and not forbidden:
        parts.append(
            f"{len(outside)} out of {total} API calls were outside "
            f"the declared scope of '{intent}'"
        )

    if factors.get("time_anomaly", 0) > 0.5:
        parts.append(f"session occurred at an unusual hour ({hour}:00)")

    if factors.get("sequence_anomaly", 0) > 0:
        parts.append("repeated calls to restricted endpoints were detected")

    if rules["flags"]:
        parts.append(f"rule engine flagged: {rules['flags'][0]}")

    if not parts:
        explanation = (
            f"Session matched declared intent '{intent}' "
            f"with zero deviation — normal behaviour."
        )
    else:
        explanation = ". ".join(parts) + "."
        explanation = explanation[0].upper() + explanation[1:]

    if score < 0.30:
        risk_level = "LOW"
    elif score < 0.65:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    risk_score = int(score * 100)

    signals = []
    if factors.get("scope_deviation", 0) > 0:
        signals.append("scope_deviation")
    if factors.get("forbidden_hits_ratio", 0) > 0:
        signals.append("forbidden_endpoint_hit")
    if factors.get("time_anomaly", 0) > 0.5:
        signals.append("time_anomaly")
    if factors.get("sequence_anomaly", 0) > 0:
        signals.append("sequence_anomaly")
    if rules["flags"]:
        signals.append("rule_engine_flag")
    if not signals:
        signals.append("no_anomaly_detected")

    return {
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "explanation":       explanation,
        "triggered_signals": signals
    }
