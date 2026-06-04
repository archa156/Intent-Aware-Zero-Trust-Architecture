"""
main.py  —  Full ZTA Pipeline (updated)

New steps added to the pipeline:
  Step 0  — Honeypot check (instant REVOKE before anything else runs)
  Step 1b — Role-based intent enforcement (clamps declared intent if outside role's whitelist)
  Step 1c — Intent confidence scoring (flags weak/ambiguous intent declarations)
  Step 7  — update_baseline now passes calls_per_minute and role
"""
import json
from database        import init_db, get_connection, get_baseline, update_baseline
from deviation_scorer import evaluate_session
from rule_engine      import run_rule_engine
from explainer        import generate_explanation
from synthetic_data   import scenario_normal, scenario_suspicious, scenario_attacker
from intent_map       import INTENT_MAP, INTENT_KEYWORDS
from role_access      import (
    enforce_role_intent,
    check_honeypots,
    inject_honeypots_into_intent_map,
    score_intent_confidence,
)

# Inject honeypot endpoints into every intent category's forbidden list at startup
inject_honeypots_into_intent_map(INTENT_MAP)


def combine_decisions(deviation_decision: str, rule_decision: str) -> str:
    if "REVOKE" in [deviation_decision, rule_decision]:
        return "REVOKE"
    if "WARN" in [deviation_decision, rule_decision]:
        return "WARN"
    return "MAINTAIN"


def run_pipeline(scenario_data: dict) -> dict:
    user_id          = scenario_data["user_id"]
    declared_intent  = scenario_data["declared_intent"]
    api_calls        = scenario_data["api_calls"]
    hour             = scenario_data["hour"]
    calls_per_minute = scenario_data.get("calls_per_minute", 10)
    user_role        = scenario_data.get("role", "junior_analyst")

    # ── Step 0 — Honeypot check (instant REVOKE) ──────────────────────────────
    honeypot_result = check_honeypots(api_calls)
    if honeypot_result["instant_revoke"]:
        explanation_text = honeypot_result["reason"]
        conn = get_connection()
        conn.execute("""
            INSERT INTO sessions
            (user_id, role, declared_intent, intent_category, original_intent,
             intent_clamped, intent_confidence, honeypot_hit,
             api_calls, hour_of_access, deviation_score, decision,
             explanation, risk_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (user_id, user_role, declared_intent, "HONEYPOT_TRIGGERED",
              declared_intent, 0, 1.0, 1,
              json.dumps(api_calls), hour, 1.0, "REVOKE",
              explanation_text, "CRITICAL"))
        conn.commit()
        conn.close()
        return {
            "session":      {"user_id": user_id, "declared_intent": declared_intent,
                             "intent_category": "HONEYPOT_TRIGGERED",
                             "api_calls": api_calls, "hour": hour,
                             "deviation_score": 1.0, "decision": "REVOKE",
                             "outside_calls": api_calls, "forbidden_hits": api_calls,
                             "inside_calls": [], "total_calls": len(api_calls),
                             "factors": {}},
            "rules":        {"flags": [f"HONEYPOT: {honeypot_result['hits']}"],
                             "rule_decision": "REVOKE", "flag_count": 1},
            "explanation":  {"risk_score": 100, "risk_level": "CRITICAL",
                             "explanation": explanation_text,
                             "triggered_signals": ["honeypot_triggered"]},
            "decision":     "REVOKE",
            "baseline_used": get_baseline(user_id),
            "honeypot":     honeypot_result,
            "role_check":   None,
            "confidence":   None,
        }

    # ── Step 1 — Fetch personal baseline ─────────────────────────────────────
    baseline = get_baseline(user_id)

    # ── Step 1b — Role-based intent enforcement ───────────────────────────────
    # Resolve raw text → category first, THEN check role whitelist
    from intent_map import resolve_intent as _resolve
    resolved_category = _resolve(declared_intent)
    role_check = enforce_role_intent(resolved_category, user_role)
    effective_intent = role_check["resolved_intent"]  # may be clamped

    # ── Step 1c — Intent confidence scoring ───────────────────────────────────
    confidence_result = score_intent_confidence(declared_intent, INTENT_KEYWORDS)

    # ── Step 2 — Deviation scoring (uses effective_intent after role clamp) ───
    session = evaluate_session(
        user_id         = user_id,
        declared_intent = effective_intent,   # use clamped intent if applicable
        api_calls       = api_calls,
        hour            = hour,
        baseline        = baseline
    )
    # Preserve original declared intent for audit log
    session["original_declared_intent"] = declared_intent
    session["intent_clamped"]           = role_check["clamped"]
    session["intent_confidence"]        = confidence_result["confidence"]

    # If intent was low-confidence, add a small risk penalty (5 points = +0.05 to score)
    if confidence_result["low_confidence"] and not role_check["clamped"]:
        session["deviation_score"] = round(
            min(session["deviation_score"] + 0.05, 1.0), 3
        )

    # ── Step 3 — Rule engine ──────────────────────────────────────────────────
    rules = run_rule_engine(
        api_calls        = api_calls,
        hour             = hour,
        calls_per_minute = calls_per_minute,
        baseline         = baseline
    )

    # If intent was clamped (user lied / exceeded role), add a WARN flag
    if role_check["clamped"]:
        rules["flags"].append(
            f"INTENT_CLAMPED: declared '{declared_intent}' "
            f"but role '{user_role}' only permits '{effective_intent}'"
        )
        rules["flag_count"] += 1
        if rules["rule_decision"] == "MAINTAIN":
            rules["rule_decision"] = "WARN"

    # ── Step 4 — Combine decisions ────────────────────────────────────────────
    final_decision      = combine_decisions(session["decision"], rules["rule_decision"])
    session["decision"] = final_decision

    # ── Step 5 — Explanation ──────────────────────────────────────────────────
    explanation = generate_explanation(session, rules)

    # ── Step 6 — Save to audit log ────────────────────────────────────────────
    conn = get_connection()
    conn.execute("""
        INSERT INTO sessions
        (user_id, role, declared_intent, intent_category, original_intent,
         intent_clamped, intent_confidence, honeypot_hit,
         api_calls, hour_of_access, deviation_score, decision,
         explanation, risk_level)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        session["user_id"],
        user_role,
        session["declared_intent"],
        session["intent_category"],
        declared_intent,
        1 if role_check["clamped"] else 0,
        confidence_result["confidence"],
        0,
        json.dumps(session["api_calls"]),
        session["hour"],
        session["deviation_score"],
        final_decision,
        explanation["explanation"],
        explanation["risk_level"],
    ))
    conn.commit()
    conn.close()

    # ── Step 7 — Update baseline ──────────────────────────────────────────────
    update_baseline(
        user_id          = user_id,
        total_calls      = session["total_calls"],
        hour             = session["hour"],
        calls_per_minute = calls_per_minute,
        role             = user_role,
    )

    return {
        "session":       session,
        "rules":         rules,
        "explanation":   explanation,
        "decision":      final_decision,
        "baseline_used": baseline,
        "honeypot":      honeypot_result,
        "role_check":    role_check,
        "confidence":    confidence_result,
    }


if __name__ == "__main__":
    init_db()

    scenarios = [
        ("SCENARIO 1 — Normal User",           {**scenario_normal(),    "role": "finance_staff"}),
        ("SCENARIO 2 — Suspicious User ★",     {**scenario_suspicious(), "role": "junior_analyst"}),
        ("SCENARIO 3 — Attacker",              {**scenario_attacker(),  "role": "junior_analyst"}),
        ("SCENARIO 4 — Role Clamp (exec→admin)",{
            "user_id": "user_exec", "role": "executive",
            "declared_intent": "System administration tasks",
            "api_calls": ["/admin", "/user_lookup", "/logs"],
            "hour": 10, "calls_per_minute": 5
        }),
        ("SCENARIO 5 — Honeypot Hit", {
            "user_id": "user_hp", "role": "junior_analyst",
            "declared_intent": "Read access only",
            "api_calls": ["/read_data", "/shadow_export", "/read_data"],
            "hour": 14, "calls_per_minute": 8
        }),
    ]

    for name, data in scenarios:
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")
        result = run_pipeline(data)

        s  = result["session"]
        e  = result["explanation"]
        r  = result["rules"]
        rc = result["role_check"]
        c  = result["confidence"]

        if rc:
            print(f"  Role               : {data.get('role')}  →  intent '{rc['original_intent']}'", end="")
            if rc["clamped"]:
                print(f"  ⚠ CLAMPED to '{rc['resolved_intent']}'")
            else:
                print(f"  ✓ permitted")

        if c:
            flag = "  ⚠ LOW CONFIDENCE" if c["low_confidence"] else ""
            print(f"  Intent Confidence  : {c['confidence']:.2f}{flag}")

        print(f"  Deviation Score    : {s['deviation_score']}")
        print(f"  Rule Flags         : {r['flags']}")
        print(f"  FINAL DECISION     : {result['decision']}")
        print(f"  Risk Level         : {e['risk_level']}")
        print(f"  Explanation        : {e['explanation']}")
