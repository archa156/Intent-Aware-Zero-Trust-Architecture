"""
role_access.py  —  Role-Based Intent Restriction + Honeypot Endpoints
======================================================================

Two jobs in one file:

  1. ROLE-BASED INTENT RESTRICTION
     Each role has a whitelist of intents it is allowed to declare.
     If a user claims an intent outside their role's whitelist, the
     system clamps it down to the most restrictive intent that role
     IS allowed — rather than trusting the user's claim at face value.
     This means even a sophisticated insider who knows your system
     cannot claim a broader intent than their role permits.

  2. HONEYPOT ENDPOINTS
     These are fake API endpoints that NO legitimate workflow would
     ever call.  The moment any session touches one, it is an instant
     REVOKE — no score calculation, no threshold, just hard block.
     They are added to the forbidden list of every intent category
     automatically at pipeline startup.

  3. INTENT CONFIDENCE SCORING
     resolve_intent() now also returns a confidence value (0.0–1.0)
     based on the gap between the top-scoring intent and the runner-up.
     A low-confidence match is a risk signal in its own right.
"""

# ── 1. Role → Permitted intents ───────────────────────────────────────────────
# Every role gets the minimum set of intents it genuinely needs.
# Roles cannot declare anything outside this list.

ROLE_INTENT_PERMISSIONS: dict[str, list[str]] = {
    "junior_analyst":    [
        "read_access_only", "data_analytics", "reporting_only"
    ],
    "senior_analyst":    [
        "read_access_only", "data_analytics", "reporting_only",
        "finance_report_generation", "audit_access"
    ],
    "it_admin":          [
        "system_administration", "debugging_logs",
        "routine_check", "security_monitoring"
    ],
    "hr_staff":          [
        "user_management", "onboarding_operations", "read_access_only"
    ],
    "compliance_officer": [
        "compliance_review", "audit_access",
        "data_export_compliance", "reporting_only"
    ],
    "security_analyst":  [
        "incident_response", "security_monitoring",
        "audit_access", "debugging_logs"
    ],
    "finance_staff":     [
        "finance_report_generation", "billing_operations",
        "reporting_only", "read_access_only"
    ],
    "executive":         [
        "reporting_only", "read_access_only"
    ],
    "data_engineer":     [
        "data_analytics", "data_export_compliance",
        "debugging_logs", "read_access_only"
    ],
    "support_agent":     [
        "read_access_only", "user_management", "routine_check"
    ],
}

# Fallback role for unknown / missing role values
_DEFAULT_ROLE = "junior_analyst"
_FALLBACK_INTENT = "read_access_only"   # most restrictive


def enforce_role_intent(declared_intent: str, user_role: str) -> dict:
    """
    Checks whether a user's declared intent is permitted for their role.

    Returns
    -------
    {
      "resolved_intent"  : str   — the intent the system will actually use,
      "original_intent"  : str   — what the user declared,
      "role"             : str   — the user's role,
      "permitted"        : bool  — True if intent was within role's whitelist,
      "clamped"          : bool  — True if intent was downgraded,
      "clamp_reason"     : str | None
    }

    Examples
    --------
    junior_analyst claims "incident_response"
      → clamped to "read_access_only", clamped=True

    it_admin claims "system_administration"
      → permitted as-is, clamped=False
    """
    role       = user_role.lower().strip() if user_role else _DEFAULT_ROLE
    permitted  = ROLE_INTENT_PERMISSIONS.get(role, ROLE_INTENT_PERMISSIONS[_DEFAULT_ROLE])

    if declared_intent in permitted:
        return {
            "resolved_intent": declared_intent,
            "original_intent": declared_intent,
            "role":            role,
            "permitted":       True,
            "clamped":         False,
            "clamp_reason":    None,
        }

    # Intent not in the role's whitelist — clamp to fallback
    reason = (
        f"Role '{role}' is not permitted to declare '{declared_intent}'. "
        f"Clamped to '{_FALLBACK_INTENT}'. "
        f"Permitted intents for this role: {permitted}"
    )
    return {
        "resolved_intent": _FALLBACK_INTENT,
        "original_intent": declared_intent,
        "role":            role,
        "permitted":       False,
        "clamped":         True,
        "clamp_reason":    reason,
    }


# ── 2. Honeypot endpoints ─────────────────────────────────────────────────────
# No legitimate workflow ever calls these.
# First hit → instant REVOKE, regardless of score.

HONEYPOT_ENDPOINTS: list[str] = [
    "/internal_bulk_transfer",
    "/shadow_export",
    "/debug_override",
    "/root_access",
    "/drop_table",
    "/bypass_auth",
    "/raw_db_dump",
]


def check_honeypots(api_calls: list[str]) -> dict:
    """
    Scans a session's API calls for honeypot endpoint access.

    Returns
    -------
    {
      "triggered"      : bool,
      "hits"           : list[str],   — which honeypots were called
      "instant_revoke" : bool,
      "reason"         : str | None
    }
    """
    hits = [c for c in api_calls if c in HONEYPOT_ENDPOINTS]
    if hits:
        return {
            "triggered":      True,
            "hits":           hits,
            "instant_revoke": True,
            "reason": (
                f"Honeypot endpoint(s) accessed: {hits}. "
                "No legitimate intent maps to these endpoints. "
                "Session instantly revoked."
            )
        }
    return {"triggered": False, "hits": [], "instant_revoke": False, "reason": None}


def inject_honeypots_into_intent_map(intent_map: dict) -> dict:
    """
    Adds all honeypot endpoints to the forbidden list of every intent category.
    Call this once at startup — modifies the dict in-place and returns it.
    """
    for category in intent_map:
        existing_forbidden = intent_map[category]["forbidden"]
        for hp in HONEYPOT_ENDPOINTS:
            if hp not in existing_forbidden:
                existing_forbidden.append(hp)
    return intent_map


# ── 3. Intent confidence scoring ─────────────────────────────────────────────

def score_intent_confidence(text: str, intent_keywords: dict) -> dict:
    """
    Runs the full keyword scoring and returns:
      - the winning intent
      - a confidence value 0.0–1.0
      - the full score breakdown

    Confidence formula:
        If only one category scored  → confidence = 1.0 (unambiguous)
        If top score = runner-up     → confidence = 0.0 (total tie, unreliable)
        Otherwise: confidence = (top - runner_up) / top

    A confidence below 0.3 is a weak match and is itself a risk signal.

    Parameters
    ----------
    text            : the user's plain-English intent declaration
    intent_keywords : the INTENT_KEYWORDS dict from intent_map.py
    """
    text_lower = text.lower()
    score_map: dict[str, int] = {}

    for category, keywords in intent_keywords.items():
        for kw in keywords:
            if kw in text_lower:
                score_map[category] = score_map.get(category, 0) + 1

    if not score_map:
        return {
            "intent":     "read_access_only",
            "confidence": 0.0,
            "scores":     {},
            "low_confidence": True,
        }

    sorted_scores = sorted(score_map.items(), key=lambda x: x[1], reverse=True)
    top_intent, top_score = sorted_scores[0]

    if len(sorted_scores) == 1:
        confidence = 1.0
    else:
        runner_up = sorted_scores[1][1]
        confidence = round((top_score - runner_up) / top_score, 3) if top_score > 0 else 0.0

    return {
        "intent":         top_intent,
        "confidence":     confidence,
        "scores":         dict(sorted_scores),
        "low_confidence": confidence < 0.3,
    }


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from intent_map import INTENT_KEYWORDS, INTENT_MAP

    print("\n── Role Enforcement Tests ──────────────────────────────────────")
    role_tests = [
        ("junior_analyst",    "incident_response",         False),
        ("it_admin",          "system_administration",     True),
        ("compliance_officer","compliance_review",         True),
        ("junior_analyst",    "read_access_only",          True),
        ("executive",         "finance_report_generation", False),
        ("security_analyst",  "incident_response",         True),
    ]
    for role, intent, should_permit in role_tests:
        result = enforce_role_intent(intent, role)
        ok = "✅" if result["permitted"] == should_permit else "❌"
        print(f"  {ok}  {role:20s} declares '{intent}' → {result['resolved_intent']}"
              f"  (clamped={result['clamped']})")

    print("\n── Honeypot Tests ──────────────────────────────────────────────")
    hp_tests = [
        (["/read_data", "/summary"],                        False),
        (["/read_data", "/shadow_export"],                  True),
        (["/drop_table", "/root_access", "/read_data"],     True),
        (["/reports", "/export_own"],                       False),
    ]
    for calls, should_trigger in hp_tests:
        result = check_honeypots(calls)
        ok = "✅" if result["triggered"] == should_trigger else "❌"
        print(f"  {ok}  {str(calls):50s} triggered={result['triggered']}")

    print("\n── Confidence Tests ────────────────────────────────────────────")
    conf_tests = [
        "Running monthly finance reports",
        "I need to do something",
        "GDPR compliance review",
        "audit trail investigation of security incident breach",
    ]
    for text in conf_tests:
        r = score_intent_confidence(text, INTENT_KEYWORDS)
        flag = "⚠ LOW" if r["low_confidence"] else "   ok"
        print(f"  {flag}  [{r['confidence']:.2f}]  {text[:45]:<45} → {r['intent']}")

    print("\n── Honeypot injection (adds to every category) ─────────────────")
    inject_honeypots_into_intent_map(INTENT_MAP)
    sample = INTENT_MAP["read_access_only"]["forbidden"]
    print(f"  read_access_only forbidden now includes: {sample}")
