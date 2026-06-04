"""
api.py  —  FastAPI REST layer (updated v2.0)
New: /login endpoint, role validation, honeypot + confidence in responses
"""
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List

from database    import init_db, get_connection, get_baseline, authenticate_user
from main        import run_pipeline
from role_access import ROLE_INTENT_PERMISSIONS, HONEYPOT_ENDPOINTS

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Intent-Aware ZTA API",
    description="ZTA with Intent Deviation Scoring, Role Enforcement, Honeypots",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"],
    allow_methods=["*"], allow_headers=["*"],
)

init_db()
KNOWN_ROLES = list(ROLE_INTENT_PERMISSIONS.keys())


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)


class SessionRequest(BaseModel):
    user_id:          str        = Field(..., min_length=1, max_length=50)
    role:             str        = Field(default="junior_analyst")
    declared_intent:  str        = Field(..., min_length=3, max_length=200)
    api_calls:        List[str]  = Field(..., min_items=1, max_items=500)
    hour:             int        = Field(..., ge=0, le=23)
    calls_per_minute: float      = Field(default=10.0, ge=0, le=1000)

    @validator("api_calls", each_item=True)
    def validate_api_calls(cls, v):
        if not v.startswith("/"):
            raise ValueError(f"Must start with /: {v}")
        return v

    @validator("role")
    def validate_role(cls, v):
        if v not in KNOWN_ROLES:
            raise ValueError(f"Unknown role. Valid: {KNOWN_ROLES}")
        return v


@app.get("/")
def root():
    return {"system": "Intent-Aware ZTA v2.0",
            "docs": "http://127.0.0.1:8000/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/login")
def login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # NOTE: permitted_intents intentionally NOT returned.
    # Exposing allowed intents gives attackers a roadmap to pick a
    # permitted-but-broad intent to evade detection.
    return {
        "success":  True,
        "username": user["username"],
        "name":     user["name"],
        "role":     user["role"],
    }


@app.post("/evaluate-session")
def evaluate_session_endpoint(request: SessionRequest):
    try:
        result = run_pipeline({
            "user_id":          request.user_id,
            "role":             request.role,
            "declared_intent":  request.declared_intent,
            "api_calls":        request.api_calls,
            "hour":             request.hour,
            "calls_per_minute": request.calls_per_minute,
        })
        s  = result["session"]
        e  = result["explanation"]
        r  = result["rules"]
        b  = result["baseline_used"]
        rc = result["role_check"]
        c  = result["confidence"]
        hp = result["honeypot"]

        return {
            "user_id":            s["user_id"],
            "role":               request.role,
            "declared_intent":    request.declared_intent,
            "intent_category":    s["intent_category"],
            "intent_clamped":     rc["clamped"] if rc else False,
            "clamp_reason":       rc["clamp_reason"] if rc else None,
            "intent_confidence":  c["confidence"] if c else 1.0,
            "low_confidence":     c["low_confidence"] if c else False,
            "honeypot_triggered": hp["triggered"],
            "honeypot_hits":      hp["hits"],
            "deviation_score":    s["deviation_score"],
            "factors":            s.get("factors", {}),
            "outside_calls":      s.get("outside_calls", []),
            "forbidden_hits":     s.get("forbidden_hits", []),
            "rule_flags":         r["flags"],
            "final_decision":     result["decision"],
            "risk_level":         e["risk_level"],
            "explanation":        e["explanation"],
            "triggered_signals":  e["triggered_signals"],
            "baseline_used":      b,
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.get("/audit-log")
def get_audit_log(limit: int = 50):
    if not 1 <= limit <= 500:
        raise HTTPException(400, "limit must be 1–500")
    conn = get_connection()
    rows = conn.execute("""
        SELECT user_id, role, declared_intent, intent_category,
               intent_clamped, intent_confidence, honeypot_hit,
               deviation_score, decision, risk_level, explanation, timestamp
        FROM sessions ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return {"total": len(rows), "sessions": [dict(r) for r in rows]}


@app.get("/user-baseline/{user_id}")
def get_user_baseline(user_id: str):
    return {"user_id": user_id, "baseline": get_baseline(user_id)}


# /roles and /honeypots endpoints intentionally removed.
# Exposing the role→intent map or honeypot list would give an attacker
# exactly the information needed to declare a safe intent and avoid traps.
# Admin-only introspection of these should go through a secured back-office
# interface, not the public API.
