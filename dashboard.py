import streamlit as st
import sqlite3
import json
import pandas as pd
from main import run_pipeline, init_db
from synthetic_data import scenario_normal, scenario_suspicious, scenario_attacker

init_db()

st.set_page_config(page_title="Intent-Aware ZTA", layout="wide")
st.title("🔐 Intent-Aware Zero Trust Architecture")
st.caption("M.Tech Project — Cybersecurity | Intent Deviation Scoring System")

st.divider()

# ── Scenario runner ───────────────────────────────────────────
st.subheader("Run a Test Scenario")
choice = st.selectbox("Select Scenario", [
    "Normal User",
    "Suspicious User ★ (Critical Test — normal call rate, wrong intent)",
    "Attacker"
])

if st.button("Evaluate Session", type="primary"):
    if choice == "Normal User":
        data = scenario_normal()
    elif "Suspicious" in choice:
        data = scenario_suspicious()
    else:
        data = scenario_attacker()

    result = run_pipeline(data)
    s = result["session"]
    e = result["explanation"]
    r = result["rules"]
    b = result["baseline_used"]

    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Deviation Score", s["deviation_score"])
    col2.metric("Risk Level",      e["risk_level"])
    decision_icon = {"MAINTAIN": "✅", "WARN": "⚠️", "REVOKE": "🚫"}
    col3.metric("Final Decision",
                f"{decision_icon.get(result['decision'],'')} {result['decision']}")
    col4.metric("Baseline Avg Hour", f"{b['avg_hour']}:00")

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Declared Intent**")
        st.info(s["declared_intent"])

        st.markdown("**Intent Category Matched**")
        st.code(s["intent_category"])

        st.markdown("**API Calls Made**")
        st.write(s["api_calls"])

        st.markdown("**Score Factor Breakdown**")
        factors = s["factors"]
        factor_df = pd.DataFrame({
            "Factor": list(factors.keys()),
            "Value":  list(factors.values())
        })
        st.dataframe(factor_df, use_container_width=True, hide_index=True)

    with col_b:
        st.markdown("**Calls Outside Scope**")
        if s["outside_calls"]:
            st.error(str(s["outside_calls"]))
        else:
            st.success("None — all calls within scope ✅")

        st.markdown("**Forbidden Endpoints Hit**")
        if s["forbidden_hits"]:
            st.error(str(s["forbidden_hits"]))
        else:
            st.success("None ✅")

        st.markdown("**Rule Engine Flags**")
        if r["flags"]:
            for flag in r["flags"]:
                st.warning(flag)
        else:
            st.success("No rule violations ✅")

        st.markdown("**Explanation**")
        st.info(e["explanation"])

        st.markdown("**Triggered Signals**")
        st.write(e["triggered_signals"])

st.divider()

# ── Evaluation metrics ────────────────────────────────────────
st.subheader("System Evaluation — 100 Session Simulation")
st.caption("Runs 50 normal + 50 attack sessions and measures detection performance.")

if st.button("Run Full Evaluation", type="secondary"):
    from evaluate import run_evaluation
    with st.spinner("Running 100 simulated sessions..."):
        results, dr, far, acc = run_evaluation(n_normal=50, n_attack=50)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Detection Rate",   f"{dr:.1f}%")
    col2.metric("False Alarm Rate", f"{far:.1f}%")

    precision = results["TP"] / (results["TP"] + results["FP"]) * 100 \
                if (results["TP"] + results["FP"]) else 0
    recall    = results["TP"] / (results["TP"] + results["FN"]) * 100 \
                if (results["TP"] + results["FN"]) else 0

    col3.metric("Precision", f"{precision:.1f}%")
    col4.metric("Recall",    f"{recall:.1f}%")

    st.divider()
    st.markdown("**Confusion Matrix**")
    cm = pd.DataFrame({
        "":               ["Predicted THREAT", "Predicted NORMAL"],
        "Actual THREAT":  [results["TP"],      results["FN"]],
        "Actual NORMAL":  [results["FP"],      results["TN"]]
    }).set_index("")
    st.dataframe(cm, use_container_width=True)

    st.caption(
        "Detection Rate = attacks correctly flagged. "
        "False Alarm Rate = normal users wrongly blocked. "
        "Precision = of all flagged, how many were real threats. "
        "Recall = of all real threats, how many were caught."
    )

st.divider()

# ── Audit log ─────────────────────────────────────────────────
st.subheader("Audit Log — All Sessions")
conn = sqlite3.connect("data/sessions.db", check_same_thread=False)
df   = pd.read_sql_query("""
    SELECT user_id, declared_intent, deviation_score,
           risk_level, decision, explanation, timestamp
    FROM sessions
    ORDER BY timestamp DESC
""", conn)
conn.close()

if df.empty:
    st.info("No sessions yet. Run a scenario above.")
else:
    def highlight(val):
        if val == "MAINTAIN": return "background-color:#d4edda"
        if val == "WARN":     return "background-color:#fff3cd"
        if val == "REVOKE":   return "background-color:#f8d7da"
        return ""
    st.dataframe(
        df.style.map(highlight, subset=["decision"]),
        use_container_width=True
    )
