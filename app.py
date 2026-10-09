"""AgentWatch dashboard.  Run `python -m agentwatch.demo` first, then `streamlit run app.py`."""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from agentwatch.hunt import ATTACKS, hunt
from agentwatch.store import Store

st.set_page_config(page_title="AgentWatch", layout="wide")
REPORT = Path("reports/latest.json")
if not REPORT.exists():
    st.error("No report yet. Run: python -m agentwatch.demo")
    st.stop()
r = json.loads(REPORT.read_text())


@st.cache_resource
def store():
    return Store()


st.title("AgentWatch")
st.caption(f"SOC for AI agents · backend: {r['backend']} · triage model: {r['llm']}")

c = st.columns(5)
c[0].metric("Events scanned", f"{r['rows']:,}")
c[1].metric("Detections run", len(r["detections"]))
c[2].metric("Total detection time", f"{sum(d['ms'] for d in r['detections']):.0f} ms")
c[3].metric("Detect to contain", f"{r['pipeline_s']} s")
c[4].metric("Contained", "Yes" if r["verify"]["contained"] else "No")

st.subheader("Detections")
st.dataframe(pd.DataFrame(r["detections"]), hide_index=True, width="stretch")

inc = r["incident"]
st.subheader(f"Incident: {inc['agent_id']} · {inc['severity'].upper()}")
left, right = st.columns([3, 2])
with left:
    st.markdown("**Attack timeline**")
    tl = pd.DataFrame(r["timeline"])
    st.dataframe(tl[["ts", "action_type", "target", "dest_host", "bytes_out", "token_scope",
                     "outcome"]], hide_index=True, width="stretch")
    lure = next((e for e in r["timeline"] if e["content_snippet"]), None)
    if lure:
        st.markdown("**Injected content the agent ingested (untrusted)**")
        st.code(lure["content_snippet"], language=None)
with right:
    st.markdown("**AI triage**")
    st.text(r["triage"])
    st.markdown("**Automated containment**")
    st.dataframe(pd.DataFrame(r["controls"])[["control", "scope", "reason"]], hide_index=True)
    v = r["verify"]
    st.success(f"Verified: {v['denied_after']} retry attempts denied, {v['allowed_after']} allowed")

st.subheader("Hunt guardrail vs hostile LLM output")
st.dataframe(pd.DataFrame(r["guardrail"]), hide_index=True, width="stretch")

st.subheader("Ask a hunting question")
q = st.text_input("Question", "Which agents used admin tokens?")
if st.button("Hunt"):
    h = hunt(store(), q)
    st.code(h.sql, language="sql")
    if h.blocked:
        st.error(f"Blocked by guardrail {h.blocked.layer}: {h.blocked.reason}")
    else:
        st.caption(f"{len(h.rows)} rows in {h.elapsed_ms:.0f} ms")
        st.dataframe(pd.DataFrame(h.rows), hide_index=True)
with st.expander("Try a hostile query"):
    name = st.selectbox("Attack", list(ATTACKS))
    st.code(ATTACKS[name], language="sql")
