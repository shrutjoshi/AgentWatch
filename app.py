"""AgentWatch dashboard.  Run `python -m agentwatch.demo` first, then `streamlit run app.py`.

Top: the incident report page (same design as docs/index.html), rendered from the latest run.
Bottom: live threat hunting against ClickHouse, which the static page cannot do.
"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from agentwatch.hunt import hunt
from agentwatch.site import render
from agentwatch.store import Store

st.set_page_config(page_title="AgentWatch", layout="wide")
st.markdown("<style>.block-container{padding-top:1rem;max-width:1240px}</style>", unsafe_allow_html=True)

REPORT = Path("reports/latest.json")
if not REPORT.exists():
    st.error("No report yet. Run: python -m agentwatch.demo")
    st.stop()
report = json.loads(REPORT.read_text())


@st.cache_resource
def store():
    return Store()


components.html(render(report), height=3600, scrolling=True)

st.divider()
st.subheader("Live hunt against ClickHouse")
st.caption("Ask a question in plain English. Generated SQL passes the guardrail before it runs.")
q = st.text_input("Question", "Which agents used admin tokens?")
if st.button("Hunt", type="primary"):
    h = hunt(store(), q)
    st.code(h.sql, language="sql")
    if h.blocked:
        st.error(f"Blocked by guardrail {h.blocked.layer}: {h.blocked.reason}")
    else:
        st.caption(f"{len(h.rows)} rows in {h.elapsed_ms:.0f} ms")
        st.dataframe(pd.DataFrame(h.rows), hide_index=True)
