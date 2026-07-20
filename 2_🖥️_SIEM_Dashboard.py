import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

from utils.data_generator import generate_dataset, get_latest_snapshot
from utils.ui_components import load_css, glass_card_open, glass_card_close, kpi_card, risk_badge_html

st.set_page_config(page_title="SIEM Dashboard", page_icon="🖥️", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("🖥️ SIEM Dashboard")
st.caption("Security Information & Event Management — simulated log streams & event correlation")

df = generate_dataset(days=180)
snapshot = get_latest_snapshot(df)

rng = np.random.default_rng(int(datetime.now().strftime("%Y%m%d")))

events_per_sec = int(rng.integers(120, 950))
log_sources = ["Authentication", "Firewall", "DNS", "Network Traffic", "Endpoint", "Web Server", "Database"]
log_status = {src: rng.choice(["🟢 Healthy", "🟢 Healthy", "🟡 Degraded"]) for src in log_sources}

c1, c2, c3, c4 = st.columns(4)
with c1: kpi_card("Security Events / sec", events_per_sec, icon="⚡")
with c2: kpi_card("Active Log Sources", f"{len(log_sources)}/7", icon="📡")
with c3: kpi_card("Open Incidents", int(rng.integers(2, 18)), icon="🗂️")
with c4: kpi_card("Correlated Alerts (24h)", int(rng.integers(30, 250)), icon="🔗")

st.markdown("---")

col1, col2 = st.columns([1.3, 1])
with col1:
    glass_card_open("📶 Security Alert Timeline (Last 48 Hours)")
    hours = pd.date_range(end=datetime.now(), periods=48, freq="h")
    alert_counts = rng.poisson(lam=events_per_sec / 40, size=48)
    ts_df = pd.DataFrame({"Time": hours, "Alerts": alert_counts})
    fig = px.line(ts_df, x="Time", y="Alerts", markers=True, color_discrete_sequence=["#00ffe5"])
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=340, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
    glass_card_close()

    glass_card_open("🧩 Event Correlation Engine — Incident Queue")
    incident_types = ["Multiple Failed Logins", "Unusual Outbound Traffic", "Malware Signature Match",
                       "Firewall Policy Violation", "Privilege Escalation Attempt", "DNS Tunneling Suspected"]
    severities = ["Low", "Medium", "High", "Critical"]
    incidents = pd.DataFrame({
        "Incident ID": [f"INC-{1000+i}" for i in range(8)],
        "Type": rng.choice(incident_types, 8),
        "Source": rng.choice(log_sources, 8),
        "Severity": rng.choice(severities, 8, p=[0.35, 0.35, 0.2, 0.1]),
        "Status": rng.choice(["Open", "Investigating", "Contained", "Closed"], 8),
        "Detected": [(datetime.now() - timedelta(minutes=int(m))).strftime("%H:%M:%S") for m in rng.integers(1, 600, 8)],
    })
    def sev_badge(s): return risk_badge_html({"Low":"Low","Medium":"Medium","High":"High","Critical":"Critical"}[s])
    incidents_display = incidents.copy()
    st.dataframe(incidents_display, use_container_width=True, hide_index=True, height=260)
    glass_card_close()

with col2:
    glass_card_open("📋 Log Collection Status")
    for src, status in log_status.items():
        st.markdown(f"**{src}**: {status}")
    glass_card_close()

    glass_card_open("🎯 Threat Score & Incident Severity")
    threat_score = float(snapshot["Threat_Severity"].mean())
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number", value=threat_score,
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#00d9ff"},
            "steps": [
                {"range": [0, 25], "color": "#0d3b24"},
                {"range": [25, 50], "color": "#3b3a0d"},
                {"range": [50, 75], "color": "#3b280d"},
                {"range": [75, 100], "color": "#3b0d0d"},
            ],
        },
        number={"suffix": "/100"},
    ))
    fig_gauge.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e6f1ff",
                             height=260, margin=dict(l=10, r=10, t=30, b=10))
    st.plotly_chart(fig_gauge, use_container_width=True)
    glass_card_close()

    glass_card_open("🔐 Authentication Log Sample")
    auth_df = pd.DataFrame({
        "User": [f"user{rng.integers(100,999)}" for _ in range(6)],
        "Result": rng.choice(["Success", "Success", "Failed"], 6),
        "IP": [".".join(str(rng.integers(1,254)) for _ in range(4)) for _ in range(6)],
        "Time": [(datetime.now() - timedelta(seconds=int(s))).strftime("%H:%M:%S") for s in rng.integers(1, 3600, 6)],
    })
    st.dataframe(auth_df, use_container_width=True, hide_index=True, height=200)
    glass_card_close()

st.caption("⚠️ All SIEM logs, events, and incidents shown are synthetically generated for demonstration purposes.")
