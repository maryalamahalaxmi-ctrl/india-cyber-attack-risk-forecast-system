import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
import time

from utils.ui_components import load_css, glass_card_open, glass_card_close, kpi_card

st.set_page_config(page_title="Real-Time Monitoring", page_icon="📡", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("📡 Real-Time Security Monitoring")
st.caption("Live simulated telemetry — refresh the page or click 'Refresh Now' to sample new values")

if st.button("🔄 Refresh Now"):
    st.rerun()

seed = int(time.time() // 5)  # changes every 5 seconds if page reruns
rng = np.random.default_rng(seed)

c1, c2, c3, c4 = st.columns(4)
with c1: kpi_card("CPU Usage", f"{rng.integers(20, 95)}%", icon="🧮")
with c2: kpi_card("Memory Usage", f"{rng.integers(30, 90)}%", icon="💾")
with c3: kpi_card("Network Traffic", f"{rng.integers(200, 4500)} Mbps", icon="🌐")
with c4: kpi_card("Active Devices", rng.integers(500, 5000), icon="💻")

c5, c6, c7, c8 = st.columns(4)
with c5: kpi_card("Connected Users", rng.integers(1000, 20000), icon="👥")
with c6: kpi_card("Failed Logins", rng.integers(0, 120), icon="🔑")
with c7: kpi_card("Suspicious Logins", rng.integers(0, 25), icon="🕵️")
with c8: kpi_card("Open Ports", rng.integers(5, 45), icon="🔌")

st.markdown("---")

col1, col2 = st.columns(2)
with col1:
    glass_card_open("🦠 Malware & Phishing Detection (Live Feed)")
    minutes = pd.date_range(end=datetime.now(), periods=30, freq="min")
    malware = rng.poisson(2, 30)
    phishing = rng.poisson(3, 30)
    live_df = pd.DataFrame({"Time": minutes, "Malware": malware, "Phishing": phishing})
    fig = px.line(live_df, x="Time", y=["Malware", "Phishing"],
                  color_discrete_sequence=["#ff1744", "#ffd600"])
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=320, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
    glass_card_close()

    glass_card_open("💣 DDoS & Ransomware Monitoring")
    ddos = rng.poisson(1.5, 30)
    ransomware = rng.poisson(0.4, 30)
    ddos_df = pd.DataFrame({"Time": minutes, "DDoS Attempts": ddos, "Ransomware Signals": ransomware})
    fig2 = px.bar(ddos_df, x="Time", y=["DDoS Attempts", "Ransomware Signals"],
                  color_discrete_sequence=["#00d9ff", "#8a2be2"], barmode="overlay")
    fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                        font_color="#e6f1ff", height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig2, use_container_width=True)
    glass_card_close()

with col2:
    glass_card_open("🚨 Live Security Alerts")
    alert_pool = [
        "Multiple failed SSH login attempts detected",
        "Outbound connection to flagged IP range blocked",
        "Unusual spike in DNS queries observed",
        "New device joined internal network segment",
        "Firewall rule triggered on port 445",
        "Endpoint flagged for signature-based malware match",
        "Abnormal data transfer volume from finance subnet",
        "Suspicious PowerShell execution chain detected",
    ]
    n_alerts = rng.integers(4, 8)
    chosen = rng.choice(alert_pool, size=n_alerts, replace=False)
    severities = rng.choice(["Low", "Medium", "High", "Critical"], size=n_alerts, p=[0.35,0.35,0.2,0.1])
    sev_icon = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}
    for alert, sev in zip(chosen, severities):
        t = (datetime.now() - timedelta(seconds=int(rng.integers(5, 900)))).strftime("%H:%M:%S")
        st.markdown(f"{sev_icon[sev]} **[{sev}]** {alert}  \n<span style='color:#9fb8d9;font-size:12px;'>{t}</span>", unsafe_allow_html=True)
        st.markdown("<hr style='margin:6px 0;'>", unsafe_allow_html=True)
    glass_card_close()

st.caption("⚠️ This module simulates live telemetry for demo purposes. No real network or system data is being read.")
st.info("Tip: Streamlit's `st_autorefresh` component (or a simple loop with `time.sleep` + `st.rerun`) can be added to auto-refresh this page on an interval — see Settings for the configurable refresh interval.", icon="💡")
