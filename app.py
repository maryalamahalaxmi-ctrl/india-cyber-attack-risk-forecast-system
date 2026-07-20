"""
India Cyber Attack Risk Forecast System
=========================================
Main entry point. Handles authentication, global session state, sidebar
navigation, and the Home / Overview SOC dashboard.

NOTE: This is an educational / final-year-project simulation. All threat,
CTI, SIEM, and log data is synthetically generated for demonstration
purposes and does not reflect real-world attack activity.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from utils.data_generator import generate_dataset, get_latest_snapshot, ALL_REGIONS
from utils.ml_models import (
    train_or_load_risk_model, train_or_load_anomaly_model,
    detect_anomalies, forecast_timeline_probabilities
)
from utils.ui_components import load_css, kpi_card, risk_badge_html, glass_card_open, glass_card_close

st.set_page_config(
    page_title="India Cyber Attack Risk Forecast System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

load_css()

# ----------------------------------------------------------------------------
# Session state defaults
# ----------------------------------------------------------------------------
defaults = {
    "authenticated": False, "username": None, "role": "Viewer",
    "dark_mode": True, "refresh_interval": 30, "notifications": True,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

DEMO_USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "analyst": {"password": "analyst123", "role": "Analyst"},
    "viewer": {"password": "viewer123", "role": "Viewer"},
}


def login_screen():
    st.markdown("<h1 style='text-align:center;'>🛡️ India Cyber Attack Risk Forecast System</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#9fb8d9;'>AI-Powered Security Operations Center — Demo / Educational Project</p>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        glass_card_open("🔐 SOC Login")
        username = st.text_input("Username", placeholder="admin / analyst / viewer")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        st.caption("Demo credentials — admin/admin123, analyst/analyst123, viewer/viewer123")
        if st.button("Login", use_container_width=True):
            user = DEMO_USERS.get(username)
            if user and user["password"] == password:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = user["role"]
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")
        glass_card_close()


def sidebar_nav():
    with st.sidebar:
        st.markdown("### 🛡️ SOC Console")
        st.markdown(f"**User:** {st.session_state.username}  \n**Role:** `{st.session_state.role}`")
        st.markdown("---")
        st.caption("Use the pages menu above ⬆️ to navigate to Threat Intel, SIEM, Real-Time Monitoring, India Map, Analytics, Threat Hunting, Reports, and Settings.")
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.rerun()


@st.cache_data(show_spinner=True)
def load_data():
    return generate_dataset(days=180)


@st.cache_resource(show_spinner=True)
def load_models(df):
    risk_model, le, acc = train_or_load_risk_model(df)
    anomaly_model = train_or_load_anomaly_model(df)
    return risk_model, le, acc, anomaly_model


def home_dashboard():
    df = load_data()
    risk_model, le, acc, anomaly_model = load_models(df)
    snapshot = get_latest_snapshot(df)

    st.markdown("## 🇮🇳 National Cyber Risk Overview")
    st.caption(f"Last updated: {snapshot['Date'].max()} • Simulated data across {len(ALL_REGIONS)} States & UTs")

    # ---- KPI Row ----
    total_attacks = int(snapshot["Total_Attacks"].sum())
    avg_severity = snapshot["Threat_Severity"].mean()
    critical_states = int((snapshot["Risk_Level"] == "Critical").sum())
    high_states = int((snapshot["Risk_Level"] == "High").sum())

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: kpi_card("Total Attacks Today", f"{total_attacks:,}", icon="⚔️")
    with c2: kpi_card("Avg Threat Severity", f"{avg_severity:.1f}/100", icon="🔥")
    with c3: kpi_card("Critical Regions", critical_states, icon="🚨")
    with c4: kpi_card("High-Risk Regions", high_states, icon="⚠️")
    with c5: kpi_card("Model Accuracy", f"{acc*100:.1f}%" if acc else "cached", icon="🤖")

    st.markdown("---")

    col_left, col_right = st.columns([1.4, 1])

    with col_left:
        glass_card_open("📈 30-Day National Attack Trend")
        trend_df = df.groupby("Date")["Total_Attacks"].sum().reset_index().tail(30)
        fig = px.area(trend_df, x="Date", y="Total_Attacks",
                      color_discrete_sequence=["#00d9ff"])
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e6f1ff", margin=dict(l=10, r=10, t=10, b=10), height=320
        )
        st.plotly_chart(fig, use_container_width=True)
        glass_card_close()

        glass_card_open("🗺️ Risk Level Distribution")
        risk_counts = snapshot["Risk_Level"].value_counts().reindex(
            ["Low", "Medium", "High", "Critical"]).fillna(0)
        colors = {"Low": "#00e676", "Medium": "#ffd600", "High": "#ff9100", "Critical": "#ff1744"}
        fig2 = go.Figure(go.Bar(
            x=risk_counts.index, y=risk_counts.values,
            marker_color=[colors[i] for i in risk_counts.index]
        ))
        fig2.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e6f1ff", margin=dict(l=10, r=10, t=10, b=10), height=280
        )
        st.plotly_chart(fig2, use_container_width=True)
        glass_card_close()

    with col_right:
        glass_card_open("🔮 AI Threat Prediction Timeline")
        timeline = forecast_timeline_probabilities(avg_severity)
        for horizon, prob in timeline.items():
            st.markdown(f"**{horizon}**")
            st.progress(min(int(prob), 100) / 100, text=f"{prob}% attack probability")
        glass_card_close()

        glass_card_open("🚨 Top 5 Highest-Risk Regions")
        top5 = snapshot.sort_values("Threat_Severity", ascending=False).head(5)
        for _, row in top5.iterrows():
            st.markdown(
                f"**{row['State']}** — {risk_badge_html(row['Risk_Level'])} "
                f"&nbsp; Severity: {row['Threat_Severity']:.0f}",
                unsafe_allow_html=True
            )
        glass_card_close()

        glass_card_open("🧪 Anomaly Snapshot")
        anomaly_df = detect_anomalies(anomaly_model, snapshot)
        n_anomalies = int((anomaly_df["Anomaly"] == "Suspicious").sum())
        st.metric("Suspicious Regions Detected", n_anomalies)
        if n_anomalies > 0:
            st.dataframe(
                anomaly_df[anomaly_df["Anomaly"] == "Suspicious"][["State", "Threat_Severity", "Anomaly_Score"]]
                .sort_values("Anomaly_Score").reset_index(drop=True),
                use_container_width=True, height=150
            )
        glass_card_close()

    st.info("Navigate using the sidebar page menu for Threat Intelligence, SIEM, Real-Time Monitoring, the Interactive India Cyber Map, Analytics, Threat Hunting, and Reports.", icon="🧭")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
if not st.session_state.authenticated:
    login_screen()
else:
    sidebar_nav()
    st.title("🛡️ India Cyber Attack Risk Forecast System")
    st.caption("AI-Powered SOC Dashboard • CTI + SIEM + ML Predictive Analytics (Simulated Data)")
    home_dashboard()
