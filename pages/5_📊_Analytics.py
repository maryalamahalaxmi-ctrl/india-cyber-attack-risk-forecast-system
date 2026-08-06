import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from utils.data_generator import generate_dataset, get_latest_snapshot
from utils.ml_models import train_or_load_risk_model, get_feature_importance
from utils.ui_components import load_css, glass_card_open, glass_card_close

st.set_page_config(page_title="Analytics", page_icon="📊", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("📊 Advanced Analytics Dashboard")
st.caption("Trends, comparisons, and model explainability across the national dataset")

df = generate_dataset(days=180)
snapshot = get_latest_snapshot(df)
risk_model, le, _ = train_or_load_risk_model(df)

tab1, tab2, tab3, tab4 = st.tabs(["📈 Trends", "🗺️ State Comparison", "🧩 Distribution & Severity", "🤖 Model Insights"])

with tab1:
    col1, col2 = st.columns(2)
    with col1:
        glass_card_open("Monthly Cyber Attack Trend")
        monthly = df.copy()
        monthly["Month"] = pd.to_datetime(monthly["Date"]).dt.to_period("M").astype(str)
        monthly_trend = monthly.groupby("Month")["Total_Attacks"].sum().reset_index()
        fig = px.line(monthly_trend, x="Month", y="Total_Attacks", markers=True,
                      color_discrete_sequence=["#00d9ff"])
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#e6f1ff", height=340)
        st.plotly_chart(fig, use_container_width=True)
        glass_card_close()
    with col2:
        glass_card_open("Risk Forecast Trend (30-Day Avg Severity)")
        sev_trend = df.groupby("Date")["Threat_Severity"].mean().reset_index().tail(30)
        fig2 = px.area(sev_trend, x="Date", y="Threat_Severity", color_discrete_sequence=["#8a2be2"])
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#e6f1ff", height=340)
        st.plotly_chart(fig2, use_container_width=True)
        glass_card_close()

    glass_card_open("Incident Timeline (Daily Total Attacks — Last 60 Days)")
    inc_df = df.groupby("Date")["Total_Attacks"].sum().reset_index().tail(60)
    fig3 = px.bar(inc_df, x="Date", y="Total_Attacks", color="Total_Attacks",
                  color_continuous_scale="Plasma")
    fig3.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=320)
    st.plotly_chart(fig3, use_container_width=True)
    glass_card_close()

with tab2:
    glass_card_open("State-wise Threat Severity Comparison")
    state_cmp = snapshot.sort_values("Threat_Severity", ascending=False)
    fig4 = px.bar(state_cmp, x="State", y="Threat_Severity", color="Risk_Level",
                  color_discrete_map={"Low": "#00e676", "Medium": "#ffd600", "High": "#ff9100", "Critical": "#ff1744"})
    fig4.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=480, xaxis_tickangle=-60)
    st.plotly_chart(fig4, use_container_width=True)
    glass_card_close()

    glass_card_open("Vulnerability Score Distribution by State")
    fig5 = px.box(df, x="State", y="Vulnerability_Score", color_discrete_sequence=["#00ffe5"])
    fig5.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=420, xaxis_tickangle=-60)
    st.plotly_chart(fig5, use_container_width=True)
    glass_card_close()

with tab3:
    col3, col4 = st.columns(2)
    with col3:
        glass_card_open("Attack Category Distribution (National)")
        cat_totals = {
            "Malware": df["Malware"].sum(), "Phishing": df["Phishing"].sum(),
            "DDoS": df["DDoS"].sum(), "Ransomware": df["Ransomware"].sum(),
            "SQL Injection": df["SQL_Injection"].sum(), "Brute Force": df["Brute_Force"].sum(),
            "Insider Threat": df["Insider_Threat"].sum(), "Botnet": df["Botnet"].sum(),
            "Zero-Day": df["Zero_Day"].sum(), "XSS": df["XSS"].sum(),
        }
        fig6 = px.pie(names=list(cat_totals.keys()), values=list(cat_totals.values()), hole=0.45,
                      color_discrete_sequence=px.colors.sequential.Tealgrn)
        fig6.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e6f1ff", height=400)
        st.plotly_chart(fig6, use_container_width=True)
        glass_card_close()
    with col4:
        glass_card_open("Security Score Gauge (National Avg)")
        security_score = 100 - snapshot["Threat_Severity"].mean()
        fig7 = go.Figure(go.Indicator(
            mode="gauge+number", value=security_score,
            title={"text": "Overall Security Posture"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#00d9ff"}}
        ))
        fig7.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e6f1ff", height=400)
        st.plotly_chart(fig7, use_container_width=True)
        glass_card_close()

    glass_card_open("Threat Severity Heatmap (State x Day, Last 21 Days)")
    heat_df = df[df["Date"] >= df["Date"].max() - pd.Timedelta(days=21)]
    pivot = heat_df.pivot_table(index="State", columns="Date", values="Threat_Severity", aggfunc="mean")
    fig8 = px.imshow(pivot, aspect="auto", color_continuous_scale="Inferno")
    fig8.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e6f1ff", height=650)
    st.plotly_chart(fig8, use_container_width=True)
    glass_card_close()

with tab4:
    col5, col6 = st.columns(2)
    with col5:
        glass_card_open("🤖 AI Model Feature Importance")
        fi_df = get_feature_importance(risk_model)
        fig9 = px.bar(fi_df, x="Importance", y="Feature", orientation="h",
                      color="Importance", color_continuous_scale="Viridis")
        fig9.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#e6f1ff", height=480, yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig9, use_container_width=True)
        glass_card_close()
    with col6:
        glass_card_open("🏆 SOC Performance Dashboard")
        soc_metrics = pd.DataFrame({
            "Metric": ["Mean Time to Detect (min)", "Mean Time to Respond (min)",
                       "Incidents Auto-Contained (%)", "False Positive Rate (%)", "Analyst Workload Index"],
            "Value": [12.4, 27.8, 68.5, 8.2, 63.0]
        })
        fig10 = px.bar(soc_metrics, x="Value", y="Metric", orientation="h",
                       color="Value", color_continuous_scale="Blues")
        fig10.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#e6f1ff", height=480)
        st.plotly_chart(fig10, use_container_width=True)
        glass_card_close()

st.caption("⚠️ All charts are generated from a synthetic dataset for demonstration purposes.")
