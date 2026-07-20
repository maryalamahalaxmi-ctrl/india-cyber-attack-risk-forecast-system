import streamlit as st
import pandas as pd
import plotly.express as px

from utils.data_generator import generate_dataset, get_latest_snapshot, get_attack_types
from utils.threat_intel import (
    MITRE_MAPPING, MALWARE_FAMILIES, RANSOMWARE_GROUPS, CVE_SAMPLES,
    generate_ioc_feed, threat_severity_score, attack_priority_level
)
from utils.ui_components import load_css, glass_card_open, glass_card_close, kpi_card

st.set_page_config(page_title="Threat Intelligence", page_icon="🔎", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("🔎 Cyber Threat Intelligence Dashboard")
st.caption("Simulated threat feed — malware families, ransomware groups, IOCs & CVEs")

df = generate_dataset(days=180)
snapshot = get_latest_snapshot(df)
attack_types = get_attack_types()

national_counts = {
    "Malware": int(snapshot["Malware"].sum()), "Phishing": int(snapshot["Phishing"].sum()),
    "DDoS": int(snapshot["DDoS"].sum()), "Ransomware": int(snapshot["Ransomware"].sum()),
    "SQL Injection": int(snapshot["SQL_Injection"].sum()), "Brute Force": int(snapshot["Brute_Force"].sum()),
    "Insider Threat": int(snapshot["Insider_Threat"].sum()), "Botnet": int(snapshot["Botnet"].sum()),
    "Zero-Day": int(snapshot["Zero_Day"].sum()), "XSS": int(snapshot["XSS"].sum()),
}
severity = threat_severity_score(national_counts)
priority = attack_priority_level(severity)

c1, c2, c3, c4 = st.columns(4)
with c1: kpi_card("Attack Severity Score", f"{severity:.1f}/100", icon="🔥")
with c2: kpi_card("Attack Priority Level", priority, icon="📌")
with c3: kpi_card("Risk Heat Index", f"{snapshot['Threat_Severity'].mean():.1f}", icon="🌡️")
with c4: kpi_card("Active Threat Categories", len(attack_types), icon="🗂️")

st.markdown("---")

col1, col2 = st.columns([1.3, 1])
with col1:
    glass_card_open("📊 Attack Category Distribution (National, Today)")
    dist_df = pd.DataFrame({"Category": list(national_counts.keys()), "Count": list(national_counts.values())})
    fig = px.bar(dist_df.sort_values("Count", ascending=True), x="Count", y="Category", orientation="h",
                 color="Count", color_continuous_scale="Tealgrn")
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                       font_color="#e6f1ff", height=380, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
    glass_card_close()

with col2:
    glass_card_open("🧭 MITRE ATT&CK Mapping")
    mitre_df = pd.DataFrame([
        {"Attack Category": k, "Tactic": v["tactic"], "Technique": v["technique"]}
        for k, v in MITRE_MAPPING.items()
    ])
    st.dataframe(mitre_df, use_container_width=True, height=380, hide_index=True)
    glass_card_close()

st.markdown("---")

col3, col4 = st.columns(2)
with col3:
    glass_card_open("🦠 Latest Malware Families (Simulated)")
    st.dataframe(pd.DataFrame(MALWARE_FAMILIES), use_container_width=True, hide_index=True)
    glass_card_close()

with col4:
    glass_card_open("💰 Active Ransomware Groups (Simulated)")
    st.dataframe(pd.DataFrame(RANSOMWARE_GROUPS), use_container_width=True, hide_index=True)
    glass_card_close()

col5, col6 = st.columns(2)
with col5:
    glass_card_open("🧬 Indicators of Compromise (IOC) Feed")
    ioc_df = generate_ioc_feed(n=20)
    st.dataframe(ioc_df, use_container_width=True, hide_index=True, height=320)
    glass_card_close()

with col6:
    glass_card_open("🛠️ CVE Vulnerability Watchlist (Simulated)")
    cve_df = pd.DataFrame(CVE_SAMPLES)
    st.dataframe(cve_df, use_container_width=True, hide_index=True, height=320)
    glass_card_close()

st.caption("⚠️ All indicators, malware family names, ransomware groups, and CVE identifiers on this page are simulated for demonstration purposes only.")
