import streamlit as st
import pandas as pd

from utils.data_generator import generate_dataset, ALL_REGIONS
from utils.threat_intel import generate_ioc_feed, CVE_SAMPLES
from utils.ui_components import load_css, glass_card_open, glass_card_close

st.set_page_config(page_title="Threat Hunting", page_icon="🕵️", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("🕵️ Threat Hunting Module")
st.caption("Search and pivot across simulated attack records, IOCs, and CVEs")

df = generate_dataset(days=180)
ioc_df = generate_ioc_feed(n=60)
cve_df = pd.DataFrame(CVE_SAMPLES)

tabs = st.tabs(["🌐 By IP", "🧨 By Threat Type", "📍 By State", "🔥 By Severity", "🧬 IOC Search", "🛠️ CVE Search"])

with tabs[0]:
    glass_card_open("Search Attack Records by IP (via IOC feed)")
    ip_query = st.text_input("Enter partial or full IP address", key="ip_search")
    ip_records = ioc_df[ioc_df["IOC Type"] == "IP Address"]
    if ip_query:
        ip_records = ip_records[ip_records["Value"].str.contains(ip_query)]
    st.dataframe(ip_records, use_container_width=True, hide_index=True)
    glass_card_close()

with tabs[1]:
    glass_card_open("Search by Threat / Attack Type")
    threat_type = st.selectbox("Select attack type", sorted(ioc_df["Threat"].unique()))
    st.dataframe(ioc_df[ioc_df["Threat"] == threat_type], use_container_width=True, hide_index=True)

    st.markdown("**Matching attack volume from dataset:**")
    col_map = {
        "Malware": "Malware", "Phishing": "Phishing", "DDoS": "DDoS", "Ransomware": "Ransomware",
        "SQL Injection": "SQL_Injection", "Brute Force": "Brute_Force", "Insider Threat": "Insider_Threat",
        "Botnet": "Botnet", "Zero-Day": "Zero_Day", "XSS": "XSS",
    }
    if threat_type in col_map:
        col = col_map[threat_type]
        agg = df.groupby("State")[col].sum().sort_values(ascending=False).reset_index()
        st.dataframe(agg, use_container_width=True, hide_index=True, height=250)
    glass_card_close()

with tabs[2]:
    glass_card_open("Search by State / Union Territory")
    state_query = st.selectbox("Select region", sorted(ALL_REGIONS))
    state_data = df[df["State"] == state_query].sort_values("Date", ascending=False)
    st.dataframe(state_data, use_container_width=True, hide_index=True, height=400)
    glass_card_close()

with tabs[3]:
    glass_card_open("Search by Severity / Risk Level")
    severity_query = st.select_slider("Minimum threat severity", options=list(range(0, 101, 5)), value=50)
    filtered = df[df["Threat_Severity"] >= severity_query].sort_values("Threat_Severity", ascending=False)
    st.write(f"Found **{len(filtered)}** matching records")
    st.dataframe(filtered.head(200), use_container_width=True, hide_index=True, height=400)
    glass_card_close()

with tabs[4]:
    glass_card_open("IOC Search")
    ioc_query = st.text_input("Search IOC value / type / threat category")
    results = ioc_df
    if ioc_query:
        mask = ioc_df.apply(lambda r: ioc_query.lower() in str(r.values).lower(), axis=1)
        results = ioc_df[mask]
    st.dataframe(results, use_container_width=True, hide_index=True, height=400)
    glass_card_close()

with tabs[5]:
    glass_card_open("CVE Search")
    cve_query = st.text_input("Search CVE ID / product")
    results_cve = cve_df
    if cve_query:
        mask = cve_df.apply(lambda r: cve_query.lower() in str(r.values).lower(), axis=1)
        results_cve = cve_df[mask]
    st.dataframe(results_cve, use_container_width=True, hide_index=True)
    glass_card_close()

st.caption("⚠️ All records searched here are part of the synthetic demo dataset.")
