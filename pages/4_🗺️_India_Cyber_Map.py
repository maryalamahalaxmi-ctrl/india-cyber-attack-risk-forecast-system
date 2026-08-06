import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium

from utils.data_generator import generate_dataset, get_latest_snapshot, get_region_coords
from utils.ml_models import train_or_load_risk_model, predict_risk, FEATURE_COLS
from utils.recommendations import generate_recommendations
from utils.ui_components import load_css, glass_card_open, glass_card_close, risk_badge_html

st.set_page_config(page_title="India Cyber Map", page_icon="🗺️", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("🗺️ Interactive India Cyber Risk Map")
st.caption("Click a marker to view detailed risk analysis for that State / Union Territory")

df = generate_dataset(days=180)
snapshot = get_latest_snapshot(df)
coords = get_region_coords()

risk_model, le, _ = train_or_load_risk_model(df)

RISK_COLOR = {"Low": "green", "Medium": "orange", "High": "#ff6f00", "Critical": "red"}
# Using folium's limited palette names where possible; Critical/High get custom via CircleMarker instead.

m = folium.Map(location=[22.9734, 78.6569], zoom_start=5, tiles="CartoDB dark_matter")

for _, row in snapshot.iterrows():
    region = row["State"]
    if region not in coords:
        continue
    lat, lon = coords[region]
    risk = row["Risk_Level"]
    color = {"Low": "#00e676", "Medium": "#ffd600", "High": "#ff9100", "Critical": "#ff1744"}[risk]

    popup_html = f"""
    <div style="font-family:sans-serif;">
    <b>{region}</b><br>
    Risk Level: <b style="color:{color};">{risk}</b><br>
    Threat Severity: {row['Threat_Severity']:.1f}/100<br>
    Vulnerability Score: {row['Vulnerability_Score']:.1f}/100<br>
    Malware: {row['Malware']} | Phishing: {row['Phishing']}<br>
    DDoS: {row['DDoS']} | Ransomware: {row['Ransomware']}<br>
    Total Attacks: {row['Total_Attacks']}
    </div>
    """
    folium.CircleMarker(
        location=[lat, lon],
        radius=8 + (row["Threat_Severity"] / 12),
        color=color, fill=True, fill_color=color, fill_opacity=0.75,
        popup=folium.Popup(popup_html, max_width=250),
        tooltip=f"{region}: {risk}",
    ).add_to(m)

col_map, col_detail = st.columns([1.4, 1])

with col_map:
    glass_card_open("🌐 National Risk Map")
    st.markdown(
        "🟢 Low &nbsp;&nbsp; 🟡 Medium &nbsp;&nbsp; 🟠 High &nbsp;&nbsp; 🔴 Critical",
    )
    map_data = st_folium(m, width=None, height=560, returned_objects=["last_object_clicked_tooltip"])
    glass_card_close()

with col_detail:
    glass_card_open("📍 Region Detail")
    selected_region = None
    if map_data and map_data.get("last_object_clicked_tooltip"):
        tooltip = map_data["last_object_clicked_tooltip"]
        selected_region = tooltip.split(":")[0].strip()

    all_regions = sorted(snapshot["State"].unique().tolist())
    default_idx = all_regions.index(selected_region) if selected_region in all_regions else 0
    chosen_region = st.selectbox("Or select a region manually:", all_regions, index=default_idx)

    region_row = snapshot[snapshot["State"] == chosen_region].iloc[0]

    st.markdown(f"### {chosen_region}")
    st.markdown(risk_badge_html(region_row["Risk_Level"]), unsafe_allow_html=True)

    feature_row = {col: region_row[col] for col in FEATURE_COLS}
    pred_risk, confidence, proba = predict_risk(risk_model, le, feature_row)

    st.markdown(f"**AI Prediction:** {pred_risk} &nbsp; (confidence {confidence:.1f}%)")
    st.progress(confidence / 100)

    m1, m2, m3 = st.columns(3)
    m1.metric("Attack Count", int(region_row["Total_Attacks"]))
    m2.metric("Vulnerability Score", f"{region_row['Vulnerability_Score']:.0f}")
    m3.metric("Threat Severity", f"{region_row['Threat_Severity']:.0f}")

    st.markdown("**Attack Breakdown:**")
    st.write(pd.DataFrame({
        "Category": ["Malware", "Phishing", "DDoS", "Ransomware"],
        "Count": [region_row["Malware"], region_row["Phishing"], region_row["DDoS"], region_row["Ransomware"]]
    }).set_index("Category").T)

    st.markdown("**🤖 AI Recommendations:**")
    attack_counts = {
        "Malware": region_row["Malware"], "Phishing": region_row["Phishing"],
        "DDoS": region_row["DDoS"], "Ransomware": region_row["Ransomware"],
        "SQL_Injection": region_row["SQL_Injection"], "Brute_Force": region_row["Brute_Force"],
        "Zero_Day": region_row["Zero_Day"],
    }
    recs = generate_recommendations(region_row["Risk_Level"], attack_counts)
    for r in recs[:6]:
        st.markdown(f"- {r}")

    glass_card_close()

st.caption("⚠️ Map coordinates are approximate state/UT centroids used for visualization; underlying data is fully simulated.")
