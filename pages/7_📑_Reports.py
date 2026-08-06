import streamlit as st
import pandas as pd
from datetime import datetime

from utils.data_generator import generate_dataset, get_latest_snapshot
from utils.recommendations import generate_recommendations
from utils.report_generator import generate_csv_report, generate_excel_report, generate_pdf_report
from utils.ui_components import load_css, glass_card_open, glass_card_close

st.set_page_config(page_title="Reports", page_icon="📑", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("📑 Security Reports")
st.caption("Generate downloadable Threat Summary, Prediction, Incident, and Risk Analysis reports")

df = generate_dataset(days=180)
snapshot = get_latest_snapshot(df)

national_counts = {
    "Malware": int(snapshot["Malware"].sum()), "Phishing": int(snapshot["Phishing"].sum()),
    "DDoS": int(snapshot["DDoS"].sum()), "Ransomware": int(snapshot["Ransomware"].sum()),
    "SQL_Injection": int(snapshot["SQL_Injection"].sum()), "Brute_Force": int(snapshot["Brute_Force"].sum()),
    "Zero_Day": int(snapshot["Zero_Day"].sum()),
}
overall_risk = snapshot.sort_values("Threat_Severity", ascending=False).iloc[0]["Risk_Level"]
recommendations = generate_recommendations(overall_risk, national_counts)

glass_card_open("🧾 Report Preview — Threat Summary")
summary_lines = [
    f"Reporting period: {df['Date'].min()} to {df['Date'].max()}",
    f"Regions covered: {snapshot['State'].nunique()} States & Union Territories",
    f"Average national threat severity: {snapshot['Threat_Severity'].mean():.1f} / 100",
    f"Critical-risk regions: {(snapshot['Risk_Level']=='Critical').sum()}",
    f"High-risk regions: {(snapshot['Risk_Level']=='High').sum()}",
    f"Total simulated attacks (latest day): {int(snapshot['Total_Attacks'].sum())}",
]
for line in summary_lines:
    st.markdown(f"- {line}")
glass_card_close()

glass_card_open("📊 Risk Analysis Table (Latest Snapshot)")
report_table = snapshot[["State", "Risk_Level", "Threat_Severity", "Vulnerability_Score",
                          "Total_Attacks", "Malware", "Phishing", "DDoS", "Ransomware"]].sort_values(
    "Threat_Severity", ascending=False).reset_index(drop=True)
st.dataframe(report_table, use_container_width=True, height=350)
glass_card_close()

glass_card_open("🤖 AI Recommendations Included in Report")
for r in recommendations:
    st.markdown(f"- {r}")
glass_card_close()

st.markdown("### ⬇️ Download Reports")
col1, col2, col3 = st.columns(3)

with col1:
    csv_bytes = generate_csv_report(report_table)
    st.download_button(
        "📄 Download CSV Report", data=csv_bytes,
        file_name=f"cyber_risk_report_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv", use_container_width=True
    )

with col2:
    excel_bytes = generate_excel_report({
        "Risk Analysis": report_table,
        "Recommendations": pd.DataFrame({"Recommendation": recommendations}),
    })
    st.download_button(
        "📊 Download Excel Report", data=excel_bytes,
        file_name=f"cyber_risk_report_{datetime.now().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True
    )

with col3:
    try:
        pdf_bytes = generate_pdf_report(
            "India Cyber Attack Risk Forecast — Security Report",
            summary_lines, report_table.head(30), recommendations
        )
        st.download_button(
            "🧾 Download PDF Report", data=pdf_bytes,
            file_name=f"cyber_risk_report_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf", use_container_width=True
        )
    except ImportError:
        st.warning("Install `reportlab` to enable PDF report generation (see requirements.txt).")

st.caption("⚠️ Reports are generated from the synthetic demo dataset and are intended for educational demonstration only.")
