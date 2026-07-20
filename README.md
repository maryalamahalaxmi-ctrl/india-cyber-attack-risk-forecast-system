# 🛡️ India Cyber Attack Risk Forecast System

An AI-powered, SOC-style Streamlit dashboard that combines **Cyber Threat
Intelligence (CTI)**, **SIEM concepts**, **Machine Learning risk forecasting**,
**anomaly detection**, an **interactive India cyber risk map**, **advanced
analytics**, **threat hunting**, and **downloadable security reports** — built
as a final-year engineering project.

> ⚠️ **Important:** All threat, log, IOC, CVE, and map data in this project is
> **synthetically generated** for demonstration purposes. Nothing here reads
> real network traffic, real threat feeds, or real systems. This is a
> simulation/education tool, not a production security product.

---

## ✨ Features

| Module | Description |
|---|---|
| **AI Risk Forecasting** | RandomForest classifier predicts Low/Medium/High/Critical risk per region with confidence scores and feature-importance explainability |
| **Anomaly Detection** | IsolationForest flags statistically abnormal regional activity |
| **Threat Intelligence Dashboard** | Simulated malware families, ransomware groups, IOC feed, CVE watchlist, MITRE ATT&CK mapping, severity scoring |
| **SIEM Dashboard** | Simulated log sources, event correlation/incident queue, alert timeline, threat-score gauge |
| **Real-Time Monitoring** | Simulated live telemetry: CPU/memory/network, login attempts, live alerts |
| **Interactive India Cyber Map** | Folium map of all 28 states + 8 UTs, color-coded by risk, clickable for full detail + AI recommendations |
| **Analytics Dashboard** | Plotly trend charts, state comparisons, heatmaps, SOC performance, model explainability |
| **Threat Hunting** | Search by IP, threat type, state, severity, IOC, or CVE |
| **Reports** | Downloadable CSV, Excel, and PDF security reports |
| **Auth & Roles** | Login/logout with Admin / Analyst / Viewer roles |
| **Settings** | Theme, refresh interval, notification threshold |

---

## 🗂️ Project Structure

```
cyberforecast/
├── app.py                     # Main entry point (auth + home dashboard)
├── requirements.txt
├── README.md
├── .streamlit/config.toml     # Theme config
├── dataset/                   # Synthetic dataset cache (CSV)
├── model/                     # Trained model cache (joblib)
├── reports/                   # (reserved for saved report exports)
├── assets/
│   └── style.css              # Glassmorphism / neon cyber theme
├── utils/
│   ├── data_generator.py      # Synthetic dataset generation
│   ├── ml_models.py           # RandomForest + IsolationForest training/inference
│   ├── threat_intel.py        # MITRE mapping, IOC/CVE/malware/ransomware data
│   ├── recommendations.py     # Rule-based AI recommendation engine
│   ├── report_generator.py    # CSV / Excel / PDF report builders
│   └── ui_components.py       # Reusable KPI cards, badges, theme loader
└── pages/
    ├── 1_🔎_Threat_Intelligence.py
    ├── 2_🖥️_SIEM_Dashboard.py
    ├── 3_📡_Real_Time_Monitoring.py
    ├── 4_🗺️_India_Cyber_Map.py
    ├── 5_📊_Analytics.py
    ├── 6_🕵️_Threat_Hunting.py
    ├── 7_📑_Reports.py
    └── 8_⚙️_Settings.py
```

---

## 🚀 Getting Started

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```

### 3. Log in
Use one of the demo accounts:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |
| `analyst` | `analyst123` | Analyst |
| `viewer` | `viewer123` | Viewer |

The synthetic dataset (180 days × 36 regions) and ML models are generated /
trained automatically on first run and cached to `dataset/` and `model/` —
subsequent runs load instantly from cache. Delete those folders (or pass
`force=True` to the generator/trainer functions) to regenerate from scratch.

---

## 🧠 How the AI Works

- **Risk Forecasting:** A `RandomForestClassifier` is trained on 16 engineered
  features (attack counts, firewall alerts, failed logins, CPU/network load,
  vulnerability score) to classify each region-day into Low/Medium/High/Critical
  risk, with `predict_proba` used for confidence scoring.
- **Anomaly Detection:** An `IsolationForest` flags region-days whose feature
  profile deviates from the learned "normal" distribution — used to highlight
  suspicious activity on the Home dashboard and SIEM view.
- **Threat Prediction Timeline:** A lightweight heuristic model projects
  short-term attack probability (next hour / 24h / 7 days / month) from the
  current severity trend.
- **Recommendation Engine:** A transparent rule-based system maps risk level
  and dominant attack categories to prioritized, actionable security
  recommendations (MFA, patching, IDS tuning, phishing training, etc.).

---

## 🛠️ Tech Stack

Python · Streamlit · Pandas · NumPy · Scikit-learn · Plotly · Matplotlib ·
Folium / streamlit-folium · SQLite-ready · Joblib · OpenPyXL · ReportLab

---

## 📌 Notes for Evaluators / Reviewers

- This project is designed to **demonstrate architecture and integration**
  (CTI + SIEM + ML + geo-visualization + reporting) end-to-end in a single
  cohesive dashboard, suitable for a final-year engineering capstone.
- All "threat intelligence," log, and monitoring data is clearly labeled as
  **simulated** throughout the UI — there is no live feed integration, and no
  real IOC/CVE database is queried.
- The architecture (`utils/` service layer + `pages/` multipage UI) is built
  to make it straightforward to swap in a real data source (e.g. a live CVE
  API, a real SIEM export, or an actual CTI feed) later without restructuring
  the app.

---

## 📄 License

This is an educational/demo project. Use and adapt freely for coursework.
