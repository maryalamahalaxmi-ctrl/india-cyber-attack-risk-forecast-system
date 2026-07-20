"""
data_generator.py
------------------
Generates a fully synthetic (simulated) cyber-activity dataset covering all
Indian States and Union Territories. This data is NOT real threat intelligence
— it is randomly generated (with a fixed seed for reproducibility) purely to
power the ML models and dashboards in this demo/final-year project.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import os

RANDOM_SEED = 42

STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
    "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
    "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim",
    "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand",
    "West Bengal"
]

UNION_TERRITORIES = [
    "Andaman and Nicobar Islands", "Chandigarh",
    "Dadra and Nagar Haveli and Daman and Diu", "Delhi", "Jammu and Kashmir",
    "Ladakh", "Lakshadweep", "Puducherry"
]

ALL_REGIONS = STATES + UNION_TERRITORIES

# Approximate centroid coordinates for map plotting
REGION_COORDS = {
    "Andhra Pradesh": (15.9129, 79.7400), "Arunachal Pradesh": (28.2180, 94.7278),
    "Assam": (26.2006, 92.9376), "Bihar": (25.0961, 85.3131),
    "Chhattisgarh": (21.2787, 81.8661), "Goa": (15.2993, 74.1240),
    "Gujarat": (22.2587, 71.1924), "Haryana": (29.0588, 76.0856),
    "Himachal Pradesh": (31.1048, 77.1734), "Jharkhand": (23.6102, 85.2799),
    "Karnataka": (15.3173, 75.7139), "Kerala": (10.8505, 76.2711),
    "Madhya Pradesh": (22.9734, 78.6569), "Maharashtra": (19.7515, 75.7139),
    "Manipur": (24.6637, 93.9063), "Meghalaya": (25.4670, 91.3662),
    "Mizoram": (23.1645, 92.9376), "Nagaland": (26.1584, 94.5624),
    "Odisha": (20.9517, 85.0985), "Punjab": (31.1471, 75.3412),
    "Rajasthan": (27.0238, 74.2179), "Sikkim": (27.5330, 88.5122),
    "Tamil Nadu": (11.1271, 78.6569), "Telangana": (18.1124, 79.0193),
    "Tripura": (23.9408, 91.9882), "Uttar Pradesh": (26.8467, 80.9462),
    "Uttarakhand": (30.0668, 79.0193), "West Bengal": (22.9868, 87.8550),
    "Andaman and Nicobar Islands": (11.7401, 92.6586),
    "Chandigarh": (30.7333, 76.7794),
    "Dadra and Nagar Haveli and Daman and Diu": (20.1809, 73.0169),
    "Delhi": (28.7041, 77.1025), "Jammu and Kashmir": (33.7782, 76.5762),
    "Ladakh": (34.1526, 77.5771), "Lakshadweep": (10.5667, 72.6417),
    "Puducherry": (11.9416, 79.8083),
}

ATTACK_TYPES = [
    "Malware", "Phishing", "DDoS", "Ransomware", "SQL Injection",
    "Brute Force", "Insider Threat", "Botnet", "Zero-Day", "XSS"
]

# Tech-hub / high-target regions get a higher baseline risk multiplier
HIGH_TARGET_REGIONS = {
    "Maharashtra": 1.8, "Karnataka": 1.9, "Delhi": 1.7, "Telangana": 1.6,
    "Tamil Nadu": 1.5, "Uttar Pradesh": 1.3, "Gujarat": 1.3,
    "West Bengal": 1.2, "Haryana": 1.4,
}


def _risk_level_from_score(score):
    if score < 25:
        return "Low"
    elif score < 50:
        return "Medium"
    elif score < 75:
        return "High"
    else:
        return "Critical"


def generate_dataset(days=180, save_path="dataset/cyber_dataset.csv", force=False):
    """Generate (or load cached) synthetic daily cyber-activity records for
    every Indian state/UT over the given number of days."""
    if os.path.exists(save_path) and not force:
        return pd.read_csv(save_path, parse_dates=["Date"])

    rng = np.random.default_rng(RANDOM_SEED)
    end_date = datetime.now().date()
    dates = [end_date - timedelta(days=i) for i in range(days)][::-1]

    records = []
    for region in ALL_REGIONS:
        multiplier = HIGH_TARGET_REGIONS.get(region, 1.0)
        base_vuln = rng.uniform(20, 60)
        for d in dates:
            # weekly seasonality: more activity mid-week
            weekday_factor = 1.0 + 0.15 * np.sin(d.weekday())
            trend_factor = 1.0 + 0.10 * np.sin(d.timetuple().tm_yday / 20)

            malware = max(0, int(rng.poisson(4 * multiplier) * weekday_factor))
            phishing = max(0, int(rng.poisson(6 * multiplier) * weekday_factor))
            ddos = max(0, int(rng.poisson(2 * multiplier) * trend_factor))
            ransomware = max(0, int(rng.poisson(1.2 * multiplier)))
            sql_injection = max(0, int(rng.poisson(2.5 * multiplier)))
            brute_force = max(0, int(rng.poisson(5 * multiplier)))
            insider_threat = max(0, int(rng.poisson(0.8 * multiplier)))
            botnet = max(0, int(rng.poisson(1.5 * multiplier)))
            zero_day = max(0, int(rng.poisson(0.4 * multiplier)))
            xss = max(0, int(rng.poisson(2.2 * multiplier)))

            firewall_alerts = int(rng.poisson(15 * multiplier))
            failed_logins = int(rng.poisson(20 * multiplier))
            cpu_usage = float(np.clip(rng.normal(45, 15), 5, 99))
            network_traffic = float(np.clip(rng.normal(500, 150) * multiplier, 50, 5000))
            open_ports = int(np.clip(rng.normal(12, 4), 1, 40))

            vuln_score = float(np.clip(base_vuln + rng.normal(0, 8), 0, 100))

            total_attacks = (malware + phishing + ddos + ransomware * 3 +
                             sql_injection + brute_force + insider_threat * 2 +
                             botnet + zero_day * 4 + xss)

            severity = float(np.clip(
                (total_attacks * 1.5) + (vuln_score * 0.3) +
                (failed_logins * 0.2) + rng.normal(0, 5), 0, 100
            ))
            risk_level = _risk_level_from_score(severity)

            records.append({
                "State": region, "Date": d, "Malware": malware,
                "Phishing": phishing, "DDoS": ddos, "Ransomware": ransomware,
                "SQL_Injection": sql_injection, "Brute_Force": brute_force,
                "Insider_Threat": insider_threat, "Botnet": botnet,
                "Zero_Day": zero_day, "XSS": xss,
                "Firewall_Alerts": firewall_alerts, "Failed_Logins": failed_logins,
                "CPU_Usage": round(cpu_usage, 2),
                "Network_Traffic": round(network_traffic, 2),
                "Open_Ports": open_ports, "Vulnerability_Score": round(vuln_score, 2),
                "Threat_Severity": round(severity, 2), "Risk_Level": risk_level,
                "Total_Attacks": total_attacks,
            })

    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    df.to_csv(save_path, index=False)
    return df


def get_latest_snapshot(df):
    """Return the most recent day's record per region."""
    latest_date = df["Date"].max()
    return df[df["Date"] == latest_date].reset_index(drop=True)


def get_region_coords():
    return REGION_COORDS


def get_attack_types():
    return ATTACK_TYPES
