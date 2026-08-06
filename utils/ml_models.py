"""
ml_models.py
------------
Trains and serves the ML models used by the dashboard:
  1. Risk Forecasting model (RandomForestClassifier) -> Low/Medium/High/Critical
  2. Anomaly Detection model (IsolationForest) -> flags abnormal activity rows

Models auto-train on first run if no cached joblib file is found, and are
then cached to /model for subsequent runs.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

FEATURE_COLS = [
    "Malware", "Phishing", "DDoS", "Ransomware", "SQL_Injection",
    "Brute_Force", "Insider_Threat", "Botnet", "Zero_Day", "XSS",
    "Firewall_Alerts", "Failed_Logins", "CPU_Usage", "Network_Traffic",
    "Open_Ports", "Vulnerability_Score",
]

RISK_MODEL_PATH = "model/risk_model.joblib"
LABEL_ENCODER_PATH = "model/label_encoder.joblib"
ANOMALY_MODEL_PATH = "model/anomaly_model.joblib"


def train_or_load_risk_model(df, force=False):
    """Train (or load cached) RandomForest risk classifier."""
    if os.path.exists(RISK_MODEL_PATH) and os.path.exists(LABEL_ENCODER_PATH) and not force:
        model = joblib.load(RISK_MODEL_PATH)
        le = joblib.load(LABEL_ENCODER_PATH)
        return model, le, None

    X = df[FEATURE_COLS]
    le = LabelEncoder()
    y = le.fit_transform(df["Risk_Level"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=250, max_depth=14, min_samples_split=4,
        random_state=42, n_jobs=-1, class_weight="balanced"
    )
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, RISK_MODEL_PATH)
    joblib.dump(le, LABEL_ENCODER_PATH)
    return model, le, acc


def train_or_load_anomaly_model(df, force=False):
    """Train (or load cached) IsolationForest anomaly detector."""
    if os.path.exists(ANOMALY_MODEL_PATH) and not force:
        return joblib.load(ANOMALY_MODEL_PATH)

    X = df[FEATURE_COLS]
    model = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1
    )
    model.fit(X)
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, ANOMALY_MODEL_PATH)
    return model


def predict_risk(model, le, feature_row: dict):
    """Predict risk level + confidence for a single record (dict of features)."""
    X = pd.DataFrame([feature_row])[FEATURE_COLS]
    proba = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    risk_level = le.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx]) * 100
    proba_dict = {cls: float(p) * 100 for cls, p in zip(le.classes_, proba)}
    return risk_level, confidence, proba_dict


def get_feature_importance(model):
    importances = model.feature_importances_
    return pd.DataFrame({
        "Feature": FEATURE_COLS, "Importance": importances
    }).sort_values("Importance", ascending=False)


def detect_anomalies(anomaly_model, df):
    """Return dataframe rows flagged as anomalous (-1 = anomaly)."""
    X = df[FEATURE_COLS]
    preds = anomaly_model.predict(X)
    scores = anomaly_model.decision_function(X)
    result = df.copy()
    result["Anomaly"] = np.where(preds == -1, "Suspicious", "Normal")
    result["Anomaly_Score"] = scores
    return result


def forecast_timeline_probabilities(current_severity: float):
    """Simple heuristic-based short-term probability forecast used for the
    'AI Threat Prediction Timeline' feature. Uses current severity as a base
    rate with mild random-walk decay/growth for each horizon."""
    rng = np.random.default_rng(int(current_severity * 100) % (2**32 - 1))
    base = current_severity / 100.0
    horizons = {
        "Next Hour": np.clip(base * 0.9 + rng.normal(0, 0.02), 0, 1),
        "Next 24 Hours": np.clip(base * 1.0 + rng.normal(0, 0.04), 0, 1),
        "Next 7 Days": np.clip(base * 1.15 + rng.normal(0, 0.06), 0, 1),
        "Next Month": np.clip(base * 1.3 + rng.normal(0, 0.08), 0, 1),
    }
    return {k: round(float(v) * 100, 1) for k, v in horizons.items()}
