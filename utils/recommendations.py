"""
recommendations.py
--------------------
Rule-based AI recommendation engine. Maps observed attack patterns / risk
levels to a prioritized list of security recommendations.
"""

RECOMMENDATION_LIBRARY = {
    "mfa": "Enable Multi-Factor Authentication on all privileged and remote-access accounts",
    "firewall": "Update Firewall Rules to block anomalous inbound/outbound traffic patterns",
    "patch": "Patch Critical Vulnerabilities identified in the current CVE watchlist",
    "block_ip": "Block Suspicious IPs flagged by the anomaly detection engine",
    "ids": "Enable / tune Intrusion Detection System (IDS) signatures for recent attack types",
    "phishing_training": "Conduct Employee Phishing Awareness Training this quarter",
    "backup": "Verify and Backup Critical Systems (test restore procedures)",
    "monitoring": "Increase Continuous Network Monitoring frequency and log retention",
    "segmentation": "Apply Network Segmentation to isolate high-value assets",
    "incident_response": "Activate Incident Response playbook and notify SOC leadership",
    "credential_rotation": "Rotate credentials and API keys exposed to brute-force attempts",
    "endpoint_hardening": "Harden endpoint configurations and disable unused services/ports",
}


def generate_recommendations(risk_level: str, attack_counts: dict, anomaly_flag: bool = False):
    """Return a prioritized list of recommendations based on risk level and
    dominant attack categories."""
    recs = []

    if risk_level in ("Critical", "High"):
        recs.append(RECOMMENDATION_LIBRARY["incident_response"])
        recs.append(RECOMMENDATION_LIBRARY["block_ip"])

    if attack_counts.get("Brute_Force", 0) > 5 or attack_counts.get("Brute Force", 0) > 5:
        recs.append(RECOMMENDATION_LIBRARY["mfa"])
        recs.append(RECOMMENDATION_LIBRARY["credential_rotation"])

    if attack_counts.get("Phishing", 0) > 5:
        recs.append(RECOMMENDATION_LIBRARY["phishing_training"])

    if attack_counts.get("DDoS", 0) > 2:
        recs.append(RECOMMENDATION_LIBRARY["firewall"])

    if attack_counts.get("Ransomware", 0) > 0:
        recs.append(RECOMMENDATION_LIBRARY["backup"])
        recs.append(RECOMMENDATION_LIBRARY["segmentation"])

    if attack_counts.get("Zero-Day", 0) > 0 or attack_counts.get("Zero_Day", 0) > 0:
        recs.append(RECOMMENDATION_LIBRARY["patch"])

    if attack_counts.get("SQL_Injection", 0) > 0 or attack_counts.get("SQL Injection", 0) > 0:
        recs.append(RECOMMENDATION_LIBRARY["patch"])
        recs.append(RECOMMENDATION_LIBRARY["endpoint_hardening"])

    if anomaly_flag:
        recs.append(RECOMMENDATION_LIBRARY["ids"])
        recs.append(RECOMMENDATION_LIBRARY["monitoring"])

    # Always include baseline hygiene recommendation
    recs.append(RECOMMENDATION_LIBRARY["monitoring"])

    # De-duplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            unique_recs.append(r)
            seen.add(r)
    return unique_recs[:8]
