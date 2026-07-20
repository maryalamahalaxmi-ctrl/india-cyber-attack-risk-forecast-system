"""
threat_intel.py
----------------
Static reference data + helper functions for the Threat Intelligence
Dashboard: MITRE ATT&CK category mapping, simulated malware families,
simulated ransomware groups, simulated IOCs, and simulated CVEs.

All indicator data here is illustrative/simulated for demo purposes and is
not sourced from a live feed.
"""

import random
import pandas as pd
from datetime import datetime, timedelta

MITRE_MAPPING = {
    "Malware": {"tactic": "Execution", "technique": "T1204 - User Execution"},
    "Phishing": {"tactic": "Initial Access", "technique": "T1566 - Phishing"},
    "DDoS": {"tactic": "Impact", "technique": "T1498 - Network DoS"},
    "Ransomware": {"tactic": "Impact", "technique": "T1486 - Data Encrypted for Impact"},
    "Insider Threat": {"tactic": "Collection", "technique": "T1074 - Data Staged"},
    "Botnet": {"tactic": "Command and Control", "technique": "T1071 - Application Layer Protocol"},
    "Zero-Day": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application"},
    "SQL Injection": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application"},
    "XSS": {"tactic": "Initial Access", "technique": "T1189 - Drive-by Compromise"},
    "Brute Force": {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
}

MALWARE_FAMILIES = [
    {"name": "Emotet-Variant-Sim", "type": "Trojan", "first_seen": "2024-02-11", "severity": "High"},
    {"name": "LockShield-Sim", "type": "Ransomware", "first_seen": "2024-06-03", "severity": "Critical"},
    {"name": "SilentMiner-Sim", "type": "Cryptominer", "first_seen": "2025-01-20", "severity": "Medium"},
    {"name": "GhostRAT-Sim", "type": "RAT", "first_seen": "2023-11-08", "severity": "High"},
    {"name": "DarkBot-Sim", "type": "Botnet", "first_seen": "2025-03-15", "severity": "Medium"},
]

RANSOMWARE_GROUPS = [
    {"name": "CrimsonLocker-Sim", "targets": "Finance, Healthcare", "activity": "High"},
    {"name": "ByteReaper-Sim", "targets": "Manufacturing, IT", "activity": "Medium"},
    {"name": "VoidCipher-Sim", "targets": "Government, Education", "activity": "Critical"},
    {"name": "ShadowVault-Sim", "targets": "Retail, Logistics", "activity": "Low"},
]

CVE_SAMPLES = [
    {"cve": "CVE-2024-SIM-3401", "cvss": 9.8, "product": "Web Server Framework", "status": "Unpatched"},
    {"cve": "CVE-2024-SIM-7710", "cvss": 8.6, "product": "VPN Gateway", "status": "Patch Available"},
    {"cve": "CVE-2025-SIM-1189", "cvss": 7.2, "product": "Database Engine", "status": "Patched"},
    {"cve": "CVE-2025-SIM-4520", "cvss": 9.1, "product": "IoT Firmware", "status": "Unpatched"},
    {"cve": "CVE-2025-SIM-6650", "cvss": 6.4, "product": "Email Gateway", "status": "Patch Available"},
]


def generate_ioc_feed(n=25, seed=42):
    """Generate a simulated list of Indicators of Compromise."""
    rng = random.Random(seed)
    ioc_types = ["IP Address", "Domain", "File Hash (SHA256)", "URL"]
    records = []
    for i in range(n):
        ioc_type = rng.choice(ioc_types)
        if ioc_type == "IP Address":
            value = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        elif ioc_type == "Domain":
            value = f"malicious-sim-{rng.randint(1000,9999)}.example"
        elif ioc_type == "URL":
            value = f"http://sim-threat-{rng.randint(100,999)}.example/payload"
        else:
            value = "".join(rng.choices("abcdef0123456789", k=64))
        records.append({
            "IOC Type": ioc_type,
            "Value": value,
            "Threat": rng.choice(list(MITRE_MAPPING.keys())),
            "Confidence": rng.choice(["Low", "Medium", "High"]),
            "First Seen": (datetime.now() - timedelta(days=rng.randint(0, 60))).strftime("%Y-%m-%d"),
        })
    return pd.DataFrame(records)


def threat_severity_score(attack_counts: dict) -> float:
    """Weighted severity score across attack categories (0-100 scale)."""
    weights = {
        "Malware": 1.0, "Phishing": 0.8, "DDoS": 1.2, "Ransomware": 2.5,
        "SQL Injection": 1.5, "Brute Force": 0.7, "Insider Threat": 2.0,
        "Botnet": 1.3, "Zero-Day": 3.0, "XSS": 1.1,
    }
    raw = sum(attack_counts.get(k, 0) * w for k, w in weights.items())
    return min(100.0, raw)


def attack_priority_level(severity_score: float) -> str:
    if severity_score < 20:
        return "Routine"
    elif severity_score < 45:
        return "Elevated"
    elif severity_score < 70:
        return "High Priority"
    else:
        return "Immediate Action"
