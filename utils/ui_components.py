"""
ui_components.py
-----------------
Reusable Streamlit UI helper components (KPI cards, badges, theme loader).
"""

import streamlit as st
import os


def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "..", "assets", "style.css")
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def risk_badge_html(risk_level: str) -> str:
    cls_map = {
        "Low": "badge-low", "Medium": "badge-medium",
        "High": "badge-high", "Critical": "badge-critical",
    }
    cls = cls_map.get(risk_level, "badge-medium")
    return f'<span class="badge {cls}">{risk_level.upper()}</span>'


def kpi_card(label: str, value, delta: str = None, icon: str = ""):
    delta_html = f'<div style="font-size:12px;color:#9fb8d9;">{delta}</div>' if delta else ""
    st.markdown(f"""
    <div class="kpi-card">
        <div style="font-size:22px;">{icon}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-label">{label}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def glass_card_open(title: str = None):
    title_html = f"<h4 style='margin-top:0;'>{title}</h4>" if title else ""
    st.markdown(f'<div class="glass-card">{title_html}', unsafe_allow_html=True)


def glass_card_close():
    st.markdown("</div>", unsafe_allow_html=True)


def risk_color(risk_level: str) -> str:
    return {
        "Low": "#00e676", "Medium": "#ffd600",
        "High": "#ff9100", "Critical": "#ff1744",
    }.get(risk_level, "#00d9ff")
