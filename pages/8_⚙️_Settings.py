import streamlit as st
from utils.ui_components import load_css, glass_card_open, glass_card_close

st.set_page_config(page_title="Settings", page_icon="⚙️", layout="wide")
load_css()

if not st.session_state.get("authenticated"):
    st.warning("Please log in from the Home page first.")
    st.stop()

st.title("⚙️ Settings")
st.caption("Configure appearance, refresh behavior, and notifications")

for k, v in {"dark_mode": True, "refresh_interval": 30, "notifications": True}.items():
    if k not in st.session_state:
        st.session_state[k] = v

glass_card_open("🎨 Appearance")
theme_choice = st.radio("Theme", ["Dark Mode (Neon SOC)", "Light Mode"],
                         index=0 if st.session_state.dark_mode else 1, horizontal=True)
st.session_state.dark_mode = theme_choice.startswith("Dark")
if not st.session_state.dark_mode:
    st.info("Light mode is a preference flag in this demo — the neon SOC theme CSS is optimized for dark backgrounds. A full light theme stylesheet can be added in assets/style.css.", icon="💡")
glass_card_close()

glass_card_open("🔄 Refresh Interval")
st.session_state.refresh_interval = st.slider(
    "Auto-refresh interval for Real-Time Monitoring (seconds)",
    min_value=5, max_value=120, value=st.session_state.refresh_interval, step=5
)
st.caption(f"Currently set to refresh every **{st.session_state.refresh_interval}** seconds.")
glass_card_close()

glass_card_open("🔔 Notification Settings")
st.session_state.notifications = st.toggle("Enable Critical Alert Notifications", value=st.session_state.notifications)
notify_threshold = st.select_slider("Notify me when threat severity exceeds:",
                                     options=list(range(0, 101, 10)), value=70)
st.caption(f"Notifications {'enabled' if st.session_state.notifications else 'disabled'} — threshold {notify_threshold}/100.")
glass_card_close()

glass_card_open("👤 Account")
st.markdown(f"**Username:** {st.session_state.get('username', 'N/A')}")
st.markdown(f"**Role:** `{st.session_state.get('role', 'Viewer')}`")
role_permissions = {
    "Admin": "Full access — manage users, retrain models, edit all settings, export all reports.",
    "Analyst": "Investigate incidents, run threat hunts, generate reports, view all dashboards.",
    "Viewer": "Read-only access to dashboards and analytics.",
}
st.info(role_permissions.get(st.session_state.get("role", "Viewer"), ""), icon="🔑")
glass_card_close()
