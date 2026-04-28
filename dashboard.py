import streamlit as st
import sqlite3
import pandas as pd
import time

DB_PATH = "fim.db"

st.set_page_config(page_title="FIM Dashboard", layout="wide")

st.title("🛡️ Real-Time File Integrity Monitor")
st.caption("PUSL3190 Final Year Project - Janith32")

# Auto-refresh every 3 seconds
st_autorefresh_placeholder = st.empty()

def get_baseline_files():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT path, hash, size FROM baseline", conn)
    conn.close()
    return df

def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 50", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def get_alert_summary():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT mitre_technique, COUNT(*) as count FROM alerts GROUP BY mitre_technique", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

# Top metrics
col1, col2, col3, col4 = st.columns(4)

baseline_df = get_baseline_files()
alerts_df = get_alerts()

with col1:
    st.metric("Files Monitored", len(baseline_df))
with col2:
    st.metric("Total Alerts", len(alerts_df))
with col3:
    high_alerts = len(alerts_df[alerts_df['severity'] == 'HIGH']) if not alerts_df.empty else 0
    st.metric("High Severity", high_alerts)
with col4:
    st.metric("System Status", "🟢 Active")

st.divider()

# Alerts table
st.subheader("Recent Alerts")
if not alerts_df.empty:
    display_df = alerts_df[['timestamp', 'event_type', 'file_path', 'severity', 'mitre_technique']]
    st.dataframe(display_df, use_container_width=True, hide_index=True)
else:
    st.info("No alerts yet. Modify a file in the monitored folder to see alerts appear here.")

# MITRE chart
st.subheader("Alerts by MITRE ATT&CK Technique")
summary_df = get_alert_summary()
if not summary_df.empty:
    st.bar_chart(summary_df.set_index('mitre_technique'))
else:
    st.info("No data to display yet.")

# Auto-refresh
time.sleep(3)
st.rerun()