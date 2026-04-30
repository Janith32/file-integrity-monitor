import streamlit as st
import sqlite3
import pandas as pd
import time
from auth import (authenticate, init_default_admin, get_all_users, create_user,
                  delete_user, log_audit, hash_password, add_monitored_path,
                  remove_monitored_path, get_monitored_paths, add_severity_rule,
                  remove_severity_rule, get_severity_rules, init_config_tables,
                  verify_chain)

DB_PATH = "fim.db"

st.set_page_config(page_title="FIM Dashboard", layout="wide", initial_sidebar_state="expanded")

init_default_admin()
init_config_tables()

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
if 'force_password_change' not in st.session_state:
    st.session_state.force_password_change = False


def show_login():
    st.title("🛡️ FIM Dashboard - Login")
    st.caption("Real-Time File Integrity and Security Monitoring")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Log In", use_container_width=True)
            
            if submit:
                if username and password:
                    success, role = authenticate(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.role = role
                        if username == "admin" and password == "admin123":
                            st.session_state.force_password_change = True
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.warning("Please enter both username and password")


def show_force_password_change():
    st.title("🔐 Password Change Required")
    st.warning("You are using the default password. You must change it before continuing.")
    
    with st.form("change_password_form"):
        new_password = st.text_input("New Password (min 8 characters)", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Change Password")
        
        if submit:
            if new_password != confirm_password:
                st.error("Passwords do not match")
            elif len(new_password) < 8:
                st.error("Password must be at least 8 characters")
            else:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                new_hash = hash_password(new_password)
                c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                          (new_hash, st.session_state.username))
                conn.commit()
                conn.close()
                log_audit(st.session_state.username, "PASSWORD_CHANGED", success=1)
                st.session_state.force_password_change = False
                st.success("Password changed. Continuing to dashboard...")
                time.sleep(2)
                st.rerun()


def show_dashboard():
    with st.sidebar:
        st.title("🛡️ FIM System")
        st.write(f"**User:** {st.session_state.username}")
        st.write(f"**Role:** {st.session_state.role}")
        st.divider()
        
        if st.session_state.role == "admin":
            page = st.radio("Navigation", ["Dashboard", "Alerts", "Configuration", "User Management", "Audit Log" ,"Chain Verify"])
        else:
            page = st.radio("Navigation", ["Dashboard", "Alerts", "Audit Log" , "Chain Verify"])
        
        st.divider()
        if st.button("Logout", use_container_width=True):
            log_audit(st.session_state.username, "LOGOUT", success=1)
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()
    
    if page == "Dashboard":
        show_main_dashboard()
    elif page == "Alerts":
        show_alerts_page()
    elif page == "Configuration":
        show_configuration()
    elif page == "User Management":
        show_user_management()
    elif page == "Audit Log":
        show_audit_log()
    elif page == "Chain Verify":
        show_chain_verify()


def get_baseline_files():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT path, hash, size FROM baseline", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 200", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def show_main_dashboard():
    st.title("🛡️ Real-Time File Integrity Monitor")
    st.caption("PUSL3190 Final Year Project")
    
    baseline_df = get_baseline_files()
    alerts_df = get_alerts()
    
    col1, col2, col3, col4 = st.columns(4)
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
    
    st.subheader("Recent Alerts (Last 10)")
    if not alerts_df.empty:
        recent = alerts_df.head(10)[['timestamp', 'event_type', 'file_path', 'severity', 'mitre_technique']]
        st.dataframe(recent, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet.")
    
    st.subheader("Alerts by MITRE ATT&CK Technique")
    if not alerts_df.empty:
        summary = alerts_df.groupby('mitre_technique').size().reset_index(name='count')
        st.bar_chart(summary.set_index('mitre_technique'))
    else:
        st.info("No data yet.")
    
    time.sleep(3)
    st.rerun()


def show_alerts_page():
    st.title("📋 All Alerts")
    
    alerts_df = get_alerts()
    
    if alerts_df.empty:
        st.info("No alerts yet.")
        return
    
    col1, col2, col3 = st.columns(3)
    with col1:
        event_filter = st.selectbox("Event Type", ["All"] + list(alerts_df['event_type'].unique()))
    with col2:
        severity_filter = st.selectbox("Severity", ["All"] + list(alerts_df['severity'].unique()))
    with col3:
        search = st.text_input("Search file path")
    
    filtered = alerts_df.copy()
    if event_filter != "All":
        filtered = filtered[filtered['event_type'] == event_filter]
    if severity_filter != "All":
        filtered = filtered[filtered['severity'] == severity_filter]
    if search:
        filtered = filtered[filtered['file_path'].str.contains(search, case=False, na=False)]
    
    st.write(f"Showing {len(filtered)} of {len(alerts_df)} alerts")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    
    csv = filtered.to_csv(index=False).encode('utf-8')
    st.download_button("Download CSV", csv, "alerts.csv", "text/csv")


def show_configuration():
    if st.session_state.role != "admin":
        st.error("Access denied. Admin only.")
        return
    
    st.title("⚙️ System Configuration")
    
    tab1, tab2 = st.tabs(["Monitored Paths", "Severity Rules"])
    
    with tab1:
        st.subheader("Currently Monitored Paths")
        paths = get_monitored_paths()
        if paths:
            paths_df = pd.DataFrame(paths, columns=['ID', 'Path', 'Enabled', 'Added By', 'Added At'])
            st.dataframe(paths_df, use_container_width=True, hide_index=True)
        else:
            st.info("No monitored paths configured.")
        
        st.divider()
        st.subheader("Add Monitored Path")
        with st.form("add_path_form"):
            new_path = st.text_input("Folder path (e.g., D:\\FIM_Project123\\Web_Server_Files)")
            if st.form_submit_button("Add Path"):
                if new_path:
                    success, msg = add_monitored_path(new_path, st.session_state.username)
                    if success:
                        st.success(msg)
                        st.warning("Restart monitor.py to apply changes")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)
        
        st.subheader("Remove Path")
        if paths:
            path_options = [p[1] for p in paths]
            path_to_remove = st.selectbox("Select path to remove", path_options)
            if st.button("Remove Path", type="primary"):
                remove_monitored_path(path_to_remove, st.session_state.username)
                st.success("Path removed")
                time.sleep(1)
                st.rerun()
    
    with tab2:
        st.subheader("Current Severity Rules")
        rules = get_severity_rules()
        if rules:
            rules_df = pd.DataFrame(rules, columns=['ID', 'Rule Name', 'Pattern', 'Severity', 'Enabled'])
            st.dataframe(rules_df, use_container_width=True, hide_index=True)
        else:
            st.info("No severity rules configured.")
        
        st.divider()
        st.subheader("Add Severity Rule")
        with st.form("add_rule_form"):
            rule_name = st.text_input("Rule name (e.g., 'Critical config files')")
            pattern = st.text_input("File pattern (e.g., '.env' or 'config' or '.conf')")
            severity = st.selectbox("Severity", ["HIGH", "MEDIUM", "LOW"])
            if st.form_submit_button("Add Rule"):
                if rule_name and pattern:
                    add_severity_rule(rule_name, pattern, severity, st.session_state.username)
                    st.success("Rule added")
                    time.sleep(1)
                    st.rerun()
        
        st.subheader("Remove Rule")
        if rules:
            rule_options = {f"{r[0]}: {r[1]}": r[0] for r in rules}
            selected = st.selectbox("Select rule to remove", list(rule_options.keys()))
            if st.button("Remove Rule", type="primary"):
                remove_severity_rule(rule_options[selected], st.session_state.username)
                st.success("Rule removed")
                time.sleep(1)
                st.rerun()


def show_user_management():
    if st.session_state.role != "admin":
        st.error("Access denied. Admin only.")
        return
    
    st.title("👥 User Management")
    
    users = get_all_users()
    
    st.subheader("Existing Users")
    if users:
        users_df = pd.DataFrame(users, columns=['ID', 'Username', 'Role', 'Created', 'Last Login'])
        st.dataframe(users_df, use_container_width=True, hide_index=True)
    
    st.divider()
    
    st.subheader("Create New User")
    with st.form("create_user_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input("Password (min 8 chars)", type="password")
        new_role = st.selectbox("Role", ["admin", "analyst"])
        if st.form_submit_button("Create User"):
            if new_username and new_password:
                success, msg = create_user(new_username, new_password, new_role)
                if success:
                    st.success(msg)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(msg)
    
    st.divider()
    
    st.subheader("Delete User")
    if users:
        usernames = [u[1] for u in users if u[1] != st.session_state.username]
        if usernames:
            user_to_delete = st.selectbox("Select user to delete", usernames)
            if st.button("Delete User", type="primary"):
                delete_user(user_to_delete)
                st.success(f"User {user_to_delete} deleted")
                time.sleep(1)
                st.rerun()


def show_audit_log():
    st.title("📜 Audit Log")
    st.caption("All security-relevant actions logged for accountability")
    
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    
    if df.empty:
        st.info("No audit logs yet.")
        return
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Export Audit Log (CSV)", csv, "audit_log.csv", "text/csv")

def show_chain_verify():
    st.title("🔗 Tamper-Evident Audit Chain")
    st.caption("Cryptographic verification of alert log integrity")
    
    if st.button("Verify Chain Integrity", type="primary"):
        with st.spinner("Verifying chain..."):
            valid, message = verify_chain()
            if valid:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ TAMPERING DETECTED: {message}")
    
    st.divider()
    st.subheader("Chain Entries")
    
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT id, timestamp, alert_data, prev_hash, entry_hash FROM chained_alerts ORDER BY id DESC LIMIT 50", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    
    if df.empty:
        st.info("No chain entries yet. Generate alerts to populate the chain.")
        return
    
    df['prev_hash'] = df['prev_hash'].apply(lambda x: x[:16] + '...' if len(x) > 16 else x)
    df['entry_hash'] = df['entry_hash'].apply(lambda x: x[:16] + '...' if len(x) > 16 else x)
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    st.info("Each entry's hash includes the previous entry's hash. Tampering with any entry breaks the chain and is detectable.")  


# === MAIN ROUTING ===
if not st.session_state.logged_in:
    show_login()
elif st.session_state.force_password_change:
    show_force_password_change()
else:
    show_dashboard()