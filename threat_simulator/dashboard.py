import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="AI-SIEM Security Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Enterprise AI-SIEM Security Incident Center")
st.markdown("Real-time telemetry tracking events ingested by Java Multi-threading and analyzed by Python Machine Learning models.")

# 2. FETCH DATA FROM DB
def load_db_data():
    if not pd.io.common.file_exists("siem_system.db"):
        st.error("Could not locate 'siem_system.db'. Make sure it's in the current folder!")
        return pd.DataFrame()
    
    conn = sqlite3.connect("siem_system.db")
    query = "SELECT id, alert_time, source_ip, username, endpoint, risk_score, attack_type, details FROM security_alerts"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

df = load_db_data()

if not df.empty:
    # 3. TOP KPI METRICS CARDS
    total_alerts = len(df)
    critical_alerts = len(df[df['risk_score'] == 5])
    warning_alerts = len(df[df['risk_score'] == 3])
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Ingested Alerts", total_alerts)
    col2.metric("🔴 Critical Threats (AI Caught)", critical_alerts)
    col3.metric("🟡 Warnings (Java Caught)", warning_alerts)
    
    st.markdown("---")
    
    # 4. DATA VISUALIZATION CHARTS
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.subheader("📊 Incidents Breakdown by Vector")
        fig_pie = px.pie(df, names='attack_type', color_discrete_sequence=px.colors.sequential.RdBu, hole=0.4)
        st.plotly_chart(fig_pie, use_container_width=True)
        
    with chart_col2:
        st.subheader("🔥 Top 5 Malicious IP Addresses")
        ip_counts = df['source_ip'].value_counts().reset_index().head(5)
        ip_counts.columns = ['IP Address', 'Incident Count']
        fig_bar = px.bar(ip_counts, x='IP Address', y='Incident Count', color='Incident Count', color_continuous_scale='Reds')
        st.plotly_chart(fig_bar, use_container_width=True)
        
    st.markdown("---")
    
    # 5. LIVE REPOSITORY LOG FILE TABLE
    st.subheader("📋 Centralized Threat Log Registry")
    st.dataframe(df.sort_values(by='id', ascending=False), use_container_width=True)
else:
    st.warning("No data found in your security alerts repository yet.")
