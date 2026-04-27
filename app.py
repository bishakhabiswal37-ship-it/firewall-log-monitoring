import streamlit as st
import pandas as pd
import sqlite3

st.title("🔥 Firewall Log Monitoring Dashboard")

conn = sqlite3.connect("firewall.db")

df = pd.read_sql_query("SELECT * FROM logs", conn)

st.subheader("Stored Firewall Logs")
st.dataframe(df)

st.subheader("Allowed vs Denied Traffic")
action_data = pd.read_sql_query("""
SELECT action, SUM(count) as total
FROM logs
GROUP BY action
""", conn)

st.bar_chart(action_data.set_index("action"))

st.subheader("🚨 Suspicious IPs")
suspicious = pd.read_sql_query("""
SELECT source_ip, SUM(count) as deny_count
FROM logs
WHERE action='DENY'
GROUP BY source_ip
HAVING deny_count >= 1
""", conn)

st.dataframe(suspicious)

conn.close()