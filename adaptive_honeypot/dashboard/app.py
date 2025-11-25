# dashboard/app.py
import streamlit as st
import requests
import pandas as pd
import time

BACKEND = "http://localhost:5000"

st.title("Adaptive Honeypot Dashboard (Dev)")

if st.button("Refresh logs"):
    pass

try:
    r = requests.get(f"{BACKEND}/logs", timeout=2)
    rows = r.json()
    if rows:
        df = pd.DataFrame(rows)
        # safe formatting
        if 'ts' in df.columns:
            df['time'] = pd.to_datetime(df['ts'], unit='s')
            st.write("Latest logs")
            st.dataframe(df.sort_values('ts', ascending=False).head(50))
        else:
            st.dataframe(df.head(50))
    else:
        st.write("No logs yet")
except Exception as e:
    st.write("Error connecting to backend:", e)

st.write("---")
st.subheader("Send simulated request")
src = st.text_input("src_ip", "1.2.3.4")
payload = st.text_area("payload", "select * from users;")
if st.button("Send"):
    try:
        resp = requests.post(f"{BACKEND}/simulate_traffic", json={"src_ip": src, "payload": payload}, timeout=3)
        st.write("Response:", resp.json())
    except Exception as e:
        st.write("Error:", e)
