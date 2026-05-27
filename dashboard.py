import streamlit as st
import pandas as pd

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="Phishing Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Load CSV
# -----------------------------
df = pd.read_csv("phishing_history.csv")

# -----------------------------
# Stats
# -----------------------------
total_records = len(df)
safe_count = len(df[df["status"] == "Safe"])
risky_count = len(df[df["status"] != "Safe"])
max_risk = df["risk_score"].max()

# -----------------------------
# Header
# -----------------------------
st.title("🛡️ Phishing Detection History")
st.caption("Recent browsing activity and phishing analysis")

# -----------------------------
# Metrics
# -----------------------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Records", total_records)
col2.metric("Safe URLs", safe_count)
col3.metric("Risky URLs", risky_count)
col4.metric("Highest Risk Score", max_risk)

st.divider()

# -----------------------------
# Risk Score Progress Bar
# -----------------------------
def risk_label(score):
    if score < 30:
        return "🟢 Low"
    elif score < 60:
        return "🟠 Medium"
    else:
        return "🔴 High"

# -----------------------------
# Table UI
# -----------------------------
st.subheader("Browsing Records")

for index, row in df.iterrows():

    with st.container(border=True):

        col1, col2 = st.columns([4, 1])

        with col1:
            st.markdown(f"### `{row['url']}`")
            st.caption(row["time"])

        with col2:
            if row["status"] == "Safe":
                st.success(row["status"])
            else:
                st.error(row["status"])

        st.write(f"**Risk Score:** {row['risk_score']} ({risk_label(row['risk_score'])})")

        st.progress(int(row["risk_score"]))

# -----------------------------
# Optional Data Table
# -----------------------------
with st.expander("View Raw CSV Data"):
    st.dataframe(df, use_container_width=True)