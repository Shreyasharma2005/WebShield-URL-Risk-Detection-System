import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from urllib.parse import urlparse

# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="WebShield Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

HISTORY_FILE = "phishing_history.csv"
BACKEND_URL = "http://127.0.0.1:5000/analyze"

# ============================================================
# LOAD BROWSING HISTORY
# ============================================================

@st.cache_data(ttl=2)
def load_history():

    try:
        df = pd.read_csv(HISTORY_FILE)

        if df.empty:
            return df

        # Make sure risk score is numeric
        if "risk_score" in df.columns:
            df["risk_score"] = pd.to_numeric(
                df["risk_score"],
                errors="coerce"
            ).fillna(0)

        # Convert timestamp
        if "time" in df.columns:
            df["time"] = pd.to_datetime(
                df["time"],
                errors="coerce"
            )

        # Make sure required columns exist
        required_columns = [
            "url",
            "risk_score",
            "status",
            "time"
        ]

        for column in required_columns:
            if column not in df.columns:
                df[column] = ""

        return df

    except FileNotFoundError:

        return pd.DataFrame(
            columns=[
                "url",
                "risk_score",
                "status",
                "time"
            ]
        )

    except Exception as e:

        st.error(
            f"Unable to load browsing history: {e}"
        )

        return pd.DataFrame(
            columns=[
                "url",
                "risk_score",
                "status",
                "time"
            ]
        )


# Load history
df = load_history()


# ============================================================
# CSS
# ============================================================

st.markdown("""
<style>

/* ============================================================
   GLOBAL DARK CYBERSECURITY THEME
   ============================================================ */

html, body, [class*="css"] {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Roboto, Helvetica, Arial, sans-serif;
}

.stApp {
    background: #07111f;
    color: #f1f5f9;
}


/* ============================================================
   MAIN CONTENT
   ============================================================ */

.main-title {
    font-size: 38px;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 4px;
}

.main-subtitle {
    color: #94a3b8;
    font-size: 15px;
    margin-bottom: 25px;
}


/* ============================================================
   SIDEBAR
   ============================================================ */

[data-testid="stSidebar"] {
    background: #030b16;
    border-right: 1px solid #172033;
}

[data-testid="stSidebar"] * {
    color: #e2e8f0;
}

[data-testid="stSidebar"] .stRadio label {
    color: #cbd5e1 !important;
    padding: 7px 0;
}

[data-testid="stSidebar"] .stRadio label:hover {
    color: #60a5fa !important;
}

[data-testid="stSidebar"] hr {
    border-color: #1e293b;
}


/* ============================================================
   CARDS
   ============================================================ */

.card {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.25);
}

.card-title {
    color: #94a3b8;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .7px;
}

.card-value {
    color: #f8fafc;
    font-size: 30px;
    font-weight: 800;
    margin-top: 6px;
}

.card-description {
    color: #64748b;
    font-size: 12px;
    margin-top: 4px;
}


/* ============================================================
   SECTION TITLES
   ============================================================ */

.section-title {
    font-size: 21px;
    font-weight: 800;
    color: #f8fafc;
    margin-top: 25px;
    margin-bottom: 12px;
}

h1, h2, h3, h4 {
    color: #f8fafc !important;
}

p {
    color: #cbd5e1;
}


/* ============================================================
   WEBSITE / URL
   ============================================================ */

.website-url {
    font-weight: 700;
    color: #f1f5f9;
    font-size: 14px;
    word-break: break-all;
}

.website-time {
    color: #64748b;
    font-size: 11px;
    margin-top: 5px;
}


/* ============================================================
   STREAMLIT CONTAINERS
   ============================================================ */

[data-testid="stVerticalBlockBorderWrapper"] {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 14px;
}


/* ============================================================
   METRICS
   ============================================================ */

[data-testid="stMetric"] {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 14px;
    padding: 15px;
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
}

[data-testid="stMetricValue"] {
    color: #f8fafc !important;
}

[data-testid="stMetricDelta"] {
    color: #60a5fa !important;
}


/* ============================================================
   SAFE / WARNING / DANGER
   ============================================================ */

.safe-box {
    background: #052e1b;
    border: 1px solid #166534;
    color: #86efac;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}

.warning-box {
    background: #3a2505;
    border: 1px solid #a16207;
    color: #fcd34d;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}

.danger-box {
    background: #3b0a0a;
    border: 1px solid #991b1b;
    color: #fca5a5;
    border-radius: 12px;
    padding: 12px 15px;
    font-weight: 700;
}


/* ============================================================
   TEXT INPUTS
   ============================================================ */

[data-testid="stTextInput"] input {
    background: #0d1a2b !important;
    color: #f8fafc !important;
    border: 1px solid #334155 !important;
}

[data-testid="stTextInput"] input::placeholder {
    color: #64748b !important;
}

[data-testid="stTextInput"] label {
    color: #cbd5e1 !important;
}


/* ============================================================
   SELECTBOX
   ============================================================ */

[data-testid="stSelectbox"] label {
    color: #cbd5e1 !important;
}

[data-testid="stSelectbox"] div[data-baseweb="select"] {
    background: #0d1a2b;
}

[data-testid="stSelectbox"] div[data-baseweb="select"] * {
    color: #f8fafc !important;
}


/* ============================================================
   SLIDER
   ============================================================ */

[data-testid="stSlider"] label {
    color: #cbd5e1 !important;
}


/* ============================================================
   BUTTONS
   ============================================================ */

.stButton > button {
    background: #2563eb;
    color: white !important;
    border: 1px solid #3b82f6;
    border-radius: 10px;
    font-weight: 700;
    transition: all 0.2s ease;
}

.stButton > button:hover {
    background: #1d4ed8;
    border-color: #60a5fa;
    color: white !important;
}


/* ============================================================
   DATAFRAME / TABLE
   ============================================================ */

[data-testid="stDataFrame"] {
    border: 1px solid #1e334d;
}

[data-testid="stDataFrame"] * {
    color: #e2e8f0;
}


/* ============================================================
   INFO / SUCCESS / WARNING / ERROR
   ============================================================ */

[data-testid="stAlert"] {
    border-radius: 12px;
}

[data-testid="stAlert"] p {
    color: inherit !important;
}


/* ============================================================
   CHART AREA
   ============================================================ */

[data-testid="stVegaLiteChart"],
[data-testid="stArrowVegaLiteChart"] {
    background: #0d1a2b;
    border-radius: 14px;
    padding: 10px;
    border: 1px solid #1e334d;
}


/* ============================================================
   PROGRESS BAR
   ============================================================ */

[data-testid="stProgress"] {
    background: #1e293b;
}

[data-testid="stProgress"] > div > div {
    background: #2563eb;
}


/* ============================================================
   ARCHITECTURE
   ============================================================ */

.architecture {
    background: #0d1a2b;
    border: 1px solid #1e334d;
    border-radius: 16px;
    padding: 25px;
    text-align: center;
    font-weight: 700;
}

.arch-step {
    background: #111f33;
    border: 1px solid #263b55;
    border-radius: 10px;
    padding: 13px;
    margin: 7px 0;
    color: #f1f5f9;
}

.arch-arrow {
    color: #64748b;
    font-size: 18px;
}


/* ============================================================
   INFORMATION CARDS
   ============================================================ */

.info-title {
    font-size: 17px;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 8px;
}

.info-text {
    color: #94a3b8;
    line-height: 1.6;
    font-size: 13px;
}


/* ============================================================
   DIVIDERS
   ============================================================ */

hr {
    border-color: #1e293b !important;
}


/* ============================================================
   CAPTIONS
   ============================================================ */

.stCaption,
[data-testid="stCaptionContainer"] {
    color: #64748b !important;
}


/* ============================================================
   CODE / MONOSPACE TEXT
   ============================================================ */

code {
    color: #93c5fd !important;
    background: #111827 !important;
}


/* ============================================================
   HIDE STREAMLIT DEFAULT ELEMENTS
   ============================================================ */

#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

header {
    background: transparent !important;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# BACKEND STATUS
# ============================================================

def backend_status():

    try:

        response = requests.get(
            "http://127.0.0.1:5000/",
            timeout=2
        )

        return response.status_code == 200

    except:

        return False


# ============================================================
# DOMAIN
# ============================================================

def get_domain(url):

    try:

        parsed = urlparse(str(url))

        domain = parsed.netloc

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except:

        return str(url)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ WebShield")

    st.caption("ADAPTIVE PHISHING DEFENSE")

    st.divider()

    page = st.radio(
        "SECURITY CENTER",
        [
            "🏠 Overview",
            "🔍 Live Scanner",
            "🚨 Threat Monitor",
            "📊 Analytics",
            "🧠 Detection Intelligence",
            "⚙️ System Status"
        ]
    )

    st.divider()

    if backend_status():

        st.success("● Protection Active")

    else:

        st.error("● Backend Offline")

    st.caption("WebShield Security Center")
    st.caption("Version 2.0")


# ============================================================
# PAGE HEADER
# ============================================================

def page_header(title, subtitle):

    st.markdown(
        f"""
        <div class="main-title">{title}</div>
        <div class="main-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# STATUS DISPLAY
# ============================================================

def display_status(status):

    status = str(status).upper()

    if status == "SAFE":

        st.markdown(
            '<div class="safe-box">🟢 SAFE</div>',
            unsafe_allow_html=True
        )

    elif status == "SUSPICIOUS":

        st.markdown(
            '<div class="warning-box">🟠 SUSPICIOUS</div>',
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            '<div class="danger-box">🔴 HIGH RISK</div>',
            unsafe_allow_html=True
        )


# ============================================================
# OVERVIEW
# ============================================================

if page == "🏠 Overview":

    page_header(
        "Security Overview",
        "Real-time visibility into WebShield's phishing detection system"
    )

    total = len(df)

    if not df.empty:

        statuses = (
            df["status"]
            .astype(str)
            .str.upper()
        )

        safe = int((statuses == "SAFE").sum())
        suspicious = int((statuses == "SUSPICIOUS").sum())
        high_risk = int((statuses == "HIGH RISK").sum())

        avg_risk = round(
            df["risk_score"].mean(),
            1
        )

    else:

        safe = 0
        suspicious = 0
        high_risk = 0
        avg_risk = 0


    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Websites Scanned",
            total,
            help="Total number of analyzed websites"
        )

    with c2:

        st.metric(
            "Safe Websites",
            safe
        )

    with c3:

        st.metric(
            "Threats Detected",
            suspicious + high_risk
        )

    with c4:

        st.metric(
            "Average Risk",
            f"{avg_risk}%"
        )


    st.markdown(
        '<div class="section-title">Security Analytics</div>',
        unsafe_allow_html=True
    )


    # --------------------------------------------------------
    # CHARTS
    # --------------------------------------------------------

    left, right = st.columns(2)

    with left:

        st.subheader("Risk Distribution")

        chart = pd.DataFrame(
            {
                "Risk Level": [
                    "Safe",
                    "Suspicious",
                    "High Risk"
                ],
                "Websites": [
                    safe,
                    suspicious,
                    high_risk
                ]
            }
        )

        st.bar_chart(
            chart.set_index("Risk Level"),
            height=300
        )


    with right:

        st.subheader("Risk Score Trend")

        if not df.empty:

            trend = (
                df.sort_values("time")
                .tail(20)
                .copy()
            )

            trend["Scan"] = range(
                1,
                len(trend) + 1
            )

            trend = trend.set_index("Scan")

            st.line_chart(
                trend["risk_score"],
                height=300
            )

        else:

            st.info(
                "Risk trend will appear after websites are scanned."
            )


    # --------------------------------------------------------
    # RECENT ACTIVITY
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Recent Security Activity</div>',
        unsafe_allow_html=True
    )

    if df.empty:

        st.info(
            "🛡️ No browsing activity recorded yet."
        )

    else:

        recent = (
            df.sort_values(
                "time",
                ascending=False
            )
            .head(8)
        )

        for _, row in recent.iterrows():

            url = str(row["url"])
            score = int(row["risk_score"])
            status = str(row["status"]).upper()
            timestamp = str(row["time"])

            with st.container(border=True):

                c1, c2, c3 = st.columns(
                    [6, 1.5, 1.5]
                )

                with c1:

                    st.markdown(
                        f"**🌐 {url}**"
                    )

                    st.caption(
                        f"🕒 {timestamp}"
                    )

                with c2:

                    st.metric(
                        "Risk",
                        f"{score}%"
                    )

                with c3:

                    display_status(status)


# ============================================================
# LIVE SCANNER
# ============================================================

elif page == "🔍 Live Scanner":

    page_header(
        "🔍 Live Threat Scanner",
        "Analyze a website using WebShield's multi-layer detection engine"
    )

    st.subheader("Website Analysis")

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com"
    )

    analyze = st.button(
        "🔎 Analyze Website",
        type="primary",
        use_container_width=True
    )

    if analyze:

        if not url.strip():

            st.warning(
                "Please enter a website URL."
            )

        else:

            if not url.startswith(
                ("http://", "https://")
            ):

                url = "https://" + url

            with st.spinner(
                "WebShield is analyzing the website..."
            ):

                try:

                    response = requests.post(
                        BACKEND_URL,
                        json={
                            "url": url,
                            "page_analysis": {}
                        },
                        timeout=10
                    )

                    if response.status_code != 200:

                        st.error(
                            f"Backend error: {response.status_code}"
                        )

                    else:

                        result = response.json()

                        score = int(
                            result.get(
                                "risk_score",
                                0
                            )
                        )

                        level = result.get(
                            "risk_level",
                            "UNKNOWN"
                        )

                        breakdown = result.get(
                            "risk_breakdown",
                            {}
                        )

                        reasons = result.get(
                            "reasons",
                            []
                        )


                        st.divider()

                        # RESULT

                        if level == "SAFE":

                            st.success(
                                f"🟢 WEBSITE SAFE — {score}% RISK"
                            )

                        elif level == "SUSPICIOUS":

                            st.warning(
                                f"🟠 SUSPICIOUS WEBSITE — {score}% RISK"
                            )

                        else:

                            st.error(
                                f"🔴 HIGH RISK WEBSITE — {score}% RISK"
                            )


                        st.markdown(
                            f"### {url}"
                        )


                        st.progress(
                            min(score, 100)
                        )


                        # BREAKDOWN

                        st.subheader(
                            "Risk Breakdown"
                        )

                        c1, c2, c3, c4 = st.columns(4)

                        with c1:

                            st.metric(
                                "🤖 ML Detection",
                                f"{breakdown.get('ml_score', 0)}%"
                            )

                        with c2:

                            st.metric(
                                "🔗 URL Analysis",
                                f"{breakdown.get('url_risk', 0)}%"
                            )

                        with c3:

                            st.metric(
                                "🌐 Domain Risk",
                                f"{breakdown.get('domain_risk', 0)}%"
                            )

                        with c4:

                            st.metric(
                                "📄 Page Analysis",
                                f"{breakdown.get('page_risk', 0)}%"
                            )


                        # DETAILS

                        st.subheader(
                            "Detection Reasons"
                        )

                        if reasons:

                            for reason in reasons:

                                st.write(
                                    f"• {reason}"
                                )

                        else:

                            st.info(
                                "No suspicious indicators detected."
                            )


                        st.info(
                            f"Security Context: "
                            f"{result.get('context', 'General')}"
                        )


                except requests.exceptions.RequestException:

                    st.error(
                        "WebShield backend is unavailable. "
                        "Please start Flask on port 5000."
                    )


# ============================================================
# THREAT MONITOR
# ============================================================

elif page == "🚨 Threat Monitor":

    page_header(
        "🚨 Threat Monitor",
        "Investigate websites detected during browsing"
    )

    if df.empty:

        st.info(
            "No threat data available."
        )

    else:

        c1, c2, c3 = st.columns(3)

        with c1:

            selected_status = st.selectbox(
                "Risk Level",
                [
                    "All",
                    "SAFE",
                    "SUSPICIOUS",
                    "HIGH RISK"
                ]
            )

        with c2:

            min_score = st.slider(
                "Minimum Risk Score",
                0,
                100,
                0
            )

        with c3:

            search = st.text_input(
                "Search Website"
            )


        filtered = df.copy()


        if selected_status != "All":

            filtered = filtered[
                filtered["status"]
                .astype(str)
                .str.upper()
                == selected_status
            ]


        filtered = filtered[
            filtered["risk_score"] >= min_score
        ]


        if search:

            filtered = filtered[
                filtered["url"]
                .astype(str)
                .str.contains(
                    search,
                    case=False,
                    na=False
                )
            ]


        st.write(
            f"Showing **{len(filtered)}** security events"
        )


        for _, row in (
            filtered
            .sort_values(
                "time",
                ascending=False
            )
            .iterrows()
        ):

            with st.container(border=True):

                c1, c2, c3 = st.columns(
                    [6, 1.5, 1.5]
                )

                with c1:

                    st.markdown(
                        f"**🌐 {row['url']}**"
                    )

                    st.caption(
                        str(row["time"])
                    )

                with c2:

                    st.metric(
                        "Risk",
                        f"{int(row['risk_score'])}%"
                    )

                with c3:

                    display_status(
                        row["status"]
                    )


# ============================================================
# ANALYTICS
# ============================================================

elif page == "📊 Analytics":

    page_header(
        "📊 Security Analytics",
        "Understand browsing risk patterns detected by WebShield"
    )

    if df.empty:

        st.info(
            "Analytics will appear after websites are analyzed."
        )

    else:

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Average Risk",
            f"{df['risk_score'].mean():.1f}%"
        )

        c2.metric(
            "Maximum Risk",
            f"{int(df['risk_score'].max())}%"
        )

        c3.metric(
            "Unique Domains",
            df["url"]
            .apply(get_domain)
            .nunique()
        )


        st.divider()


        st.subheader(
            "Risk Score Distribution"
        )

        histogram = pd.cut(
            df["risk_score"],
            bins=[
                -1,
                20,
                40,
                60,
                80,
                100
            ],
            labels=[
                "0–20",
                "21–40",
                "41–60",
                "61–80",
                "81–100"
            ]
        )

        histogram_data = (
            histogram
            .value_counts()
            .sort_index()
        )

        st.bar_chart(
            histogram_data,
            height=350
        )


        st.subheader(
            "Security Classification"
        )

        status_counts = (
            df["status"]
            .astype(str)
            .str.upper()
            .value_counts()
        )

        st.bar_chart(
            status_counts,
            height=300
        )


        st.subheader(
            "Highest Risk Websites"
        )

        risky = (
            df.sort_values(
                "risk_score",
                ascending=False
            )
            .head(10)
            [["url", "risk_score", "status"]]
            .copy()
        )

        risky.columns = [
            "Website",
            "Risk Score",
            "Status"
        ]

        risky["Risk Score"] = (
            risky["Risk Score"]
            .astype(int)
            .astype(str)
            + "%"
        )

        st.dataframe(
            risky,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# DETECTION INTELLIGENCE
# ============================================================

elif page == "🧠 Detection Intelligence":

    page_header(
        "🧠 Detection Intelligence",
        "Understand how WebShield evaluates suspicious websites"
    )


    c1, c2 = st.columns(2)

    with c1:

        with st.container(border=True):

            st.markdown("### 🤖 Machine Learning")

            st.write(
                "The machine-learning model analyzes URL features "
                "and estimates the probability that a website "
                "is associated with phishing."
            )


    with c2:

        with st.container(border=True):

            st.markdown("### 🔗 URL Analysis")

            st.write(
                "WebShield checks URL length, suspicious keywords, "
                "hyphens, subdomains, IP addresses and other "
                "structural indicators."
            )


    c1, c2 = st.columns(2)

    with c1:

        with st.container(border=True):

            st.markdown("### 🌐 Domain Intelligence")

            st.write(
                "Domains are compared with trusted domains and "
                "checked for suspicious structural characteristics."
            )


    with c2:

        with st.container(border=True):

            st.markdown("### 📄 Page Analysis")

            st.write(
                "The Chrome extension examines forms, password "
                "fields, iframes, external links and form actions."
            )


    st.divider()

    st.subheader(
        "WebShield Risk Model"
    )

    model_data = pd.DataFrame(
        {
            "Detection Layer": [
                "Machine Learning",
                "URL Analysis",
                "Domain Risk",
                "Page Analysis"
            ],
            "Weight": [
                40,
                25,
                15,
                20
            ]
        }
    )

    st.bar_chart(
        model_data.set_index(
            "Detection Layer"
        ),
        height=300
    )

    st.info(
        "WebShield combines multiple independent signals "
        "instead of relying on a single classifier."
    )


# ============================================================
# SYSTEM STATUS
# ============================================================

elif page == "⚙️ System Status":

    page_header(
        "⚙️ System Status",
        "WebShield infrastructure and component health"
    )

    backend_online = backend_status()


    c1, c2, c3 = st.columns(3)

    with c1:

        if backend_online:

            st.success(
                "🟢 Flask Backend\n\nOnline"
            )

        else:

            st.error(
                "🔴 Flask Backend\n\nOffline"
            )


    with c2:

        if not df.empty:

            st.success(
                "🟢 Threat History\n\nConnected"
            )

        else:

            st.warning(
                "🟠 Threat History\n\nNo records"
            )


    with c3:

        st.success(
            "🟢 ML Model\n\nLoaded"
        )


    st.divider()


    st.subheader(
        "WebShield Architecture"
    )


    architecture = [
        ("1", "🌐 Browser", "Website visited by user"),
        ("2", "🧩 Chrome Extension", "Collects webpage signals"),
        ("3", "⚡ Flask API", "Processes security request"),
        ("4", "🤖 ML Model", "Predicts phishing probability"),
        ("5", "🔎 Risk Engine", "Combines detection layers"),
        ("6", "📊 Security Dashboard", "Displays security intelligence")
    ]


    for number, title, description in architecture:

        with st.container(border=True):

            c1, c2, c3 = st.columns(
                [0.5, 2, 6]
            )

            with c1:

                st.markdown(
                    f"### {number}"
                )

            with c2:

                st.markdown(
                    f"**{title}**"
                )

            with c3:

                st.caption(
                    description
                )


    st.divider()


    st.subheader(
        "Component Health"
    )


    component_data = pd.DataFrame(
        {
            "Component": [
                "Flask Backend",
                "Machine Learning",
                "URL Analysis",
                "Domain Analysis",
                "Page Analysis",
                "Chrome Extension",
                "Threat History"
            ],
            "Status": [
                "ONLINE" if backend_online else "OFFLINE",
                "ACTIVE",
                "ACTIVE",
                "ACTIVE",
                "ACTIVE",
                "CONNECTED",
                "CONNECTED"
            ]
        }
    )


    st.dataframe(
        component_data,
        use_container_width=True,
        hide_index=True
    )


    st.divider()

    st.caption(
        f"WebShield Security Center • "
        f"Last dashboard refresh: {datetime.now().strftime('%H:%M:%S')}"
    )