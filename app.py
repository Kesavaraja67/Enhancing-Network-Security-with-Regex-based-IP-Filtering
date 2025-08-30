import os
import io
import json
import sqlite3
import random
from typing import List, Dict, Any, Tuple

import pandas as pd
import streamlit as st
import requests

# Use the safer third-party "regex" engine which supports timeouts
try:
    import regex as re
    HAS_REGEX = True
except Exception:
    import re  # fallback (no timeout)
    HAS_REGEX = False

# ---------- Load configuration ----------
# In a real app, this would be from a .env file or a secure vault
APP_NAME = "Advanced IP Filter & Threat Tracker"
ENABLE_IPV6 = True
REGEX_TIMEOUT_MS = 50
ANCHOR_PATTERNS = True
IP_GEOLOCATION_API = "http://ip-api.com/json/"

# ---------- Database Setup (using SQLite for simplicity) ----------
DB_FILE = "ip_data.db"


@st.cache_resource
def get_db_conn():
    """Initializes and returns a database connection."""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_history (
            ip TEXT,
            matched_rule TEXT,
            action TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            as_number TEXT,
            latitude REAL,
            longitude REAL,
            is_mobile BOOLEAN,
            threat_score INTEGER,
            threat_description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


# ---------- Regex building blocks ----------
OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
IPV4_FULL = rf"^(?:{OCTET}\.){{3}}{OCTET}$"
PRIVATE_IPV4 = rf"^(?:10(?:\.{OCTET}){{3}}|172\.(?:1[6-9]|2\d|3[01])(?:\.{OCTET}){{2}}|192\.168(?:\.{OCTET}){{2}})$"

IPV6_FULL = r"""^( 
    ([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4} |
    ([0-9A-Fa-f]{1,4}:){1,7}: |
    ([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4} |
    ([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2} |
    ([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3} |
    ([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4} |
    ([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5} |
    [0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6}) |
    :((:[0-9A-Fa-f]{1,4}){1,7}|:)
    )$"""
IPV6_LINK_LOCAL = r"^fe8[0-9A-Fa-f]:([0-9A-Fa-f]{0,4}:){0,6}[0-9A-Fa-f]{0,4}$"
IPV6_ULA = r"^f[cd][0-9A-Fa-f]{2}:([0-9A-Fa-f]{0,4}:){0,6}[0-9A-Fa-f]{0,4}$"

# ---------- Helpers ----------


def ensure_anchored(pat: str) -> str:
    """Adds ^ and $ to a regex pattern if not present."""
    if not ANCHOR_PATTERNS:
        return pat
    if not pat.startswith("^"):
        pat = "^" + pat
    if not pat.endswith("$"):
        pat = pat + "$"
    return pat


@st.cache_resource(show_spinner=False)
def compile_pattern(pat: str):
    """Compiles a regex pattern with verbose flag."""
    try:
        return re.compile(pat, re.VERBOSE)
    except Exception as e:
        raise ValueError(f"Invalid regex: {e}")


def safe_fullmatch(compiled, text: str) -> bool:
    """Performs a regex fullmatch with a timeout if available."""
    if HAS_REGEX:
        try:
            return compiled.fullmatch(text, timeout=REGEX_TIMEOUT_MS / 1000.0) is not None
        except re.TimeoutError:
            return False
    else:
        return compiled.fullmatch(text) is not None


def evaluate_rules(ip: str, rules: List[Dict[str, Any]]) -> Tuple[bool, str, str]:
    """Evaluates an IP against the defined regex rules."""
    ordered = sorted(rules, key=lambda r: int(r.get("priority", 9999)))
    for r in ordered:
        if not r.get("active", True):
            continue
        pat = ensure_anchored(str(r.get("pattern", "")))
        try:
            c = compile_pattern(pat)
        except ValueError:
            continue
        if safe_fullmatch(c, ip):
            action = r.get("action", "block")
            return True, str(r.get("name", "")), action
    return False, "", "allow"


def parse_uploaded_ips(file) -> List[str]:
    """Parses IPs from a CSV or TXT file."""
    name = file.name.lower()
    data = file.read()
    if name.endswith(".csv"):
        df = pd.read_csv(io.BytesIO(data))
        col = "ip" if "ip" in (c.lower()
                               for c in df.columns) else df.columns[0]
        return [str(x).strip() for x in df[col].astype(str).tolist()]
    else:
        text = data.decode("utf-8", errors="ignore")
        tokens = []
        for line in text.splitlines():
            for item in re.split(r"[\s,;]+", line.strip()):
                if item:
                    tokens.append(item)
        return tokens


def get_default_rules() -> List[Dict[str, Any]]:
    """Generates the default set of rules."""
    presets = [
        {
            "active": True,
            "name": "Private IPv4",
            "pattern": PRIVATE_IPV4,
            "action": "block",
            "priority": 1,
        },
    ]
    if ENABLE_IPV6:
        presets.extend([
            {"active": True, "name": "IPv6 Link-Local",
                "pattern": IPV6_LINK_LOCAL, "action": "block", "priority": 2},
            {"active": True,
                "name": "Private IPv6 (ULA)", "pattern": IPV6_ULA, "action": "block", "priority": 3},
            {"active": False, "name": "Any valid IPv6",
                "pattern": IPV6_FULL, "action": "allow", "priority": 20},
        ])
    return presets


@st.cache_data(show_spinner="Fetching IP details...")
def fetch_ip_details(ip: str) -> Dict[str, Any]:
    """Fetches geolocation and other details for a given IP address."""
    try:
        response = requests.get(f"{IP_GEOLOCATION_API}{ip}", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as_number": data.get("as", ""),
                "latitude": data.get("lat", None),
                "longitude": data.get("lon", None),
                "is_mobile": data.get("mobile", False)
            }
    except requests.exceptions.RequestException as e:
        st.warning(f"Could not fetch details for {ip}: {e}")
    return {"latitude": None, "longitude": None}


def analyze_ip_threat(ip: str) -> Dict[str, Any]:
    """
    Simulates a call to a threat intelligence API to get a safety score.
    Returns a score from 0-100 and a description.
    """
    # Simple logic for demonstration purposes
    if ip.startswith(("10.", "172.16", "192.168", "fe80", "fc")):
        return {"threat_score": 0, "description": "Private/Safe IP"}

    score = random.randint(0, 100)
    if score < 20:
        return {"threat_score": score, "description": "Low risk"}
    elif score < 60:
        return {"threat_score": score, "description": "Medium risk, associated with general traffic."}
    elif score < 90:
        return {"threat_score": score, "description": "High risk, potentially associated with spam or botnets."}
    else:
        return {"threat_score": score, "description": "Very high risk, known malicious IP."}


def save_results_to_db(results: List[Dict[str, Any]], conn: sqlite3.Connection):
    """Saves a list of results to the database."""
    c = conn.cursor()
    for r in results:
        details = fetch_ip_details(r["ip"])
        threat_info = analyze_ip_threat(r["ip"])
        c.execute("""
            INSERT INTO ip_history (ip, matched_rule, action, country, city, isp, org, as_number, latitude, longitude, is_mobile, threat_score, threat_description) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r["ip"],
            r["matched_rule"],
            r["action"],
            details.get("country"),
            details.get("city"),
            details.get("isp"),
            details.get("org"),
            details.get("as_number"),
            details.get("latitude"),
            details.get("longitude"),
            details.get("is_mobile"),
            threat_info.get("threat_score"),
            threat_info.get("description")
        ))
    conn.commit()


# ---------- UI Layout ----------
st.set_page_config(page_title=APP_NAME, page_icon="🕵️", layout="wide")
st.title(f"🕵️ {APP_NAME}")
st.caption(
    "Regex-based IP filtering with geolocation, mobile detection, and threat analysis."
)
conn = get_db_conn()

# Initialize session state for rules
if "rules" not in st.session_state:
    st.session_state.rules = get_default_rules()

# Tabs for different functionalities
tab1, tab2 = st.tabs(["IP Evaluator", "Tracking Dashboard"])

with tab1:
    st.markdown("### 1) Define your rules")
    rules_df = pd.DataFrame(st.session_state.rules)
    action_options = ["block", "allow"]

    edited = st.data_editor(
        rules_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "active": st.column_config.CheckboxColumn("active"),
            "name": st.column_config.TextColumn("name", required=True),
            "pattern": st.column_config.TextColumn("pattern (regex)", required=True),
            "action": st.column_config.SelectboxColumn("action", options=action_options),
            "priority": st.column_config.NumberColumn("priority"),
        },
        hide_index=True,
        key="rules_editor",
    )
    st.session_state.rules = edited.to_dict(orient="records")

    # Rules management buttons
    colA, colB, colC = st.columns([1, 1, 1])
    with colA:
        if st.button("Reset to presets", type="secondary"):
            st.session_state.rules = get_default_rules()
            st.rerun()
    with colB:
        export_json = json.dumps(st.session_state.rules, indent=2)
        st.download_button("Export rules.json", data=export_json,
                           file_name="rules.json", mime="application/json")
    with colC:
        up = st.file_uploader(
            "", type=["json"], accept_multiple_files=False, label_visibility="collapsed")
        if up is not None:
            try:
                new_rules = json.loads(up.read().decode("utf-8"))
                if isinstance(new_rules, list):
                    st.session_state.rules = new_rules
                    st.success("Rules imported.")
                    st.rerun()
                else:
                    st.error("Invalid rules format.")
            except Exception as e:
                st.error(f"Failed to import: {e}")

    # Single IP test
    st.markdown("### 2) Test a single IP")
    test_ip = st.text_input("Enter an IP to test")
    if st.button("Test"):
        if not test_ip.strip():
            st.warning("Enter an IP.")
        else:
            ip = test_ip.strip()
            matched, rule_name, action = evaluate_rules(
                ip, st.session_state.rules)
            details = fetch_ip_details(ip)
            threat_info = analyze_ip_threat(ip)

            st.write(f"**IP:** `{ip}`")
            st.write(f"**Action:** `{action.upper()}`")
            if matched:
                st.write(f"**Matched Rule:** `{rule_name}`")
            else:
                st.write("**Matched Rule:** No rule matched")

            st.subheader("IP Details & Threat Analysis")
            if details:
                st.markdown(
                    f"**Country:** {details.get('country', 'N/A')}, **City:** {details.get('city', 'N/A')}")
                st.markdown(f"**ISP:** {details.get('isp', 'N/A')}")
                st.markdown(
                    f"**AS:** {details.get('as_number', 'N/A')} ({details.get('org', 'N/A')})")
                st.markdown(
                    f"**Connection Type:** {'Mobile' if details.get('is_mobile') else 'Wired/Other'}")
                st.markdown(
                    f"**Threat Score:** `{threat_info.get('threat_score')}/100`")
                st.markdown(
                    f"**Safety:** `{threat_info.get('description', 'N/A')}`")
            else:
                st.info("No external details found for this IP.")

            st.divider()

    # Bulk evaluation
    st.markdown("### 3) Bulk evaluate")
    left, right = st.columns(2)
    with left:
        pasted = st.text_area("Paste IPs", height=180)
    with right:
        uploaded = st.file_uploader("Upload CSV/TXT", type=["csv", "txt"])

    ips: List[str] = []
    if pasted.strip():
        ips.extend(token.strip()
                   for token in re.split(r"[\s,;]+", pasted.strip()) if token)
    if uploaded:
        try:
            ips.extend(parse_uploaded_ips(uploaded))
        except Exception as e:
            st.error(f"Could not read file: {e}")

    if st.button("Evaluate & Track", type="primary"):
        if not ips:
            st.warning("Paste or upload some IPs first.")
        else:
            results = []
            with st.spinner("Analyzing IPs..."):
                for ip in ips:
                    matched, rule_name, action = evaluate_rules(
                        ip, st.session_state.rules)
                    results.append({
                        "ip": ip,
                        "matched_rule": rule_name,
                        "action": action,
                    })
                save_results_to_db(results, conn)

            st.success(
                f"Successfully processed {len(results)} IPs and saved to database.")

with tab2:
    st.markdown("### Tracking Dashboard")
    st.caption("View historical IP analysis data.")

    # Fetch data from the database
    df_history = pd.read_sql_query("SELECT * FROM ip_history", conn)

    if df_history.empty:
        st.info(
            "No IP data in the database yet. Use the 'IP Evaluator' tab to add some.")
    else:
        st.markdown("#### IP History Table")
        st.dataframe(df_history, use_container_width=True)

        st.markdown("#### Summary Charts")

        # Action distribution
        action_counts = df_history['action'].value_counts().reset_index()
        action_counts.columns = ['Action', 'Count']
        st.markdown("##### Actions (Block vs. Allow)")
        st.bar_chart(action_counts, x="Action", y="Count")

        # Threat score distribution
        threat_counts = df_history.groupby('threat_description')[
            'ip'].count().reset_index()
        threat_counts.columns = ['Threat Description', 'Count']
        st.markdown("##### Threat Score Distribution")
        st.bar_chart(threat_counts, x="Threat Description", y="Count")

        # Top Countries
        country_counts = df_history['country'].value_counts(
        ).reset_index().head(10)
        country_counts.columns = ['Country', 'Count']
        st.markdown("##### Top 10 Countries")
        st.bar_chart(country_counts, x="Country", y="Count")

        # Map of IP locations
        st.markdown("##### IP Locations on a Map")
        # Filter out rows with null latitudes or longitudes before passing to the map
        df_map_data = df_history.dropna(subset=['latitude', 'longitude'])

        if not df_map_data.empty:
            st.map(df_map_data.rename(
                columns={"latitude": "lat", "longitude": "lon"}))
            # The image will be dynamically generated by the map function.
        else:
            st.info("No geolocatable IPs found in the history to display on the map.")

        # Download history
        csv = df_history.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Historical Data as CSV",
            data=csv,
            file_name='ip_history.csv',
            mime='text/csv',
        )

st.markdown("---")
st.caption("Tip: This is a powerful tool for analyzing web server logs or network traffic data to identify common threats and patterns.")
