import os
import io
import json
from typing import List, Dict, Any, Tuple

import pandas as pd
import streamlit as st


# Use the safer third-party "regex" engine which supports timeouts
try:
    import regex as re
    HAS_REGEX = True
except Exception:
    import re  # fallback (no timeout)
    HAS_REGEX = False


APP_NAME = os.getenv("APP_NAME", "Regex IP Filter")
ENABLE_IPV6 = os.getenv("ENABLE_IPV6", "false").strip().lower() == "true"
REGEX_TIMEOUT_MS = int(os.getenv("REGEX_TIMEOUT_MS", "50"))
ANCHOR_PATTERNS = os.getenv(
    "ANCHOR_PATTERNS", "true").strip().lower() == "true"

# Optional default rule pulled from .env
DEFAULT_ENV_RULE = None
env_name = os.getenv("DEFAULT_REGEX_1_NAME")
env_pat = os.getenv("DEFAULT_REGEX_1_PATTERN")
env_action = os.getenv("DEFAULT_REGEX_1_ACTION", "block").lower()
env_priority = int(os.getenv("DEFAULT_REGEX_1_PRIORITY", "1"))
if env_name and env_pat:
    DEFAULT_ENV_RULE = {
        "active": True,
        "name": env_name,
        "pattern": env_pat,
        "action": env_action if env_action in {"block", "allow"} else "block",
        "priority": env_priority,
    }

# ---------- Regex building blocks ----------
OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
IPV4_FULL = rf"^(?:{OCTET}\.){{3}}{OCTET}$"
PRIVATE_IPV4 = rf"^(?:10(?:\.{OCTET}){{3}}|172\.(?:1[6-9]|2\d|3[01])(?:\.{OCTET}){{2}}|192\.168(?:\.{OCTET}){{2}})$"

# IPv6
IPV6_FULL = r"""^(     ([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4} |
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
    if not ANCHOR_PATTERNS:
        return pat
    if not pat.startswith("^"):
        pat = "^" + pat
    if not pat.endswith("$"):
        pat = pat + "$"
    return pat


@st.cache_resource(show_spinner=False)
def compile_pattern(pat: str):
    try:
        return re.compile(pat, re.VERBOSE)
    except Exception as e:
        raise ValueError(f"Invalid regex: {e}")


def safe_fullmatch(compiled, text: str) -> bool:
    if HAS_REGEX:
        try:
            return compiled.fullmatch(text, timeout=REGEX_TIMEOUT_MS / 1000.0) is not None
        except re.TimeoutError:
            return False
    else:
        return compiled.fullmatch(text) is not None


def evaluate_rules(ip: str, rules: List[Dict[str, Any]]) -> Tuple[bool, str, str]:
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
    return False, "", "allow"  # others are allowed by default


def parse_uploaded_ips(file) -> List[str]:
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


def default_rules() -> List[Dict[str, Any]]:
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
    if DEFAULT_ENV_RULE:
        presets.insert(0, DEFAULT_ENV_RULE)
    return presets


# ---------- UI ----------
st.set_page_config(page_title=APP_NAME, page_icon="🧩", layout="wide")
st.title(f"🧩 {APP_NAME}")
st.caption(
    "Regex-based IP filtering: Blocks Private IPs automatically; others are allowed.")

if "rules" not in st.session_state:
    st.session_state.rules = default_rules()

# Sidebar
with st.sidebar:
    st.subheader("Quick Start")
    st.markdown(
        """1. Edit rules. 2. Paste or upload IPs. 3. Click Evaluate. 4. Export results."""
    )
    st.divider()
    st.checkbox("Auto-anchor patterns (^...$)",
                value=ANCHOR_PATTERNS, key="anchor_box")
    st.caption(
        f"Regex engine: {'regex (with timeout)' if HAS_REGEX else 're (no timeout)'}")

# Rules editor
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

# Reset/export/import
colA, colB, colC = st.columns([1, 1, 1])
with colA:
    if st.button("Reset to presets", type="secondary"):
        st.session_state.rules = default_rules()
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
        matched, rule_name, action = evaluate_rules(
            test_ip.strip(), st.session_state.rules)
        if matched:
            st.success(
                f"Matched rule: *{rule_name}* → action: *{action.upper()}*")
        else:
            st.info("No rule matched → action: allow")

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

if st.button("Evaluate", type="primary"):
    if not ips:
        st.warning("Paste or upload some IPs first.")
    else:
        results = []
        for ip in ips:
            matched, rule_name, action = evaluate_rules(
                ip, st.session_state.rules)
            results.append({
                "ip": ip,
                "matched": matched,
                "matched_rule": rule_name,
                "action": action,
            })
        df = pd.DataFrame(results)
        st.markdown("#### Results")
        st.dataframe(df, use_container_width=True, height=400)

        st.markdown("#### Summary")
        total = len(df)
        blocks = (df["action"] == "block").sum()
        allows = (df["action"] == "allow").sum()
        st.write(
            f"Total: *{total}* · Block: *{blocks}* · Allow: *{allows}*")

        st.download_button("Download CSV", data=df.to_csv(
            index=False), file_name="ip_filter_results.csv", mime="text/csv")

st.markdown("---")
st.caption("Tip: Anchored patterns prevent partial matches. Private IPs are blocked automatically; others allowed.")
