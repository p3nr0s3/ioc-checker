"""
Theme helpers: inject custom CSS with configurable tint colour.
"""
from __future__ import annotations

import streamlit as st


DEFAULT_TINT = "#00D4FF"

VERDICT_COLORS = {
    "malicious":  "#FF4C4C",
    "suspicious": "#FFB74D",
    "clean":      "#4CAF82",
    "unknown":    "#78909C",
    "error":      "#B0BEC5",
}

VERDICT_ICONS = {
    "malicious":  "🔴",
    "suspicious": "🟡",
    "clean":      "🟢",
    "unknown":    "⚪",
    "error":      "⚫",
}


def get_tint() -> str:
    """Read tint from secrets or fall back to default."""
    try:
        return st.secrets.get("theme", {}).get("tint", DEFAULT_TINT)
    except Exception:
        return DEFAULT_TINT


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def inject_css(tint: str = DEFAULT_TINT) -> None:
    """Inject global dark-material CSS with configurable tint."""
    r, g, b = _hex_to_rgb(tint)

    css = f"""
<style>
/* ── Google Fonts ────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Rajdhani:wght@400;500;600;700&display=swap');

/* ── Root tokens ─────────────────────────────────────────────── */
:root {{
    --tint:          {tint};
    --tint-r:        {r};
    --tint-g:        {g};
    --tint-b:        {b};
    --tint-dim:      rgba({r},{g},{b},0.15);
    --tint-mid:      rgba({r},{g},{b},0.35);
    --tint-glow:     rgba({r},{g},{b},0.6);
    --bg-base:       #08091A;
    --bg-card:       #0F1120;
    --bg-elevated:   #161827;
    --bg-hover:      #1C1F35;
    --border:        rgba({r},{g},{b},0.18);
    --border-strong: rgba({r},{g},{b},0.45);
    --text-primary:  #E8EAFF;
    --text-secondary:#8891B3;
    --text-dim:      #525A7A;
    --font-mono:     'JetBrains Mono', monospace;
    --font-display:  'Rajdhani', sans-serif;
    --radius-sm:     6px;
    --radius-md:     10px;
    --radius-lg:     16px;
    --shadow-card:   0 4px 24px rgba(0,0,0,0.45),
                     0 0 0 1px var(--border);
    --shadow-glow:   0 0 20px var(--tint-mid);
}}

/* ── Global reset ────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {{
    background-color: var(--bg-base) !important;
    font-family: var(--font-mono) !important;
    color: var(--text-primary) !important;
}}

[data-testid="stSidebar"] {{
    background: var(--bg-card) !important;
    border-right: 1px solid var(--border) !important;
}}

/* ── Typography ──────────────────────────────────────────────── */
h1, h2, h3 {{
    font-family: var(--font-display) !important;
    letter-spacing: 0.04em;
    color: var(--text-primary) !important;
}}

h1 {{ font-size: 2.2rem !important; font-weight: 700 !important; }}
h2 {{ font-size: 1.5rem !important; font-weight: 600 !important; }}
h3 {{ font-size: 1.1rem !important; font-weight: 500 !important; }}

/* ── Buttons ─────────────────────────────────────────────────── */
.stButton > button {{
    background: var(--tint-dim) !important;
    color: var(--tint) !important;
    border: 1px solid var(--border-strong) !important;
    border-radius: var(--radius-sm) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    padding: 0.5rem 1.4rem !important;
    transition: all 0.2s ease !important;
}}
.stButton > button:hover {{
    background: var(--tint-mid) !important;
    box-shadow: var(--shadow-glow) !important;
    transform: translateY(-1px) !important;
}}

/* ── Primary action button ───────────────────────────────────── */
.stButton > button[kind="primary"] {{
    background: linear-gradient(135deg, rgba({r},{g},{b},0.8) 0%, rgba({r},{g},{b},0.4) 100%) !important;
    color: #fff !important;
    border: 1px solid var(--tint) !important;
    box-shadow: 0 2px 12px var(--tint-mid) !important;
}}
.stButton > button[kind="primary"]:hover {{
    box-shadow: 0 4px 24px var(--tint-glow) !important;
}}

/* ── Inputs & textareas ──────────────────────────────────────── */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
.stTextInput input, .stTextArea textarea {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
    transition: border-color 0.2s ease !important;
}}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {{
    border-color: var(--tint) !important;
    box-shadow: 0 0 0 2px var(--tint-dim) !important;
    outline: none !important;
}}

/* ── Selectbox ───────────────────────────────────────────────── */
[data-testid="stSelectbox"] > div > div {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
}}

/* ── Expander ────────────────────────────────────────────────── */
[data-testid="stExpander"] {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
}}
[data-testid="stExpander"] summary {{
    color: var(--tint) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
}}

/* ── Tabs ─────────────────────────────────────────────────────── */
[data-testid="stTabs"] [data-testid="stTab"] {{
    font-family: var(--font-mono) !important;
    font-size: 0.78rem !important;
    color: var(--text-secondary) !important;
    border-bottom: 2px solid transparent !important;
    transition: all 0.2s ease !important;
}}
[data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"] {{
    color: var(--tint) !important;
    border-bottom-color: var(--tint) !important;
}}

/* ── Metric cards ─────────────────────────────────────────────── */
[data-testid="stMetric"] {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    padding: 1rem !important;
}}
[data-testid="stMetricValue"] {{
    color: var(--tint) !important;
    font-family: var(--font-display) !important;
    font-size: 1.8rem !important;
    font-weight: 700 !important;
}}
[data-testid="stMetricLabel"] {{
    color: var(--text-secondary) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.7rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
}}

/* ── Divider ─────────────────────────────────────────────────── */
hr {{
    border-color: var(--border) !important;
    opacity: 1 !important;
}}

/* ── Scrollbar ───────────────────────────────────────────────── */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: var(--bg-base); }}
::-webkit-scrollbar-thumb {{
    background: var(--border-strong);
    border-radius: 3px;
}}
::-webkit-scrollbar-thumb:hover {{ background: var(--tint); }}

/* ── Custom card component ───────────────────────────────────── */
.ioc-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.4rem 1.6rem;
    margin-bottom: 0.8rem;
    box-shadow: var(--shadow-card);
    transition: border-color 0.2s ease;
    position: relative;
    overflow: hidden;
}}
.ioc-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 3px; height: 100%;
    background: var(--tint);
}}
.ioc-card:hover {{ border-color: var(--border-strong); }}

/* Verdict-specific card borders */
.ioc-card.malicious::before  {{ background: #FF4C4C; }}
.ioc-card.suspicious::before {{ background: #FFB74D; }}
.ioc-card.clean::before      {{ background: #4CAF82; }}
.ioc-card.unknown::before    {{ background: #78909C; }}

/* ── Verdict badge ───────────────────────────────────────────── */
.verdict-badge {{
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 20px;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
}}
.verdict-badge.malicious  {{ background: rgba(255,76,76,0.15);  color: #FF4C4C;  border: 1px solid rgba(255,76,76,0.4);  }}
.verdict-badge.suspicious {{ background: rgba(255,183,77,0.15); color: #FFB74D;  border: 1px solid rgba(255,183,77,0.4); }}
.verdict-badge.clean      {{ background: rgba(76,175,130,0.15); color: #4CAF82;  border: 1px solid rgba(76,175,130,0.4); }}
.verdict-badge.unknown    {{ background: rgba(120,144,156,0.15);color: #78909C;  border: 1px solid rgba(120,144,156,0.4);}}
.verdict-badge.error      {{ background: rgba(176,190,197,0.1); color: #90A4AE;  border: 1px solid rgba(176,190,197,0.2);}}

/* ── Source result chip ──────────────────────────────────────── */
.source-chip {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.3rem 0.7rem;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--text-secondary);
    margin: 0.2rem;
    cursor: default;
}}

/* ── Progress / score bar ────────────────────────────────────── */
.score-bar-container {{
    background: var(--bg-elevated);
    border-radius: 3px;
    height: 4px;
    overflow: hidden;
    margin-top: 0.3rem;
}}
.score-bar {{
    height: 4px;
    border-radius: 3px;
    transition: width 0.6s ease;
}}

/* ── Header banner ───────────────────────────────────────────── */
.app-header {{
    padding: 2rem 0 1.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
}}
.app-title {{
    font-family: var(--font-display);
    font-size: 2.4rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: var(--text-primary);
    line-height: 1.1;
}}
.app-title span {{
    color: var(--tint);
}}
.app-subtitle {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-top: 0.3rem;
}}

/* ── API status dots ─────────────────────────────────────────── */
.api-status {{
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--text-secondary);
    padding: 0.3rem 0;
}}
.api-dot {{
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.api-dot.active   {{ background: #4CAF82; box-shadow: 0 0 6px #4CAF82; }}
.api-dot.inactive {{ background: var(--text-dim); }}

/* ── Notification / info boxes ───────────────────────────────── */
[data-testid="stInfo"],
[data-testid="stWarning"],
[data-testid="stError"],
[data-testid="stSuccess"] {{
    border-radius: var(--radius-md) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.8rem !important;
}}

/* ── Sidebar labels ──────────────────────────────────────────── */
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] p {{
    font-family: var(--font-mono) !important;
    font-size: 0.78rem !important;
    color: var(--text-secondary) !important;
}}
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {{
    font-family: var(--font-display) !important;
    color: var(--text-primary) !important;
}}

/* ── Hide Streamlit branding ─────────────────────────────────── */
#MainMenu {{ visibility: hidden; }}
footer     {{ visibility: hidden; }}
header     {{ visibility: hidden; }}

/* ── DataFrame / table ───────────────────────────────────────── */
[data-testid="stDataFrame"] {{
    font-family: var(--font-mono) !important;
    font-size: 0.75rem !important;
}}
</style>
"""
    st.markdown(css, unsafe_allow_html=True)
