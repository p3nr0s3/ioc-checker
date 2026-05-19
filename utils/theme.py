"""
Theme helpers — Option B terminal aesthetic.
JetBrains Mono + Syne, near-black base, configurable tint accent.
"""
from __future__ import annotations

import streamlit as st


DEFAULT_TINT = "#FF6B6B"

VERDICT_COLORS = {
    "malicious":  "#FF6B6B",
    "suspicious": "#FFD93D",
    "clean":      "#50FA7B",
    "unknown":    "#3A4060",
    "error":      "#3A4060",
}

VERDICT_ICONS = {
    "malicious":  "●",
    "suspicious": "●",
    "clean":      "●",
    "unknown":    "○",
    "error":      "○",
}

SOURCE_ABBR = {
    "VirusTotal":     "VT",
    "AbuseIPDB":      "AB",
    "Shodan":         "SH",
    "OTX AlienVault": "OT",
    "URLScan.io":     "US",
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
    """Inject global CSS — Option B terminal style."""
    r, g, b = _hex_to_rgb(tint)

    css = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Syne:wght@500;700&display=swap');

:root {{
    --tint:          {tint};
    --tint-r:        {r};
    --tint-g:        {g};
    --tint-b:        {b};
    --tint-dim:      rgba({r},{g},{b},0.08);
    --tint-mid:      rgba({r},{g},{b},0.18);
    --tint-border:   rgba({r},{g},{b},0.28);
    --bg-base:       #06070F;
    --bg-surface:    #0B0D1A;
    --bg-row-hover:  #111428;
    --border-dim:    rgba(255,255,255,0.05);
    --border-mid:    rgba(255,255,255,0.09);
    --text-primary:  #C8D0E8;
    --text-secondary:#4A5578;
    --text-dim:      #262B40;
    --font-mono:     'JetBrains Mono', monospace;
    --font-display:  'Syne', sans-serif;
    --v-mal:         #FF6B6B;
    --v-sus:         #FFD93D;
    --v-cln:         #50FA7B;
    --v-unk:         #3A4060;
}}

/* ── Base ───────────────────────────────────────────── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"] {{
    background-color: var(--bg-base) !important;
    font-family: var(--font-mono) !important;
    color: var(--text-primary) !important;
}}

/* ── Hide sidebar ───────────────────────────────────── */
[data-testid="stSidebar"],
[data-testid="collapsedControl"] {{
    display: none !important;
}}
.stMainBlockContainer {{
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    max-width: 1200px !important;
}}

/* ── Typography ─────────────────────────────────────── */
h1, h2, h3 {{
    font-family: var(--font-display) !important;
    color: var(--text-primary) !important;
    letter-spacing: 0.04em;
}}

/* ── Topbar ─────────────────────────────────────────── */
.tc-topbar {{
    display: flex;
    align-items: stretch;
    background: var(--bg-base);
    border-bottom: 1px solid var(--border-dim);
    height: 48px;
    margin-bottom: 24px;
    margin-left: -1.5rem;
    margin-right: -1.5rem;
    padding: 0 1.5rem;
}}
.tc-logo {{
    font-family: var(--font-display);
    font-size: 14px;
    font-weight: 700;
    color: var(--tint);
    letter-spacing: 0.05em;
    display: flex;
    align-items: center;
    gap: 9px;
    margin-right: 32px;
    flex-shrink: 0;
}}
.tc-logo-sq {{
    width: 15px;
    height: 15px;
    background: var(--tint);
    border-radius: 3px;
    transform: rotate(45deg);
    flex-shrink: 0;
}}
.tc-nav {{ display: flex; height: 100%; }}
.tc-tab {{
    padding: 0 18px;
    height: 100%;
    display: inline-flex;
    align-items: center;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    border-bottom: 1px solid transparent;
    letter-spacing: 0.08em;
    white-space: nowrap;
}}
.tc-tab.active {{
    color: var(--tint);
    border-bottom-color: var(--tint);
    background: var(--tint-dim);
}}
.tc-right {{
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 14px;
}}
.tc-dots {{ display: flex; gap: 5px; align-items: center; }}
.tc-dot {{
    width: 7px;
    height: 7px;
    border-radius: 50%;
}}
.tc-dot.on  {{ background: #50FA7B; }}
.tc-dot.off {{ background: var(--text-dim); }}
.tc-tint-swatch {{
    width: 18px;
    height: 18px;
    border-radius: 3px;
    background: var(--tint);
    opacity: 0.75;
    cursor: pointer;
    border: 1px solid var(--tint-border);
}}

/* ── Stat strip ─────────────────────────────────────── */
.tc-stats {{
    display: flex;
    gap: 1px;
    margin-bottom: 20px;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--border-dim);
}}
.tc-stat {{
    flex: 1;
    background: var(--bg-surface);
    padding: 10px 16px;
    border-top: 2px solid transparent;
}}
.tc-stat.mal {{ border-top-color: var(--v-mal); }}
.tc-stat.sus {{ border-top-color: var(--v-sus); }}
.tc-stat.cln {{ border-top-color: var(--v-cln); }}
.tc-stat.tot {{ border-top-color: var(--tint);  }}
.tc-stat-num {{
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 600;
    line-height: 1;
    margin-bottom: 3px;
}}
.tc-stat-num.mal {{ color: var(--v-mal); }}
.tc-stat-num.sus {{ color: var(--v-sus); }}
.tc-stat-num.cln {{ color: var(--v-cln); }}
.tc-stat-num.tot {{ color: var(--tint);  }}
.tc-stat-lbl {{
    font-size: 9px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-family: var(--font-mono);
}}

/* ── Shell prompt ───────────────────────────────────── */
.tc-shell-wrap {{
    display: flex;
    align-items: stretch;
    background: var(--bg-surface);
    border: 1px solid var(--tint-border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 16px;
}}
.tc-prompt {{
    padding: 0 14px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--tint);
    border-right: 1px solid var(--tint-dim);
    background: var(--tint-dim);
    white-space: nowrap;
    display: flex;
    align-items: center;
    flex-shrink: 0;
}}

/* Input inside shell — override Streamlit */
.tc-shell-wrap [data-testid="stTextInput"],
.tc-shell-wrap [data-testid="stTextInput"] > div {{
    flex: 1 !important;
    border: none !important;
    background: transparent !important;
    padding: 0 !important;
    box-shadow: none !important;
}}
.tc-shell-wrap [data-testid="stTextInput"] input {{
    background: transparent !important;
    border: none !important;
    border-radius: 0 !important;
    padding: 10px 14px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    color: var(--text-primary) !important;
    box-shadow: none !important;
    outline: none !important;
}}
.tc-shell-wrap [data-testid="stTextInput"] input::placeholder {{
    color: var(--text-dim) !important;
}}

/* ── Table ──────────────────────────────────────────── */
.tc-thead {{
    display: grid;
    grid-template-columns: 2.2fr 72px 130px 110px 92px;
    padding: 7px 14px;
    border-bottom: 1px solid var(--border-dim);
}}
.tc-th {{
    font-size: 9px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-family: var(--font-mono);
}}
.tc-th.right {{ text-align: right; }}
.tc-row {{
    display: grid;
    grid-template-columns: 2.2fr 72px 130px 110px 92px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-dim);
    align-items: center;
    font-family: var(--font-mono);
    transition: background 0.1s;
    cursor: pointer;
}}
.tc-row:hover {{ background: var(--bg-row-hover); }}
.tc-ioc {{
    font-size: 12px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    padding-right: 10px;
}}
.tc-ioc-type {{
    font-size: 10px;
    color: var(--text-secondary);
}}
.tc-score-wrap {{
    display: flex;
    align-items: center;
    gap: 7px;
    padding-right: 8px;
}}
.tc-score-bg {{
    flex: 1;
    height: 3px;
    background: var(--bg-base);
    border-radius: 2px;
    overflow: hidden;
}}
.tc-score-fill {{
    height: 100%;
    border-radius: 2px;
}}
.tc-score-val {{ font-size: 10px; min-width: 22px; text-align: right; }}
.tc-srcs {{ display: flex; gap: 3px; }}
.tc-sq {{
    width: 16px;
    height: 16px;
    border-radius: 2px;
    font-size: 8px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
    letter-spacing: 0;
}}
.tc-sq.mal {{ background: rgba(255,107,107,0.18); color: #FF6B6B; }}
.tc-sq.cln {{ background: rgba(80,250,123,0.10);  color: #50FA7B; }}
.tc-sq.unk {{ background: var(--bg-surface); color: var(--text-dim); }}
.tc-verdict {{ font-size: 10px; text-align: right; font-weight: 500; letter-spacing: 0.06em; }}
.tc-verdict.mal {{ color: var(--v-mal); }}
.tc-verdict.sus {{ color: var(--v-sus); }}
.tc-verdict.cln {{ color: var(--v-cln); }}
.tc-verdict.unk {{ color: var(--text-secondary); }}

/* ── Source detail panel ────────────────────────────── */
.tc-detail {{
    background: var(--bg-surface);
    border: 1px solid var(--border-dim);
    border-radius: 6px;
    padding: 14px 18px;
    margin: 4px 0 12px;
}}
.tc-detail-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 8px;
}}
.tc-src-card {{
    background: var(--bg-base);
    border: 1px solid var(--border-dim);
    border-radius: 4px;
    padding: 10px 12px;
}}
.tc-src-header {{
    font-size: 10px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 7px;
    display: flex;
    align-items: center;
    gap: 6px;
}}
.tc-src-vdot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.tc-kv {{
    display: flex;
    justify-content: space-between;
    gap: 8px;
    padding: 2px 0;
    font-size: 10px;
}}
.tc-kv-k {{ color: var(--text-secondary); white-space: nowrap; }}
.tc-kv-v {{
    color: var(--text-primary);
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 55%;
}}
.tc-link {{
    display: inline-block;
    margin-top: 7px;
    font-size: 10px;
    color: var(--tint);
    text-decoration: none;
    opacity: 0.65;
}}
.tc-link:hover {{ opacity: 1; }}

/* ── Bulk hint ──────────────────────────────────────── */
.tc-hint {{
    margin-top: 8px;
    padding: 10px 14px;
    background: var(--tint-dim);
    border: 1px dashed var(--tint-border);
    border-radius: 6px;
    font-size: 10px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    text-align: center;
}}

/* ── Section label ──────────────────────────────────── */
.tc-section {{
    font-size: 9px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-family: var(--font-mono);
    margin-bottom: 8px;
    padding-bottom: 5px;
    border-bottom: 1px solid var(--border-dim);
}}

/* ── Buttons ────────────────────────────────────────── */
.stButton > button {{
    background: transparent !important;
    color: var(--tint) !important;
    border: 1px solid var(--tint-border) !important;
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    padding: 0.45rem 1.2rem !important;
    transition: background 0.15s !important;
}}
.stButton > button:hover {{
    background: var(--tint-dim) !important;
}}
.stButton > button[kind="primary"] {{
    background: var(--tint) !important;
    color: #06070F !important;
    border-color: var(--tint) !important;
    font-weight: 700 !important;
}}
.stButton > button[kind="primary"]:hover {{
    opacity: 0.85 !important;
}}

/* ── Selectbox ──────────────────────────────────────── */
[data-testid="stSelectbox"] > div > div {{
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 4px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
}}

/* ── Textarea ───────────────────────────────────────── */
[data-testid="stTextArea"] textarea {{
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    line-height: 1.6 !important;
}}
[data-testid="stTextArea"] textarea:focus {{
    border-color: var(--tint-border) !important;
    box-shadow: none !important;
    outline: none !important;
}}

/* ── Streamlit tabs ─────────────────────────────────── */
[data-testid="stTabs"] [data-testid="stTab"] {{
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    letter-spacing: 0.06em !important;
    color: var(--text-secondary) !important;
}}
[data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"] {{
    color: var(--tint) !important;
    border-bottom-color: var(--tint) !important;
}}

/* ── Alerts ─────────────────────────────────────────── */
[data-testid="stInfo"],
[data-testid="stWarning"],
[data-testid="stError"],
[data-testid="stSuccess"] {{
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    background: var(--bg-surface) !important;
}}

/* ── Progress ───────────────────────────────────────── */
[data-testid="stProgressBar"] > div {{
    background: var(--bg-surface) !important;
    border-radius: 2px !important;
    height: 3px !important;
}}
[data-testid="stProgressBar"] > div > div {{
    background: var(--tint) !important;
    border-radius: 2px !important;
}}

/* ── DataFrame ──────────────────────────────────────── */
[data-testid="stDataFrame"] {{
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
}}

/* ── Scrollbar ──────────────────────────────────────── */
::-webkit-scrollbar {{ width: 4px; height: 4px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{
    background: var(--border-mid);
    border-radius: 2px;
}}

/* ── Divider ────────────────────────────────────────── */
hr {{
    border-color: var(--border-dim) !important;
    opacity: 1 !important;
}}

/* ── Caption ────────────────────────────────────────── */
[data-testid="stCaptionContainer"] p {{
    font-family: var(--font-mono) !important;
    font-size: 10px !important;
    color: var(--text-secondary) !important;
}}

/* ── Download button ────────────────────────────────── */
[data-testid="stDownloadButton"] > button {{
    background: transparent !important;
    color: var(--text-secondary) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 10px !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    padding: 0.35rem 0.8rem !important;
}}
[data-testid="stDownloadButton"] > button:hover {{
    border-color: var(--tint-border) !important;
    color: var(--tint) !important;
}}

/* ── Color picker ───────────────────────────────────── */
[data-testid="stColorPicker"] {{
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
}}

/* ── Hide chrome ────────────────────────────────────── */
#MainMenu {{ visibility: hidden; }}
footer     {{ visibility: hidden; }}
header     {{ visibility: hidden; }}
</style>
"""
    st.markdown(css, unsafe_allow_html=True)


def topbar_html(active_tab: str, api_keys: dict[str, str]) -> str:
    """Render topbar with active tab indicator and API dot status."""
    tabs = [
        ("single",  "/ scan"),
        ("bulk",    "/ bulk"),
        ("history", "/ history"),
    ]
    tabs_html = "".join(
        f'<span class="tc-tab{" active" if k == active_tab else ""}">{label}</span>'
        for k, label in tabs
    )

    source_keys = ["virustotal", "abuseipdb", "shodan", "otx", "urlscan"]
    dots_html = "".join(
        f'<div class="tc-dot {"on" if api_keys.get(k, "").strip() else "off"}" '
        f'title="{k}"></div>'
        for k in source_keys
    )

    return f"""
<div class="tc-topbar">
  <div class="tc-logo"><div class="tc-logo-sq"></div>THREAT·CHECK</div>
  <div class="tc-nav">{tabs_html}</div>
  <div class="tc-right">
    <div class="tc-dots">{dots_html}</div>
  </div>
</div>
"""


def stat_strip_html(
    malicious: int, suspicious: int, clean: int, total: int
) -> str:
    """4-cell stat strip."""
    return f"""
<div class="tc-stats">
  <div class="tc-stat mal"><div class="tc-stat-num mal">{malicious}</div>
    <div class="tc-stat-lbl">Malicious</div></div>
  <div class="tc-stat sus"><div class="tc-stat-num sus">{suspicious}</div>
    <div class="tc-stat-lbl">Suspicious</div></div>
  <div class="tc-stat cln"><div class="tc-stat-num cln">{clean}</div>
    <div class="tc-stat-lbl">Clean</div></div>
  <div class="tc-stat tot"><div class="tc-stat-num tot">{total}</div>
    <div class="tc-stat-lbl">Total</div></div>
</div>
"""
