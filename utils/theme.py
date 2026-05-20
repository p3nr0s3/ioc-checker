"""
Theme helpers — adaptive light/dark with configurable tint.
Mode is read from secrets (theme.mode) or auto-detected via JS.
"""
from __future__ import annotations

import streamlit as st

DEFAULT_TINT = "#FF6B6B"
DEFAULT_MODE = "dark"   # "dark" | "light" | "auto"

VERDICT_COLORS = {
    "malicious":  "#FF6B6B",
    "suspicious": "#FFD93D",
    "clean":      "#50FA7B",
    "unknown":    "#6B7A99",
    "error":      "#6B7A99",
}

SOURCE_ABBR = {
    "VirusTotal":     "VT",
    "AbuseIPDB":      "AB",
    "Shodan":         "SH",
    "OTX AlienVault": "OT",
    "URLScan.io":     "US",
}


def get_tint() -> str:
    try:
        return st.secrets.get("theme", {}).get("tint", DEFAULT_TINT)
    except Exception:
        return DEFAULT_TINT


def get_mode() -> str:
    try:
        return st.secrets.get("theme", {}).get("mode", DEFAULT_MODE).lower()
    except Exception:
        return DEFAULT_MODE


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def inject_css(tint: str = DEFAULT_TINT, mode: str = DEFAULT_MODE) -> None:
    r, g, b = _hex_to_rgb(tint)

    # ── Palette tokens per mode ───────────────────────────────────
    if mode == "light":
        bg_base      = "#F4F5FA"
        bg_surface   = "#FFFFFF"
        bg_hover     = "#ECEEF6"
        border_dim   = "rgba(0,0,0,0.07)"
        border_mid   = "rgba(0,0,0,0.12)"
        text_primary = "#1A1D2E"
        text_secondary = "#5A6280"
        text_dim     = "#A0A8C0"
        topbar_bg    = "#FFFFFF"
        topbar_border = "rgba(0,0,0,0.08)"
        sq_unk_bg    = "#ECEEF6"
        sq_unk_fg    = "#A0A8C0"
        stat_bg      = "#FFFFFF"
    else:  # dark (default)
        bg_base      = "#06070F"
        bg_surface   = "#0B0D1A"
        bg_hover     = "#111428"
        border_dim   = "rgba(255,255,255,0.05)"
        border_mid   = "rgba(255,255,255,0.09)"
        text_primary = "#C8D0E8"
        text_secondary = "#4A5578"
        text_dim     = "#262B40"
        topbar_bg    = "#06070F"
        topbar_border = "rgba(255,255,255,0.05)"
        sq_unk_bg    = "#0B0D1A"
        sq_unk_fg    = "#262B40"
        stat_bg      = "#0B0D1A"

    css = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Syne:wght@500;700&display=swap');

:root {{
    --tint:           {tint};
    --tint-r:         {r};
    --tint-g:         {g};
    --tint-b:         {b};
    --tint-dim:       rgba({r},{g},{b},0.09);
    --tint-mid:       rgba({r},{g},{b},0.20);
    --tint-border:    rgba({r},{g},{b},0.30);
    --bg-base:        {bg_base};
    --bg-surface:     {bg_surface};
    --bg-hover:       {bg_hover};
    --border-dim:     {border_dim};
    --border-mid:     {border_mid};
    --text-primary:   {text_primary};
    --text-secondary: {text_secondary};
    --text-dim:       {text_dim};
    --topbar-bg:      {topbar_bg};
    --topbar-border:  {topbar_border};
    --sq-unk-bg:      {sq_unk_bg};
    --sq-unk-fg:      {sq_unk_fg};
    --stat-bg:        {stat_bg};
    --font-mono:      'JetBrains Mono', monospace;
    --font-display:   'Syne', sans-serif;
    --v-mal:          #FF6B6B;
    --v-sus:          #FFD93D;
    --v-cln:          #50FA7B;
    --v-unk:          #6B7A99;
}}

/* ── Base ─────────────────────────────────────────── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"] {{
    background-color: var(--bg-base) !important;
    font-family: var(--font-mono) !important;
    color: var(--text-primary) !important;
}}
[data-testid="stSidebar"],
[data-testid="collapsedControl"] {{
    display: none !important;
}}
.stMainBlockContainer,
[data-testid="stAppViewBlockContainer"],
.block-container {{
    max-width: 100% !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    padding-top: 62px !important;
}}

/* ── Topbar — position:fixed, true 100vw ─────────── */
.tc-topbar {{
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    width: 100vw;
    z-index: 9999;
    display: flex;
    align-items: stretch;
    background: var(--topbar-bg);
    border-bottom: 1px solid var(--topbar-border);
    height: 48px;
    padding: 0 1.5rem;
    box-sizing: border-box;
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
    width: 15px; height: 15px;
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
    font-size: 12px;
    color: var(--text-secondary);
    border-bottom: 1px solid transparent;
    letter-spacing: 0.08em;
    white-space: nowrap;
    transition: color 0.15s;
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
.tc-dot {{ width: 7px; height: 7px; border-radius: 50%; }}
.tc-dot.on  {{ background: #50FA7B; }}
.tc-dot.off {{ background: var(--text-dim); }}

/* ── Stat strip ───────────────────────────────────── */
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
    background: var(--stat-bg);
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
    font-size: 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-family: var(--font-mono);
}}

/* ── Shell prompt ─────────────────────────────────── */
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
    font-size: 12px;
    color: var(--tint);
    border-right: 1px solid var(--tint-dim);
    background: var(--tint-dim);
    white-space: nowrap;
    display: flex;
    align-items: center;
    flex-shrink: 0;
}}
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
    font-size: 13px !important;
    color: var(--text-primary) !important;
    box-shadow: none !important;
    outline: none !important;
}}
.tc-shell-wrap [data-testid="stTextInput"] input::placeholder {{
    color: var(--text-dim) !important;
}}

/* ── Results table ────────────────────────────────── */
.tc-thead {{
    display: grid;
    grid-template-columns: 2.2fr 72px 130px 110px 92px;
    padding: 7px 14px;
    border-bottom: 1px solid var(--border-dim);
    background: var(--bg-surface);
    border-radius: 6px 6px 0 0;
    border: 1px solid var(--border-dim);
    border-bottom: none;
}}
.tc-th {{
    font-size: 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-family: var(--font-mono);
}}
.tc-th.right {{ text-align: right; }}
.tc-table-body {{
    border: 1px solid var(--border-dim);
    border-radius: 0 0 6px 6px;
    overflow: hidden;
}}
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
.tc-row:last-child {{ border-bottom: none; }}
.tc-row:hover {{ background: var(--bg-hover); }}
.tc-ioc {{
    font-size: 13px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    padding-right: 10px;
}}
.tc-ioc-type {{ font-size: 11px; color: var(--text-secondary); }}
.tc-score-wrap {{
    display: flex;
    align-items: center;
    gap: 7px;
    padding-right: 8px;
}}
.tc-score-bg {{
    flex: 1;
    height: 3px;
    background: var(--border-mid);
    border-radius: 2px;
    overflow: hidden;
}}
.tc-score-fill {{ height: 100%; border-radius: 2px; }}
.tc-score-val {{ font-size: 11px; min-width: 22px; text-align: right; }}
.tc-srcs {{ display: flex; gap: 3px; }}
.tc-sq {{
    width: 16px; height: 16px;
    border-radius: 2px;
    font-size: 9px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
}}
.tc-sq.mal {{ background: rgba(255,107,107,0.18); color: #FF6B6B; }}
.tc-sq.sus {{ background: rgba(255,217,61,0.15);  color: #FFD93D; }}
.tc-sq.cln {{ background: rgba(80,250,123,0.12);  color: #50FA7B; }}
.tc-sq.unk {{ background: var(--sq-unk-bg); color: var(--sq-unk-fg); }}
.tc-verdict {{ font-size: 11px; text-align: right; font-weight: 500; letter-spacing: 0.06em; }}
.tc-verdict.mal {{ color: var(--v-mal); }}
.tc-verdict.sus {{ color: var(--v-sus); }}
.tc-verdict.cln {{ color: var(--v-cln); }}
.tc-verdict.unk {{ color: var(--text-secondary); }}

/* ── Detail panel ─────────────────────────────────── */
/* ── Detail panel wrapper ───────────────────────── */
.tc-detail {{
    background: var(--bg-surface);
    border: 1px solid var(--border-dim);
    border-radius: 8px;
    padding: 0;
    margin: 4px 0 12px;
    overflow: hidden;
}}

/* Each source = one full-width section */
.tc-detail-grid {{
    display: flex;
    flex-direction: column;
    gap: 0;
}}

/* Source section header bar */
.tc-src-card {{
    border-bottom: 1px solid var(--border-dim);
    padding: 0;
}}
.tc-src-card:last-child {{ border-bottom: none; }}

.tc-src-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 20px;
    background: var(--bg-hover);
    border-bottom: 1px solid var(--border-dim);
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}}
.tc-src-vdot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.tc-src-score-badge {{
    margin-left: auto;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
}}

/* KV table inside each source — fixed 2-col layout */
.tc-kv-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    padding: 4px 0 8px;
}}
.tc-kv {{
    display: flex;
    align-items: baseline;
    gap: 0;
    padding: 5px 20px;
    font-size: 12px;
    border-bottom: 1px solid var(--border-dim);
}}
.tc-kv:nth-last-child(-n+2) {{
    border-bottom: none;
}}
.tc-kv-k {{
    color: var(--text-secondary);
    white-space: nowrap;
    width: 160px;
    flex-shrink: 0;
    font-size: 11px;
    letter-spacing: 0.03em;
}}
.tc-kv-v {{
    color: var(--text-primary);
    font-size: 12px;
    word-break: break-word;
    white-space: normal;
    flex: 1;
    min-width: 0;
}}

/* Full-span KV row (for long values like comments, CVE lists) */
.tc-kv.full-span {{
    grid-column: 1 / -1;
    border-bottom: 1px solid var(--border-dim);
}}
.tc-kv.full-span:last-child {{ border-bottom: none; }}

/* Report link */
.tc-src-footer {{
    padding: 8px 20px;
    border-top: 1px solid var(--border-dim);
    background: var(--bg-hover);
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

/* ── Source selector ──────────────────────────────── */
.tc-src-selector {{
    display: flex;
    gap: 0;
    background: var(--bg-surface);
    border: 1px solid var(--border-dim);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 16px;
}}
.tc-src-option {{
    flex: 1;
    padding: 8px 14px;
    border-right: 1px solid var(--border-dim);
    font-family: var(--font-mono);
    font-size: 11px;
}}
.tc-src-option:last-child {{ border-right: none; }}
.tc-src-name {{
    color: var(--text-primary);
    font-weight: 500;
    margin-bottom: 2px;
}}
.tc-src-types {{
    font-size: 10px;
    color: var(--text-dim);
    letter-spacing: 0.04em;
}}
.tc-src-active .tc-src-name  {{ color: var(--tint); }}

/* ── Misc UI ──────────────────────────────────────── */
.tc-section {{
    font-size: 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-family: var(--font-mono);
    margin-bottom: 8px;
    padding-bottom: 5px;
    border-bottom: 1px solid var(--border-dim);
}}
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
.tc-mode-badge {{
    font-family: var(--font-mono);
    font-size: 9px;
    color: var(--text-dim);
    letter-spacing: 0.1em;
    padding: 2px 7px;
    border: 1px solid var(--border-dim);
    border-radius: 3px;
}}

/* ── Buttons ──────────────────────────────────────── */
.stButton > button {{
    background: transparent !important;
    color: var(--tint) !important;
    border: 1px solid var(--tint-border) !important;
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
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
    color: {"#06070F" if mode == "dark" else "#FFFFFF"} !important;
    border-color: var(--tint) !important;
    font-weight: 700 !important;
}}
.stButton > button[kind="primary"]:hover {{
    opacity: 0.85 !important;
}}

/* ── Inputs ───────────────────────────────────────── */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {{
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 13px !important;
}}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {{
    border-color: var(--tint-border) !important;
    box-shadow: none !important;
    outline: none !important;
}}

/* ── Selectbox ────────────────────────────────────── */
[data-testid="stSelectbox"] > div > div {{
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 4px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
}}

/* ── Checkboxes ───────────────────────────────────── */
[data-testid="stCheckbox"] label {{
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    color: var(--text-primary) !important;
}}

/* ── Tabs ─────────────────────────────────────────── */
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

/* ── Progress ─────────────────────────────────────── */
[data-testid="stProgressBar"] > div {{
    background: var(--border-mid) !important;
    border-radius: 2px !important;
    height: 3px !important;
}}
[data-testid="stProgressBar"] > div > div {{
    background: var(--tint) !important;
    border-radius: 2px !important;
}}

/* ── Alerts ───────────────────────────────────────── */
[data-testid="stInfo"],
[data-testid="stWarning"],
[data-testid="stError"],
[data-testid="stSuccess"] {{
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    background: var(--bg-surface) !important;
}}

/* ── Download button ──────────────────────────────── */
[data-testid="stDownloadButton"] > button {{
    background: transparent !important;
    color: var(--text-secondary) !important;
    border: 1px solid var(--border-mid) !important;
    border-radius: 4px !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    padding: 0.35rem 0.8rem !important;
}}
[data-testid="stDownloadButton"] > button:hover {{
    border-color: var(--tint-border) !important;
    color: var(--tint) !important;
    background: var(--tint-dim) !important;
}}

/* ── Caption ──────────────────────────────────────── */
[data-testid="stCaptionContainer"] p {{
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    color: var(--text-secondary) !important;
}}

/* ── Scrollbar ────────────────────────────────────── */
::-webkit-scrollbar {{ width: 4px; height: 4px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{
    background: var(--border-mid);
    border-radius: 2px;
}}

/* ── Divider / hr ─────────────────────────────────── */
hr {{
    border-color: var(--border-dim) !important;
    opacity: 1 !important;
}}

/* ── Hide Streamlit chrome + deploy bar ──────────── */
#MainMenu  {{ visibility: hidden; }}
footer     {{ visibility: hidden; }}
header     {{ visibility: hidden; }}
/* Streamlit's own header sits above everything — push it behind our topbar */
[data-testid="stHeader"] {{
    display: none !important;
}}
/* Remove default top padding Streamlit adds for its header */
[data-testid="stAppViewContainer"] > section:first-child {{
    padding-top: 0 !important;
}}
</style>
"""
    st.markdown(css, unsafe_allow_html=True)


def topbar_html(active_tab: str, api_keys: dict[str, str], mode: str = "dark") -> str:
    tabs = [("single", "/ scan"), ("bulk", "/ bulk"),
            ("history", "/ history"), ("settings", "/ settings")]
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
    mode_badge = f'<span class="tc-mode-badge">{mode}</span>'
    return f"""
<div class="tc-topbar">
  <div class="tc-logo"><div class="tc-logo-sq"></div>THREAT·CHECK</div>
  <div class="tc-nav">{tabs_html}</div>
  <div class="tc-right">
    <div class="tc-dots">{dots_html}</div>
    {mode_badge}
  </div>
</div>
"""


def stat_strip_html(mal: int, sus: int, cln: int, total: int) -> str:
    return f"""
<div class="tc-stats">
  <div class="tc-stat mal"><div class="tc-stat-num mal">{mal}</div>
    <div class="tc-stat-lbl">Malicious</div></div>
  <div class="tc-stat sus"><div class="tc-stat-num sus">{sus}</div>
    <div class="tc-stat-lbl">Suspicious</div></div>
  <div class="tc-stat cln"><div class="tc-stat-num cln">{cln}</div>
    <div class="tc-stat-lbl">Clean</div></div>
  <div class="tc-stat tot"><div class="tc-stat-num tot">{total}</div>
    <div class="tc-stat-lbl">Total</div></div>
</div>
"""
