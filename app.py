"""
IOC Threat Intelligence Checker — v3
=====================================
+ Source selector: choose which Threat Intel APIs to query
+ Detailed export: per-source columns in CSV, verbose JSON
"""
from __future__ import annotations

import time

import streamlit as st

from components.result_card import (
    render_results_table,
    render_stat_strip,
)
from utils.export import results_to_csv, results_to_json, results_to_csv_summary
from utils.ioc_detector import IOC_TYPE_LABELS, IOCType, detect_ioc_type, parse_bulk_input
from utils.osint_api import OsintResult, check_ioc
from utils.theme import get_tint, inject_css, topbar_html, stat_strip_html

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="threat·check",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

tint = get_tint()
inject_css(tint)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_api_keys() -> dict[str, str]:
    try:
        s = st.secrets.get("api_keys", {})
        return {
            "virustotal": s.get("virustotal", ""),
            "abuseipdb":  s.get("abuseipdb",  ""),
            "shodan":     s.get("shodan",      ""),
            "otx":        s.get("otx",         ""),
            "urlscan":    s.get("urlscan",      ""),
        }
    except Exception:
        return {k: "" for k in ("virustotal", "abuseipdb", "shodan", "otx", "urlscan")}


def get_results() -> list[OsintResult]:
    if "results" not in st.session_state:
        st.session_state["results"] = []
    return st.session_state["results"]


# Source metadata: key → (display name, supported IOC types)
SOURCES_META: dict[str, tuple[str, str]] = {
    "virustotal": ("VirusTotal",     "IP · Domain · URL · Hash"),
    "abuseipdb":  ("AbuseIPDB",      "IP only"),
    "shodan":     ("Shodan",         "IP only"),
    "otx":        ("OTX AlienVault", "IP · Domain · URL · Hash"),
    "urlscan":    ("URLScan.io",     "IP · Domain · URL"),
}


def source_selector_widget(
    prefix: str,
    api_keys: dict[str, str],
    default_all: bool = True,
) -> dict[str, str]:
    """
    Render a compact source selector row.
    Returns filtered api_keys dict containing only selected + configured sources.
    """
    st.markdown('<div class="tc-section">Threat Intel sources</div>', unsafe_allow_html=True)

    configured = {k: v for k, v in api_keys.items() if v.strip()}
    if not configured:
        st.error(
            "No API keys configured. "
            "Add them under **Settings → Secrets** on Streamlit Cloud."
        )
        return {}

    cols = st.columns(len(SOURCES_META))
    selected: dict[str, str] = {}

    for col, (key, (name, types)) in zip(cols, SOURCES_META.items()):
        is_configured = bool(api_keys.get(key, "").strip())
        with col:
            if is_configured:
                checked = st.checkbox(
                    name,
                    value=default_all,
                    key=f"{prefix}_src_{key}",
                    help=f"Supports: {types}",
                )
                st.markdown(
                    f'<div style="font-family:var(--font-mono);font-size:9px;'
                    f'color:var(--text-secondary);margin-top:-10px;'
                    f'letter-spacing:0.04em;">{types}</div>',
                    unsafe_allow_html=True,
                )
                if checked:
                    selected[key] = api_keys[key]
            else:
                # Greyed out — no key
                st.checkbox(
                    name,
                    value=False,
                    disabled=True,
                    key=f"{prefix}_src_{key}_disabled",
                    help=f"No API key configured. Supports: {types}",
                )
                st.markdown(
                    '<div style="font-family:var(--font-mono);font-size:9px;'
                    'color:var(--text-dim);margin-top:-10px;">no key</div>',
                    unsafe_allow_html=True,
                )

    if not selected:
        st.warning("Select at least one source to run a check.")

    return selected


# ── Session init ──────────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state["results"] = []

API_KEYS = load_api_keys()

# ── Topbar ────────────────────────────────────────────────────────────────────
st.markdown(topbar_html("single", API_KEYS), unsafe_allow_html=True)

tab_scan, tab_bulk, tab_history, tab_settings = st.tabs(
    ["/ scan", "/ bulk", "/ history", "/ settings"]
)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SCAN
# ══════════════════════════════════════════════════════════════════════════════
with tab_scan:
    results = get_results()
    if results:
        render_stat_strip(results)

    # ── Source selector ───────────────────────────────────────────
    selected_sources = source_selector_widget("scan", API_KEYS)

    # ── Shell input ───────────────────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:16px;">Indicator</div>',
        unsafe_allow_html=True,
    )

    col_prompt, col_input, col_type, col_btn = st.columns([1.6, 8, 2, 1.6])

    with col_prompt:
        st.markdown(
            '<div class="tc-prompt" style="height:42px;">ioc@check:~$</div>',
            unsafe_allow_html=True,
        )
    with col_input:
        single_ioc = st.text_input(
            "ioc",
            placeholder="IP · domain · URL · MD5 · SHA1 · SHA256 · email",
            label_visibility="collapsed",
            key="single_input",
        )
    with col_type:
        detected = detect_ioc_type(single_ioc) if single_ioc.strip() else IOCType.UNKNOWN
        type_label = IOC_TYPE_LABELS.get(detected, "?").split()[-1]
        st.markdown(
            f'<div style="height:42px;display:flex;align-items:center;'
            f'font-family:var(--font-mono);font-size:10px;'
            f'color:var(--text-secondary);letter-spacing:0.08em;">'
            f'{type_label if single_ioc.strip() else "AUTO"}</div>',
            unsafe_allow_html=True,
        )
    with col_btn:
        run = st.button(
            "Run",
            type="primary",
            key="btn_single",
            use_container_width=True,
            disabled=not bool(selected_sources),
        )

    # ── Execute ───────────────────────────────────────────────────
    if run:
        ioc_val = single_ioc.strip()
        if not ioc_val:
            st.warning("Enter an IOC value.")
        elif detected == IOCType.UNKNOWN:
            st.error("Unrecognised IOC format — check the value and try again.")
        elif not selected_sources:
            st.warning("Select at least one source above.")
        else:
            with st.spinner(
                f"Querying {len(selected_sources)} source(s): "
                f"{', '.join(SOURCES_META[k][0] for k in selected_sources)}…"
            ):
                result = check_ioc(ioc_val, detected, selected_sources)
                st.session_state["results"].insert(0, result)

            results = get_results()
            render_stat_strip(results)

    # ── Results ───────────────────────────────────────────────────
    if results:
        st.markdown(
            f'<div class="tc-section" style="margin-top:20px;">'
            f'Recent results — {len(results)} IOC(s)</div>',
            unsafe_allow_html=True,
        )
        render_results_table(results[:20])
        if len(results) > 20:
            st.markdown(
                f'<div class="tc-hint">showing 20 of {len(results)} — '
                f'see full list in / history</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="padding:2.5rem 0;text-align:center;font-family:var(--font-mono);'
            'font-size:11px;color:var(--text-dim);">'
            'no results yet — enter an indicator and press run</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB: BULK
# ══════════════════════════════════════════════════════════════════════════════
with tab_bulk:
    # ── Source selector ───────────────────────────────────────────
    bulk_selected = source_selector_widget("bulk", API_KEYS)

    # ── IOC input ─────────────────────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:16px;">IOC list</div>',
        unsafe_allow_html=True,
    )
    st.caption("One per line or comma-separated. Mixed types supported.")

    bulk_raw = st.text_area(
        "IOC list",
        height=160,
        placeholder=(
            "185.220.101.47\n"
            "cdn-assets-free[.]ru\n"
            "https://phish.example.com/login\n"
            "d41d8cd98f00b204e9800998ecf8427e\n"
            "attacker@malicious.biz"
        ),
        label_visibility="collapsed",
        key="bulk_input",
    )

    parsed: list[str] = []
    if bulk_raw.strip():
        parsed = parse_bulk_input(bulk_raw)
        preview = ", ".join(
            f"`{ioc}` ({IOC_TYPE_LABELS.get(detect_ioc_type(ioc), '?').split()[-1]})"
            for ioc in parsed[:4]
        )
        suffix = f" … +{len(parsed)-4} more" if len(parsed) > 4 else ""
        st.caption(f"**{len(parsed)}** unique IOC(s): {preview}{suffix}")

    col_run, col_sp = st.columns([2, 8])
    with col_run:
        run_bulk = st.button(
            "Run bulk check",
            type="primary",
            key="btn_bulk",
            disabled=not bool(parsed and bulk_selected),
            use_container_width=True,
        )

    if run_bulk and parsed and bulk_selected:
        prog   = st.progress(0, text="Starting…")
        status = st.empty()
        bulk_new: list[OsintResult] = []
        src_names = ", ".join(SOURCES_META[k][0] for k in bulk_selected)

        for idx, ioc_val in enumerate(parsed):
            ioc_t = detect_ioc_type(ioc_val)
            status.markdown(
                f'<span style="font-family:var(--font-mono);font-size:11px;'
                f'color:var(--text-secondary);">checking '
                f'<code style="color:var(--tint)">{ioc_val}</code> via '
                f'<span style="color:var(--text-primary)">{src_names}</span> '
                f'({idx+1}/{len(parsed)})</span>',
                unsafe_allow_html=True,
            )
            if ioc_t == IOCType.UNKNOWN:
                st.warning(f"Skipped `{ioc_val}` — unrecognised type.")
                prog.progress((idx + 1) / len(parsed))
                continue

            result = check_ioc(ioc_val.strip(), ioc_t, bulk_selected)
            bulk_new.append(result)
            st.session_state["results"].insert(0, result)
            prog.progress((idx + 1) / len(parsed), text=f"{idx+1}/{len(parsed)}")
            time.sleep(0.04)

        status.empty()
        prog.empty()

        if bulk_new:
            st.success(f"Done — {len(bulk_new)} IOC(s) processed.")
            render_stat_strip(bulk_new)
            st.markdown(
                '<div class="tc-section" style="margin-top:16px;">Results</div>',
                unsafe_allow_html=True,
            )
            render_results_table(bulk_new)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab_history:
    results = get_results()

    if not results:
        st.markdown(
            '<div style="padding:3rem 0;text-align:center;font-family:var(--font-mono);'
            'font-size:11px;color:var(--text-dim);">session history is empty</div>',
            unsafe_allow_html=True,
        )
    else:
        # ── Filter / sort / export row ────────────────────────────
        c1, c2, c3, c4, c5, c6 = st.columns([2, 2, 1.4, 1.4, 1.4, 1.4])

        with c1:
            filter_v = st.selectbox(
                "Verdict",
                ["all", "malicious", "suspicious", "clean", "unknown"],
            )
        with c2:
            sort_order = st.selectbox("Sort", ["Newest first", "Oldest first"])
        with c3:
            st.download_button(
                "⬇ JSON",
                data=results_to_json(results),
                file_name="ioc_intel.json",
                mime="application/json",
                use_container_width=True,
                help="Verbose JSON — full detail per source per IOC",
            )
        with c4:
            st.download_button(
                "⬇ CSV (wide)",
                data=results_to_csv(results),
                file_name="ioc_intel_wide.csv",
                mime="text/csv",
                use_container_width=True,
                help="One row per IOC · per-source column blocks",
            )
        with c5:
            st.download_button(
                "⬇ CSV (long)",
                data=results_to_csv_summary(results),
                file_name="ioc_intel_long.csv",
                mime="text/csv",
                use_container_width=True,
                help="One row per IOC × source — good for pivot tables",
            )
        with c6:
            if st.button("🗑 Clear", use_container_width=True):
                st.session_state["results"] = []
                st.rerun()

        # ── Filter + sort ─────────────────────────────────────────
        filtered = (
            results if filter_v == "all"
            else [r for r in results if r.overall_verdict == filter_v]
        )
        if sort_order == "Oldest first":
            filtered = list(reversed(filtered))

        render_stat_strip(filtered)
        st.caption(f"Showing {len(filtered)} of {len(results)} IOC(s)")

        # ── Export format explainer ───────────────────────────────
        with st.expander("About export formats", expanded=False):
            st.markdown(
                """
**JSON** — Full nested structure. Each IOC contains a `sources` object with keys per
Threat Intel provider. All available detail fields are included (engine counts,
ASN info, open ports, CVEs, pulse tags, etc.).

**CSV (wide)** — One row per IOC. Each source gets its own column block:
`{source}_verdict`, `{source}_score`, `{source}_report_url`, `{source}_error`,
plus source-specific detail columns (e.g. `virustotal_engines_malicious`,
`abuseipdb_confidence_pct`, `shodan_cve_count`, `otx_alienvault_pulse_count`,
`urlscanio_malicious_scans`). Best for direct analysis in Excel/Sheets.

**CSV (long)** — One row per IOC × source combination. Better for pivot tables
or importing into SIEM / ticketing systems.
"""
            )

        st.markdown(
            '<div class="tc-section" style="margin-top:8px;">Results</div>',
            unsafe_allow_html=True,
        )
        render_results_table(filtered)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_settings:
    # ── Theme tint ────────────────────────────────────────────────
    st.markdown('<div class="tc-section">Theme</div>', unsafe_allow_html=True)
    col_picker, col_info = st.columns([2, 5])
    with col_picker:
        new_tint = st.color_picker(
            "Accent tint",
            value=tint,
            help="To persist: update `theme.tint` in Streamlit Secrets.",
        )
        if new_tint != tint:
            inject_css(new_tint)
            st.toast("Tint updated — reload for full effect.", icon="🎨")
    with col_info:
        st.caption(
            "Affects topbar logo, active tab, score bars, buttons, stat strip. "
            "Changes reset on reload unless saved in Secrets."
        )

    # ── API source status table ───────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:24px;">API sources</div>',
        unsafe_allow_html=True,
    )

    for key, (name, types) in SOURCES_META.items():
        configured = bool(API_KEYS.get(key, "").strip())
        status_color = "#50FA7B" if configured else "#3A4060"
        status_text  = "✓ configured" if configured else "— not set"
        url = {
            "virustotal": "virustotal.com/gui/join-us",
            "abuseipdb":  "abuseipdb.com/register",
            "shodan":     "account.shodan.io",
            "otx":        "otx.alienvault.com/api",
            "urlscan":    "urlscan.io/user/signup",
        }[key]
        st.markdown(
            f'<div style="display:flex;align-items:center;justify-content:space-between;'
            f'padding:9px 14px;border-bottom:1px solid var(--border-dim);'
            f'font-family:var(--font-mono);font-size:11px;">'
            f'<span style="color:var(--text-primary);min-width:155px">{name}</span>'
            f'<span style="color:var(--text-secondary);flex:1">{types}</span>'
            f'<a href="https://{url}" target="_blank" style="color:var(--tint);'
            f'font-size:10px;opacity:0.55;min-width:200px;text-align:center">{url}</a>'
            f'<span style="color:{status_color};min-width:110px;text-align:right">'
            f'{status_text}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Secrets format ────────────────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:24px;">Secrets format</div>',
        unsafe_allow_html=True,
    )
    st.code(
        """[api_keys]
virustotal = "YOUR_VT_KEY"
abuseipdb  = "YOUR_ABUSEIPDB_KEY"
shodan     = "YOUR_SHODAN_KEY"
otx        = "YOUR_OTX_KEY"
urlscan    = "YOUR_URLSCAN_KEY"

[theme]
tint = "#FF6B6B"   # any hex colour""",
        language="toml",
    )
    st.caption(
        "Paste into **Streamlit Cloud → App → Settings → Secrets**. "
        "Omit any key you don't have — that source will be skipped silently."
    )

    # ── Export column reference ───────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:24px;">CSV column reference</div>',
        unsafe_allow_html=True,
    )

    col_ref = {
        "VirusTotal": [
            "vt_verdict", "vt_score", "vt_report_url",
            "vt_engines_malicious", "vt_engines_suspicious", "vt_engines_total",
            "vt_country", "vt_asn", "vt_as_owner",
            "vt_file_name", "vt_file_type", "vt_file_size_bytes",
        ],
        "AbuseIPDB": [
            "abuseipdb_verdict", "abuseipdb_score", "abuseipdb_report_url",
            "abuseipdb_confidence_pct", "abuseipdb_total_reports",
            "abuseipdb_country", "abuseipdb_isp", "abuseipdb_domain",
            "abuseipdb_usage_type", "abuseipdb_is_tor", "abuseipdb_is_vpn",
        ],
        "Shodan": [
            "shodan_verdict", "shodan_score", "shodan_report_url",
            "shodan_org", "shodan_isp", "shodan_country", "shodan_os",
            "shodan_open_port_count", "shodan_open_ports",
            "shodan_cve_count", "shodan_cves", "shodan_tags", "shodan_hostnames",
        ],
        "OTX AlienVault": [
            "otx_alienvault_verdict", "otx_alienvault_score", "otx_alienvault_report_url",
            "otx_alienvault_pulse_count", "otx_alienvault_reputation",
            "otx_alienvault_country", "otx_alienvault_tags",
        ],
        "URLScan.io": [
            "urlscanio_verdict", "urlscanio_score", "urlscanio_report_url",
            "urlscanio_total_scans", "urlscanio_malicious_scans",
            "urlscanio_latest_country", "urlscanio_latest_server",
            "urlscanio_latest_ip", "urlscanio_verdict_tags",
        ],
    }

    for src, cols in col_ref.items():
        with st.expander(f"{src} — {len(cols)} columns", expanded=False):
            st.code("\n".join(cols), language="text")
