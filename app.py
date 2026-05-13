"""
IOC Threat Intelligence Checker — Option B UI
==============================================
Terminal aesthetic · top navigation bar · dense table results.
API keys loaded from st.secrets (Streamlit Cloud → Settings → Secrets).
"""
from __future__ import annotations

import time

import pandas as pd
import streamlit as st

from components.result_card import render_results_table, render_stat_strip, render_result_row, render_table_header
from utils.export import results_to_csv, results_to_json, results_to_sigma, results_to_yara
from utils.ioc_detector import IOC_TYPE_LABELS, IOCType, detect_ioc_type, parse_bulk_input, parse_bulk_csv
from utils.osint_api import OsintResult, check_ioc
from utils.theme import get_tint, inject_css, topbar_html, stat_strip_html

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="threat·check",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Theme ─────────────────────────────────────────────────────────────────────
tint = get_tint()
inject_css(tint)


# ── Session helpers ───────────────────────────────────────────────────────────

def load_api_keys() -> dict[str, str]:
    try:
        s = st.secrets.get("api_keys", {})
        return {
            "virustotal": s.get("virustotal", ""),
            "abuseipdb":  s.get("abuseipdb",  ""),
            "shodan":     s.get("shodan",      ""),
            "otx":        s.get("otx",         ""),
            "urlscan":    s.get("urlscan",      ""),
            "greynoise":  s.get("greynoise",    ""),
        }
    except Exception:
        return {k: "" for k in ("virustotal", "abuseipdb", "shodan", "otx", "urlscan", "greynoise")}


def get_results() -> list[OsintResult]:
    if "results" not in st.session_state:
        st.session_state["results"] = []
    return st.session_state["results"]


def get_tab() -> str:
    return st.session_state.get("active_tab", "single")


def set_tab(tab: str) -> None:
    st.session_state["active_tab"] = tab


# ── Init ──────────────────────────────────────────────────────────────────────
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "single"
if "results" not in st.session_state:
    st.session_state["results"] = []

API_KEYS = load_api_keys()

# ── Topbar ────────────────────────────────────────────────────────────────────
st.markdown(topbar_html(get_tab(), API_KEYS), unsafe_allow_html=True)

# Tab switch buttons rendered invisibly via Streamlit columns — we overlay
# the custom topbar visually and use st.tabs for actual routing.
# Streamlit doesn't support real custom nav, so we use query_params + tabs.

# ── Navigation via st.tabs (styled to match topbar) ──────────────────────────
tab_scan, tab_bulk, tab_history, tab_settings = st.tabs(
    ["/ scan", "/ bulk", "/ history", "/ settings"]
)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SCAN
# ══════════════════════════════════════════════════════════════════════════════
with tab_scan:
    results = get_results()

    # ── Stat strip (always visible) ───────────────────────────────
    if results:
        render_stat_strip(results)

    # ── Shell prompt input ────────────────────────────────────────
    st.markdown('<div class="tc-section">Check indicator</div>', unsafe_allow_html=True)

    st.markdown('<div class="tc-shell-wrap">', unsafe_allow_html=True)
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
        run = st.button("Run", type="primary", key="btn_single", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Run check ─────────────────────────────────────────────────
    if run:
        ioc_val = single_ioc.strip()
        if not ioc_val:
            st.warning("Enter an IOC value.")
        elif detected == IOCType.UNKNOWN:
            st.error("Unrecognised IOC format — check the value and try again.")
        else:
            active = {k: v for k, v in API_KEYS.items() if v.strip()}
            if not active:
                st.error(
                    "No API keys found. Add them under **Settings → Secrets** "
                    "on Streamlit Cloud using the `secrets.toml.example` format."
                )
            else:
                with st.spinner(""):
                    result = check_ioc(ioc_val, detected, active)
                    st.session_state["results"].insert(0, result)
                results = get_results()
                render_stat_strip(results)

    # ── Results table ─────────────────────────────────────────────
    if results:
        st.markdown(
            f'<div class="tc-section" style="margin-top:20px;">'
            f'Recent results — {len(results)} IOC(s)</div>',
            unsafe_allow_html=True,
        )
        render_results_table(results[:20])  # show latest 20 on scan tab

        # ── Inline export buttons ──────────────────────────────
        col_dl1, col_dl2, col_dl3, _ = st.columns([1.5, 1.5, 1.5, 6.5])
        with col_dl1:
            st.download_button(
                "⬇ CSV", data=results_to_csv(results[:20]),
                file_name="ioc_scan.csv", mime="text/csv",
                use_container_width=True,
            )
        with col_dl2:
            st.download_button(
                "⬇ JSON", data=results_to_json(results[:20]),
                file_name="ioc_scan.json", mime="application/json",
                use_container_width=True,
            )
        with col_dl3:
            st.download_button(
                "⬇ Sigma", data=results_to_sigma(results[:20]),
                file_name="ioc_rules.yml", mime="text/yaml",
                use_container_width=True,
            )

        if len(results) > 20:
            st.markdown(
                f'<div class="tc-hint">showing 20 of {len(results)} — '
                f'see full history in / history tab</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="padding:3rem 0;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            'no results yet — enter an indicator above and press run</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB: BULK
# ══════════════════════════════════════════════════════════════════════════════
with tab_bulk:
    st.markdown('<div class="tc-section">Bulk indicator check</div>', unsafe_allow_html=True)

    # ── Input mode toggle ──────────────────────────────────────────
    input_mode = st.radio(
        "Input method",
        ["✏ Paste text", "📂 Upload CSV / TXT"],
        horizontal=True,
        label_visibility="collapsed",
    )

    parsed: list[str] = []

    if input_mode == "✏ Paste text":
        st.caption("One IOC per line or comma-separated. Mixed types supported.")
        bulk_raw = st.text_area(
            "IOC list",
            height=180,
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
        if bulk_raw.strip():
            parsed = parse_bulk_input(bulk_raw)

    else:  # Upload mode
        st.caption("Upload a .csv or .txt file — all cells scanned for valid IOCs (IP, domain, URL, hash, email).")
        uploaded_file = st.file_uploader(
            "Upload IOC file",
            type=["csv", "txt"],
            label_visibility="collapsed",
            key="bulk_upload",
        )
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            parsed = parse_bulk_csv(file_bytes)
            if not parsed:
                st.warning("No recognisable IOCs found in the uploaded file.")

    if parsed:
        type_summary = ", ".join(
            f"`{ioc}` → {IOC_TYPE_LABELS.get(detect_ioc_type(ioc), '?').split()[-1]}"
            for ioc in parsed[:4]
        )
        suffix = f" … +{len(parsed)-4} more" if len(parsed) > 4 else ""
        st.caption(f"**{len(parsed)}** unique IOCs detected: {type_summary}{suffix}")

    col_run, _ = st.columns([2, 8])
    with col_run:
        run_bulk = st.button(
            "Run bulk check",
            type="primary",
            key="btn_bulk",
            disabled=not bool(parsed),
            use_container_width=True,
        )

    if run_bulk and parsed:
        active = {k: v for k, v in API_KEYS.items() if v.strip()}
        if not active:
            st.error("No API keys configured.")
        else:
            prog       = st.progress(0, text="Starting…")
            status     = st.empty()
            bulk_new: list[OsintResult] = []

            for idx, ioc_val in enumerate(parsed):
                ioc_t = detect_ioc_type(ioc_val)
                status.markdown(
                    f'<span style="font-family:var(--font-mono);font-size:11px;'
                    f'color:var(--text-secondary);">checking '
                    f'<code style="color:var(--tint)">{ioc_val}</code> '
                    f'({idx+1}/{len(parsed)})</span>',
                    unsafe_allow_html=True,
                )

                if ioc_t == IOCType.UNKNOWN:
                    st.warning(f"Skipped `{ioc_val}` — unrecognised type.")
                    prog.progress((idx + 1) / len(parsed))
                    continue

                result = check_ioc(ioc_val.strip(), ioc_t, active)
                bulk_new.append(result)
                st.session_state["results"].insert(0, result)
                prog.progress((idx + 1) / len(parsed), text=f"{idx+1}/{len(parsed)}")
                time.sleep(0.04)

            status.empty()
            prog.empty()

            if bulk_new:
                st.success(f"Done — {len(bulk_new)} IOC(s) processed.")
                render_stat_strip(bulk_new)

                # ── Export buttons ─────────────────────────────────
                ec1, ec2, ec3, ec4, _ = st.columns([1.5, 1.5, 1.5, 1.5, 5])
                with ec1:
                    st.download_button(
                        "⬇ CSV", data=results_to_csv(bulk_new),
                        file_name="bulk_results.csv", mime="text/csv",
                        use_container_width=True,
                    )
                with ec2:
                    st.download_button(
                        "⬇ JSON", data=results_to_json(bulk_new),
                        file_name="bulk_results.json", mime="application/json",
                        use_container_width=True,
                    )
                with ec3:
                    st.download_button(
                        "⬇ Sigma", data=results_to_sigma(bulk_new),
                        file_name="bulk_rules.yml", mime="text/yaml",
                        use_container_width=True,
                    )
                with ec4:
                    st.download_button(
                        "⬇ YARA", data=results_to_yara(bulk_new),
                        file_name="bulk_hashes.yar", mime="text/plain",
                        use_container_width=True,
                    )

                st.markdown('<div class="tc-section" style="margin-top:16px;">Results</div>', unsafe_allow_html=True)
                render_results_table(bulk_new)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab_history:
    results = get_results()

    if not results:
        st.markdown(
            '<div style="padding:3rem 0;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            'session history is empty</div>',
            unsafe_allow_html=True,
        )
    else:
        # ── Controls row ──────────────────────────────────────────
        c1, c2, c3 = st.columns([2, 2, 1.5])
        with c1:
            filter_v = st.selectbox(
                "Verdict",
                ["all", "malicious", "suspicious", "clean", "unknown"],
                label_visibility="visible",
            )
        with c2:
            sort_order = st.selectbox(
                "Sort",
                ["Newest first", "Oldest first"],
                label_visibility="visible",
            )
        with c3:
            if st.button("🗑 Clear session", use_container_width=True):
                st.session_state["results"] = []
                st.rerun()

        # ── Export row ────────────────────────────────────────────
        e1, e2, e3, e4 = st.columns([1.5, 1.5, 1.5, 1.5])
        with e1:
            st.download_button(
                "⬇ CSV", data=results_to_csv(results),
                file_name="ioc_results.csv", mime="text/csv",
                use_container_width=True,
            )
        with e2:
            st.download_button(
                "⬇ JSON", data=results_to_json(results),
                file_name="ioc_results.json", mime="application/json",
                use_container_width=True,
            )
        with e3:
            st.download_button(
                "⬇ Sigma", data=results_to_sigma(results),
                file_name="ioc_rules.yml", mime="text/yaml",
                use_container_width=True,
            )
        with e4:
            st.download_button(
                "⬇ YARA", data=results_to_yara(results),
                file_name="ioc_hashes.yar", mime="text/plain",
                use_container_width=True,
            )

        # ── Filter + sort ─────────────────────────────────────────
        filtered = (
            results if filter_v == "all"
            else [r for r in results if r.overall_verdict == filter_v]
        )
        if sort_order == "Oldest first":
            filtered = list(reversed(filtered))

        render_stat_strip(filtered)
        st.caption(f"Showing {len(filtered)} of {len(results)} IOC(s)")

        st.markdown('<div class="tc-section" style="margin-top:8px;">Results</div>', unsafe_allow_html=True)
        render_results_table(filtered)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_settings:
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
            "Accent colour affects the topbar logo, active tab indicator, "
            "score bars, buttons, and stat strip highlights. "
            "Changes apply immediately but reset on reload unless saved in Secrets."
        )

    st.markdown('<div class="tc-section" style="margin-top:24px;">API sources</div>', unsafe_allow_html=True)

    source_info = {
        "virustotal": ("VirusTotal",     "virustotal.com",          "IP · Domain · URL · Hash"),
        "abuseipdb":  ("AbuseIPDB",      "abuseipdb.com",           "IP only"),
        "shodan":     ("Shodan",         "account.shodan.io",       "IP only"),
        "otx":        ("OTX AlienVault", "otx.alienvault.com",      "IP · Domain · URL · Hash"),
        "urlscan":    ("URLScan.io",     "urlscan.io",              "IP · Domain · URL"),
        "greynoise":  ("GreyNoise",      "www.greynoise.io",        "IP only · Noise reduction"),
    }

    rows = []
    for key, (name, url, types) in source_info.items():
        configured = "✓ configured" if API_KEYS.get(key, "").strip() else "— not set"
        color = "var(--v-cln)" if API_KEYS.get(key, "").strip() else "var(--text-dim)"
        rows.append({
            "Source":      name,
            "Supports":    types,
            "Docs":        f"https://{url}",
            "Status":      configured,
        })

    for row in rows:
        configured = "✓" in row["Status"]
        status_color = "#50FA7B" if configured else "#3A4060"
        st.markdown(
            f'<div style="display:flex;align-items:center;justify-content:space-between;'
            f'padding:9px 14px;border-bottom:1px solid var(--border-dim);'
            f'font-family:var(--font-mono);font-size:11px;">'
            f'<span style="color:var(--text-primary);min-width:160px">{row["Source"]}</span>'
            f'<span style="color:var(--text-secondary);flex:1">{row["Supports"]}</span>'
            f'<a href="{row["Docs"]}" target="_blank" style="color:var(--tint);'
            f'font-size:10px;opacity:0.6;min-width:140px;text-align:center">{row["Docs"].replace("https://","")}</a>'
            f'<span style="color:{status_color};min-width:100px;text-align:right">{row["Status"]}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="tc-section" style="margin-top:24px;">Secrets format</div>', unsafe_allow_html=True)
    st.code(
        """[api_keys]
virustotal = "YOUR_VT_KEY"
abuseipdb  = "YOUR_ABUSEIPDB_KEY"
shodan     = "YOUR_SHODAN_KEY"
otx        = "YOUR_OTX_KEY"
urlscan    = "YOUR_URLSCAN_KEY"
greynoise  = "YOUR_GREYNOISE_KEY"   # optional — https://www.greynoise.io/

[theme]
tint = "#FF6B6B"   # any hex colour""",
        language="toml",
    )
    st.caption(
        "Paste this into **Streamlit Cloud → App → Settings → Secrets**. "
        "Omit any key you don't have — that source will be skipped silently. "
        "GreyNoise free community key available at greynoise.io."
    )
