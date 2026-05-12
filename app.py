"""
IOC Threat Intelligence Checker
================================
Streamlit Cloud app — single & bulk IOC analysis via OSINT APIs.
API keys loaded from st.secrets (Settings > Secrets on Streamlit Cloud).
"""
from __future__ import annotations

import time

import pandas as pd
import streamlit as st

from components.result_card import (
    render_api_status_sidebar,
    render_ioc_result_card,
    render_summary_metrics,
)
from utils.export import results_to_csv, results_to_json
from utils.ioc_detector import IOC_TYPE_LABELS, IOCType, detect_ioc_type, parse_bulk_input
from utils.osint_api import OsintResult, check_ioc
from utils.theme import get_tint, inject_css

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IOC Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme injection ───────────────────────────────────────────────────────────
tint = get_tint()
inject_css(tint)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_api_keys() -> dict[str, str]:
    """Load API keys from Streamlit secrets (gracefully handles missing keys)."""
    try:
        section = st.secrets.get("api_keys", {})
        return {
            "virustotal": section.get("virustotal", ""),
            "abuseipdb":  section.get("abuseipdb", ""),
            "shodan":     section.get("shodan", ""),
            "otx":        section.get("otx", ""),
            "urlscan":    section.get("urlscan", ""),
        }
    except Exception:
        return {"virustotal": "", "abuseipdb": "", "shodan": "",
                "otx": "", "urlscan": ""}


def session_results() -> list[OsintResult]:
    if "results" not in st.session_state:
        st.session_state["results"] = []
    return st.session_state["results"]


def clear_results() -> None:
    st.session_state["results"] = []


# ── Session state init ────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state["results"] = []

# ── Load keys once ────────────────────────────────────────────────────────────
API_KEYS = load_api_keys()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        '<div style="font-family:var(--font-display);font-size:1.6rem;'
        'font-weight:700;letter-spacing:0.08em;color:var(--tint);'
        'padding:0.5rem 0 1rem;">⬡ IOC INTEL</div>',
        unsafe_allow_html=True,
    )

    render_api_status_sidebar(API_KEYS)

    st.divider()

    # ── Tint colour picker ─────────────────────────────────────────
    st.markdown("### Theme")
    new_tint = st.color_picker(
        "Accent tint",
        value=tint,
        help="Pick a custom accent colour. "
             "To persist this across sessions, update `theme.tint` in your Streamlit Secrets.",
    )
    if new_tint != tint:
        inject_css(new_tint)
        st.toast("Tint updated — reload page to apply fully.", icon="🎨")

    st.divider()

    # ── Session history controls ───────────────────────────────────
    st.markdown("### Session")
    results = session_results()
    st.caption(f"{len(results)} IOC(s) in history")

    if results:
        col_a, col_b = st.columns(2)
        with col_a:
            st.download_button(
                "⬇ JSON",
                data=results_to_json(results),
                file_name="ioc_results.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_b:
            st.download_button(
                "⬇ CSV",
                data=results_to_csv(results),
                file_name="ioc_results.csv",
                mime="text/csv",
                use_container_width=True,
            )
        if st.button("🗑 Clear history", use_container_width=True):
            clear_results()
            st.rerun()

    st.divider()
    st.markdown(
        '<div style="font-family:var(--font-mono);font-size:0.65rem;'
        'color:var(--text-dim);line-height:1.6;">'
        "Keys stored in Streamlit Secrets.<br>"
        "No data persisted server-side.<br>"
        "For bulk: one IOC per line or CSV.</div>",
        unsafe_allow_html=True,
    )


# ── Main content ──────────────────────────────────────────────────────────────

st.markdown(
    """
<div class="app-header">
  <div class="app-title">IOC <span>Intelligence</span></div>
  <div class="app-subtitle">Threat indicator lookup · OSINT-powered · Multi-source</div>
</div>
""",
    unsafe_allow_html=True,
)

# ── Input tabs ────────────────────────────────────────────────────────────────
tab_single, tab_bulk, tab_history = st.tabs(["Single IOC", "Bulk Check", "History"])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — Single IOC
# ─────────────────────────────────────────────────────────────────────────────
with tab_single:
    st.markdown("#### Check a single indicator")

    col_input, col_type = st.columns([4, 1])
    with col_input:
        single_ioc = st.text_input(
            "Enter IOC",
            placeholder="IP · Domain · URL · MD5 · SHA1 · SHA256 · Email",
            label_visibility="collapsed",
        )
    with col_type:
        detected_type = detect_ioc_type(single_ioc) if single_ioc else IOCType.UNKNOWN
        st.markdown(
            f'<div style="padding:0.55rem 0;font-family:var(--font-mono);'
            f"font-size:0.78rem;color:var(--text-secondary);\">"
            f"{IOC_TYPE_LABELS.get(detected_type, '❓')} detected</div>",
            unsafe_allow_html=True,
        )

    run_single = st.button("🔍 Check IOC", type="primary", key="btn_single")

    if run_single:
        if not single_ioc.strip():
            st.warning("Enter an IOC value first.")
        elif detected_type == IOCType.UNKNOWN:
            st.error(
                "Could not detect IOC type. Check the value and try again."
            )
        else:
            active_keys = {k: v for k, v in API_KEYS.items() if v.strip()}
            if not active_keys:
                st.error(
                    "No API keys configured. Add them under **Settings > Secrets** "
                    "in Streamlit Cloud using the format in `secrets.toml.example`."
                )
            else:
                with st.spinner(f"Querying {len(active_keys)} source(s)…"):
                    result = check_ioc(
                        single_ioc.strip(), detected_type, active_keys
                    )
                    st.session_state["results"].insert(0, result)

                st.success(
                    f"Done — {result.malicious_count}/{result.source_count} "
                    f"sources flagged **{single_ioc}** as "
                    f"{result.overall_verdict.upper()}."
                )
                render_ioc_result_card(result, expanded=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — Bulk IOC
# ─────────────────────────────────────────────────────────────────────────────
with tab_bulk:
    st.markdown("#### Bulk indicator check")
    st.caption(
        "One IOC per line, or comma-separated. Mixed types supported. "
        "Results are appended to session history."
    )

    bulk_input = st.text_area(
        "IOC list",
        height=200,
        placeholder="8.8.8.8\n1.1.1.1\nevil-domain.xyz\nhttps://phish.example.com/login\nd41d8cd98f00b204e9800998ecf8427e",
        label_visibility="collapsed",
    )

    # Preview parse
    parsed_preview: list[str] = []
    if bulk_input.strip():
        parsed_preview = parse_bulk_input(bulk_input)
        preview_types = [
            f"{ioc} → {IOC_TYPE_LABELS.get(detect_ioc_type(ioc), '❓')}"
            for ioc in parsed_preview[:5]
        ]
        suffix = f" … +{len(parsed_preview)-5} more" if len(parsed_preview) > 5 else ""
        st.caption(
            f"**{len(parsed_preview)} unique IOC(s)** detected: "
            + ", ".join(f"`{t}`" for t in preview_types)
            + suffix
        )

    run_bulk = st.button("🔍 Run Bulk Check", type="primary", key="btn_bulk",
                         disabled=not bool(parsed_preview))

    if run_bulk and parsed_preview:
        active_keys = {k: v for k, v in API_KEYS.items() if v.strip()}
        if not active_keys:
            st.error("No API keys configured.")
        else:
            progress_bar  = st.progress(0, text="Initialising…")
            status_text   = st.empty()
            bulk_results: list[OsintResult] = []

            for idx, ioc_val in enumerate(parsed_preview):
                ioc_t = detect_ioc_type(ioc_val)
                status_text.markdown(
                    f'<span style="font-family:var(--font-mono);font-size:0.8rem;'
                    f"color:var(--text-secondary);\">Checking "
                    f"<code>{ioc_val}</code> "
                    f"({idx+1}/{len(parsed_preview)})…</span>",
                    unsafe_allow_html=True,
                )

                if ioc_t == IOCType.UNKNOWN:
                    st.warning(f"Skipped `{ioc_val}` — unrecognised IOC type.")
                    progress_bar.progress(
                        (idx + 1) / len(parsed_preview),
                        text=f"{idx+1}/{len(parsed_preview)}"
                    )
                    continue

                result = check_ioc(ioc_val.strip(), ioc_t, active_keys)
                bulk_results.append(result)
                st.session_state["results"].insert(0, result)

                progress_bar.progress(
                    (idx + 1) / len(parsed_preview),
                    text=f"{idx+1}/{len(parsed_preview)} checked"
                )
                time.sleep(0.05)   # small visual pacing

            status_text.empty()
            progress_bar.empty()

            if bulk_results:
                st.success(f"Bulk check complete — {len(bulk_results)} IOC(s) processed.")
                render_summary_metrics(bulk_results)
                st.divider()
                for r in bulk_results:
                    render_ioc_result_card(r)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 — History
# ─────────────────────────────────────────────────────────────────────────────
with tab_history:
    results = session_results()

    if not results:
        st.markdown(
            '<div style="padding:3rem;text-align:center;'
            'font-family:var(--font-mono);font-size:0.85rem;'
            "color:var(--text-dim);\">"
            "No IOCs checked yet in this session.</div>",
            unsafe_allow_html=True,
        )
    else:
        render_summary_metrics(results)
        st.divider()

        # ── Quick filter ───────────────────────────────────────────
        filter_col, sort_col = st.columns([3, 1])
        with filter_col:
            filter_verdict = st.selectbox(
                "Filter by verdict",
                ["all", "malicious", "suspicious", "clean", "unknown"],
                label_visibility="visible",
            )
        with sort_col:
            sort_newest = st.selectbox(
                "Sort",
                ["Newest first", "Oldest first"],
                label_visibility="visible",
            )

        filtered = results if filter_verdict == "all" else [
            r for r in results if r.overall_verdict == filter_verdict
        ]
        if sort_newest == "Oldest first":
            filtered = list(reversed(filtered))

        st.caption(f"Showing {len(filtered)} / {len(results)} IOC(s)")

        # ── Table summary ──────────────────────────────────────────
        if filtered:
            table_data = [
                {
                    "IOC":          r.ioc,
                    "Type":         IOC_TYPE_LABELS.get(r.ioc_type, "?"),
                    "Verdict":      r.overall_verdict.upper(),
                    "Flagged":      f"{r.malicious_count}/{r.source_count}",
                    "Checked":      time.strftime(
                        "%H:%M:%S UTC", time.gmtime(r.checked_at)
                    ),
                }
                for r in filtered
            ]
            st.dataframe(
                pd.DataFrame(table_data),
                use_container_width=True,
                hide_index=True,
            )
            st.divider()

            # Detailed cards
            for r in filtered:
                render_ioc_result_card(r)
