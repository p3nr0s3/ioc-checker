"""
IOC Threat Intelligence Checker — v4
=====================================
+ Adaptive light/dark theme (Secrets: theme.mode = "dark"|"light")
+ Source selector checkboxes
+ IOC-type-aware detail fields per source
+ Detailed export (wide CSV, long CSV, JSON)
"""
from __future__ import annotations

import time

import streamlit as st

from components.result_card import render_results_table, render_stat_strip
from utils.export import results_to_csv, results_to_json, results_to_csv_summary
from utils.ioc_detector import IOC_TYPE_LABELS, IOCType, detect_ioc_type, parse_bulk_input
from utils.osint_api import OsintResult, check_ioc
from utils.theme import get_tint, get_mode, inject_css, topbar_html, stat_strip_html

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="threat·check",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Theme — read mode from secrets or session override ───────────────────────
if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = get_mode()
if "theme_tint" not in st.session_state:
    st.session_state["theme_tint"] = get_tint()

current_mode = st.session_state["theme_mode"]
current_tint = st.session_state["theme_tint"]
inject_css(tint=current_tint, mode=current_mode)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_api_keys() -> dict[str, str]:
    try:
        s = st.secrets.get("api_keys", {})
        return {k: s.get(k, "") for k in
                ("virustotal", "abuseipdb", "shodan", "otx", "urlscan")}
    except Exception:
        return {k: "" for k in ("virustotal", "abuseipdb", "shodan", "otx", "urlscan")}


def get_results() -> list[OsintResult]:
    if "results" not in st.session_state:
        st.session_state["results"] = []
    return st.session_state["results"]


SOURCES_META: dict[str, tuple[str, str]] = {
    "virustotal": ("VirusTotal",     "IP · Domain · URL · Hash"),
    "abuseipdb":  ("AbuseIPDB",      "IP only"),
    "shodan":     ("Shodan",         "IP only"),
    "otx":        ("OTX AlienVault", "IP · Domain · URL · Hash · Email"),
    "urlscan":    ("URLScan.io",     "IP · Domain · URL"),
}


def source_selector(prefix: str, api_keys: dict[str, str]) -> dict[str, str]:
    """Checkbox row for selecting active Threat Intel sources."""
    configured = {k: v for k, v in api_keys.items() if v.strip()}
    if not configured:
        st.error(
            "No API keys found. Add them under **Settings → Secrets** "
            "on Streamlit Cloud."
        )
        return {}

    st.markdown(
        '<div class="tc-section">Threat Intel sources</div>',
        unsafe_allow_html=True,
    )

    cols    = st.columns(len(SOURCES_META))
    selected: dict[str, str] = {}

    for col, (key, (name, types)) in zip(cols, SOURCES_META.items()):
        is_avail = bool(api_keys.get(key, "").strip())
        with col:
            if is_avail:
                checked = st.checkbox(
                    name,
                    value=True,
                    key=f"{prefix}_src_{key}",
                    help=f"Supports: {types}",
                )
                st.markdown(
                    f'<div style="font-family:var(--font-mono);font-size:9px;'
                    f'color:var(--text-secondary);margin-top:-10px;">'
                    f'{types}</div>',
                    unsafe_allow_html=True,
                )
                if checked:
                    selected[key] = api_keys[key]
            else:
                st.checkbox(
                    name, value=False, disabled=True,
                    key=f"{prefix}_src_{key}_dis",
                    help=f"No API key set. Supports: {types}",
                )
                st.markdown(
                    '<div style="font-family:var(--font-mono);font-size:9px;'
                    'color:var(--text-dim);margin-top:-10px;">no key</div>',
                    unsafe_allow_html=True,
                )

    if configured and not selected:
        st.warning("Select at least one source.")

    return selected


# ── Session / API init ────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state["results"] = []

API_KEYS = load_api_keys()

# ── Topbar ────────────────────────────────────────────────────────────────────
st.markdown(
    topbar_html("single", API_KEYS, mode=current_mode),
    unsafe_allow_html=True,
)

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

    selected = source_selector("scan", API_KEYS)

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
        detected  = detect_ioc_type(single_ioc) if single_ioc.strip() else IOCType.UNKNOWN
        type_lbl  = IOC_TYPE_LABELS.get(detected, "?").split()[-1]
        st.markdown(
            f'<div style="height:42px;display:flex;align-items:center;'
            f'font-family:var(--font-mono);font-size:10px;'
            f'color:var(--text-secondary);letter-spacing:0.08em;">'
            f'{type_lbl if single_ioc.strip() else "AUTO"}</div>',
            unsafe_allow_html=True,
        )
    with col_btn:
        run = st.button(
            "Run", type="primary", key="btn_single",
            use_container_width=True,
            disabled=not bool(selected),
        )

    if run:
        ioc_val = single_ioc.strip()
        if not ioc_val:
            st.warning("Enter an IOC value.")
        elif detected == IOCType.UNKNOWN:
            st.error("Unrecognised IOC format.")
        elif not selected:
            st.warning("Select at least one source.")
        else:
            src_names = ", ".join(SOURCES_META[k][0] for k in selected)
            with st.spinner(f"Querying: {src_names}…"):
                result = check_ioc(ioc_val, detected, selected)
                st.session_state["results"].insert(0, result)
            results = get_results()
            render_stat_strip(results)

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
            '<div style="padding:2.5rem 0;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            'no results yet — enter an indicator and press run</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB: BULK
# ══════════════════════════════════════════════════════════════════════════════
with tab_bulk:
    bulk_selected = source_selector("bulk", API_KEYS)

    st.markdown(
        '<div class="tc-section" style="margin-top:16px;">IOC list</div>',
        unsafe_allow_html=True,
    )
    st.caption("One per line or comma-separated. Mixed types supported.")

    bulk_raw = st.text_area(
        "IOC list", height=160, label_visibility="collapsed", key="bulk_input",
        placeholder=(
            "185.220.101.47\n"
            "cdn-assets-free[.]ru\n"
            "https://phish.example.com/login\n"
            "d41d8cd98f00b204e9800998ecf8427e\n"
            "attacker@malicious.biz"
        ),
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

    col_run, _ = st.columns([2, 8])
    with col_run:
        run_bulk = st.button(
            "Run bulk check", type="primary", key="btn_bulk",
            disabled=not bool(parsed and bulk_selected),
            use_container_width=True,
        )

    if run_bulk and parsed and bulk_selected:
        src_names  = ", ".join(SOURCES_META[k][0] for k in bulk_selected)
        prog       = st.progress(0, text="Starting…")
        status     = st.empty()
        bulk_new: list[OsintResult] = []

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
            '<div style="padding:3rem 0;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            'session history is empty</div>',
            unsafe_allow_html=True,
        )
    else:
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
                help="Full nested JSON — all detail fields per source",
            )
        with c4:
            st.download_button(
                "⬇ CSV wide",
                data=results_to_csv(results),
                file_name="ioc_intel_wide.csv",
                mime="text/csv",
                use_container_width=True,
                help="1 row per IOC · per-source column blocks · IOC-type-aware",
            )
        with c5:
            st.download_button(
                "⬇ CSV long",
                data=results_to_csv_summary(results),
                file_name="ioc_intel_long.csv",
                mime="text/csv",
                use_container_width=True,
                help="1 row per IOC × source — pivot table friendly",
            )
        with c6:
            if st.button("🗑 Clear", use_container_width=True):
                st.session_state["results"] = []
                st.rerun()

        filtered = (
            results if filter_v == "all"
            else [r for r in results if r.overall_verdict == filter_v]
        )
        if sort_order == "Oldest first":
            filtered = list(reversed(filtered))

        render_stat_strip(filtered)
        st.caption(f"Showing {len(filtered)} of {len(results)} IOC(s)")

        with st.expander("About export formats", expanded=False):
            st.markdown("""
**JSON** — Nested per source. All non-empty fields included.
Fields are IOC-type aware: IP results include country/ASN/ISP; hash results include
file name/type/size/hashes/threat name; domain results include registrar/DNS/WHOIS;
URL results include HTTP status/title/server/categories.

**CSV (wide)** — One row per IOC. Column blocks per source, type-aware:
- *IP:* `abuseipdb_country_name`, `abuseipdb_isp`, `abuseipdb_asn`, `abuseipdb_usage_type`,
  `abuseipdb_is_tor`, `abuseipdb_abuse_categories`, `shodan_org`, `shodan_open_ports`,
  `shodan_cves`, `virustotal_as_owner`, `otx_alienvault_country_name` …
- *Hash:* `virustotal_file_name`, `virustotal_file_type`, `virustotal_sha256`,
  `virustotal_popular_threat_name`, `virustotal_signature_product` …
- *Domain:* `virustotal_registrar`, `virustotal_dns_records`, `virustotal_whois_snippet`,
  `otx_alienvault_alexa_rank` …
- *URL:* `virustotal_final_url`, `virustotal_http_status`, `virustotal_server`,
  `urlscanio_page_title`, `urlscanio_unique_domains` …

**CSV (long)** — One row per IOC × source. All details collapsed to `key=value | …` string.
Best for pivot tables or SIEM import.
""")

        st.markdown(
            '<div class="tc-section" style="margin-top:8px;">Results</div>',
            unsafe_allow_html=True,
        )
        render_results_table(filtered)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_settings:

    # ── Theme controls ────────────────────────────────────────────
    st.markdown('<div class="tc-section">Theme</div>', unsafe_allow_html=True)

    col_mode, col_tint, col_info = st.columns([2, 2, 5])

    with col_mode:
        new_mode = st.selectbox(
            "Mode",
            ["dark", "light"],
            index=0 if current_mode == "dark" else 1,
            help="dark = near-black bg, light = white bg. "
                 "To persist: set `theme.mode` in Secrets.",
        )
        if new_mode != current_mode:
            st.session_state["theme_mode"] = new_mode
            inject_css(tint=current_tint, mode=new_mode)
            st.rerun()

    with col_tint:
        new_tint = st.color_picker(
            "Accent tint",
            value=current_tint,
            help="To persist: set `theme.tint` in Secrets.",
        )
        if new_tint != current_tint:
            st.session_state["theme_tint"] = new_tint
            inject_css(tint=new_tint, mode=current_mode)
            st.rerun()

    with col_info:
        st.caption(
            f"Current: **{current_mode}** mode · tint `{current_tint}`. "
            "Changes apply immediately and persist in this session. "
            "Set `theme.mode` and `theme.tint` in Secrets to make them permanent."
        )

    # ── API source status ─────────────────────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:24px;">API sources</div>',
        unsafe_allow_html=True,
    )

    source_urls = {
        "virustotal": "virustotal.com/gui/join-us",
        "abuseipdb":  "abuseipdb.com/register",
        "shodan":     "account.shodan.io",
        "otx":        "otx.alienvault.com/api",
        "urlscan":    "urlscan.io/user/signup",
    }

    for key, (name, types) in SOURCES_META.items():
        configured   = bool(API_KEYS.get(key, "").strip())
        status_color = "#50FA7B" if configured else "var(--text-dim)"
        status_text  = "✓ configured" if configured else "— not set"
        url          = source_urls[key]
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
tint = "#FF6B6B"          # any hex colour
mode = "dark"             # "dark" or "light" """,
        language="toml",
    )

    # ── CSV column reference per IOC type ─────────────────────────
    st.markdown(
        '<div class="tc-section" style="margin-top:24px;">'
        'CSV column reference — by IOC type</div>',
        unsafe_allow_html=True,
    )

    from utils.export import _get_fields_for, SOURCE_ORDER, _src_prefix
    ioc_type_tabs = st.tabs(["IP", "Domain", "URL", "Hash (MD5/SHA)", "Email"])
    type_map_tabs = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.EMAIL]

    for tab, itype in zip(ioc_type_tabs, type_map_tabs):
        with tab:
            lines: list[str] = [
                "ioc", "ioc_type", "overall_verdict",
                "malicious_sources", "sources_queried", "checked_at",
            ]
            for sname in SOURCE_ORDER:
                pfx = _src_prefix(sname)
                lines += [
                    f"{pfx}_verdict", f"{pfx}_score",
                    f"{pfx}_report_url", f"{pfx}_error",
                ]
                for _, col in _get_fields_for(sname, itype):
                    lines.append(f"{pfx}_{col}")
            st.code("\n".join(lines), language="text")
            st.caption(f"{len(lines)} columns for {itype.value} IOCs")
