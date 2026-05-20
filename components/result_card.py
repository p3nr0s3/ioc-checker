"""
UI components — Option B terminal aesthetic.
Dense table rows + expandable per-source detail panels.
Detail fields are IOC-type-aware; layout is sectioned per source.
"""
from __future__ import annotations

import time

import streamlit as st

from utils.ioc_detector import IOC_TYPE_LABELS, IOCType
from utils.osint_api import OsintResult, SourceResult
from utils.theme import VERDICT_COLORS, SOURCE_ABBR
from utils.export import _get_fields_for, _fmt


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vcls(verdict: str) -> str:
    return {"malicious": "mal", "suspicious": "sus", "clean": "cln"}.get(verdict, "unk")


def _sq_cls(verdict: str) -> str:
    return {"malicious": "mal", "suspicious": "sus", "clean": "cln"}.get(verdict, "unk")


# Fields whose values tend to be long — render full-span across both columns
_FULL_SPAN_KEYS = {
    "last_comment", "whois", "whois_snippet", "dns_records", "last_dns_records",
    "cves", "critical_cves", "high_cves", "open_ports", "services",
    "abuse_categories", "tags", "top_tags", "top_pulse_names", "malware_families",
    "attack_ids", "categories", "verdict_tags", "hostnames", "domains",
    "last_report_comment",
}

# Fields that get coloured highlight when non-zero / critical
_HIGHLIGHT_KEYS = {
    "confidence_score", "engines_malicious", "vuln_count", "pulse_count",
    "total_reports", "malicious_scans", "critical_cves",
}

_WARN_TRUE_KEYS = {"is_tor", "is_vpn"}


def _val_style(detail_key: str, val: object, vcolor: str) -> str:
    if detail_key in _HIGHLIGHT_KEYS:
        if isinstance(val, (int, float)) and val > 0:
            return f'style="color:{vcolor};font-weight:700"'
    if detail_key in _WARN_TRUE_KEYS and val is True:
        return 'style="color:#FF6B6B;font-weight:700"'
    return ""


# ── Source section HTML ───────────────────────────────────────────────────────

def _source_card_html(sr: SourceResult, ioc_type: IOCType) -> str:
    """
    One full-width source section:
      • coloured header bar with source name, verdict, score badge
      • 2-column KV grid; long-value fields span both columns
      • report link in footer
    """
    vcolor = VERDICT_COLORS.get(sr.verdict, "#6B7A99")

    # ── Header ────────────────────────────────────────────────────
    verdict_label = sr.verdict.upper() if sr.verdict not in ("error",) else "ERROR"
    score_badge   = (
        f'<span class="tc-src-score-badge" style="color:{vcolor}">'
        f'{sr.score:.0f}/100</span>'
        if sr.score is not None else ""
    )

    header_html = (
        f'<div class="tc-src-header">'
        f'<div class="tc-src-vdot" style="background:{vcolor}"></div>'
        f'<span>{sr.source}</span>'
        f'<span style="color:{vcolor};font-size:10px;'
        f'font-weight:600;letter-spacing:0.1em">{verdict_label}</span>'
        f'{score_badge}'
        f'</div>'
    )

    # ── Error state ───────────────────────────────────────────────
    if sr.error:
        return (
            f'<div class="tc-src-card">'
            f'{header_html}'
            f'<div style="padding:12px 20px;font-size:11px;color:#FF6B6B">'
            f'⚠ {sr.error}</div>'
            f'</div>'
        )

    # ── Collect fields ────────────────────────────────────────────
    fields = _get_fields_for(sr.source, ioc_type)
    rows: list[tuple[str, str, str, bool]] = []  # (label, display, style, full_span)

    for detail_key, col_suffix in fields:
        val = sr.details.get(detail_key)
        if val in (None, "", "—", [], {}):
            continue
        display = _fmt(val)
        if not display:
            continue
        label     = col_suffix.replace("_", " ")
        vstyle    = _val_style(detail_key, val, vcolor)
        full_span = detail_key in _FULL_SPAN_KEYS
        rows.append((label, display, vstyle, full_span))

    # Fallback
    if not rows and sr.details:
        for k, v in list(sr.details.items())[:16]:
            display = _fmt(v)
            if display:
                rows.append((k.replace("_", " "), display, "", False))

    # ── Build KV HTML ─────────────────────────────────────────────
    kv_html = ""
    for label, display, vstyle, full_span in rows:
        span_cls = " full-span" if full_span else ""
        kv_html += (
            f'<div class="tc-kv{span_cls}">'
            f'<span class="tc-kv-k">{label}</span>'
            f'<span class="tc-kv-v" {vstyle}>{display}</span>'
            f'</div>'
        )

    # ── Footer link ───────────────────────────────────────────────
    footer_html = ""
    if sr.url:
        footer_html = (
            f'<div class="tc-src-footer">'
            f'<a class="tc-link" href="{sr.url}" target="_blank">'
            f'↗ view full report on {sr.source}</a>'
            f'</div>'
        )

    return (
        f'<div class="tc-src-card">'
        f'{header_html}'
        f'<div class="tc-kv-grid">{kv_html}</div>'
        f'{footer_html}'
        f'</div>'
    )


# ── Table header ──────────────────────────────────────────────────────────────

def render_table_header() -> None:
    st.markdown(
        '<div class="tc-thead">'
        '<div class="tc-th">Indicator</div>'
        '<div class="tc-th">Type</div>'
        '<div class="tc-th">Threat score</div>'
        '<div class="tc-th">Sources</div>'
        '<div class="tc-th right">Verdict</div>'
        '</div>',
        unsafe_allow_html=True,
    )


# ── Single result row + detail expander ──────────────────────────────────────

def render_result_row(result: OsintResult, idx: int) -> None:
    verdict   = result.overall_verdict
    vcls      = _vcls(verdict)
    vcolor    = VERDICT_COLORS.get(verdict, "#6B7A99")
    ioc_label = IOC_TYPE_LABELS.get(result.ioc_type, "?").split()[-1]

    scores    = [s.score for s in result.sources if s.score is not None]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    # Source squares
    all_sources = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX AlienVault", "URLScan.io"]
    src_map     = {s.source: s for s in result.sources}
    sq_html     = ""
    for sname in all_sources:
        abbr  = SOURCE_ABBR.get(sname, sname[:2])
        scls  = _sq_cls(src_map[sname].verdict) if sname in src_map else "unk"
        title = f"{sname}: {src_map[sname].verdict}" if sname in src_map else f"{sname}: not queried"
        sq_html += f'<div class="tc-sq {scls}" title="{title}">{abbr}</div>'

    st.markdown(
        f'<div class="tc-row">'
        f'<div class="tc-ioc">{result.ioc}</div>'
        f'<div class="tc-ioc-type">{ioc_label}</div>'
        f'<div class="tc-score-wrap">'
        f'  <div class="tc-score-bg">'
        f'    <div class="tc-score-fill" style="width:{avg_score:.0f}%;background:{vcolor}"></div>'
        f'  </div>'
        f'  <span class="tc-score-val" style="color:{vcolor}">{avg_score:.0f}</span>'
        f'</div>'
        f'<div class="tc-srcs">{sq_html}</div>'
        f'<div class="tc-verdict {vcls}">{verdict.upper()}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Expander with sectioned detail ────────────────────────────
    ts    = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(result.checked_at))
    label = (
        f"{result.ioc}  ·  "
        f"{result.malicious_count}/{result.source_count} sources flagged  ·  "
        f"{ioc_label}  ·  {ts}"
    )
    with st.expander(label, expanded=False):
        if not result.sources:
            st.caption("No sources returned results.")
            return

        cards_html = "".join(
            _source_card_html(sr, result.ioc_type)
            for sr in result.sources
        )
        st.markdown(
            f'<div class="tc-detail"><div class="tc-detail-grid">{cards_html}</div></div>',
            unsafe_allow_html=True,
        )


# ── Full results table ────────────────────────────────────────────────────────

def render_results_table(results: list[OsintResult]) -> None:
    if not results:
        st.markdown(
            '<div style="padding:2.5rem;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            'no results yet</div>',
            unsafe_allow_html=True,
        )
        return

    render_table_header()
    st.markdown('<div class="tc-table-body">', unsafe_allow_html=True)
    for i, r in enumerate(results):
        render_result_row(r, i)
    st.markdown('</div>', unsafe_allow_html=True)


# ── Stat strip ────────────────────────────────────────────────────────────────

def render_stat_strip(results: list[OsintResult]) -> None:
    from utils.theme import stat_strip_html
    mal = sum(1 for r in results if r.overall_verdict == "malicious")
    sus = sum(1 for r in results if r.overall_verdict == "suspicious")
    cln = sum(1 for r in results if r.overall_verdict == "clean")
    st.markdown(stat_strip_html(mal, sus, cln, len(results)), unsafe_allow_html=True)
