"""
UI components — Option B terminal aesthetic.
Dense table rows + expandable per-source detail panels.
Detail fields are IOC-type-aware: only relevant fields shown per source.
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


# ── Source detail card ────────────────────────────────────────────────────────

def _source_card_html(sr: SourceResult, ioc_type: IOCType) -> str:
    """
    Render one source card — full width, two-column KV grid inside.
    Values are never truncated; long strings wrap naturally.
    """
    vcolor = VERDICT_COLORS.get(sr.verdict, "#6B7A99")

    verdict_span = (
        f'<span style="color:{vcolor};font-size:9px;font-weight:600;'
        f'margin-left:8px;letter-spacing:0.08em">{sr.verdict.upper()}</span>'
        if sr.verdict not in ("error", "unknown") else ""
    )

    # ── Collect all KV rows first, then render ────────────────────
    kv_rows: list[tuple[str, str, str]] = []  # (label, display, val_style)

    if sr.score is not None:
        kv_rows.append(("score", f"{sr.score:.0f} / 100",
                         f'style="color:{vcolor};font-weight:600"'))

    if sr.error:
        header = (
            f'<div class="tc-src-card">'
            f'<div class="tc-src-header">'
            f'<div class="tc-src-vdot" style="background:{vcolor}"></div>'
            f'{sr.source}{verdict_span}'
            f'</div>'
            f'<div style="font-size:10px;color:#FF6B6B;padding:4px 0">⚠ {sr.error}</div>'
            f'</div>'
        )
        return header

    # IOC-type-aware fields
    fields = _get_fields_for(sr.source, ioc_type)
    shown  = 0
    for detail_key, col_suffix in fields:
        val = sr.details.get(detail_key)
        if val in (None, "", "—", [], {}):
            continue
        display = _fmt(val)
        if not display:
            continue
        label = col_suffix.replace("_", " ")

        val_style = ""
        if detail_key in ("confidence_score", "engines_malicious") \
                and isinstance(val, (int, float)) and val > 0:
            val_style = f'style="color:{vcolor};font-weight:600"'
        elif detail_key == "is_tor" and val is True:
            val_style = 'style="color:#FF6B6B;font-weight:600"'
        elif detail_key in ("vuln_count", "pulse_count") \
                and isinstance(val, (int, float)) and val > 0:
            val_style = f'style="color:{vcolor};font-weight:600"'
        elif detail_key in ("total_reports", "num_distinct_users") \
                and isinstance(val, int) and val > 100:
            val_style = f'style="color:{vcolor}"'

        kv_rows.append((label, display, val_style))
        shown += 1

    # Fallback if no mapped fields
    if shown == 0 and sr.details:
        for k, v in list(sr.details.items())[:12]:
            display = _fmt(v)
            if display:
                kv_rows.append((k.replace("_", " "), display, ""))

    # ── Build HTML ────────────────────────────────────────────────
    kv_html = ""
    for label, display, val_style in kv_rows:
        kv_html += (
            f'<div class="tc-kv">'
            f'<span class="tc-kv-k">{label}</span>'
            f'<span class="tc-kv-v" {val_style}>{display}</span>'
            f'</div>'
        )

    link_html = ""
    if sr.url:
        link_html = (
            f'<a class="tc-link" href="{sr.url}" target="_blank">'
            f'↗ view full report</a>'
        )

    return (
        f'<div class="tc-src-card">'
        f'<div class="tc-src-header">'
        f'<div class="tc-src-vdot" style="background:{vcolor}"></div>'
        f'{sr.source}{verdict_span}'
        f'</div>'
        f'<div class="tc-kv-grid">{kv_html}</div>'
        f'{link_html}'
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
    verdict  = result.overall_verdict
    vcls     = _vcls(verdict)
    vcolor   = VERDICT_COLORS.get(verdict, "#6B7A99")
    ioc_label = IOC_TYPE_LABELS.get(result.ioc_type, "?").split()[-1]

    scores = [s.score for s in result.sources if s.score is not None]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    # Source squares — all 5 slots, grey if not queried
    all_sources = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX AlienVault", "URLScan.io"]
    src_map = {s.source: s for s in result.sources}
    sq_html = ""
    for sname in all_sources:
        abbr = SOURCE_ABBR.get(sname, sname[:2])
        if sname in src_map:
            scls = _sq_cls(src_map[sname].verdict)
        else:
            scls = "unk"
        sq_html += (
            f'<div class="tc-sq {scls}" title="{sname}: '
            f'{src_map[sname].verdict if sname in src_map else "not queried"}">'
            f'{abbr}</div>'
        )

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

    # Detail expander
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(result.checked_at))
    label = (
        f"{result.ioc}  ·  "
        f"{result.malicious_count}/{result.source_count} flagged  ·  "
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
            f'<div class="tc-detail tc-detail-grid">{cards_html}</div>',
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
