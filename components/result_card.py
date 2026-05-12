"""
UI components — Option B terminal aesthetic.
Results rendered as dense table rows with expandable detail panels.
"""
from __future__ import annotations

import time

import streamlit as st

from utils.ioc_detector import IOC_TYPE_LABELS, IOCType
from utils.osint_api import OsintResult, SourceResult
from utils.theme import VERDICT_COLORS, SOURCE_ABBR


# ── Helpers ───────────────────────────────────────────────────────────────────

def _verdict_cls(verdict: str) -> str:
    return {"malicious": "mal", "suspicious": "sus", "clean": "cln"}.get(
        verdict, "unk"
    )


def _score_color(verdict: str) -> str:
    return VERDICT_COLORS.get(verdict, "#3A4060")


def _src_sq_cls(verdict: str) -> str:
    return {"malicious": "mal", "clean": "cln"}.get(verdict, "unk")


def _abbr(source_name: str) -> str:
    return SOURCE_ABBR.get(source_name, source_name[:2].upper())


# ── Table header ──────────────────────────────────────────────────────────────

def render_table_header() -> None:
    st.markdown(
        """
<div class="tc-thead">
  <div class="tc-th">Indicator</div>
  <div class="tc-th">Type</div>
  <div class="tc-th">Threat score</div>
  <div class="tc-th">Sources</div>
  <div class="tc-th right">Verdict</div>
</div>
""",
        unsafe_allow_html=True,
    )


# ── Single source card inside detail panel ────────────────────────────────────

def _source_card_html(sr: SourceResult) -> str:
    vcls  = _verdict_cls(sr.verdict)
    vcolor = _score_color(sr.verdict)

    header = f"""
<div class="tc-src-card">
  <div class="tc-src-header">
    <div class="tc-src-vdot" style="background:{vcolor}"></div>
    {sr.source}
    {"— <span style='color:" + vcolor + ";font-size:9px'>" + sr.verdict.upper() + "</span>" if sr.verdict != "error" else ""}
  </div>
"""
    if sr.error:
        return header + f'<div style="font-size:10px;color:#FF6B6B">Error: {sr.error}</div></div>'

    rows_html = ""

    # Score row
    if sr.score is not None:
        rows_html += f"""
<div class="tc-kv">
  <span class="tc-kv-k">score</span>
  <span class="tc-kv-v" style="color:{vcolor}">{sr.score:.0f}/100</span>
</div>"""

    # Key details — cap to most useful 6
    priority_keys = [
        "malicious", "suspicious", "undetected", "total_engines",
        "confidence_score", "total_reports",
        "pulse_count", "total_scans", "malicious_scans",
        "country", "asn", "as_owner", "isp", "org",
        "open_ports", "port_count", "vuln_count",
        "meaningful_name", "type_description",
    ]
    shown = 0
    for key in priority_keys:
        if key not in sr.details or shown >= 6:
            continue
        val = sr.details[key]
        if isinstance(val, list):
            display = ", ".join(str(x) for x in val[:4]) if val else "—"
        elif isinstance(val, bool):
            display = "yes" if val else "no"
        else:
            display = str(val) if val not in (None, "", "—") else "—"
        if display == "—":
            continue
        label = key.replace("_", " ")
        rows_html += f"""
<div class="tc-kv">
  <span class="tc-kv-k">{label}</span>
  <span class="tc-kv-v">{display}</span>
</div>"""
        shown += 1

    link_html = ""
    if sr.url:
        link_html = f'<a class="tc-link" href="{sr.url}" target="_blank">↗ view report</a>'

    return header + rows_html + link_html + "</div>"


# ── Full result row + expandable detail ───────────────────────────────────────

def render_result_row(result: OsintResult, idx: int) -> None:
    """Render one table row + an expander with per-source detail cards."""
    verdict  = result.overall_verdict
    vcls     = _verdict_cls(verdict)
    vcolor   = _score_color(verdict)
    ioc_label = IOC_TYPE_LABELS.get(result.ioc_type, "?").split()[-1]  # short label

    # Score = average of available source scores
    scores = [s.score for s in result.sources if s.score is not None]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    # Source squares HTML
    src_squares = ""
    all_sources = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX AlienVault", "URLScan.io"]
    src_map = {s.source: s for s in result.sources}
    for sname in all_sources:
        abbr = _abbr(sname)
        if sname in src_map:
            scls = _src_sq_cls(src_map[sname].verdict)
        else:
            scls = "unk"
        src_squares += f'<div class="tc-sq {scls}" title="{sname}">{abbr}</div>'

    row_html = f"""
<div class="tc-row">
  <div class="tc-ioc">{result.ioc}</div>
  <div class="tc-ioc-type">{ioc_label}</div>
  <div class="tc-score-wrap">
    <div class="tc-score-bg">
      <div class="tc-score-fill" style="width:{avg_score:.0f}%;background:{vcolor}"></div>
    </div>
    <span class="tc-score-val" style="color:{vcolor}">{avg_score:.0f}</span>
  </div>
  <div class="tc-srcs">{src_squares}</div>
  <div class="tc-verdict {vcls}">{verdict.upper()}</div>
</div>
"""
    st.markdown(row_html, unsafe_allow_html=True)

    # Expandable detail panel
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(result.checked_at))
    with st.expander(
        f"  {result.ioc}  ·  {result.malicious_count}/{result.source_count} flagged  ·  {ts}",
        expanded=False,
    ):
        if not result.sources:
            st.caption("No sources returned results.")
            return

        src_cards_html = "".join(_source_card_html(sr) for sr in result.sources)
        st.markdown(
            f'<div class="tc-detail"><div class="tc-detail-grid">'
            f"{src_cards_html}"
            f"</div></div>",
            unsafe_allow_html=True,
        )


# ── Bulk results table ────────────────────────────────────────────────────────

def render_results_table(results: list[OsintResult]) -> None:
    """Render full table with header + rows."""
    if not results:
        st.markdown(
            '<div style="padding:2.5rem;text-align:center;'
            'font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">'
            "no results yet</div>",
            unsafe_allow_html=True,
        )
        return

    render_table_header()
    for i, r in enumerate(results):
        render_result_row(r, i)


# ── Stat strip (delegate to theme) ───────────────────────────────────────────

def render_stat_strip(results: list[OsintResult]) -> None:
    from utils.theme import stat_strip_html
    malicious  = sum(1 for r in results if r.overall_verdict == "malicious")
    suspicious = sum(1 for r in results if r.overall_verdict == "suspicious")
    clean      = sum(1 for r in results if r.overall_verdict == "clean")
    st.markdown(
        stat_strip_html(malicious, suspicious, clean, len(results)),
        unsafe_allow_html=True,
    )
