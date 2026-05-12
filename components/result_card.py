"""
Reusable Streamlit UI components for IOC result rendering.
"""
from __future__ import annotations

import time

import streamlit as st

from utils.ioc_detector import IOC_TYPE_LABELS, IOCType
from utils.osint_api import OsintResult, SourceResult
from utils.theme import VERDICT_COLORS, VERDICT_ICONS


def _score_bar_html(score: float, verdict: str) -> str:
    color = VERDICT_COLORS.get(verdict, "#78909C")
    return f"""
<div class="score-bar-container">
  <div class="score-bar" style="width:{score}%; background:{color};"></div>
</div>
"""


def render_source_result(sr: SourceResult) -> None:
    """Render a single source result inside an expander."""
    icon  = VERDICT_ICONS.get(sr.verdict, "⚪")
    color = VERDICT_COLORS.get(sr.verdict, "#78909C")

    label = f"{icon} **{sr.source}** — `{sr.verdict.upper()}`"
    if sr.score is not None:
        label += f"  · score: **{sr.score:.0f}**"

    with st.expander(label, expanded=False):
        if sr.error:
            st.error(f"Error: {sr.error}")
            return

        # Score bar
        if sr.score is not None:
            st.markdown(
                _score_bar_html(sr.score, sr.verdict),
                unsafe_allow_html=True,
            )
            st.caption(f"Threat score: {sr.score:.1f} / 100")

        # Details grid
        if sr.details:
            items = [(k.replace("_", " ").title(), v) for k, v in sr.details.items()]
            # Split into 2 columns
            half = max(1, len(items) // 2 + len(items) % 2)
            col1, col2 = st.columns(2)
            for i, (k, v) in enumerate(items):
                target = col1 if i < half else col2
                with target:
                    if isinstance(v, list):
                        if v:
                            st.markdown(
                                f"**{k}**  \n`{'`, `'.join(str(x) for x in v)}`"
                            )
                    elif isinstance(v, bool):
                        st.markdown(f"**{k}**: {'✅' if v else '—'}")
                    elif v and str(v) != "—":
                        st.markdown(f"**{k}**: `{v}`")

        if sr.url:
            st.markdown(
                f'<a href="{sr.url}" target="_blank" style="color:var(--tint);'
                f'font-size:0.75rem;text-decoration:none;">↗ View full report</a>',
                unsafe_allow_html=True,
            )


def verdict_badge_html(verdict: str) -> str:
    """Return HTML for a verdict badge span."""
    icon = VERDICT_ICONS.get(verdict, "⚪")
    return (
        f'<span class="verdict-badge {verdict}">'
        f'{icon} {verdict.upper()}'
        f"</span>"
    )


def render_ioc_result_card(result: OsintResult, expanded: bool = False) -> None:
    """Render a full IOC result card."""
    verdict = result.overall_verdict
    ioc_label = IOC_TYPE_LABELS.get(result.ioc_type, "❓ Unknown")
    checked_ts = time.strftime(
        "%Y-%m-%d %H:%M UTC", time.gmtime(result.checked_at)
    )

    # ── Card header ───────────────────────────────────────────────
    st.markdown(
        f"""
<div class="ioc-card {verdict}">
  <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:0.5rem;">
    <div>
      <div style="font-family:var(--font-mono);font-size:1.05rem;font-weight:600;
                  color:var(--text-primary);word-break:break-all;">
        {result.ioc}
      </div>
      <div style="margin-top:0.3rem;display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;">
        <span style="font-family:var(--font-mono);font-size:0.7rem;
                     color:var(--text-dim);background:var(--bg-elevated);
                     padding:0.15rem 0.5rem;border-radius:3px;">
          {ioc_label}
        </span>
        {verdict_badge_html(verdict)}
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-dim);">
        {checked_ts}
      </div>
      <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-secondary);
                  margin-top:0.25rem;">
        {result.malicious_count}/{result.source_count} sources flagged
      </div>
    </div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    # ── Source results ─────────────────────────────────────────────
    if result.sources:
        for sr in result.sources:
            render_source_result(sr)
    else:
        st.caption("No API sources were queried (check API key configuration).")

    st.markdown("<hr style='margin:1rem 0;opacity:0.15;'>", unsafe_allow_html=True)


def render_summary_metrics(results: list[OsintResult]) -> None:
    """Render top-line summary metrics row."""
    if not results:
        return

    total      = len(results)
    malicious  = sum(1 for r in results if r.overall_verdict == "malicious")
    suspicious = sum(1 for r in results if r.overall_verdict == "suspicious")
    clean      = sum(1 for r in results if r.overall_verdict == "clean")
    unknown    = sum(1 for r in results if r.overall_verdict in ("unknown", "error"))

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total IOCs", total)
    c2.metric("🔴 Malicious",  malicious)
    c3.metric("🟡 Suspicious", suspicious)
    c4.metric("🟢 Clean",      clean)
    c5.metric("⚪ Unknown",    unknown)


def render_api_status_sidebar(api_keys: dict[str, str]) -> None:
    """Render coloured API status dots in the sidebar."""
    source_labels = {
        "virustotal": "VirusTotal",
        "abuseipdb":  "AbuseIPDB",
        "shodan":     "Shodan",
        "otx":        "OTX AlienVault",
        "urlscan":    "URLScan.io",
    }
    st.sidebar.markdown("### API Sources")
    for key, label in source_labels.items():
        active = bool(api_keys.get(key, "").strip())
        dot_cls = "active" if active else "inactive"
        status_txt = "connected" if active else "no key"
        st.sidebar.markdown(
            f'<div class="api-status">'
            f'<div class="api-dot {dot_cls}"></div>'
            f"<span>{label}</span>"
            f'<span style="margin-left:auto;font-size:0.65rem;'
            f"color:{'var(--tint)' if active else 'var(--text-dim)'}\">"
            f"{status_txt}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
