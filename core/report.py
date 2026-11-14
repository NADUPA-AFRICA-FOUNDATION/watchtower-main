"""Rendering sweep results. Terminal for the glance, markdown for the record."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from core.sweep import SweepResult

BANDS = [(80, "HIGH"), (60, "MED"), (30, "LOW"), (0, "WEAK")]


def band(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "WEAK"


def slug(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:limit] or "sweep"


def _short(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + "..."


def _cell(value: object) -> str:
    """Keep user/provider text from breaking Markdown tables."""
    return _md_text(value)


def _md_text(value: object) -> str:
    """Escape provider/page text before placing it in a Markdown document."""
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    # Escape the characters that can introduce links, HTML, emphasis, code or
    # table structure.  Reports are often opened in capable Markdown viewers,
    # so scraped content must remain data rather than executable markup.
    return re.sub(r"([\\`*_[\]{}()<>#!|])", r"\\\1", text)


def _md_url(value: object) -> str:
    """Return a safe Markdown destination, or an empty string if unsafe."""
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or any(ch.isspace() for ch in raw)):
        return ""
    return raw.replace("\\", "%5C").replace("<", "%3C").replace(">", "%3E")


def _md_link(label: object, url: object) -> str:
    """Render a link only when its destination is an HTTP(S) URL."""
    text = _md_text(label)
    destination = _md_url(url)
    return f"[{text}](<{destination}>)" if destination else text


def progress_line(event: dict) -> str:
    """Render a sweep progress event as a CLI line. The web UI renders the same
    events as telemetry; neither owns the format."""
    kind = event.get("type")
    if kind == "source":
        name, count = event["name"], event["count"]
        if event.get("skipped"):
            return f"  {name:<14} not searched ({event['skipped']})"
        if event.get("error"):
            # Prefer the real reason over the exception class name: "HTTP 429"
            # tells you what to do, "SourceError" does not.
            return f"  {name:<14} FAILED ({event.get('reason') or event['error']})"
        return f"  {name:<14} {count} hit(s)"
    if kind == "partial":
        return f"  {event['name']:<14} {event['count']} so far"
    if kind == "stage":
        stage = event["stage"]
        if stage == "dedupe":
            return f"  deduped        {event['before']} -> {event['after']}"
        if stage == "fetch":
            return f"  fetching       {event['count']} article body(ies)"
        if stage == "score":
            return f"  scoring        {event['count']} item(s) with Claude"
    if kind == "scored":
        return f"    [{event['relevance']:>3}] {event['title']}"
    return ""


def _verdict_line(item) -> str:
    """The plain-language reading of an indexed social result, on one line ('' if it has none)."""
    v = (item.raw_meta or {}).get("verdict") or {}
    if not v.get("label"):
        return ""
    return " ".join(x for x in (f"{v['label']}:", v.get("reason", ""), v.get("action", "")) if x)


# ------------------------------------------------------------- terminal

def terminal(result: SweepResult, top: int = 20) -> str:
    if not result.items:
        # "Nothing found" is a claim about the world. Only make it when every
        # source was actually searched.
        complete = getattr(result, "complete", True)
        out = [f'\nNothing found for "{result.query}".' if complete
               else f'\nINCOMPLETE SWEEP for "{result.query}" — '
                    "no results, but not every source was searched.",
               ""]
        for name, why in getattr(result, "failed", {}).items():
            out.append(f"  {name:<14} FAILED — {why}")
        for name, why in getattr(result, "skipped", {}).items():
            out.append(f"  {name:<14} not searched — {why}")
        if complete:
            out.append("Try a wider --hours window or fewer/looser terms.")
        else:
            out.append("\nDo not read this as a clean result.")
        return "\n".join(out) + "\n"

    lines = [
        "",
        f'  "{result.query}"',
        f"  {len(result.items)} result(s)"
        + (f", {len(result.strong)} strong" if result.enriched else "")
        + ("" if result.enriched else
           f"  [keyword ranking only — {getattr(result, 'scoring_error', '') or 'no API key'}]"),
        "  " + "-" * 66,
    ]

    for i, item in enumerate(result.items[:top], 1):
        lines.append(f"  {i:>2}. [{band(item.relevance):<4} {item.relevance:>3}] "
                     f"{_short(item.title, 62) or '(untitled)'}")
        meta = item.source
        if item.published_at:
            meta += f"  |  {item.published_at[:16]}"
        lines.append(f"      {meta}")
        lines.append(f"      {item.url}")
        verdict = _verdict_line(item)
        if verdict:
            lines.append(f"      >> {verdict}")
        body = item.summary or _short(item.text, 150)
        if body:
            lines.append(f"      {body}")
        lines.append("")

    if len(result.items) > top:
        lines.append(f"  ... and {len(result.items) - top} more in the report file")

    if result.entities:
        lines.append("  Recurring names:")
        lines.append("      " + ",  ".join(
            f"{name} ({n})" for name, n in result.entities[:10]))
        lines.append("")

    failed = getattr(result, "failed", {})
    skipped = getattr(result, "skipped", {})
    lines.append("  Sources: " + ",  ".join(
        f"{k} {'FAILED' if k in failed else 'skipped' if k in skipped else v}"
        for k, v in result.per_source.items()))
    for name, why in failed.items():
        lines.append(f"    ! {name}: {why}")
    for name, why in skipped.items():
        lines.append(f"    - {name} not searched: {why}")
    if failed or skipped:
        lines.append("  Coverage is incomplete — these counts are a floor, "
                     "not a finding.")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------- markdown

def markdown(result: SweepResult) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    searched = sum(1 for name in result.per_source
                   if name not in result.failed and name not in result.skipped)
    requested = len(result.per_source)
    strong = len(result.strong)
    ranking = "AI-assisted" if result.enriched else "Keyword-only"
    md = [
        f"# Sweep: {_md_text(result.query)}",
        "",
        f"*Generated {stamp}*",
        "",
        "## Executive summary",
        "",
        f"- **Results:** {len(result.items)} findings; {strong} scored medium or high.",
        f"- **Coverage:** {searched} of {requested} requested sources searched.",
        f"- **Ranking:** {ranking}.",
        "",
    ]

    if not result.enriched:
        reason = result.scoring_error or "No model API key was available"
        md += [f"> **Ranking limitation:** {_cell(reason)}. Scores indicate keyword "
               "overlap, not a verified risk assessment.", ""]

    if not result.complete:
        md += ["> **Coverage warning:** This sweep is incomplete. Missing sources "
               "mean the findings are a floor, not proof that nothing else exists.", ""]

    watchlist = [item for item in result.items if item.source_type == "watchlist"]
    if watchlist:
        md += ["## Watchlist matches", ""]
        for watch_item in watchlist:
            md += [f"- **{_md_link(watch_item.title, watch_item.url)}** — "
                   f"{_md_text(watch_item.text)}"]
        md.append("")

    if result.entities:
        md += ["## Recurring names", "",
               "| Name | Mentions |", "| --- | ---: |"]
        md += [f"| {_cell(n)} | {c} |" for n, c in result.entities]
        md.append("")

    ordinary = [i for i in result.items if i.source_type != "watchlist"]
    if ordinary:
        md += ["## Priority findings", "",
               "| Score | Finding | Source | Published |",
               "| ---: | --- | --- | --- |"]
        for item in ordinary[:10]:
            title = item.title or "Untitled"
            published = _cell(item.published_at[:10] if item.published_at else "—")
            md.append(f"| **{band(item.relevance)} {item.relevance}** | "
                      f"{_md_link(title, item.url)} | {_cell(item.source)} | {published} |")
        md.append("")

    md += ["## Finding details", ""]
    for finding_index, item in enumerate(ordinary, 1):
        md += [f"### {finding_index}. {_md_text(item.title or '(untitled)')}", "",
               f"**Priority:** {band(item.relevance)} ({item.relevance}/100)  ",
               f"**Source:** {_cell(item.source)}"
               + (f" · {_cell(item.published_at[:16])}" if item.published_at else "")
               + (f" · {_cell(item.author)}" if item.author else ""),
               "",
               f"**Original:** {_md_link(item.url, item.url)}", ""]
        if _verdict_line(item):
            md += [f"**Reading:** {_md_text(_verdict_line(item))}", ""]
        if item.summary:
            md += [f"**Summary:** {_md_text(_short(item.summary, 500))}", ""]
        elif item.text:
            md += [f"**Extract:** {_md_text(_short(item.text, 240))}", ""]
        if item.categories:
            md += ["Tags: " + ", ".join(f"`{_md_text(c)}`" for c in item.categories), ""]
        if item.entities:
            md += ["Entities: " + ", ".join(_md_text(e) for e in item.entities), ""]

    md += ["## Source coverage", "",
           "| Source | Status | Hits | Detail |",
           "| --- | --- | ---: | --- |"]
    for name, hits in result.per_source.items():
        if name in result.failed:
            status, detail = "Failed", result.failed[name]
        elif name in result.skipped:
            status, detail = "Not searched", result.skipped[name]
        else:
            status, detail = "Searched", "—"
        md.append(f"| {_cell(name)} | {status} | {hits} | {_cell(detail)} |")
    md.append("")

    if result.errors:
        md += ["### Errors", ""] + [f"- `{_md_text(e)}`" for e in result.errors] + [""]

    md += ["---", "",
           "Collected from public APIs and published feeds. Verify anything "
           "material against the primary source before acting on it.", ""]
    return "\n".join(md)


# --------------------------------------------------------------- print-ready HTML

def _href(value: str) -> str:
    """Allow only public web links in generated report anchors."""
    parsed = urlsplit(value or "")
    return escape(value, quote=True) if parsed.scheme in {"http", "https"} else "#"


def _html_text(value: object) -> str:
    return escape(str(value or ""), quote=False)


def html_report(result: SweepResult) -> str:
    """Build a self-contained, readable report that browsers can print to PDF.

    The dark neon presentation is the screen view; print media switches to
    white paper with high-contrast ink so exported PDFs remain legible.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    searched = sum(1 for name in result.per_source
                   if name not in result.failed and name not in result.skipped)
    requested = len(result.per_source)
    coverage_class = "ok" if result.complete else "warn"
    rows = []
    ordinary = [item for item in result.items if item.source_type != "watchlist"]
    for index, item in enumerate(ordinary, 1):
        label = band(item.relevance)
        details = _html_text(item.summary or _short(item.text, 500))
        rows.append(
            f'<article class="finding finding-{label.lower()}">'
            f'<div class="finding-index">{index:02d}</div>'
            f'<div class="finding-main"><div class="finding-top">'
            f'<span class="score score-{label.lower()}">{label} · {item.relevance}/100</span>'
            f'<span class="source">{_html_text(item.source)}</span></div>'
            f'<h3><a href="{_href(item.url)}">{_html_text(item.title or "Untitled")}</a></h3>'
            + (f'<p><strong>{_html_text(_verdict_line(item))}</strong></p>' if _verdict_line(item) else "")
            + f'<p>{details or "No article body was available."}</p>'
            f'<div class="finding-meta">{_html_text(item.published_at[:16] if item.published_at else "Date unavailable")}'
            f'{" · " + _html_text(item.author) if item.author else ""}</div></div></article>'
        )
    watchlist_rows = []
    for item in [item for item in result.items if item.source_type == "watchlist"]:
        watchlist_rows.append(
            f'<li><a href="{_href(item.url)}">{_html_text(item.title or "Watchlist match")}</a>'
            f'<span>{_html_text(item.text or item.summary)}</span></li>'
        )
    entity_rows = "".join(
        f'<li><span>{_html_text(name)}</span><strong>{count}</strong></li>'
        for name, count in result.entities
    )
    coverage_rows = []
    for name, hits in result.per_source.items():
        if name in result.failed:
            status, detail = "FAILED", result.failed[name]
        elif name in result.skipped:
            status, detail = "NOT SEARCHED", result.skipped[name]
        else:
            status, detail = "SEARCHED", ""
        coverage_rows.append(
            f'<tr><td>{_html_text(name)}</td><td><span class="status status-{status.lower().replace(" ", "-")}">{status}</span></td>'
            f'<td>{hits}</td><td>{_html_text(detail)}</td></tr>'
        )
    limitation = "" if result.enriched else (
        f'<aside class="notice warn"><strong>Ranking limitation:</strong> '
        f'{_html_text(result.scoring_error or "No model API key was available")}. '
        "Scores indicate keyword overlap, not a verified risk assessment.</aside>"
    )
    warning = "" if result.complete else (
        '<aside class="notice warn"><strong>Coverage warning:</strong> '
        "This sweep is incomplete. Findings are a floor, not proof that nothing else exists.</aside>"
    )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mnara // {_html_text(result.query)}</title>
<style>
:root {{ color-scheme: dark; --bg:#070b12; --panel:#0d1420; --line:#1b3548; --ink:#e8f7ff; --muted:#87a7b8; --cyan:#00e5ff; --pink:#ff3cac; --amber:#ffbf3f; --red:#ff5c7a; --green:#6dff9b; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; }}
.page {{ max-width:1080px; margin:0 auto; padding:44px 34px 64px; }}
.kicker {{ color:var(--cyan); letter-spacing:.2em; font-size:11px; text-transform:uppercase; }}
h1 {{ margin:8px 0 4px; font-size:clamp(25px,4vw,42px); letter-spacing:-.05em; }} h2 {{ margin:36px 0 14px; color:var(--cyan); font-size:16px; letter-spacing:.12em; text-transform:uppercase; }}
.stamp {{ color:var(--muted); font-size:12px; }} .summary {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:28px 0; }}
.metric {{ border:1px solid var(--line); border-left:3px solid var(--cyan); background:var(--panel); padding:16px; }} .metric strong {{ display:block; font-size:24px; color:var(--ink); }} .metric span {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
.notice {{ border:1px solid var(--line); padding:14px 16px; margin:14px 0; background:var(--panel); }} .notice.warn {{ border-left:3px solid var(--amber); color:#ffe5a1; }}
.finding {{ display:grid; grid-template-columns:48px 1fr; gap:14px; border:1px solid var(--line); border-left:3px solid var(--cyan); background:var(--panel); margin:12px 0; padding:15px; break-inside:avoid; }}
.finding-high {{ border-left-color:var(--pink); }} .finding-med {{ border-left-color:var(--amber); }} .finding-low {{ border-left-color:var(--green); }} .finding-index {{ color:var(--muted); font-size:18px; }}
.finding-top {{ display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; font-size:11px; }} .score {{ color:var(--cyan); font-weight:700; }} .score-high {{ color:var(--pink); }} .score-med {{ color:var(--amber); }} .score-low {{ color:var(--green); }} .source,.finding-meta {{ color:var(--muted); }}
h3 {{ margin:7px 0; font-size:16px; }} a {{ color:var(--ink); text-decoration-color:var(--cyan); text-underline-offset:3px; }} a:hover {{ color:var(--cyan); }} .finding p {{ margin:8px 0; color:#c3d7df; }}
ul {{ list-style:none; padding:0; margin:0; }} .entity-list {{ display:grid; grid-template-columns:repeat(2,1fr); gap:6px 24px; }} .entity-list li {{ display:flex; justify-content:space-between; border-bottom:1px dotted var(--line); padding:5px 0; }}
.watchlist li {{ border:1px solid var(--line); background:var(--panel); padding:10px 12px; margin:7px 0; }} .watchlist span {{ display:block; color:var(--muted); margin-top:3px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }} th,td {{ text-align:left; border-bottom:1px solid var(--line); padding:9px 8px; vertical-align:top; }} th {{ color:var(--cyan); text-transform:uppercase; letter-spacing:.08em; font-size:10px; }}
.status {{ font-size:10px; letter-spacing:.08em; }} .status-searched {{ color:var(--green); }} .status-failed {{ color:var(--red); }} .status-not-searched {{ color:var(--amber); }} .footer {{ margin-top:44px; border-top:1px solid var(--line); padding-top:14px; color:var(--muted); font-size:11px; }}
@media (max-width:650px) {{ .page {{ padding:28px 16px 48px; }} .summary {{ grid-template-columns:1fr; }} .entity-list {{ grid-template-columns:1fr; }} table {{ display:block; overflow-x:auto; white-space:nowrap; }} }}
@media print {{ :root {{ color-scheme:light; }} body {{ background:#fff; color:#111; font:10pt/1.45 Arial,sans-serif; }} .page {{ max-width:none; padding:0; }} h1,h2,.kicker,.score,th {{ color:#111; }} h2 {{ border-bottom:2px solid #111; padding-bottom:4px; }} .metric,.finding,.notice,.watchlist li {{ background:#fff; border-color:#999; }} .metric {{ border-left-color:#111; }} .finding-high,.finding-med,.finding-low {{ border-left-color:#111; }} .finding p,a {{ color:#111; }} .source,.finding-meta,.stamp,.entity-list li,.watchlist span,.footer {{ color:#444; }} .status {{ color:#111; }} .finding {{ break-inside:avoid; }} a {{ text-decoration:underline; }} }}
</style></head><body><main class="page">
<div class="kicker">MNARA // intelligence report</div><h1>{_html_text(result.query)}</h1><div class="stamp">Generated {stamp}</div>
<div class="summary"><div class="metric"><strong>{len(result.items)}</strong><span>findings</span></div><div class="metric"><strong>{len(result.strong)}</strong><span>medium/high priority</span></div><div class="metric"><strong class="coverage-{coverage_class}">{searched}/{requested}</strong><span>sources searched</span></div></div>
{limitation}{warning}
{f'<section><h2>Watchlist matches</h2><ul class="watchlist">{"".join(watchlist_rows)}</ul></section>' if watchlist_rows else ''}
{f'<section><h2>Recurring entities</h2><ul class="entity-list">{entity_rows}</ul></section>' if entity_rows else ''}
<section><h2>Priority findings</h2>{''.join(rows) if rows else '<div class="notice">No findings were returned.</div>'}</section>
<section><h2>Source coverage</h2><table><thead><tr><th>Source</th><th>Status</th><th>Hits</th><th>Detail</th></tr></thead><tbody>{''.join(coverage_rows)}</tbody></table></section>
{f'<section><h2>Errors</h2><ul class="watchlist">{"".join(f"<li>{_html_text(e)}</li>" for e in result.errors)}</ul></section>' if result.errors else ''}
<div class="footer">Collected from public APIs and published feeds. Verify material findings against the primary source before acting.</div>
</main></body></html>'''


def save(result: SweepResult, out_dir: str | Path = "out") -> Path:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = d / f"sweep-{slug(result.query)}-{stamp}.md"
    path.write_text(markdown(result), encoding="utf-8")
    path.with_suffix(".html").write_text(html_report(result), encoding="utf-8")
    return path
