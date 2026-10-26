"""HTML -> clean text. No LLM involved, and that's the point.

trafilatura strips nav, ads, footers and comment sections better than anything
you'd write yourself, and it costs nothing per call. Do this BEFORE anything
touches the model: it typically cuts token count by well over half.
"""

from __future__ import annotations

_CONFIG = None


def _load():
    """trafilatura (with lxml) is ~150ms to import and only article extraction needs it, so it loads on
    first use rather than at server start."""
    global _CONFIG
    import trafilatura
    if _CONFIG is None:
        from trafilatura.settings import use_config
        # Silence trafilatura's signal-based timeout, which breaks in threads.
        _CONFIG = use_config()
        _CONFIG.set("DEFAULT", "EXTRACTION_TIMEOUT", "0")
    return trafilatura


def extract(html: str, url: str = "") -> dict[str, str]:
    """Returns title, text, author, published_at, lang. Empty strings on failure."""
    blank = {"title": "", "text": "", "author": "", "published_at": "", "lang": ""}
    if not html:
        return blank

    trafilatura = _load()
    meta = trafilatura.extract_metadata(html, default_url=url)
    text = trafilatura.extract(
        html,
        config=_CONFIG,
        include_comments=False,
        include_tables=True,
        favor_precision=True,
        url=url or None,
    ) or ""

    return {
        "title": (getattr(meta, "title", "") or "").strip(),
        "text": text.strip(),
        "author": (getattr(meta, "author", "") or "").strip(),
        "published_at": (getattr(meta, "date", "") or "").strip(),
        "lang": (getattr(meta, "language", "") or "").strip(),
    }


def truncate(text: str, max_chars: int = 12000) -> str:
    """Cap what goes to the model. Most articles are well under this; the ones
    that aren't are usually liveblogs or transcripts where the top is enough."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + " [...truncated]"
