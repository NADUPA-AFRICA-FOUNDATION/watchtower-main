"""Hit score: a documented sum, nothing learned and nothing hidden.

    best term match     exact phrase 40, or every word present (any order, or run together
                        in a handle) 25
    more terms          +5 for each further watchlist term matched, at most +15
    recency             published within 1 day 20, 7 days 15, 30 days 10, 365 days 5
    engagement          round(2.5 * log10(1 + likes + comments + shares + views)), at most 10
    lure wording        +15 when the account name or wording matches a known scam pattern

Maximum 100. A value the source did not give scores 0 and the reason says "unknown", so a
low score can be told apart from a low-quality sighting. Every point appears in `reasons`.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone

CONFIDENCE = {"ok": 0.9, "partial": 0.7, "snippet_only": 0.5}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w@#]+", " ", (text or "").lower())).strip()


def match_term(term: str, haystack: str, compact: str) -> str | None:
    """'exact', 'fuzzy' or None. `compact` is the text with everything but letters and digits removed."""
    t = _norm(term)
    if not t:
        return None
    if re.search(rf"(?<!\w){re.escape(t)}(?!\w)", haystack):
        return "exact"
    words = t.split()
    if len(words) > 1 and all(re.search(rf"(?<!\w){re.escape(w)}(?!\w)", haystack) for w in words):
        return "fuzzy"
    squeezed = re.sub(r"[^a-z0-9]", "", t)
    if len(squeezed) >= 5 and squeezed in compact:
        return "fuzzy"                                  # "fuliza boost" inside the handle @fulizaboost1
    return None


def _age_days(published_at: str | None, now_ms: int) -> float | None:
    if not published_at:
        return None
    try:
        dt = datetime.fromisoformat(str(published_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now_ms / 1000 - dt.timestamp()) / 86400)


def score_hit(hit: dict, terms: list[dict], now_ms: int, lure: bool = False) -> dict:
    """terms: [{"term": str, "match_type": "exact"|"fuzzy"}]. Returns score, reasons, matched_terms, confidence."""
    text = " ".join(str(x) for x in (hit.get("title"), hit["content"].get("text"), hit["author"].get("username"),
                                     hit["author"].get("display_name"), hit.get("url")) if x)
    haystack, compact = _norm(text), re.sub(r"[^a-z0-9]", "", text.lower())
    matches = []
    for t in terms:
        kind = match_term(t["term"], haystack, compact)
        if kind == "exact" or (kind == "fuzzy" and t.get("match_type", "fuzzy") != "exact"):
            matches.append((t["term"], kind))
    reasons = []
    if matches:
        best = "exact" if any(k == "exact" for _, k in matches) else "fuzzy"
        reasons.append({"signal": "term_match", "points": 40 if best == "exact" else 25,
                        "basis": f"{best} match: {', '.join(t for t, _ in matches)}"})
        if len(matches) > 1:
            reasons.append({"signal": "more_terms", "points": min(15, 5 * (len(matches) - 1)),
                            "basis": f"{len(matches)} watchlist terms matched"})
    else:
        reasons.append({"signal": "term_match", "points": 0, "basis": "no watchlist term found in the text"})

    age = _age_days(hit["content"].get("published_at"), now_ms)
    if age is None:
        reasons.append({"signal": "recency", "points": 0, "basis": "published date unknown"})
    else:
        pts = 20 if age <= 1 else 15 if age <= 7 else 10 if age <= 30 else 5 if age <= 365 else 0
        reasons.append({"signal": "recency", "points": pts, "basis": f"published {age:.0f} day(s) ago"})

    known = [v for v in hit["engagement"].values() if isinstance(v, (int, float))]
    if known:
        pts = min(10, round(2.5 * math.log10(1 + sum(known))))
        reasons.append({"signal": "engagement", "points": pts, "basis": f"{int(sum(known))} known interactions"})
    else:
        reasons.append({"signal": "engagement", "points": 0, "basis": "engagement unknown"})

    if lure:
        reasons.append({"signal": "lure_wording", "points": 15, "basis": "account name or wording matches a known scam pattern"})

    return {"score": min(100, sum(r["points"] for r in reasons)), "reasons": reasons,
            "matched_terms": [t for t, _ in matches], "confidence": CONFIDENCE.get(hit.get("status"), 0.0)}
