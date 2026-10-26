"""One keyword in, a ranked set of findings out.

    findings = sweep("beneficial ownership Kenya", hours=72)

Pipeline: fan out across every backend -> dedupe on content hash -> fetch
article bodies concurrently -> clean -> score against the query with Claude ->
rank with source diversity -> roll up entities.

Runs fine with no API key at all. You lose scoring and summaries, and fall back
to keyword-overlap ranking, but you still get results.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field

from core.clean import extract, truncate
from core.enrich import Enricher
from core.fetch import Fetcher
from core.models import Item
from core.sources import BACKENDS, DEFAULT_BACKENDS, SourceError, SourceSkipped

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "for", "to", "at", "by",
    "with", "from", "is", "was", "are", "were", "be", "been", "as", "that",
    "this", "it", "its", "has", "have", "had", "not", "but", "they", "their",
}


@dataclass
class SweepResult:
    query: str
    items: list[Item] = field(default_factory=list)
    entities: list[tuple[str, int]] = field(default_factory=list)
    per_source: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    enriched: bool = False
    # name -> reason. Sources that failed, and sources never attempted, kept
    # apart from each other and from a genuine zero. `per_source` says how many
    # hits; only these say whether the number can be trusted.
    failed: dict[str, str] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    # Why scoring fell back to keywords, when it wasn't simply a missing key.
    scoring_error: str = ""

    @property
    def strong(self) -> list[Item]:
        return [i for i in self.items if i.relevance >= 60]

    @property
    def complete(self) -> bool:
        """True when every requested source was actually searched. A zero-item
        sweep that is not complete must never be reported as 'nothing found'."""
        return not self.failed and not self.skipped


def _terms(query: str) -> list[str]:
    words = re.findall(r"[a-z0-9']+", query.lower())
    return [w for w in words if w not in STOPWORDS and len(w) > 2]


def _keyword_score(item: Item, terms: list[str]) -> int:
    """Fallback ranking when there's no API key. Crude but not useless:
    title matches count double, and coverage of the query matters more than
    raw frequency, so a doc mentioning every term beats one repeating a single
    term twenty times."""
    if not terms:
        return 0
    title = item.title.lower()
    body = item.text.lower()
    covered = sum(1 for t in terms if t in title or t in body)
    weighted = sum((2 if t in title else 0) + min(body.count(t), 5) for t in terms)
    return min(100, int((covered / len(terms)) * 60 + min(weighted, 20) * 2))


def _domain_of(item: Item) -> str:
    d = item.raw_meta.get("domain")
    if d:
        return str(d).lower()
    parts = item.url.split("/")
    return parts[2].lower() if len(parts) > 2 else ""


# A regulator's own circular and a content farm are not equally good evidence.
# Multiplied into the keyword score, so a primary source has to be roughly as
# on-topic as an aggregator to outrank it — this tilts ties, it doesn't
# manufacture relevance out of nothing.
SOURCE_TIER = {
    "watchlist": 1.30,     # opensanctions — a listing is a fact, not a claim
    "regulatory": 1.25,    # sec_edgar, regulator pages
    "dataset": 1.15,       # gleif, opencorporates — registry records
    "news": 1.00,
    "reference": 0.85,     # wikipedia: useful background, rarely the finding
    "social": 0.75,        # mastodon, bluesky, reddit, hn, x — a lead, not proof
}


def _headline_only(item: Item) -> bool:
    """No body worth scoring — a title and little else.

    GDELT with fetch_body=False returns headlines. Scoring those as though the
    article had been read overstates them: a matching headline says the words
    appeared, not that the piece is about your query.
    """
    return len(item.text.strip()) < 200


def _adjust(score: int, item: Item) -> int:
    """Apply source tier, corroboration and headline penalty to a raw score."""
    adjusted = score * SOURCE_TIER.get(item.source_type, 1.0)

    # Corroboration: +6 per extra independent domain, capped. Deliberately
    # additive and small — it should promote a well-attested story over an
    # equally-relevant single-source one, not rescue an irrelevant one.
    extra = max(0, int(item.raw_meta.get("corroboration", 1)) - 1)
    adjusted += min(extra * 6, 18)

    # Bait phrases on an indexed social lead ("guaranteed", "hit admin inbox",
    # "slots almost full"). Additive and capped like corroboration: it lifts a
    # lure above how-to videos, it cannot make an unrelated row relevant.
    from core.fraud_lexicon import SUBJECT_FAMILIES
    # Subject families ("fuliza limit increase") match every on-topic result, so they say nothing
    # about whether it is a lure; only behavioural families (fees, funnels, guarantees...) count.
    bait = [b for b in (item.raw_meta.get("bait_signals") or []) if b not in SUBJECT_FAMILIES]
    if len(bait) >= 2 and not item.raw_meta.get("advisory"):
        adjusted += min(len(bait) * 6, 18)

    if _headline_only(item):
        # Cap rather than scale: an unread headline should not reach the top
        # band on keyword overlap alone.
        adjusted = min(adjusted * 0.8, 55)
        item.raw_meta["headline_only"] = True

    return max(0, min(100, int(round(adjusted))))


def _preview(item: Item, terms: list[str]) -> dict:
    """Small JSON-safe finding for live delivery before final processing.

    This score is deliberately labelled provisional by the UI: article-body
    extraction, cross-source deduplication and model scoring happen later.
    """
    relevance = _adjust(_keyword_score(item, terms), item)
    band_name = ("HIGH" if relevance >= 80 else "MED" if relevance >= 60
                 else "LOW" if relevance >= 30 else "WEAK")
    return {
        "url": item.url,
        "title": item.title or "(untitled)",
        "source": item.source,
        "source_type": item.source_type,
        "published_at": item.published_at,
        "author": item.author,
        "text": (item.text or "")[:320],
        "summary": "",
        "categories": [],
        "raw_meta": item.raw_meta,
        "relevance": relevance,
        "band": band_name,
        "provisional": True,
    }


def _diversify(items: list[Item], cap_per_domain: int = 3) -> list[Item]:
    """Stop one prolific outlet burying everything else. Syndicated wire copy
    means a single story can occupy your entire top ten otherwise."""
    seen: Counter[str] = Counter()
    kept, overflow = [], []
    for item in items:
        domain = item.raw_meta.get("domain") or item.url.split("/")[2:3]
        domain = domain if isinstance(domain, str) else (domain[0] if domain else "?")
        if seen[domain] < cap_per_domain:
            seen[domain] += 1
            kept.append(item)
        else:
            overflow.append(item)
    return kept + overflow


def sweep(query: str, fetcher: Fetcher, hours: int = 72,
          backends: list[str] | None = None, limit: int = 40,
          fetch_bodies: bool = True, enricher: Enricher | None = None,
          max_enrich: int = 25, workers: int = 6, budget: float | None = None,
          protected_backends: set[str] | None = None,
          progress=lambda event: None) -> SweepResult:
    """`progress` receives dicts, not strings, so callers can render them
    however they like: a CLI line, an SSE frame, a log record."""

    backends = backends or DEFAULT_BACKENDS
    protected_backends = protected_backends or set()
    result = SweepResult(query=query)
    terms = _terms(query)

    # `budget` exists for hosts that kill a request at a fixed wall clock —
    # serverless, mostly. Running out of time is reported through the same
    # `skipped` channel as a missing key, because it is the same fact: that
    # source was not searched, and the result must not read as if it were.
    deadline = (time.monotonic() + budget) if budget else None

    def time_left() -> float:
        return float("inf") if deadline is None else deadline - time.monotonic()

    # --- 1. fan out ---------------------------------------------------
    # Concurrent, not sequential: every backend is a different host, so there
    # is nothing to gain by serialising them and a lot to lose — one slow
    # source used to stall every lane behind it, which is why a live sweep
    # looked frozen for 58s and then finished all at once. Per-domain rate
    # limiting still holds because Fetcher._throttle checks and sets the
    # last-hit timestamp under one lock (see fetch_test in sweep_test.py).
    collected: list[Item] = []
    runnable = []
    for name in backends:
        fn = BACKENDS.get(name)
        if fn is None:
            result.errors.append(f"unknown backend: {name}")
            continue
        runnable.append((name, fn))

    def run_backend(name, fn):
        return name, fn(query, fetcher, hours=hours, limit=limit)

    # Not a `with` block: __exit__ calls shutdown(wait=True), which blocks until
    # the slowest backend finishes and would make the budget cosmetic — we'd
    # stop *waiting* on time and then get killed anyway. Shut down without
    # waiting and let the straggler die with the process.
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(runnable) or 1)))
    try:
        futures = {pool.submit(run_backend, n, f): n for n, f in runnable}
        done_iter = []
        try:
            # Process futures as they complete. Materialising as_completed into
            # a list first held every progress event until the slowest source
            # finished, making the live monitor look frozen for the full
            # request budget even when most sources had already answered.
            wait_for = None if deadline is None else max(0.0, time_left())
            for future in as_completed(futures, timeout=wait_for):
                done_iter.append(future)
                name = futures[future]
                try:
                    _, got = future.result()
                except SourceSkipped as e:
                    result.skipped[name] = str(e)
                    result.per_source[name] = 0
                    progress({"type": "source", "name": name, "count": 0,
                              "skipped": str(e)})
                except Exception as e:
                    reason = (str(e) if isinstance(e, SourceError)
                              else f"{type(e).__name__}: {e}")
                    result.failed[name] = reason
                    result.errors.append(f"{name}: {reason}")
                    result.per_source[name] = 0
                    progress({"type": "source", "name": name, "count": 0,
                              "error": type(e).__name__, "reason": reason})
                else:
                    collected.extend(got)
                    result.per_source[name] = len(got)
                    progress({"type": "source", "name": name,
                              "count": len(got),
                              "preview": [_preview(item, terms)
                                          for item in got[:5]]})
        except FuturesTimeout:
            pass
        # A paid request may settle upstream even if we stop waiting locally.
        # Let only explicitly protected paid futures finish so their results
        # are not discarded; the deadline still applies to every other source
        # and to all downstream body-fetch/model-scoring work.
        protected_futures = [
            future for future, name in futures.items()
            if name in protected_backends and future not in done_iter
        ]
        for future in protected_futures:
            try:
                future.result()
            except Exception:
                pass
            done_iter.append(future)
        for fut in futures:
            name = futures[fut]
            if fut not in done_iter:
                fut.cancel()
                result.skipped[name] = "exceeded the sweep time budget"
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "skipped": "exceeded the sweep time budget"})
                continue
            # Ordinary completed futures were handled immediately above.
            # Only protected futures can arrive here without having been
            # rendered yet because they are allowed to finish after deadline.
            if fut not in protected_futures:
                continue
            try:
                _, got = fut.result()
            except SourceSkipped as e:
                result.skipped[name] = str(e)
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "skipped": str(e)})
            except Exception as e:
                reason = str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"
                result.failed[name] = reason
                result.errors.append(f"{name}: {reason}")
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "error": type(e).__name__, "reason": reason})
            else:
                collected.extend(got)
                result.per_source[name] = len(got)
                progress({"type": "source", "name": name, "count": len(got),
                          "preview": [_preview(item, terms)
                                      for item in got[:5]]})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Completion order is nondeterministic; reports should not be. Restore the
    # order the caller asked for.
    result.per_source = {n: result.per_source[n] for n, _ in runnable
                         if n in result.per_source}
    collected.sort(key=lambda i: (i.source, i.url))

    if not collected:
        return result

    # --- 2. dedupe, keeping the corroboration ---------------------------
    # Collapsing five outlets into one row is right; throwing away the fact
    # that five independent outlets carried it is not. The number of distinct
    # domains reporting a story is the cheapest strong signal that it is real,
    # and it costs nothing — we already have the duplicates in hand.
    by_hash: dict[str, Item] = {}
    domains_by_hash: dict[str, set] = {}
    sources_by_hash: dict[str, set] = {}
    for item in collected:
        h = item.content_hash
        domains_by_hash.setdefault(h, set()).add(_domain_of(item))
        sources_by_hash.setdefault(h, set()).add(item.source)
        existing = by_hash.get(h)
        if existing is None:
            by_hash[h] = item
        elif len(item.text) > len(existing.text):
            by_hash[h] = item                      # keep the fuller copy

    deduped = list(by_hash.values())
    for item in deduped:
        h = item.content_hash
        domains = sorted(d for d in domains_by_hash.get(h, set()) if d)
        item.raw_meta["corroboration"] = len(domains)
        item.raw_meta["corroborating_domains"] = domains[:8]
        item.raw_meta["corroborating_sources"] = sorted(sources_by_hash.get(h, set()))

    progress({"type": "stage", "stage": "dedupe",
              "before": len(collected), "after": len(deduped)})

    # --- 3. fetch bodies ----------------------------------------------
    needs_body = [i for i in deduped
                  if fetch_bodies and len(i.text) < 400
                  and i.source_type not in ("watchlist", "reference", "social")]
    if needs_body and time_left() <= 1.0:
        result.skipped["article bodies"] = "exceeded the sweep time budget"
        needs_body = []
    if needs_body:
        progress({"type": "stage", "stage": "fetch", "count": len(needs_body)})

        def pull(item: Item) -> Item:
            res = fetcher.get(item.url, retries=1)
            if res.ok:
                c = extract(res.html, item.url)
                if len(c["text"]) > len(item.text):
                    item.text = c["text"]
                item.title = item.title or c["title"]
                item.author = item.author or c["author"]
                item.published_at = item.published_at or c["published_at"]
                item.lang = item.lang or c["lang"]
            else:
                item.raw_meta["fetch_error"] = res.error
            return item

        with ThreadPoolExecutor(max_workers=workers) as pool:
            body_futures = [pool.submit(pull, i) for i in needs_body]
            for f in as_completed(body_futures):
                try:
                    f.result()
                except Exception as e:
                    result.errors.append(f"body fetch: {type(e).__name__}: {e}")

    # --- 4. score ------------------------------------------------------
    # Cheap keyword pass over everything first, so the model only ever sees
    # the plausible candidates. This is what keeps a sweep affordable.
    for item in deduped:
        if not item.enriched:
            item.relevance = _adjust(_keyword_score(item, terms), item)
    deduped.sort(key=lambda i: -i.relevance)

    if enricher and enricher.enabled:
        candidates = [i for i in deduped if not i.enriched][:max_enrich]
        progress({"type": "stage", "stage": "score", "count": len(candidates)})
        scored_any = False
        for item in candidates:
            if time_left() <= 2.0:
                result.scoring_error = "ran out of time before scoring finished"
                break
            out = enricher.enrich(item.title, truncate(item.text), focus=query)
            if out.get("fatal"):
                # Account-level failure: every remaining call would fail the
                # same way. Record it once and fall back to keyword ranking.
                result.scoring_error = out["skipped"]
                result.errors.append(f"Claude scoring stopped: {out['skipped']}")
                break
            if out.get("skipped"):
                result.errors.append(out["skipped"])
                continue
            item.summary = out.get("summary", "")
            item.entities = out.get("entities", []) or []
            item.categories = out.get("categories", []) or []
            item.relevance = int(out.get("relevance", item.relevance))
            item.enriched = True
            scored_any = True
            progress({"type": "scored", "title": item.title[:80],
                      "relevance": item.relevance})
        # Only claim the run was model-scored if something actually was. This
        # used to be an unconditional True, so a run where every call failed
        # still rendered as "N scored 60+" — a keyword ranking wearing the
        # model's credibility, which is the worst way for this to fail.
        result.enriched = scored_any
        # The model scores each item alone, so it cannot see that five outlets
        # carried the same story or that this one came from a regulator. Fold
        # those in afterwards rather than trying to explain them in a prompt.
        for item in candidates:
            if item.enriched:
                item.relevance = _adjust(item.relevance, item)

    # --- 5. rank and roll up -------------------------------------------
    deduped.sort(key=lambda i: (-i.relevance, i.published_at), reverse=False)
    deduped.sort(key=lambda i: -i.relevance)
    result.items = _diversify(deduped)

    counts: Counter[str] = Counter()
    for item in result.items:
        for ent in item.entities:
            if ent.strip():
                counts[ent.strip()] += 1
    result.entities = counts.most_common(15)

    return result
