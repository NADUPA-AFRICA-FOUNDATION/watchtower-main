"""Watchlist term -> discovery -> dedupe by canonical URL -> enrichment -> score -> hits.

Everything runs as queued jobs. No web request waits on a crawl: a search enqueues jobs and
returns a run id, and the run records what each source said so an empty result can always be
explained ("DuckDuckGo: blocked, retrying at 14:05") instead of rendering as a blank list.

Job kinds
  discover   one term on one platform through the search engine
  enrich     details for one hit from that platform's documented endpoint, where one exists
  watchlist  fan out `discover` jobs for every active term (the scheduler enqueues this)
  purge      retention
"""
from __future__ import annotations

import os
import random
import re
from urllib.parse import urlsplit

from social.adapters import Outcome, duckduckgo, exa, reddit_json, x_oembed
from social.net import PoliteClient, now_ms
from social.schema import PLATFORMS, author_from_url, canonical_url, merge_hit, new_hit, platform_of
from social.scoring import score_hit
from social.store import DAY_MS

DISCOVERY_SOURCE = duckduckgo.SOURCE


def discovery_sources() -> list:
    """Keyless first and always; a keyed source joins only when its key is set."""
    return [duckduckgo] + ([exa] if exa.enabled() else [])
ENRICHERS = {"x": x_oembed, "reddit": reddit_json}
# What can be said, without testing, about platforms that have no enrichment adapter.
ENRICHMENT_NOTE = {
    "tiktok": "no keyless source of post details: TikTok's oEmbed returns only an embed player",
    "facebook": "page and post HTML is excluded by policy; search snippets only",
    "instagram": "page and post HTML is excluded by policy; search snippets only",
    "reddit": "Reddit refuses unauthenticated clients (Phase 1 matrix); search snippets only",
}
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (300, 1200, 3600)          # multiplied by a random 0.75-1.25
MIN_PURPOSE = 5


class Retry(Exception):
    def __init__(self, delay_ms: int, reason: str):
        super().__init__(reason)
        self.delay_ms, self.reason = delay_ms, reason


def retention_ms() -> int:
    return int(float(os.environ.get("SOCIAL_RETENTION_DAYS", "90")) * DAY_MS)


def dismissed_retention_ms() -> int:
    return int(float(os.environ.get("SOCIAL_DISMISSED_RETENTION_DAYS", "7")) * DAY_MS)


def classify_query(query: str) -> dict:
    """An ad hoc input is a URL, a handle or a keyword. Decided by shape only."""
    q = " ".join(query.split())
    if re.match(r"^https?://", q, re.I):
        url = canonical_url(q)
        return {"kind": "url", "term": url, "platform": platform_of(url)}
    if re.fullmatch(r"@[\w.]{2,40}", q):
        return {"kind": "handle", "term": q[1:], "platform": None}
    return {"kind": "keyword", "term": q, "platform": None}


def _verdict(platform: str, url: str, title: str, text: str) -> tuple[dict, bool]:
    """The same account-name and wording rules the Monitor view uses, so the two cannot disagree."""
    from core.sources import (_bait_analysis, _is_official_handle, _lure_identity, _social_kind, is_likely_lure,
                              social_verdict)
    parts = urlsplit(url)
    host = parts.netloc
    official = _is_official_handle(parts.path)
    bait, terms, advisory = ([], {}, False) if official else _bait_analysis(title or "", text or "")
    kind, account = _social_kind(host, parts.path)
    identity = "" if (official or advisory) else _lure_identity(PLATFORMS[platform][0], parts.path, kind, title or "", text or "")
    meta = {"platform": host, "kind": kind, "account": account, "bait_signals": bait, "bait_terms": terms,
            "advisory": advisory, "official_account": official, "lure_identity": identity}
    verdict = social_verdict(meta)
    return {k: verdict[k] for k in ("level", "label", "reason", "action")}, is_likely_lure(meta)


class Engine:
    def __init__(self, store, client: PoliteClient | None = None, clock=now_ms, rng: random.Random | None = None):
        self.store, self.clock = store, clock
        self.client = client or PoliteClient(store, clock=clock)
        self.rng = rng or random.Random()

    # ---------------------------------------------------------------- submitting work

    def _terms(self, extra: dict | None = None) -> list[dict]:
        terms = [{"term": w["term"], "match_type": w["match_type"]} for w in self.store.watchlist_list(active_only=True)]
        if extra and all(t["term"].lower() != extra["term"].lower() for t in terms):
            terms.append(extra)
        return terms

    def submit_search(self, query: str, purpose: str, user: str, platforms: list[str] | None = None) -> str:
        """Queue an ad hoc search and return its run id. Raises ValueError on input that must not be run."""
        if len(" ".join(query.split())) < 2:
            raise ValueError("enter a keyword, a handle (@name) or a URL")
        if len((purpose or "").strip()) < MIN_PURPOSE:
            # Kenya's Data Protection Act: processing needs a stated purpose. This search may be about a person.
            raise ValueError("say why you are running this search; the purpose is recorded with it")
        now, kind = self.clock(), classify_query(query)
        if kind["kind"] == "url":
            if kind["platform"] is None:
                raise ValueError("that URL is not on Reddit, TikTok, X, Facebook or Instagram")
            wanted = [kind["platform"]]
        else:
            wanted = [p for p in (platforms or list(PLATFORMS)) if p in PLATFORMS] or list(PLATFORMS)
        run_id = self.store.run_create("adhoc", " ".join(query.split()), purpose.strip(), user, wanted, now)
        self.store.audit(user, f"search:{kind['kind']}", " ".join(query.split()), [a.SOURCE for a in discovery_sources()], purpose.strip(), now)
        for platform in wanted:
            self.store.job_enqueue("discover", {"run_id": run_id, "term": kind["term"], "platform": platform,
                                                "match_type": "fuzzy" if kind["kind"] == "handle" else "exact",
                                                "only_url": kind["term"] if kind["kind"] == "url" else None}, now)
        return run_id

    def enqueue_watchlist(self, user: str = "scheduler") -> int:
        """One run per active term, one discover job per platform. Returns the number of jobs queued."""
        now, queued = self.clock(), 0
        for w in self.store.watchlist_list(active_only=True):
            run_id = self.store.run_create("watchlist", w["term"], "watchlist monitoring", user, w["platforms"], now)
            for platform in w["platforms"]:
                if platform in PLATFORMS and self.store.job_enqueue(
                        "discover", {"run_id": run_id, "term": w["term"], "platform": platform, "match_type": w["match_type"],
                                     "only_url": None}, now, dedupe_key=f"discover:{w['term'].lower()}:{platform}"):
                    queued += 1
        if queued:
            self.store.audit(user, "watchlist_run", f"{queued} job(s)", [a.SOURCE for a in discovery_sources()], "watchlist monitoring", now)
        return queued

    # ------------------------------------------------------------------ running work

    def work_once(self) -> bool:
        """Claim and run one job. False when nothing is due."""
        job = self.store.job_claim(self.clock())
        if job is None:
            return False
        try:
            {"discover": self._discover, "enrich": self._enrich, "watchlist": lambda j: self.enqueue_watchlist(),
             "purge": lambda j: self.purge()}[job["kind"]](job)
        except Retry as r:
            if job["attempts"] >= MAX_ATTEMPTS:
                self.store.job_finish(job["id"], False, f"gave up after {job['attempts']} attempts: {r.reason}", self.clock())
            else:
                self.store.job_retry(job["id"], self.clock() + r.delay_ms, r.reason)
        except Exception as exc:                                   # noqa: BLE001 - a bad job must not stop the queue
            self.store.job_finish(job["id"], False, f"{type(exc).__name__}: {exc}"[:300], self.clock())
        else:
            self.store.job_finish(job["id"], True, None, self.clock())
        return True

    def _backoff(self, attempts: int) -> int:
        base = BACKOFF_SECONDS[min(attempts, len(BACKOFF_SECONDS)) - 1]
        return int(base * self.rng.uniform(0.75, 1.25) * 1000)

    def _source(self, name: str) -> dict | None:
        return next((s for s in self.store.source_health(self.clock()) if s["source"] == name), None)

    def _guarded(self, name: str, call) -> Outcome:
        """Run one adapter call behind its circuit breaker and record the attempt."""
        state = self._source(name)
        if state and state["breaker"] == "open":
            return Outcome(name, "blocked", "paused after repeated failures; not asked this time")
        outcome = call(state)
        if outcome.status != "disabled":
            self.store.source_event(name, outcome.answered, outcome.status, outcome.detail, self.clock())
        return outcome

    def _discover(self, job: dict) -> None:
        p, now = job["payload"], self.clock()
        platform, domain = p["platform"], PLATFORMS[p["platform"]][0]
        term = p["term"]
        search_term = re.sub(r"^https?://", "", term) if p.get("only_url") else term
        terms = self._terms({"term": term, "match_type": p.get("match_type", "exact")} if not p.get("only_url") else None)
        outcomes, any_results = [], False
        for adapter in discovery_sources():
            outcome = self._guarded(adapter.SOURCE, lambda state, adapter=adapter: adapter.search(
                self.client, search_term, domain, last_success_at=(state or {}).get("last_success_at"), now=now,
                rotation=job["attempts"], aliases=PLATFORMS[platform][1:]))
            results = outcome.results
            if p.get("only_url"):
                results = [r for r in results if r["url"] == p["only_url"]]
                if outcome.status == "ok" and not results:
                    outcome = Outcome(outcome.source, "not_found", "the search engine has no entry for that exact URL")
            new = 0
            for r in results:
                hit = new_hit(platform, r["url"], f"search_snippet:{adapter.SOURCE}", "snippet_only", now,
                              username=author_from_url(platform, r["url"]) or r.get("author"), text=r["snippet"] or None,
                              title=r["title"] or None, published_at=r["published_at"])
                new += self._save(hit, terms, now, p.get("run_id"))["created"]
            any_results = any_results or bool(results)
            detail = outcome.detail + (f"; {new} new" if results else "")
            if platform in ENRICHMENT_NOTE and results:
                detail += f". Details: {ENRICHMENT_NOTE[platform]}"
            self.store.run_outcome(p.get("run_id") or "", platform, outcome.source, outcome.status, detail, len(results), now)
            outcomes.append(outcome)
        if p.get("only_url") and not any_results and ENRICHERS.get(platform) and ENRICHERS[platform].applies(p["only_url"]):
            # No search entry, but this platform has a documented details endpoint: ask it directly.
            self.store.job_enqueue("enrich", {"run_id": p.get("run_id"), "url": p["only_url"], "create": True}, now,
                                   dedupe_key=f"enrich:{p['only_url']}")
        # Retry only when no source could look. One source answering ("nothing here") settles it.
        if not any(o.answered for o in outcomes):
            failed = [o for o in outcomes if o.status != "disabled"]
            if failed:
                raise Retry(self._backoff(job["attempts"]),
                            "; ".join(f"{o.source}: {o.status} ({o.detail})" for o in failed))

    def _save(self, hit: dict, terms: list[dict], now: int, run_id: str | None) -> dict:
        old = self.store.hit_get_by_url(hit["url"])
        doc = merge_hit(old, hit) if old else hit
        verdict, lure = _verdict(doc["platform"], doc["url"], doc.get("title") or "", doc["content"].get("text") or "")
        scored = score_hit(doc, terms, now, lure=lure)
        matched = sorted(set((old or {}).get("matched_terms", [])) | set(scored["matched_terms"]))
        doc.update(score=scored["score"], reasons=scored["reasons"], matched_terms=matched,
                   confidence=scored["confidence"], verdict=verdict)
        saved = self.store.hit_put(doc, now, run_id)
        enricher = ENRICHERS.get(doc["platform"])
        if enricher and doc["status"] == "snippet_only" and enricher.applies(doc["url"]):
            self.store.job_enqueue("enrich", {"run_id": run_id, "url": doc["url"]}, now, dedupe_key=f"enrich:{doc['url']}")
        return saved

    def _enrich(self, job: dict) -> None:
        p, now = job["payload"], self.clock()
        url, platform = p["url"], platform_of(p["url"])
        enricher = ENRICHERS.get(platform or "")
        existing = self.store.hit_get_by_url(url)
        if enricher is None or not enricher.applies(url) or (existing is None and not p.get("create")):
            return
        outcome = self._guarded(enricher.SOURCE, lambda state: enricher.enrich(self.client, url))
        if p.get("create") or not outcome.answered:
            self.store.run_outcome(p.get("run_id") or "", platform, outcome.source, outcome.status, outcome.detail,
                                   1 if outcome.status == "ok" else 0, now)
        if outcome.status == "ok":
            f = outcome.results[0]
            hit = new_hit(platform, url, f"enrichment:{enricher.SOURCE}", "partial", now,
                          username=f.get("username") or author_from_url(platform, url), display_name=f.get("display_name"),
                          profile_url=f.get("profile_url"), text=f.get("text"), published_at=f.get("published_at"),
                          likes=f.get("likes"), comments=f.get("comments"))
            if not hit["missing_fields"]:
                hit["status"] = "ok"
            self._save(hit, self._terms(), now, p.get("run_id"))
        elif outcome.status == "not_found" and existing:
            existing.setdefault("raw", {})["enrichment"] = {"source": outcome.source, "status": "not_found", "detail": outcome.detail}
            self.store.hit_put(existing, now)
        elif not outcome.answered and outcome.status != "disabled":
            raise Retry(self._backoff(job["attempts"]), f"{outcome.source}: {outcome.status} ({outcome.detail})")

    # --------------------------------------------------------------------- housekeeping

    def purge(self) -> dict:
        now = self.clock()
        counts = self.store.purge(now, retention_ms(), dismissed_retention_ms())
        if any(counts.values()):
            self.store.audit("scheduler", "purge", str(counts), [], "retention limit", now)
        return counts

    def tick(self) -> None:
        """Heartbeat, and (when the store does not schedule itself) the watchlist and purge timers."""
        now = self.clock()
        self.store.kv_set("worker_heartbeat", str(now))
        if getattr(self.store, "schedules_itself", False):
            return
        interval = int(float(os.environ.get("SOCIAL_WATCH_INTERVAL_MINUTES", "360")) * 60_000)
        if now - int(self.store.kv_get("last_watchlist_at") or 0) >= interval:
            self.store.kv_set("last_watchlist_at", str(now))
            self.enqueue_watchlist()
        if now - int(self.store.kv_get("last_purge_at") or 0) >= DAY_MS:
            self.store.kv_set("last_purge_at", str(now))
            self.store.job_enqueue("purge", {}, now, dedupe_key="purge")
