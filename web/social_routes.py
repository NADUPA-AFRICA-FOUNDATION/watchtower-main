"""HTTP API for social discovery: /api/social/* and /health/social.

Built by `build_router(...)` like the hunter's, so the web app injects where data lives and who
the caller is. Rules this layer keeps:

  * No request waits on a crawl. A search enqueues jobs and returns a run id to poll.
  * An empty answer is always explained: every run carries what each source said.
  * Every search, review and watchlist change is written to the audit log with who did it,
    and an ad hoc search is refused without a stated purpose.
  * Authentication is the app's middleware; nothing here weakens it.
"""
import re
from datetime import datetime, timezone
from typing import Callable, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request

from social.adapters import load_config
from social.pipeline import DISCOVERY_SOURCE, ENRICHERS, ENRICHMENT_NOTE, Engine, discovery_sources
from social.schema import PLATFORMS, REVIEW_STATUSES

_ID = re.compile(r"^[A-Za-z0-9_|:.\-]{1,120}$")
_ACTIONS = {"relevant": "relevant", "dismiss": "dismissed", "escalate": "escalated", "reopen": "new"}
_TIME_KEYS = {"first_seen", "last_seen", "reviewed_at", "fetched_at", "created_at", "at", "last_success_at",
              "last_failure_at", "breaker_until"}
WORKER_STALE_MS = 120_000


def _iso(ms) -> Optional[str]:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="seconds") if ms else None


def _times(obj):
    """Milliseconds inside, ISO-8601 at the boundary."""
    if isinstance(obj, list):
        return [_times(x) for x in obj]
    if isinstance(obj, dict):
        return {k: (_iso(v) if k in _TIME_KEYS and isinstance(v, (int, float)) else _times(v)) for k, v in obj.items()}
    return obj


def build_router(get_store: Callable[[], object], identity: Callable[[Request, str], tuple],
                 clock: Optional[Callable[[], int]] = None) -> APIRouter:
    from social.net import now_ms
    clock = clock or now_ms
    router = APIRouter(tags=["social"])

    def check_id(value: str) -> str:
        if not _ID.match(value or ""):
            raise HTTPException(400, "invalid id")
        return value

    def who(request: Request, claimed: str) -> str:
        name, kind = identity(request, claimed)
        if not name:
            raise HTTPException(400, "enter your name; it is recorded with this action")
        return name if kind == "authenticated" else f"{name} (self-asserted)"

    def platforms_or_400(value) -> list:
        if value in (None, []):
            return list(PLATFORMS)
        if not isinstance(value, list) or any(p not in PLATFORMS for p in value):
            raise HTTPException(400, f"platforms must be a list from: {', '.join(PLATFORMS)}")
        return list(dict.fromkeys(value))

    def worker_state(store) -> dict:
        beat = int(store.kv_get("worker_heartbeat") or 0)
        alive = bool(beat and clock() - beat < WORKER_STALE_MS)
        return {"running": alive, "last_seen": _iso(beat),
                "note": "" if alive else "No worker is running. Searches are queued and will start when one does."}

    def run_view(store, run_id: str) -> dict:
        run = store.run_get(check_id(run_id))
        if run is None:
            raise HTTPException(404, "unknown search")
        latest: dict = {}
        for o in run["outcomes"]:
            latest[(o["platform"], o["source"])] = o          # the most recent attempt per source is the current truth
        asked = {p for p, _ in latest}
        waiting = [{"platform": p, "source": DISCOVERY_SOURCE, "status": "queued", "detail": "not asked yet", "count": 0, "at": None}
                   for p in run["platforms"] if p not in asked]
        hits = store.hits_list(run_id=run_id, limit=200)
        return _times({**run, "outcomes": list(latest.values()) + waiting, "state": "running" if run["pending_jobs"] else "finished",
                       "hits": hits, "worker": worker_state(store)})

    @router.get("/api/social/status")
    def status():
        store = get_store()
        return {"storage": store.backend, "worker": worker_state(store), "pending_jobs": store.jobs_pending(),
                "discovery": [a.SOURCE for a in discovery_sources()],
                "platforms": {p: {"discovery": "search-engine snippets",
                                  "details": (ENRICHERS[p].SOURCE if p in ENRICHERS and load_config(ENRICHERS[p].SOURCE).get("enabled")
                                              else None),
                                  "note": ENRICHMENT_NOTE.get(p, "")} for p in PLATFORMS}}

    @router.get("/health/social")
    @router.get("/api/social/health")
    def health():
        """Per source: last success, last failure, breaker state, 7-day success rate."""
        store = get_store()
        sources = store.source_health(clock())
        return {"checked_at": _iso(clock()), "worker": worker_state(store), "pending_jobs": store.jobs_pending(),
                "sources": _times(sources),
                "note": "" if sources else "No source has been asked yet, so there is nothing to report. This is not a healthy reading."}

    @router.get("/api/social/hits")
    def hits(review: str = Query("new"), platform: str = Query(""), limit: int = Query(100, ge=1, le=500)):
        if review not in (*REVIEW_STATUSES, "all"):
            raise HTTPException(400, f"review must be one of: {', '.join(REVIEW_STATUSES)}, all")
        if platform and platform not in PLATFORMS:
            raise HTTPException(400, "unknown platform")
        store = get_store()
        rows = store.hits_list(review_status=None if review == "all" else review, platform=platform or None, limit=limit)
        return {"hits": _times(rows), "count": len(rows), "worker": worker_state(store), "pending_jobs": store.jobs_pending(),
                "sources": _times(store.source_health(clock()))}

    @router.post("/api/social/hits/{hit_id}/review")
    def review_hit(hit_id: str, request: Request, payload: dict = Body(...)):
        action = str(payload.get("action", ""))
        if action not in _ACTIONS:
            raise HTTPException(400, f"action must be one of: {', '.join(_ACTIONS)}")
        store, user = get_store(), who(request, str(payload.get("analyst", "")))
        hit = store.hit_get(check_id(hit_id))
        if hit is None:
            raise HTTPException(404, "unknown hit")
        store.hit_review(hit_id, _ACTIONS[action], user, clock())
        store.audit(user, f"review:{_ACTIONS[action]}", hit["url"], [], "", clock())
        return {"id": hit_id, "review_status": _ACTIONS[action]}

    @router.get("/api/social/watchlist")
    def watchlist():
        return {"watchlist": _times(get_store().watchlist_list()), "platforms": list(PLATFORMS)}

    @router.post("/api/social/watchlist", status_code=201)
    def watchlist_add(request: Request, payload: dict = Body(...)):
        term = " ".join(str(payload.get("term", "")).split())
        if not 2 <= len(term) <= 80:
            raise HTTPException(400, "a watchlist term is 2 to 80 characters")
        match_type = str(payload.get("match_type", "exact"))
        if match_type not in {"exact", "fuzzy"}:
            raise HTTPException(400, "match_type is exact or fuzzy")
        store, user = get_store(), who(request, str(payload.get("analyst", "")))
        if any(w["term"].lower() == term.lower() for w in store.watchlist_list()):
            raise HTTPException(409, "that term is already on the watchlist")
        row = store.watchlist_add(term, match_type, platforms_or_400(payload.get("platforms")), user, clock())
        store.audit(user, "watchlist:add", term, [], "watchlist monitoring", clock())
        return _times(row)

    @router.patch("/api/social/watchlist/{watch_id}")
    def watchlist_update(watch_id: str, request: Request, payload: dict = Body(...)):
        if not isinstance(payload.get("active"), bool):
            raise HTTPException(400, "active must be true or false")
        store, user = get_store(), who(request, str(payload.get("analyst", "")))
        if not store.watchlist_update(check_id(watch_id), payload["active"]):
            raise HTTPException(404, "unknown watchlist term")
        store.audit(user, "watchlist:resume" if payload["active"] else "watchlist:pause", watch_id, [], "", clock())
        return {"id": watch_id, "active": payload["active"]}

    @router.delete("/api/social/watchlist/{watch_id}")
    def watchlist_delete(watch_id: str, request: Request, analyst: str = Query("")):
        store, user = get_store(), who(request, analyst)
        if not store.watchlist_delete(check_id(watch_id)):
            raise HTTPException(404, "unknown watchlist term")
        store.audit(user, "watchlist:delete", watch_id, [], "", clock())
        return {"id": watch_id, "deleted": True}

    @router.post("/api/social/watchlist/run", status_code=202)
    def watchlist_run(request: Request, payload: dict = Body(default={})):
        store, user = get_store(), who(request, str(payload.get("analyst", "")))
        queued = Engine(store, clock=clock).enqueue_watchlist(user)
        return {"queued": queued, "worker": worker_state(store),
                "note": "" if queued else "Nothing was queued: the watchlist is empty, paused, or already queued."}

    @router.post("/api/social/search", status_code=202)
    def search(request: Request, payload: dict = Body(...)):
        store, user = get_store(), who(request, str(payload.get("analyst", "")))
        query = str(payload.get("query", ""))[:300]
        try:
            run_id = Engine(store, clock=clock).submit_search(query, str(payload.get("purpose", ""))[:300], user,
                                                              platforms_or_400(payload.get("platforms")))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"run_id": run_id, "poll": f"/api/social/search/{run_id}", "worker": worker_state(store)}

    @router.get("/api/social/search/{run_id}")
    def search_status(run_id: str):
        return run_view(get_store(), run_id)

    return router
