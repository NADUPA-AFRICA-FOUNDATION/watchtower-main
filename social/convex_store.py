"""Convex implementation of the social store contract (see social/store.py for the contract).

Talks to the deployment's HTTP API (`/api/query`, `/api/mutation`) with httpx, so no extra
Python dependency is needed. Every function in convex/ checks the shared server key, because
the tables hold personal data and a deployment URL is reachable by anyone who has it.

Set on the Render service (both web and worker):
    CONVEX_URL           https://<deployment>.convex.cloud
    CONVEX_SERVER_KEY    the same value as MNARA_SERVER_KEY on the Convex deployment
"""
from __future__ import annotations

import httpx

from social.store import hit_columns  # noqa: F401  (kept importable from here for callers that expect it)


def _ints(value):
    """Convex numbers arrive as JSON floats (1.0). Whole numbers go back to int so a score reads
    55, not 55.0, and values compare and serialise exactly as the SQLite store's do."""
    if isinstance(value, float) and value.is_integer() and abs(value) < 2**53:
        return int(value)
    if isinstance(value, list):
        return [_ints(v) for v in value]
    if isinstance(value, dict):
        return {k: _ints(v) for k, v in value.items()}
    return value


class ConvexError(RuntimeError):
    """A Convex call failed. The message never contains the server key."""


class ConvexStore:
    backend = "convex"
    shared = True              # web and worker on different machines see the same rows
    schedules_itself = True    # convex/crons.ts queues the watchlist and purge jobs

    def __init__(self, url: str, server_key: str, transport=None, timeout: float = 20.0):
        if not server_key:
            raise ConvexError("CONVEX_SERVER_KEY is not set; refusing to use Convex without it")
        self.url = url.rstrip("/")
        self._key = server_key
        self.http = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self.http.close()

    def _call(self, endpoint: str, path: str, args: dict):
        # Positional args only: function arguments such as `kind` must not collide with ours.
        payload = {"path": path, "args": {"key": self._key, **{k: v for k, v in args.items() if v is not None}}, "format": "json"}
        try:
            res = self.http.post(f"{self.url}/api/{endpoint}", json=payload)
        except httpx.HTTPError as exc:
            raise ConvexError(f"Convex {path}: {type(exc).__name__}") from None
        try:
            body = res.json()
        except ValueError:
            raise ConvexError(f"Convex {path}: HTTP {res.status_code} with a non-JSON body") from None
        if res.status_code != 200 or body.get("status") != "success":
            message = str(body.get("errorMessage") or body.get("message") or f"HTTP {res.status_code}")
            raise ConvexError(f"Convex {path}: {message.replace(self._key, '<key>')[:300]}")
        return _ints(body.get("value"))

    def _q(self, path: str, **args):
        return self._call("query", path, args)

    def _m(self, path: str, **args):
        return self._call("mutation", path, args)

    # ------------------------------------------------------------------ watchlist
    def watchlist_add(self, term, match_type, platforms, created_by, now):
        return self._m("watchlist:add", term=term, match_type=match_type, platforms=platforms, created_by=created_by, now=now)

    def watchlist_list(self, active_only: bool = False):
        return self._q("watchlist:list", active_only=active_only)

    def watchlist_update(self, wid, active):
        return self._m("watchlist:update", id=wid, active=active)

    def watchlist_delete(self, wid):
        return self._m("watchlist:remove", id=wid)

    # ------------------------------------------------------------------------ jobs
    def job_enqueue(self, kind, payload, now, run_after=None, dedupe_key=None):
        return self._m("jobs:enqueue", kind=kind, payload=payload, now=now, run_after=run_after, dedupe_key=dedupe_key,
                       run_id=payload.get("run_id"))

    def job_claim(self, now, lock_ms: int = 600_000):
        return self._m("jobs:claim", now=now, lock_ms=lock_ms)

    def job_finish(self, jid, ok, error, now):
        self._m("jobs:finish", id=jid, ok=ok, error=error, now=now)

    def job_retry(self, jid, run_after, error):
        self._m("jobs:retry", id=jid, run_after=run_after, error=error)

    def jobs_pending(self, run_id=None):
        return self._q("jobs:pending", run_id=run_id)

    # ----------------------------------------------------------------------- cache
    def cache_get(self, key, now):
        return self._q("cache:get", cache_key=key, now=now)

    def cache_put(self, key, body, status, now, ttl_ms):
        self._m("cache:put", cache_key=key, body=body, status=status, now=now, ttl_ms=ttl_ms)

    # ------------------------------------------------------------------------ hits
    def hit_get(self, hid):
        return self._q("hits:get", id=hid)

    def hit_get_by_url(self, url):
        return self._q("hits:getByUrl", url=url)

    def hit_put(self, doc, now, run_id=None):
        return self._m("hits:put", doc=doc, now=now, run_id=run_id)

    def hits_list(self, review_status=None, platform=None, run_id=None, limit: int = 100):
        return self._q("hits:list", review_status=review_status, platform=platform, run_id=run_id, limit=limit)

    def hit_review(self, hid, review_status, user, now):
        return self._m("hits:review", id=hid, review_status=review_status, user=user, now=now)

    # ----------------------------------------------------------------------- audit
    def audit(self, user, action, query, sources_used, purpose, now):
        self._m("audit:add", user=user, action=action, query=query, sources_used=sources_used, purpose=purpose or "", now=now)

    def audit_list(self, limit: int = 50):
        return self._q("audit:list", limit=limit)

    # --------------------------------------------------------------- source health
    def source_event(self, source, ok, status, detail, now, breaker_threshold=3, breaker_base_ms=1_800_000,
                     breaker_max_ms=21_600_000):
        return self._m("sources:event", source=source, ok=ok, status=status, detail=detail, now=now,
                       threshold=breaker_threshold, base_ms=breaker_base_ms, max_ms=breaker_max_ms)

    def source_health(self, now):
        return self._q("sources:health", now=now)

    # ------------------------------------------------------------------------ runs
    def run_create(self, kind, query, purpose, user, platforms, now):
        return self._m("runs:create", kind=kind, query=query, purpose=purpose or "", user=user, platforms=platforms, now=now)

    def run_outcome(self, run_id, platform, source, status, detail, count, now):
        self._m("runs:outcome", run_id=run_id, platform=platform, source=source, status=status, detail=detail, count=count, now=now)

    def run_get(self, run_id):
        return self._q("runs:get", id=run_id)

    # -------------------------------------------------------------------------- kv
    def kv_get(self, key):
        return self._q("kv:get", name=key)

    def kv_set(self, key, value):
        self._m("kv:set", name=key, value=value)

    # ----------------------------------------------------------------------- purge
    def purge(self, now, retention_ms, dismissed_ms):
        totals = {"dismissed_hits": 0, "expired_hits": 0, "cache_rows": 0, "finished_jobs": 0, "runs": 0}
        for _ in range(50):            # each call is one bounded batch; stop when nothing is left
            got = self._m("purge:run", now=now, retention_ms=retention_ms, dismissed_ms=dismissed_ms)
            for k in totals:
                totals[k] += got[k]
            if not got["more"]:
                break
        return totals
