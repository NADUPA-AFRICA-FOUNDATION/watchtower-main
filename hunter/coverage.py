"""Source coverage: which sources are working, and which are not.

A source that is off, never run, failing, rate limited or behind an open circuit must look different
from one that is healthy. Silence is not coverage. Sources the hunter does not support at all are
listed as unavailable with the reason, so their absence is stated rather than implied.
"""
from __future__ import annotations

from datetime import datetime, timedelta

SOURCES = (
    ("certificate_transparency", "discovery", "ct.enabled"),
    ("permutation", "discovery", "permutations.enabled"),
    ("search_discovery", "discovery", "search_discovery.enabled"),
    ("dns", "enrichment", None), ("rdap", "enrichment", None), ("tls", "enrichment", None), ("http", "enrichment", None),
    ("search", "pivot", "pivots.search"), ("reverse_ip", "pivot", "pivots.reverse_ip"),
)
UNSUPPORTED = {
    "x": "direct social-platform crawling is intentionally absent; profiles are indicators found on pages",
    "reddit": "not implemented in the hunter",
    "bluesky": "retired: unauthenticated search is inconsistent",
    "mastodon": "retired: unauthenticated search is inconsistent",
    "tiktok": "no usable public API and scraping is prohibited",
    "instagram": "no usable public API and scraping is prohibited",
    "facebook": "no usable public API and scraping is prohibited",
    "linkedin": "no usable public API and scraping is prohibited",
    "threat_intel_feeds": "adapter exists in intelligence/ but is not wired into the hunter",
}


def _enabled(cfg, path: str | None) -> bool:
    if path is None:
        return True
    obj = cfg
    for part in path.split("."):
        obj = getattr(obj, part)
    return bool(obj)


def breaker(health: dict | None, sched, now: datetime) -> tuple[bool, str | None]:
    """Open once `breaker_failures` consecutive failures have happened and the cool-down has not passed."""
    if not health or health["consecutive_failures"] < sched.breaker_failures or not health["last_failure"]:
        return False, None
    until = datetime.fromisoformat(health["last_failure"]) + timedelta(minutes=sched.breaker_cooldown_minutes)
    return (now < until), until.isoformat()


def source_coverage(store, cfg, now: datetime | None = None) -> list[dict]:
    now = now or store.clock()
    health = {h["provider"]: h for h in store.provider_health()}
    rows = []
    for name, kind, flag in SOURCES:
        h = health.get(name)
        runs = [r for r in store.discovery_runs(500) if r["provider"] == name][:20]
        ok = sum(1 for r in runs if r["status"] in {"operational", "partial"})
        is_open, until = breaker(h, cfg.scheduler, now)
        if not _enabled(cfg, flag):
            status = "disabled"
        elif h is None:
            status = "not_run"
        elif is_open:
            status = "circuit_open"
        else:
            status = {"operational": "healthy", "partial": "degraded", "limited": "degraded", "rate_limited": "rate_limited"}.get(h["status"], "failing")
        rows.append({"source": name, "kind": kind, "status": status, "enabled": _enabled(cfg, flag),
                     "last_success": h and h["last_success"], "last_failure": h and h["last_failure"],
                     "last_error": h and h["last_error"], "last_result_count": h and h["last_result_count"],
                     "avg_latency_ms": h and round(h["avg_latency_ms"] or 0), "rate_limit": (h or {}).get("rate_limit", {}),
                     "consecutive_failures": h["consecutive_failures"] if h else 0,
                     "availability": round(ok / len(runs), 2) if runs else None, "circuit_until": until if is_open else None})
    for name, reason in UNSUPPORTED.items():
        rows.append({"source": name, "kind": "unsupported", "status": "unavailable", "enabled": False, "reason": reason,
                     "last_success": None, "last_failure": None, "last_error": None, "last_result_count": None,
                     "avg_latency_ms": None, "rate_limit": {}, "consecutive_failures": 0, "availability": None, "circuit_until": None})
    return rows
