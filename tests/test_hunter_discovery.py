import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from hunter.config import load
from hunter.ingest import run_discovery
from hunter.providers.base import Discovered, DiscoveryResult, HuntProvider
from hunter.providers.ct import CertificateTransparencyProvider
from hunter.providers.permutation import PermutationProvider
from hunter.ratelimit import RateLimiter
from hunter.store import HuntStore
from watchtower.discovery.base import SourceHealth

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def ts(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000")


def cert(cid, names, days_ago=1.0, issuer="C=US, O=Let's Encrypt"):
    return {"id": cid, "min_cert_id": cid, "name_value": "\n".join(names), "issuer_name": issuer,
            "entry_timestamp": ts(days_ago), "not_before": ts(days_ago)}


@pytest.fixture
def cfg():
    c = load("hunter.yaml")
    c.ct.min_interval_seconds = 0
    return c


@pytest.fixture
def brand(cfg):
    return cfg.brand()


@pytest.fixture
def store():
    return HuntStore(":memory:")


def provider(handler, limiter=None):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return CertificateTransparencyProvider(
        client, limiter or RateLimiter(0, sleep=lambda s: asyncio.sleep(0)), clock=lambda: NOW)


def by_term(mapping, default=None):
    def handler(request):
        term = request.url.params["q"].strip("%")
        value = mapping.get(term, default)
        if isinstance(value, httpx.Response):
            return value
        if isinstance(value, Exception):
            raise value
        return httpx.Response(200, json=value if value is not None else [])
    return handler


def run(coro):
    return asyncio.run(coro)


# -- CT ---------------------------------------------------------------------------------

def test_terms_cover_hyphen_and_related_brands(brand):
    terms = CertificateTransparencyProvider.terms(brand)
    assert {"mpesa", "m-pesa", "safaricom"} <= set(terms) and "fuliza" in terms


def test_ct_happy_path_metadata_and_prescore(cfg, brand, store):
    rows = [cert(1, ["mpesa-secure-example.test", "*.mpesa-secure-example.test", "cdn.unrelated-host.com"], 0.5)]
    p = provider(by_term({"mpesa": rows}))
    s = run(run_discovery(store, p, brand, cfg))
    assert s.status == "operational" and s.found == 1 and s.noise_filtered == 1
    row = store.find("mpesa-secure-example.test")
    assert row["discovery_source"] == "certificate_transparency" and row["status"] == "QUEUED"
    meta = json.loads(store.observations(row["id"])[0]["metadata"])
    assert meta["certificate_id"] == "1" and meta["sibling_names"] == ["cdn.unrelated-host.com"]
    # a half-day-old certificate lifts the pre-score above the same name without one
    assert {r["signal"] for r in meta["prescore"]["reasons"]} >= {"brand_token", "new_certificate"}
    assert row["priority"] == meta["prescore"]["score"]
    assert store.find("unrelated-host.com") is None


def test_ct_skips_official_and_counts_malformed(cfg, brand, store):
    rows = [cert(1, ["login.safaricom.co.ke", "www.m-pesa.co.ke", "bad..mpesa.com", "user@mpesa.com",
                     "mpesa-help.xyz"])]
    s = run(run_discovery(store, provider(by_term({"mpesa": rows})), brand, cfg))
    assert s.submitted == 1 and store.find("mpesa-help.xyz")
    assert store.find("login.safaricom.co.ke") is None
    assert store.stats()["rejected"] == 0  # malformed names are counted on the run, not queued


def test_ct_cursor_returns_only_new_certificates(cfg, brand, store):
    old = cert(1, ["mpesa-old.xyz"], days_ago=3)
    p1 = provider(by_term({"mpesa": [old]}))
    assert run(run_discovery(store, p1, brand, cfg)).submitted == 1
    new = cert(2, ["mpesa-new.xyz"], days_ago=0.1)
    p2 = provider(by_term({"mpesa": [old, new]}))
    s = run(run_discovery(store, p2, brand, cfg))
    assert s.found == 1 and store.find("mpesa-new.xyz")
    assert store.find("mpesa-old.xyz")["observation_count"] == 1  # not re-sighted


def test_ct_404_is_a_searched_zero_not_a_failure(cfg, brand, store):
    s = run(run_discovery(store, provider(by_term({}, httpx.Response(404))), brand, cfg))
    assert s.status == "operational" and s.found == 0
    assert store.provider_health()[0]["consecutive_failures"] == 0


def test_ct_429_stops_run_keeps_cursor_and_cools_down(cfg, brand, store):
    calls = []

    def handler(request):
        calls.append(request.url.params["q"])
        return httpx.Response(429, headers={"retry-after": "120"})
    limiter = RateLimiter(0, sleep=lambda s: asyncio.sleep(0))
    p = provider(handler, limiter)
    s = run(run_discovery(store, p, brand, cfg))
    assert s.status == "rate_limited" and "429" in s.error and len(calls) == 1  # did not hammer the other terms
    assert store.get_state() == {}
    again = run(run_discovery(store, p, brand, cfg))
    assert again.status == "rate_limited" and len(calls) == 1  # no request while cooling down
    h = store.provider_health()[0]
    assert h["consecutive_failures"] == 2 and h["rate_limit"]["blocked"] is True


def test_ct_one_failing_term_is_partial_and_its_cursor_is_kept_back(cfg, brand, store):
    good = [cert(1, ["mpesa-ok.xyz"])]
    p = provider(by_term({"mpesa": good, "m-pesa": httpx.Response(503)}))
    s = run(run_discovery(store, p, brand, cfg))
    assert s.status == "partial" and "503" in s.error and store.find("mpesa-ok.xyz")
    keys = store.get_state()
    assert any(k.endswith(":mpesa") for k in keys) and not any(k.endswith(":m-pesa") for k in keys)
    h = store.provider_health()[0]
    assert h["last_success"] and h["last_failure"] and h["consecutive_failures"] == 1


@pytest.mark.parametrize("bad", [
    httpx.Response(200, text=""),                          # overloaded crt.sh: empty 200
    httpx.Response(200, text="<html>Bad Gateway</html>"),
    httpx.Response(200, json={"error": "x"}),              # wrong shape
    httpx.Response(500),
    httpx.ConnectTimeout("slow"),
    httpx.ConnectError("refused"),
])
def test_ct_bad_answers_are_errors_never_empty_results(cfg, brand, store, bad):
    s = run(run_discovery(store, provider(by_term({}, bad)), brand, cfg))
    assert s.status == "provider_error" and s.found == 0 and s.error
    assert store.get_state() == {}


def test_ct_row_cap_is_visible(cfg, brand, store):
    cfg.ct.max_rows_per_term = 2
    rows = [cert(i, [f"mpesa-x{i}.xyz"], days_ago=i) for i in range(1, 6)]
    s = run(run_discovery(store, provider(by_term({"mpesa": rows})), brand, cfg))
    assert s.found == 2 and any("max_rows_per_term" in n for n in s.notes)
    assert store.find("mpesa-x1.xyz") and store.find("mpesa-x5.xyz") is None  # newest kept


# -- permutation provider -----------------------------------------------------------------

def test_permutations_submit_once_per_config(cfg, brand, store):
    first = run(run_discovery(store, PermutationProvider(), brand, cfg))
    assert first.created == first.submitted > 300
    assert first.queued + first.stored_only == first.submitted
    again = run(run_discovery(store, PermutationProvider(), brand, cfg))
    assert again.found == 0 and again.status == "operational"
    assert store.stats()["total"] == first.created  # no phantom re-sightings
    cfg.permutations.max_candidates = 100
    changed = run(run_discovery(store, PermutationProvider(), brand, cfg))
    assert changed.found == 100
    forced = run(run_discovery(store, PermutationProvider(force=True), brand, cfg))
    assert forced.found == 100


def test_store_only_band_stays_new_and_queued_band_gets_priority(cfg, brand, store):
    run(run_discovery(store, PermutationProvider(), brand, cfg))
    new = store.list("NEW", limit=1000)
    queued = store.list("QUEUED", limit=1000)
    assert new and queued
    assert all(r["priority"] <= cfg.prescore.store_max for r in new)
    assert all(r["priority"] > cfg.prescore.store_max for r in queued)
    top = store.claim(1)[0]
    assert top["priority"] == max(r["priority"] for r in queued)


# -- failure isolation ------------------------------------------------------------------------

class Exploding(HuntProvider):
    name = "exploding"

    async def discover(self, brand, cfg, cursors):
        raise RuntimeError("boom")


class Hanging(HuntProvider):
    name = "hanging"

    async def discover(self, brand, cfg, cursors):
        await asyncio.sleep(30)


class Static(HuntProvider):
    name = "static"

    def __init__(self, items, status="operational"):
        self.items, self.status = items, status

    async def discover(self, brand, cfg, cursors):
        return DiscoveryResult(self.items, SourceHealth(self.name, self.status, ()), {f"static:{brand.name}:c": "1"})


def test_raising_provider_is_recorded_and_others_still_run(cfg, brand, store):
    async def go():
        a = await run_discovery(store, Exploding(), brand, cfg)
        b = await run_discovery(store, Static([Discovered("mpesa-help.xyz", "domain", "static")]), brand, cfg)
        return a, b
    a, b = run(go())
    assert a.status == "provider_error" and "RuntimeError: boom" in a.error
    assert b.status == "operational" and b.submitted == 1
    health = {h["provider"]: h for h in store.provider_health()}
    assert health["exploding"]["consecutive_failures"] == 1 and health["static"]["consecutive_failures"] == 0
    assert [r["status"] for r in store.discovery_runs()] == ["operational", "provider_error"]


def test_hanging_provider_times_out(cfg, brand, store):
    s = run(run_discovery(store, Hanging(), brand, cfg, timeout=0.05))
    assert s.status == "timeout" and "exceeded" in s.error


def test_garbage_candidates_are_rejected_visibly(cfg, brand, store):
    items = [Discovered("not a domain!!", "domain", "static"), Discovered("mpesa-a.xyz", "domain", "static")]
    s = run(run_discovery(store, Static(items), brand, cfg))
    assert s.rejected == 1 and s.submitted == 1 and store.stats()["rejected"] == 1


def test_budget_truncation_holds_the_cursor_back(cfg, brand, store):
    cfg.max_candidates_per_run = 2
    items = [Discovered(f"mpesa-b{i}.xyz", "domain", "static") for i in range(5)]
    s = run(run_discovery(store, Static(items), brand, cfg))
    assert s.truncated and s.submitted == 2 and store.get_state() == {}
    assert any("cursor not advanced" in n for n in s.notes)
    cfg.max_candidates_per_run = 10
    s2 = run(run_discovery(store, Static(items), brand, cfg))
    assert not s2.truncated and store.get_state() == {"static:M-PESA:c": "1"}
    assert store.stats()["total"] == 5


def test_official_domains_are_counted_not_queued(cfg, brand, store):
    s = run(run_discovery(store, Static([Discovered("login.safaricom.co.ke", "domain", "static")]), brand, cfg))
    assert s.skipped_official == 1 and store.stats()["total"] == 0


def test_health_streak_resets_on_success(cfg, brand, store):
    run(run_discovery(store, Static([], status="provider_error"), brand, cfg))
    run(run_discovery(store, Static([], status="provider_error"), brand, cfg))
    assert store.provider_health()[0]["consecutive_failures"] == 2
    run(run_discovery(store, Static([]), brand, cfg))
    h = store.provider_health()[0]
    assert h["consecutive_failures"] == 0 and h["runs"] == 3 and h["last_failure"]


def test_rate_limiter_spacing_and_cooldown():
    now = [0.0]
    slept = []

    async def sleep(d):
        slept.append(d)
        now[0] += d
    lim = RateLimiter(2.0, monotonic=lambda: now[0], sleep=sleep)

    async def go():
        await lim.wait(); await lim.wait()
    asyncio.run(go())
    assert slept == [2.0] and lim.requests == 2 and not lim.blocked
    lim.penalize(60)
    assert lim.blocked and lim.status()["retry_in_seconds"] == 60.0
    now[0] += 61
    assert not lim.blocked
