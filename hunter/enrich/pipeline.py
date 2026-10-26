"""Staged enrichment of claimed candidates.

  light  DNS (A/AAAA/CNAME/NS) + RDAP, then re-score with the registration age.
  deep   DNS (MX/TXT) + live TLS certificate, only for candidates whose re-score
         is FULL or HIGH, and only within `max_deep_per_hour`.

Routing after the light pass:
  name does not resolve   deferred to a slow re-check schedule (registered later is the
                          common case for generated names); when the schedule is spent the
                          candidate is IGNORED with the reason, and can be re-queued.
  could not look          (SERVFAIL, RDAP 5xx) fail() -> retry with backoff. Never "clean".
  RDAP rate limited       deferred until the cool-down ends, reason stated.
  otherwise               re-scored; strong candidates are queued for the deep pass,
                          the rest complete as ENRICHED.

Facts go to the graph store as immutable evidence (identical answers dedupe, changed
answers add a row), so history is kept and the existing graph API can show it.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from investigation.models import Entity, Evidence, Relationship

from ..config import Brand, HuntConfig
from ..normalize import DOMAIN
from ..market import detect_market
from ..pivots import PIVOT_TYPES, PivotEngine, pivot_search
from ..prescore import prescore
from ..changes import detect_changes
from ..correlate import Correlator
from ..scoring import rescore, rescore_and_route, target_status
from ..signals import extract_signals
from ..store import HuntStore
from .dns import DEEP_TYPES, LIGHT_TYPES, lookup_domain
from .rdap import RdapResult

UNSUPPORTED_NOTE = "no enrichers defined for indicator type {}"


class EnrichmentFailed(Exception):
    """Raised when a candidate could not be looked at; the batch turns it into fail()."""


@dataclass
class Enrichers:
    dns_lookup: Any
    rdap: Any
    tls: Any
    acquire: Any = None         # a ContentAcquisitionProvider; None disables page capture
    searcher: Any = None        # a SearchBackend for indicator pivots; None = graph lookups only
    reverse_ip: Any = None      # optional ReverseIpBackend


@dataclass
class ProviderStats:
    ok: int = 0
    failed: int = 0
    rate_limited: int = 0
    latency_ms: float = 0.0
    last_error: str | None = None

    @property
    def calls(self) -> int:
        return self.ok + self.failed + self.rate_limited

    @property
    def status(self) -> str:
        if self.rate_limited:
            return "rate_limited"
        if self.failed and self.ok:
            return "partial"
        return "provider_error" if self.failed else "operational"


@dataclass
class BatchSummary:
    claimed: int = 0
    outcomes: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def bump(self, outcome: str) -> None:
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1


class EnrichContext:
    def __init__(self, store: HuntStore, graph, cfg: HuntConfig, brands: dict[str, Brand],
                 enrichers: Enrichers, clock=None):
        self.store, self.graph, self.cfg, self.brands, self.en = store, graph, cfg, brands, enrichers
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.stats: dict[str, ProviderStats] = {}
        self._inv: dict[str, str] = {}
        self.pivot_engine = PivotEngine(store, cfg)
        self.correlator = Correlator(store, graph, cfg)

    def investigation_id(self, brand: str) -> str:
        """One long-lived graph investigation per brand holds all autonomous evidence."""
        if brand not in self._inv:
            key = f"investigation:{brand}"
            found = self.store.get_state(key).get(key)
            if not found:
                found = self.graph.create(brand, "autonomous hunt", ["hunter"], {"source": "hunter"})
                self.store.set_state({key: found})
            self._inv[brand] = found
        return self._inv[brand]

    async def timed(self, provider: str, coro, *, failed=lambda r: False, limited=lambda r: False,
                    error=lambda r: None):
        st = self.stats.setdefault(provider, ProviderStats())
        t0 = time.monotonic()
        try:
            result = await coro
        except Exception as exc:
            st.failed += 1
            st.last_error = f"{type(exc).__name__}: {exc}"[:300]
            raise
        finally:
            st.latency_ms += (time.monotonic() - t0) * 1000
        if limited(result):
            st.rate_limited += 1
            st.last_error = error(result)
        elif failed(result):
            st.failed += 1
            st.last_error = error(result)
        else:
            st.ok += 1
        return result


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class _Batch:
    """Accumulates one candidate's graph writes."""

    def __init__(self, ctx: EnrichContext, iid: str, entity: Entity):
        self.ctx, self.iid, self.domain = ctx, iid, entity
        self.entities: list = [entity]
        self.evidence: list = []
        self.relationships: list = []
        self.sigs: list = []          # PageSignals gathered this pass, for the pivot engine
        self.ev_map: dict = {}        # (type, canonical) -> evidence id of the sighting

    def fact(self, entity: Entity, source: str, etype: str, value, url=None, meta=None, conf=1.0) -> Evidence:
        ev = Evidence(self.iid, entity.id, source, etype, value if isinstance(value, str) else _canon(value),
                      url, meta or {}, conf)
        self.evidence.append(ev)
        return ev

    def link(self, target: Entity, rel: str, ev: Evidence, conf=1.0) -> None:
        self.entities.append(target)
        self.relationships.append(Relationship(self.iid, self.domain.id, target.id, rel, conf, ev.id))

    def save(self) -> None:
        self.ctx.graph.persist(self.iid, self.entities, self.evidence, self.relationships)


def _record_dns(b: _Batch, res) -> None:
    ev = b.fact(b.domain, "dns", "dns_lookup", res.facts(), None,
                {"status": res.status, "complete": res.complete, "notes": res.notes})
    for kind, values in res.records.items():
        for v in values:
            if kind in {"A", "AAAA"}:
                ent = Entity("ip_address", v, v, metadata={"record_type": kind})
                b.link(ent, "resolves_to", b.fact(ent, "dns", "dns_observation", v, None,
                                                   {"record_type": kind, "domain": res.domain}))
            elif kind == "NS":
                ent = Entity("nameserver", v, v)
                b.link(ent, "uses_nameserver", ev)
            elif kind == "CNAME":
                ent = Entity("domain", v, v, metadata={"via": "cname"})
                b.link(ent, "cname_to", ev)
            elif kind == "MX":
                host = v.split(" ", 1)[-1]
                ent = Entity("dns_record", f"MX {host}", v, metadata={"record_type": "MX"})
                b.link(ent, "uses_dns_record", ev)


def _record_rdap(b: _Batch, r: RdapResult) -> None:
    ev = b.fact(b.domain, "rdap", "rdap_lookup", r.facts(), r.source_url,
                {"status": r.status, "personal_data": bool(r.registrant.get("personal_data"))},
                0.9 if r.status == "registered" else 0.8)
    for ns in r.nameservers:
        b.link(Entity("nameserver", ns, ns), "uses_nameserver", ev, 0.95)
    if r.registrar:
        b.link(Entity("registrar", r.registrar.lower(), r.registrar), "registered_with", ev, 0.9)


def _record_pages(b: _Batch, cap, snapshot_chars: int) -> None:
    """Store each fetched page (and failed landing attempts) as immutable evidence.

    The snapshot is visible text only, capped; raw HTML is not stored. Form fields are
    names/types, never values. Page text can contain contact identifiers, so it falls
    under the same retention limit as other collected personal data.
    """
    from urllib.parse import urlsplit

    from ..prescore import registrable
    for n, page in enumerate([*cap.attempts, *cap.pages]):
        url = page.final_url or page.requested_url
        ev = b.fact(b.domain, "http", "http_response", page.facts(), url,
                    {"status": page.status, "error_kind": page.error_kind,
                     "landing": page is cap.landing}, 1.0)
        if (page.analyzable and page.html_fingerprint and len(page.visible_text) >= 300
                and not page.js_shell_suspected and not page.unassessed_reason):
            # A distinctive page template reused across domains is a strong link; thin or empty pages are
            # excluded because identical blank shells would "match" everywhere.
            fp = Entity("html_fingerprint", "sha256:" + page.html_fingerprint, page.html_fingerprint)
            b.link(fp, "uses_html_fingerprint", ev, 0.7)
        if page.analyzable and page.visible_text:
            b.fact(b.domain, "http", "page_text", page.visible_text[:snapshot_chars], url,
                   {"sha256": page.body_sha256, "simhash": str(page.simhash),
                    "truncated": len(page.visible_text) > snapshot_chars, "personal_data": True}, 1.0)
        if page is cap.landing:
            targets = {urlsplit(page.final_url).hostname: ("redirects_to", 0.95)} if page.final_url else {}
            if page.meta_refresh:
                targets[urlsplit(page.meta_refresh).hostname] = ("redirects_to", 0.6)
            for host, (rel, conf) in targets.items():
                if host and registrable(host) != registrable(b.domain.canonical_value):
                    b.link(Entity("domain", host.lower(), host.lower(), metadata={"via": "redirect"}), rel, ev, conf)


_SIGNAL_REL = {"phone_number": "uses_phone", "whatsapp": "uses_whatsapp", "telegram": "uses_telegram",
               "email": "uses_email", "payment_identifier": "uses_payment_identifier",
               "crypto_wallet": "uses_crypto_wallet", "social_account": "uses_social_account",
               "analytics_id": "uses_analytics_id", "domain": "links_to"}
_PERSONAL = {"phone_number", "whatsapp", "telegram", "email", "social_account"}


def _record_signals(b: _Batch, sig) -> dict:
    """One `page_signals` evidence per page (the scorer cites it), one evidence per indicator."""
    b.fact(b.domain, "signals", "page_signals", sig.facts(), sig.url,
           {"flags_true": sorted(k for k, v in sig.flags.items() if v), "market": sig.market.market}, 1.0)
    ids = {}
    for ind in sig.indicators:
        ent = Entity(ind.type, ind.canonical, ind.original)
        ev = b.fact(ent, "signals", "extracted_indicator", ind.canonical, sig.url,
                    {"where": sorted(ind.where), "snippet": ind.snippet, "pivot_value": ind.pivot_value,
                     "found_on": b.domain.canonical_value, "personal_data": ind.type in _PERSONAL, **ind.meta},
                    ind.confidence)
        b.link(ent, _SIGNAL_REL[ind.type], ev, ind.confidence)
        ids[(ind.type, ind.canonical)] = ev.id
    return ids


def _record_tls(b: _Batch, t) -> None:
    facts = t.facts()
    b.fact(b.domain, "tls", "tls_lookup", facts, None, {"status": t.status})
    if t.status == "ok":
        cert = Entity("certificate", "sha256:" + t.fingerprint, t.fingerprint,
                      metadata={"sans": t.sans, "not_before": t.not_before, "not_after": t.not_after,
                                "issuer": t.issuer, "verified": t.verified})
        cev = b.fact(cert, "tls", "tls_certificate", t.fingerprint, None, cert.metadata)
        b.link(cert, "uses_certificate", cev)


def _cert_age_days(store: HuntStore, cid: str, now: datetime) -> float | None:
    """Age of the newest certificate a discovery source reported for this candidate."""
    ages: list[float] = []
    for obs in store.observations(cid):
        try:
            nb = json.loads(obs["metadata"] or "{}").get("not_before")
            dt = datetime.fromisoformat(nb) if nb else None
        except (ValueError, TypeError):
            continue
        if dt:
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            ages.append(max((now - dt).total_seconds() / 86400, 0.0))
    return min(ages) if ages else None


def _changes(ctx: EnrichContext, cid: str) -> str:
    """Record what differs from the previous observation; mention only the meaningful ones."""
    found = [c for c in detect_changes(ctx.store, ctx.graph, cid) if c["meaningful"]]
    return f"; CHANGED: {'; '.join(c['summary'] for c in found[:3])}" if found else ""


def _correlate(ctx: EnrichContext, cid: str, brand: Brand, iid: str):
    """Link this domain to others through shared nodes. Returns (note, results)."""
    results = ctx.correlator.update_for(cid, brand.name, iid, "deep_pass")
    if not results:
        return "", []
    r = results[0]
    return (f"; campaign {r['public_id']} ({len(r['members'])} domains, {r['confidence']:.2f})" + (" NEW" if r["created"] else "")), results


def _rescore_neighbors(ctx: EnrichContext, cid: str, results: list) -> None:
    """A new link can change the other members' scores. Done only after this candidate's own score
    is recorded, so they see it (never through each other's linked-factor: see scoring)."""
    for r in results:
        for m in r["members"]:
            if m != cid:
                rescore_and_route(ctx.store, ctx.graph, ctx.cfg, ctx.brands, m, "campaign_change", ctx.clock())


async def _capture_site(ctx: EnrichContext, b: _Batch, domain: str, dns, brand: Brand, cand_id: str) -> str:
    acquire = ctx.en.acquire
    if acquire is None:
        return ""
    if dns.status != "resolved":
        return f"; page not fetched (dns {dns.status})"
    if dns.ips and set(dns.ips) <= set(dns.non_public_ips):
        return "; page not fetched (every address is non-public)"
    cap = await ctx.timed("http", acquire.capture(domain))
    _record_pages(b, cap, ctx.cfg.acquisition.snapshot_chars)
    flags, numbers = set(), []
    for page in [*cap.attempts, *cap.pages]:
        if page.analyzable and page.html:
            sig = extract_signals(page, brand, ctx.cfg.signals)
            b.ev_map.update(_record_signals(b, sig))
            b.sigs.append(sig)
            flags |= {k for k, v in sig.flags.items() if v}
            numbers += [i.canonical for i in sig.indicators if i.type in {"phone_number", "whatsapp"}
                        and i.canonical.startswith("+")]
        page.html = ""                     # raw markup is not retained once extracted
    market_note = ""
    texts = " ".join(p.visible_text for p in cap.pages if p.analyzable)
    if texts or numbers:
        guess = detect_market(texts, numbers, domain)
        b.fact(b.domain, "signals", "market_estimate", guess.facts(), None, {"market": guess.market}, guess.confidence)
        ctx.store.set_market(cand_id, guess.market, guess.confidence)
        market_note = f", market {guess.market} ({guess.confidence})"
    land = cap.landing
    detail = f"{land.status}" if land and land.ok else (land.error_kind if land else "none")
    extra = f" +{len(cap.pages) - 1} pages" if len(cap.pages) > 1 else ""
    unseen = f" UNASSESSED ({land.unassessed_reason})" if land and land.unassessed_reason else ""
    return f"; page {detail}{extra}{unseen}" + (f", signals: {', '.join(sorted(flags))}" if flags else "") + market_note


async def investigate(ctx: EnrichContext, cand: dict) -> str:
    """Enrich one claimed candidate. Returns an outcome label; raises EnrichmentFailed."""
    store, cfg = ctx.store, ctx.cfg.enrichment
    cid, now = cand["id"], ctx.clock()
    brand = ctx.brands.get(cand["brand"]) or next(iter(ctx.brands.values()))
    if cand["indicator_type"] != DOMAIN:
        if cand["indicator_type"] in PIVOT_TYPES:
            return await pivot_search(ctx, cand, brand)
        store.complete(cid, "ENRICHED", note=UNSUPPORTED_NOTE.format(cand["indicator_type"]))
        return "unsupported_type"
    domain = cand["canonical"]
    entity = Entity("domain", domain, domain)
    iid = ctx.investigation_id(brand.name)
    deep = cand["stage"] == "light"

    if deep:
        recent = store.recent_events("deep_started", 3600)
        if len(recent) >= cfg.max_deep_per_hour:
            until = datetime.fromisoformat(recent[0]) + timedelta(hours=1)
            store.defer(cid, f"deep-investigation budget reached ({cfg.max_deep_per_hour}/hour)", until)
            return "deferred_budget"
        store.log_event(cid, "deep_started")

    b = _Batch(ctx, iid, entity)
    if deep:
        dns = await ctx.timed("dns", lookup_domain(domain, ctx.en.dns_lookup, DEEP_TYPES),
                              failed=lambda r: r.status == "error", error=lambda r: str(r.errors))
        tls = await ctx.timed("tls", ctx.en.tls.fetch(domain))
        _record_dns(b, dns)
        _record_tls(b, tls)
        note = f"deep: dns {dns.status}, tls {tls.status}" + (f" ({tls.error})" if tls.error else "")
        if dns.non_public_ips:
            note += f"; resolves to non-public {dns.non_public_ips}"
        note += await _capture_site(ctx, b, domain, dns, brand, cid)
        b.save()
        change_note = _changes(ctx, cid)
        corr_note, corr_results = _correlate(ctx, cid, brand, iid)
        public_ips = [ip for ip in dns.ips if ip not in dns.non_public_ips]
        if b.sigs or (ctx.cfg.pivots.reverse_ip and public_ips):
            rep = ctx.pivot_engine.plan(cand, brand, b.sigs, b.ev_map, public_ips)
            if rep.created or rep.suppressed_advisory:
                note += f"; pivots: {rep.queued} queued, {rep.stored_only} stored" + (" (advisory page: suppressed)" if rep.suppressed_advisory else "")
        note += corr_note + change_note
        res, _ = rescore(store, ctx.graph, ctx.cfg, ctx.brands, cid, "deep", now)
        _rescore_neighbors(ctx, cid, corr_results)
        store.complete(cid, target_status(res, ctx.cfg.scoring), stage="deep", risk_score=res.score,
                       note=f"{note}; score {res.score} {res.classification}")
        return "deep"

    dns, rdap = await asyncio.gather(
        ctx.timed("dns", lookup_domain(domain, ctx.en.dns_lookup, LIGHT_TYPES),
                  failed=lambda r: r.status == "error", error=lambda r: str(r.errors)),
        ctx.timed("rdap", ctx.en.rdap.lookup(domain),
                  failed=lambda r: r.status == "error", limited=lambda r: r.status == "rate_limited",
                  error=lambda r: r.error))
    _record_dns(b, dns)
    _record_rdap(b, rdap)
    b.save()  # facts are kept even when the routing below defers or fails
    change_note = _changes(ctx, cid)

    if dns.status == "error":
        raise EnrichmentFailed(f"DNS lookup failed: {dns.errors}")
    if rdap.status == "error":
        raise EnrichmentFailed(f"RDAP lookup failed: {rdap.error}")
    if rdap.status == "rate_limited":
        until = now + timedelta(seconds=rdap.retry_after or 300)
        store.defer(cid, f"RDAP rate limited: {rdap.error}", until)
        return "deferred_rate_limit"

    if dns.status == "nxdomain":
        verdict = ("not registered (RDAP 404 and NXDOMAIN)" if rdap.status == "not_found"
                   else f"does not resolve (NXDOMAIN); registration unverified: RDAP {rdap.status}")
        n = store.count_events(cid, "unregistered_recheck")
        schedule = cfg.unregistered_recheck_days
        if n >= len(schedule):
            store.ignore(cid, f"{verdict}; still not resolving after {n} re-checks over {sum(schedule):g} days")
            return "ignored_unregistered"
        store.log_event(cid, "unregistered_recheck", verdict)
        store.defer(cid, f"{verdict}; re-check {n + 1}/{len(schedule)}", now + timedelta(days=schedule[n]))
        return "deferred_unregistered"

    ps = prescore(domain, brand, ctx.cfg.prescore, domain_age_days=rdap.age_days(now),
                  cert_age_days=_cert_age_days(store, cid, now))
    res, _ = rescore(store, ctx.graph, ctx.cfg, ctx.brands, cid, "light", now)
    note = (f"light: dns {dns.status}, rdap {rdap.status}, prescore {ps.score} {ps.band}; score {res.score} {res.classification}"
            + change_note)
    ancestor = store.ancestor_risk(cid)
    lineage = ancestor >= ctx.cfg.pivots.deep_if_ancestor_score
    if ps.band in {"FULL", "HIGH"} or lineage:
        why = f"re-score {ps.score} {ps.band}" if ps.band in {"FULL", "HIGH"} else f"reached from a candidate scored {ancestor:.0f}"
        store.requeue(cid, priority=max(ps.score, cand.get("priority") or 0), exact_priority=True, stage="light",
                      reason=f"{why}: queued for deep pass")
        return "queued_deep"
    store.complete(cid, target_status(res, ctx.cfg.scoring), stage="light", priority=ps.score,
                   risk_score=res.score, note=note)
    return "light"


async def enrich_batch(ctx: EnrichContext, limit: int = 20, *, stale_after: float = 900) -> BatchSummary:
    ctx.store.recover_stale(stale_after)
    ctx.stats = {}
    summary = BatchSummary()
    claimed = ctx.store.claim(limit)
    summary.claimed = len(claimed)
    sem = asyncio.Semaphore(ctx.cfg.enrichment.concurrency)
    deadline = time.monotonic() + ctx.cfg.enrichment.max_batch_seconds

    async def one(cand):
        async with sem:
            if time.monotonic() > deadline:
                ctx.store.defer(cand["id"], f"batch time budget exhausted ({ctx.cfg.enrichment.max_batch_seconds:g}s)",
                                ctx.clock() + timedelta(minutes=1))
                summary.bump("deferred_time_budget")
                return
            try:
                summary.bump(await investigate(ctx, cand))
            except EnrichmentFailed as exc:
                summary.bump("failed_" + ctx.store.fail(cand["id"], str(exc)).lower())
            except Exception as exc:
                summary.bump("failed_" + ctx.store.fail(cand["id"], f"{type(exc).__name__}: {exc}").lower())
    await asyncio.gather(*(one(c) for c in claimed))

    started = ctx.clock().isoformat(timespec="microseconds")
    for name, st in ctx.stats.items():
        limiter: dict = getattr(ctx.en.rdap, "rate_limit_status", lambda: {})() if name == "rdap" else {}
        ctx.store.record_run(name, None, status=st.status, started_at=started,
                             duration_ms=int(st.latency_ms / max(st.calls, 1)), found=st.ok,
                             detail=f"{st.ok} ok, {st.failed} failed, {st.rate_limited} rate limited",
                             error=st.last_error, rate_limit=limiter)
    summary.stats = {k: v.__dict__ for k, v in ctx.stats.items()}
    return summary
