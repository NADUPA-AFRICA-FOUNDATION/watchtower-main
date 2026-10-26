"""Recursive hunting: turn what an investigation found into bounded new work.

    extract -> normalize -> dedupe -> evaluate pivot value -> queue

Two parts:

  PivotEngine.plan()      after a deep pass, decides which of a page's indicators become new
                          candidates (depth + 1, parent recorded) and which are only stored.
  pivot_search()          when an indicator candidate is claimed, looks for other places it
                          appears: first the local graph, then public search (and, if enabled,
                          reverse-IP for addresses).

What stops it running away, every one of them configurable and every skip counted and logged
on the parent (`pivots` / `pivot_suppressed` history events), never silently dropped:
  max_depth, max_pivots_per_entity, max_jobs_per_lineage (campaign, or originating candidate until
  one exists), max_pivots_per_day, max_search_queries_per_day, search rate limits, and the
  batch time budget in the enrichment loop.

Never pivoted from: advisory pages (quoted IOCs are not the actor's), common infrastructure (CDNs,
major cloud, search engines, popular social platforms), a site's own domain in its own email.
Generic outbound links are stored for the graph but not queued unless `queue_low` is set.
Search ranking is a lead, not evidence: a result earns a relationship only when its own page is
later seen to carry the indicator.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlsplit

from core.trusted_domains import is_trusted_domain

from .normalize import CRYPTO, DOMAIN, EMAIL, IP, PAYMENT, PHONE, SOCIAL, TELEGRAM, WHATSAPP, Indicator
from .prescore import is_official, is_shared_hosting, registrable
from .search import SearchHit, is_common_infra_ip, search_queries

ANALYTICS = "analytics_id"
PRIORITY = {"high": 70.0, "medium": 45.0, "low": 15.0}
_RANK = {"high": 3, "medium": 2, "low": 1}
SEARCHABLE = {PHONE, WHATSAPP, TELEGRAM, PAYMENT, CRYPTO, EMAIL, SOCIAL}
PIVOT_TYPES = SEARCHABLE | {DOMAIN, ANALYTICS, IP}

# Popular platforms and infrastructure: a link to one says nothing about who runs the page.
INFRA_APEX = frozenset({
    "cloudflare.com", "cloudflare.net", "cloudfront.net", "amazonaws.com", "awsstatic.com", "azure.com",
    "windows.net", "azureedge.net", "googleusercontent.com", "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "apple.com", "fastly.net", "akamaihd.net", "akamai.net", "github.com", "wikipedia.org",
    "duckduckgo.com", "bing.com", "yahoo.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "tiktok.com", "youtube.com", "linkedin.com", "t.me", "wa.me", "whatsapp.com", "telegram.org",
})


def is_infra_host(host: str) -> bool:
    return registrable(host) in INFRA_APEX or host in INFRA_APEX


@dataclass
class PivotReport:
    queued: int = 0
    stored_only: int = 0
    already_known: int = 0
    rejected: int = 0
    skipped: dict = field(default_factory=dict)
    created: list = field(default_factory=list)       # (type, canonical, pivot_value)
    suppressed_advisory: bool = False

    def skip(self, reason: str, n: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + n

    def summary(self) -> dict:
        return {"queued": self.queued, "stored_only": self.stored_only, "already_known": self.already_known,
                "rejected": self.rejected, "skipped": dict(sorted(self.skipped.items())),
                "advisory_suppressed": self.suppressed_advisory}


class PivotEngine:
    def __init__(self, store, cfg):
        self.store, self.cfg = store, cfg

    # -- budgets -----------------------------------------------------------------------------------
    def _budgets(self, cand: dict) -> dict:
        pc = self.cfg.pivots
        key = cand.get("campaign_id") or cand.get("root_id") or cand["id"]
        return {
            "entity_cap": pc.max_pivots_per_entity - self.store.count_children(cand["id"]),
            "lineage_cap": pc.max_jobs_per_lineage - self.store.count_lineage(key),
            "daily_cap": pc.max_pivots_per_day - self.store.count_observations_since("pivot:", 86400),
        }

    def _submit(self, cand, brand, ind: Indicator, value: str, source: str, *, where: str, snippet: str,
                confidence: float, evidence_id: str | None, rep: PivotReport, budgets: dict | None,
                query: str | None = None) -> bool:
        """Apply the policy to one indicator and submit it. Returns True if a new job was spent."""
        pc = self.cfg.pivots
        known = self.store.get(_cid(ind)) is not None
        if not known and budgets is not None:
            if cand["depth"] + 1 > pc.max_depth:
                rep.skip("depth_limit")
                return False
            for name in ("entity_cap", "lineage_cap", "daily_cap"):
                if budgets[name] <= 0:
                    rep.skip(name)
                    return False
        queue = value == "high" or (value == "medium" and pc.queue_medium) or (value == "low" and pc.queue_low)
        meta = {"pivot_from": cand["canonical"], "where": where, "snippet": snippet[:160], "pivot_value": value,
                **({"evidence_id": evidence_id} if evidence_id else {})}
        sub = self.store.submit(
            ind.canonical, source, indicator=ind, query=query or f"{cand['canonical']} ({where})", brand=brand.name,
            parent_id=cand["id"], depth=cand["depth"] + 1, priority=PRIORITY[value] + 10 * confidence,
            confidence=confidence, metadata=meta, enqueue=queue)
        if not sub.accepted:
            rep.rejected += 1
            return False
        if known:
            rep.already_known += 1
            return False
        if budgets is not None:
            for name in ("entity_cap", "lineage_cap", "daily_cap"):
                budgets[name] -= 1
        rep.created.append((ind.type, ind.canonical, value))
        rep.queued += int(queue)
        rep.stored_only += int(not queue)
        return True

    # -- from a page --------------------------------------------------------------------------------
    def plan(self, cand: dict, brand, signals: list, evidence_ids: dict, ips: list | tuple = ()) -> PivotReport:
        rep, pc = PivotReport(), self.cfg.pivots
        merged: dict[tuple, dict] = {}
        for sg in signals:
            for i in sg.indicators:
                key = (i.type, i.canonical)
                cur = merged.get(key)
                if cur is None or (_RANK[i.pivot_value], i.confidence) > (_RANK[cur["value"]], cur["conf"]):
                    merged[key] = {"ind": i, "value": i.pivot_value, "conf": i.confidence,
                                   "where": ",".join(sorted(i.where)), "snippet": i.snippet}
        if any(sg.flags.get("quoting_advisory") for sg in signals):
            rep.suppressed_advisory = True
            rep.skip("advisory_page", len(merged))
            self._log(cand, rep)
            return rep

        items = []
        for (typ, canon), m in merged.items():
            if typ not in PIVOT_TYPES:
                continue
            if typ == WHATSAPP and not canon.startswith("+"):
                rep.skip("not_a_number")                       # group / business-link codes: nothing to search by
                continue
            if typ == TELEGRAM and canon.startswith("invite:"):
                rep.skip("invite_code")
                continue
            if typ == DOMAIN and (is_infra_host(canon) or is_official(canon, brand)):
                rep.skip("common_infrastructure")
                continue
            if typ == EMAIL and registrable(canon.split("@", 1)[1]) == registrable(cand["canonical"]):
                rep.skip("own_domain_email")
                continue
            items.append((typ, canon, m))
        if pc.reverse_ip:
            for ip in ips:
                if not is_common_infra_ip(ip):
                    items.append((IP, ip, {"ind": Indicator(IP, ip, ip), "value": "high", "conf": 0.9,
                                           "where": "dns", "snippet": f"{cand['canonical']} resolves to {ip}"}))
        items.sort(key=lambda t: (-_RANK[t[2]["value"]], -t[2]["conf"], t[0], t[1]))
        budgets = self._budgets(cand)
        for typ, canon, m in items:
            self._submit(cand, brand, m["ind"], m["value"], f"pivot:{typ}", where=m["where"], snippet=m["snippet"],
                         confidence=m["conf"], evidence_id=evidence_ids.get((typ, canon)), rep=rep, budgets=budgets)
        self._log(cand, rep)
        return rep

    def _log(self, cand, rep: PivotReport) -> None:
        if rep.created or rep.skipped or rep.already_known or rep.suppressed_advisory:
            self.store.log_event(cand["id"], "pivot_suppressed" if rep.suppressed_advisory else "pivots",
                                 json.dumps(rep.summary(), sort_keys=True))


def _cid(ind: Indicator) -> str:
    from investigation.models import stable_id
    return stable_id(ind.type, ind.canonical)


# ------------------------------------------------------------------------------------------------------
def _hosts_from_hits(hits: list[SearchHit], brand, own: str = "") -> list[tuple[str, SearchHit]]:
    out, seen = [], set()
    for h in hits:
        host = (urlsplit(h.url).hostname or "").lower().removeprefix("www.")
        if not host or host in seen or host == own:
            continue
        seen.add(host)
        if is_infra_host(host) or is_official(host, brand) or (not is_shared_hosting(host) and is_trusted_domain(host)):
            continue                                            # a lead only if it could be the actor's
        out.append((host, h))
    return out


async def pivot_search(ctx, cand: dict, brand) -> str:
    """Process a claimed indicator candidate. Returns an outcome label; may defer or raise."""
    from .enrich.pipeline import EnrichmentFailed
    store, pc, en = ctx.store, ctx.cfg.pivots, ctx.en
    engine = ctx.pivot_engine
    now = ctx.clock()
    typ, canon, cid = cand["indicator_type"], cand["canonical"], cand["id"]
    rep = PivotReport()
    facts: dict = {"indicator": f"{typ}:{canon}", "queries": [], "domains": [], "neighbors": []}
    budgets = engine._budgets(cand)

    def lead(host: str, source: str, where: str, snippet: str, conf: float, query: str):
        engine._submit(cand, brand, Indicator(DOMAIN, host, host), "high", source, where=where, snippet=snippet,
                       confidence=conf, evidence_id=None, rep=rep, budgets=budgets, query=query)

    # 1. the local graph: free, instant, and the strongest kind of link (observed, not ranked).
    #    Ancestors are excluded: the domain this indicator was found on is where it came from, not a lead.
    ancestors = {c["canonical"] for c in store.lineage(cid)}
    for host in _graph_neighbors(ctx.graph, typ, canon):
        if host in ancestors:
            continue
        facts["neighbors"].append(host)
        lead(host, "pivot:graph", "graph", f"{host} already uses {typ} {canon}", 0.9, f"graph: {typ} {canon}")

    # 2. an address: optional reverse lookup
    if typ == IP:
        return await _pivot_ip(ctx, cand, brand, rep, facts, budgets)

    # 3. public search
    queries = search_queries(typ, canon) if (pc.search and en.searcher is not None) else []
    status = "internal_only" if not queries else "ok"
    if queries:
        stamps = store.search_events_24h()
        if len(stamps) + len(queries) > pc.max_search_queries_per_day:
            until = datetime_after(now, stamps, 86400)
            store.defer(cid, f"daily search budget reached ({pc.max_search_queries_per_day}/day)", until)
            return "deferred_search_budget"
        failures = []
        for q in queries:
            store.log_event(cid, "pivot_search", q)
            out = await ctx.timed("search", en.searcher.search(q, 10), failed=lambda r: r.status == "error",
                                  limited=lambda r: r.status in {"blocked", "rate_limited"}, error=lambda r: r.error)
            facts["queries"].append({"q": q, "status": out.status, "hits": len(out.hits), **({"error": out.error} if out.error else {})})
            if not out.searched:
                failures.append(out)
                if out.status in {"blocked", "rate_limited"}:
                    break                                          # do not keep knocking on a door that is shut
                continue
            for host, h in _hosts_from_hits(out.hits, brand):
                facts["domains"].append(host)
                lead(host, "pivot:search", "search", (h.title or h.snippet), 0.3, q)
        searched = sum(1 for x in facts["queries"] if x["status"] in {"ok", "no_results"})
        if failures and not searched:
            facts["status"] = "not_searched"
            _save_fact(ctx, cid, typ, canon, facts, cand)
            first = failures[0]
            if first.status in {"blocked", "rate_limited"}:
                store.defer(cid, f"search {first.status}: {first.error}", now + timedelta(seconds=max(first.retry_after or 900, 900)))
                return "deferred_search_blocked"
            raise EnrichmentFailed(f"search failed: {first.error}")
        status = "partial" if failures else ("ok" if facts["domains"] or any(x["hits"] for x in facts["queries"]) else "no_results")
    facts["status"] = status
    _save_fact(ctx, cid, typ, canon, facts, cand)
    note = (f"pivot search {status}: {len(facts['queries'])} queries, {len(facts['neighbors'])} graph neighbours, "
            f"{rep.queued} queued, {rep.already_known} known" + (f", skipped {rep.skipped}" if rep.skipped else ""))
    if status == "partial":
        note += " (PARTIAL: some queries could not be run, so this is not a complete negative)"
    store.complete(cid, "ENRICHED", stage="pivot", note=note)
    return "pivot_partial" if status == "partial" else "pivot"


async def _pivot_ip(ctx, cand, brand, rep, facts, budgets) -> str:
    from .enrich.pipeline import EnrichmentFailed
    store, pc, en = ctx.store, ctx.cfg.pivots, ctx.en
    cid, ip, now = cand["id"], cand["canonical"], ctx.clock()
    if is_common_infra_ip(ip):
        store.complete(cid, "ENRICHED", stage="pivot", note="common CDN address: not pivoted")
        return "pivot_skipped_infra"
    if en.reverse_ip is None or not pc.reverse_ip:
        store.complete(cid, "ENRICHED", stage="pivot", note="reverse-IP lookup is disabled; graph neighbours only")
        return "pivot"
    out = await ctx.timed("reverse_ip", en.reverse_ip.lookup(ip, pc.shared_ip_max_domains),
                          failed=lambda r: r.status == "error", limited=lambda r: r.status == "rate_limited",
                          error=lambda r: r.error)
    facts["reverse_ip"] = {"status": out.status, "total": out.total, **({"error": out.error} if out.error else {})}
    if out.status == "rate_limited":
        store.defer(cid, f"reverse-IP rate limited: {out.error}", now + timedelta(hours=1))
        return "deferred_search_blocked"
    if out.status == "error":
        raise EnrichmentFailed(f"reverse-IP failed: {out.error}")
    for host in out.domains:
        if not is_infra_host(host) and not is_official(host, brand):
            facts["domains"].append(host)
            ctx.pivot_engine._submit(cand, brand, Indicator(DOMAIN, host, host), "high", "pivot:reverse_ip", where="reverse_ip",
                                     snippet=f"shares {ip}", confidence=0.5, evidence_id=None, rep=rep, budgets=budgets,
                                     query=f"reverse-ip {ip}")
    facts["status"] = out.status
    _save_fact(ctx, cid, IP, ip, facts, cand)
    note = {"shared_hosting": f"{out.total} domains share this address: shared hosting, not a link",
            "no_results": "no other domains found on this address"}.get(out.status, f"{len(out.domains)} domains on this address, {rep.queued} queued")
    store.complete(cid, "ENRICHED", stage="pivot", note=note)
    return "pivot"


def _graph_neighbors(graph, typ: str, canon: str) -> list[str]:
    types = ("phone_number", "whatsapp") if typ in {PHONE, WHATSAPP} else (typ,)
    q = ",".join("?" * len(types))
    rows = graph.conn.execute(
        f"""SELECT DISTINCT d.canonical_value AS host FROM entities n
            JOIN relationships r ON r.target_entity_id=n.id JOIN entities d ON d.id=r.source_entity_id
            WHERE n.canonical_value=? AND n.entity_type IN ({q}) AND d.entity_type='domain'""", (canon, *types)).fetchall()
    return sorted(r["host"] for r in rows)


def _save_fact(ctx, cid, typ, canon, facts, cand):
    from investigation.models import Entity, Evidence
    iid = ctx.investigation_id(cand.get("brand") or next(iter(ctx.brands)))
    ent = Entity(typ, canon, canon)
    ev = Evidence(iid, ent.id, "pivot", "pivot_search", json.dumps(facts, sort_keys=True), None,
                  {"status": facts.get("status")}, 1.0)
    ctx.graph.persist(iid, [ent], [ev], [])


def datetime_after(now, stamps: list[str], seconds: float):
    """When the oldest event in a rolling window ages out."""
    from datetime import datetime
    return datetime.fromisoformat(stamps[0]) + timedelta(seconds=seconds) if stamps else now + timedelta(hours=1)
