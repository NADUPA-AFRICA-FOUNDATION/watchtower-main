"""Wiring: build the real services (HTTP clients, resolvers, providers) for the scheduler and the CLI."""
from __future__ import annotations

import os

import httpx

from investigation.storage import InvestigationStore

from .acquire import NativeFetcher
from .alerts import AlertEngine
from .enrich.dns import system_lookup
from .enrich.pipeline import EnrichContext, Enrichers
from .enrich.rdap import RdapClient
from .enrich.tls import TlsEnricher
from .providers.ct import CertificateTransparencyProvider
from .providers.permutation import PermutationProvider
from .providers.search_discovery import SearchDiscoveryProvider
from .ratelimit import RateLimiter
from .scheduler import Services, check_persistent_storage
from .search import DuckDuckGoHtml, HackerTargetReverseIp
from .store import HuntStore


def user_agent() -> str:
    return os.environ.get("WATCHTOWER_USER_AGENT", f"Watchtower/1.0 OSINT (contact: {os.environ.get('WATCHTOWER_CONTACT', 'unset')})")


def build_services(cfg, db_path: str, *, require_persistent: bool = False) -> Services:
    if require_persistent:
        check_persistent_storage(db_path)
    store, graph, e, pc = HuntStore(db_path), InvestigationStore(db_path), cfg.enrichment, cfg.pivots
    http = httpx.AsyncClient(timeout=e.rdap_timeout_seconds, follow_redirects=False, headers={"User-Agent": user_agent()})
    rdap = RdapClient(http, store, min_interval=e.rdap_min_interval_seconds, cache_hours=e.rdap_cache_hours)
    acquire = NativeFetcher.create(cfg.acquisition, user_agent())
    searcher = DuckDuckGoHtml(limiter=RateLimiter(pc.search_min_interval_seconds), timeout=pc.search_timeout_seconds) if pc.search else None
    reverse = HackerTargetReverseIp() if pc.reverse_ip else None
    ctx = EnrichContext(store, graph, cfg, {b.name: b for b in cfg.brands},
                        Enrichers(system_lookup(e.dns_timeout_seconds), rdap, TlsEnricher(e.tls_timeout_seconds), acquire, searcher, reverse))
    sv = Services(store, graph, ctx, CertificateTransparencyProvider(), PermutationProvider(),
                  alerts=AlertEngine(store, graph, cfg))
    if searcher is not None:
        sv.search_discovery = SearchDiscoveryProvider(
            searcher, queries_available=lambda: pc.max_search_queries_per_day - len(store.search_events_24h()),
            on_query=lambda q: store.log_event("system:search", "discovery_search", q))
    sv.closers = [http.aclose, acquire.close, sv.ct.close] + ([searcher.close] if searcher else []) + ([reverse.close] if reverse else [])
    return sv
