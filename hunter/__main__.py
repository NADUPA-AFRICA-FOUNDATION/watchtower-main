"""python -m hunter <command>: inspect and exercise the hunter by hand.

  brands                      list configured brands
  permute [--limit N]         show ranked impersonation candidates (no network)
  score DOMAIN                explain the pre-score of one domain (no network)
  discover PROVIDER           run permutation | ct once and feed the queue
  fetch DOMAIN [--signals]    capture one site through the safe fetcher; --signals also extracts indicators
  campaigns                   list campaigns; campaigns ID shows members, infrastructure and why they are related
  correlate                   rebuild campaigns from the whole graph (no network)
  lineage VALUE               show the chain of how the hunter came to look at a candidate
  explain DOMAIN              show the stored score, every reason with its evidence, and history
  rescore [DOMAIN|--all]      recompute from stored evidence (no network), e.g. after editing weights
  run [--once]                run the autonomous hunter (scheduler); --once runs every job a single time
  coverage                    which sources are healthy, degraded, rate limited, circuit-open, disabled or unsupported
  alerts [--evaluate]         list alerts (and evaluate what is pending)
  changes DOMAIN              meaningful changes recorded for a domain
  purge [--dry-run]           apply the retention limit to personal data
  enrich [--limit N]          claim queued candidates and run DNS/RDAP/TLS stages
  status                      queue counts and provider health
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .config import ConfigError, load
from .ingest import run_discovery
from .permute import generate
from .prescore import prescore
from .providers.ct import CertificateTransparencyProvider
from .providers.permutation import PermutationProvider
from .store import HuntStore


def _db_path() -> str:
    import os
    from pathlib import Path
    # Same rule as web/app.py's DATA_DIR. The two used to differ (`data/` here, the repo root there), so the
    # scheduler filled one database while the dashboard read another and showed an empty queue.
    root = Path(__file__).resolve().parent.parent
    base = Path(os.environ.get("WATCHTOWER_DATA_DIR") or (Path("/tmp/watchtower") if os.environ.get("VERCEL") else root))
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "hunter.db")


async def _discover(args, cfg) -> int:
    providers: dict = {"permutation": lambda: PermutationProvider(force=args.force),
                       "ct": CertificateTransparencyProvider}
    if args.provider not in providers:
        print(f"unknown provider: {args.provider} (choose: {', '.join(providers)})", file=sys.stderr)
        return 2
    if args.provider == "ct" and not cfg.ct.enabled:
        print("certificate_transparency is disabled in hunter.yaml", file=sys.stderr)
        return 2
    store, provider = HuntStore(_db_path()), providers[args.provider]()
    try:
        summary = await run_discovery(store, provider, cfg.brand(args.brand), cfg)
    finally:
        await provider.close()
    print(json.dumps(summary.dict(), indent=2))
    return 0 if summary.ok else 1  # a degraded run must not exit 0


def _graph_ctx(cfg):
    from investigation.storage import InvestigationStore
    path = _db_path()
    return HuntStore(path), InvestigationStore(path), {b.name: b for b in cfg.brands}


def _explain(args, cfg) -> int:
    from .normalize import InvalidIndicator
    store, graph, _ = _graph_ctx(cfg)
    try:
        cand = store.find(args.domain, hint="domain")
    except InvalidIndicator as exc:
        print(f"invalid domain: {exc}", file=sys.stderr)
        return 2
    latest = cand and store.latest_score(cand["id"])
    if not latest:
        print("no stored score for that domain (not enriched yet?)", file=sys.stderr)
        return 1
    print(f"{cand['canonical']}  {latest['score']}/100  {latest['classification']}  ({latest['assessment']})")
    print(f"status {cand['status']}  market {cand['market'] or '-'}  scored under config {latest['config_hash']}")
    if latest["coverage"].get("unassessed"):
        print("NOT ASSESSED:", "; ".join(latest["coverage"]["unassessed"]))
    for r in latest["reasons"]:
        ids = f"  [{', '.join(i[:20] for i in r['evidence_ids'])}]" if r["evidence_ids"] else f"  [{r['basis']}]"
        print(f"  {r['weight']:+g}  {r['signal']}: {r['evidence']}{ids}")
    print("history:")
    for h in store.score_history(cand["id"]):
        delta = "" if h["delta"] is None else f" ({h['delta']:+d})"
        print(f"  {h['scored_at'][:19]}  {h['score']} {h['classification']}{delta}  <- {h['trigger']}")
    return 0


def _campaigns(args, cfg) -> int:
    from .graphq import GraphQueries
    store, graph, _ = _graph_ctx(cfg)
    q = GraphQueries(store, graph)
    if args.id:
        c = q.campaign(args.id)
        if c is None:
            print("unknown campaign", file=sys.stderr)
            return 1
        print(f"{c['public_id']}  {c['name']}  confidence {c['correlation_score']} ({c['correlation_label']})  "
              f"threat {c['threat_score']} {c['system_classification']}")
        print("infrastructure:", ", ".join(f"{v} {k}" for k, v in c["infrastructure"].items()))
        for m in c["members"]:
            print(f"  {m['domain']:40} {m['risk_score'] if m['risk_score'] is not None else '-':>4} {m['classification'] or '-':14} {m['status']}")
        print("why related:")
        for w in c["why_related"]:
            print(f"  {w['link']}: {', '.join(w['nodes'])} between {' / '.join(w['between'])}  [{len(w['based_on'])} sightings]")
        return 0
    for c in q.campaigns():
        print(f"{c['public_id']}  {c['name']:50} {len(c['members'])} domains  {c['system_classification']}  last active {c['last_active'][:10]}")
    return 0


def _correlate_all(args, cfg) -> int:
    from .correlate import Correlator
    store, graph, brands = _graph_ctx(cfg)
    brand = next(iter(brands))
    iid = graph.conn.execute("SELECT id FROM investigations ORDER BY started_at LIMIT 1").fetchone()
    out = Correlator(store, graph, cfg).rebuild(brand, iid["id"] if iid else graph.create(brand, "autonomous hunt", ["hunter"], {}))
    print(json.dumps({"campaigns": len(out), "members": sum(len(o["members"]) for o in out)}))
    return 0


def _lineage(args, cfg) -> int:
    from .normalize import InvalidIndicator
    store, _, _ = _graph_ctx(cfg)
    try:
        cand = store.find(args.value)
    except InvalidIndicator as exc:
        print(f"invalid indicator: {exc}", file=sys.stderr)
        return 2
    if cand is None:
        print("unknown candidate", file=sys.stderr)
        return 1
    for step in store.lineage(cand["id"]):
        via = step["via"]
        how = f"  via {via.get('where')} on {via.get('pivot_from')}" if via.get("pivot_from") else ""
        print(f"{'  ' * step['depth']}{step['type']}:{step['canonical']}  <- {step['source']}"
              f"{' (' + step['query'] + ')' if step['query'] else ''}{how}")
    return 0


def _rescore(args, cfg) -> int:
    from .scoring import rescore
    store, graph, brands = _graph_ctx(cfg)
    ids = [c["id"] for c in store.list(limit=100000) if store.latest_score(c["id"])] if args.all else \
        [store.find(args.domain, hint="domain")["id"]]
    changed = 0
    for cid in ids:
        res, rec = rescore(store, graph, cfg, brands, cid, "manual_rescore")
        changed += rec["recorded"]
    print(json.dumps({"rescored": len(ids), "changed": changed}))
    return 0


def _user_agent() -> str:
    import os
    return os.environ.get("WATCHTOWER_USER_AGENT",
                          f"Watchtower/1.0 OSINT (contact: {os.environ.get('WATCHTOWER_CONTACT', 'unset')})")


async def _fetch(args, cfg) -> int:
    from .acquire import NativeFetcher
    from .normalize import InvalidIndicator, normalize
    try:
        target = normalize(args.target)
    except InvalidIndicator as exc:
        print(f"invalid target: {exc}", file=sys.stderr)
        return 2
    host = target.canonical if target.type == "domain" else target.meta.get("host", "")
    fetcher = NativeFetcher.create(cfg.acquisition, _user_agent())
    try:
        cap = await fetcher.capture(host)
    finally:
        await fetcher.close()
    signals = []
    if args.signals:
        from .signals import extract_signals
        brand = cfg.brand(args.brand)
        for p in cap.pages:
            if p.analyzable and p.html:
                sg = extract_signals(p, brand, cfg.signals)
                signals.append({"url": p.final_url, "flags_true": sorted(k for k, v in sg.flags.items() if v),
                                "market": sg.market.facts() if sg.market else None,
                                "indicators": [f"{i.type}:{i.canonical} ({','.join(i.where)}, {i.pivot_value})"
                                               for i in sg.indicators],
                                "phrases": [f"{x['rule']} x{x['count']}" + (f" (+{x['advisory_count']} advisory)" if x["advisory_count"] else "")
                                            for x in sg.phrases],
                                "forms": [{"solicits": f["solicits"], "formless": f["formless"],
                                           "cross_origin": f["cross_origin"]} for f in sg.forms]})
    out = [{"url": p.final_url or p.requested_url, "status": p.status, "error_kind": p.error_kind,
            "title": p.title, "robots": p.robots.get("verdict"), "forms": len(p.forms),
            "links": len(p.links), "js_shell_suspected": p.js_shell_suspected,
            "technology": p.technology} for p in [*cap.attempts, *cap.pages]]
    print(json.dumps({"domain": host, "notes": cap.notes, "pages": out, **({"signals": signals} if args.signals else {})},
                     indent=2))
    return 0 if cap.landing and cap.landing.ok else 1


async def _enrich(args, cfg) -> int:
    from .enrich.pipeline import enrich_batch
    from .runner import build_services
    sv = build_services(cfg, _db_path())
    try:
        summary = await enrich_batch(sv.ctx, args.limit)
    finally:
        await sv.close()
    print(json.dumps({"claimed": summary.claimed, "outcomes": summary.outcomes, "providers": summary.stats}, indent=2))
    return 0


async def _run(args, cfg) -> int:
    import signal

    from .runner import build_services
    from .scheduler import Scheduler, SchedulerRefused
    try:
        sv = build_services(cfg, _db_path(), require_persistent=True)
    except SchedulerRefused as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 3
    sch = Scheduler(sv, cfg)
    try:
        changed = sch.startup()
        if changed:
            print(f"scoring configuration changed: rescored {changed}", file=sys.stderr)
        if args.once:
            results = await sch.run_once()
            for r in results:
                print(f"{r.name:28} {r.status}" + (f"  {r.error}" if r.error else ""))
            return 0 if all(r.status in {"ok", "skipped_disabled"} for r in results) else 1
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:      # not available on every platform
                pass
        print("hunter running; Ctrl-C to stop. Jobs:", ", ".join(j["job"] for j in sch.status() if j["enabled"]), file=sys.stderr)
        await sch.run_forever(stop)
        return 0
    finally:
        await sv.close()


def _coverage(args, cfg) -> int:
    from .coverage import source_coverage
    store, _, _ = _graph_ctx(cfg)
    print(f"{'SOURCE':26} {'STATUS':13} {'LAST OK':20} {'RESULTS':>7} {'LATENCY':>8} {'AVAIL':>6}  NOTE")
    for r in source_coverage(store, cfg):
        note = r.get("reason") or (r["last_error"] or "")[:60] or ("breaker until " + r["circuit_until"][:19] if r["circuit_until"] else "")
        print(f"{r['source']:26} {r['status']:13} {(r['last_success'] or '-')[:19]:20} {str(r['last_result_count'] if r['last_result_count'] is not None else '-'):>7} "
              f"{str(r['avg_latency_ms'] if r['avg_latency_ms'] is not None else '-') + 'ms':>8} {str(r['availability'] if r['availability'] is not None else '-'):>6}  {note}")
    return 0


def _alerts(args, cfg) -> int:
    from .alerts import AlertEngine
    store, graph, _ = _graph_ctx(cfg)
    engine = AlertEngine(store, graph, cfg)
    if args.evaluate:
        out = engine.evaluate()
        print(f"raised {len(out['raised'])}, suppressed {out['suppressed']}")
    for a in engine.list(50):
        print(f"{a['at'][:19]}  {a['severity']:6} {a['kind']:24} {a['title']}" + ("" if not a["acknowledged_at"] else "  (acknowledged)"))
    return 0


def _changes(args, cfg) -> int:
    store, _, _ = _graph_ctx(cfg)
    cand = store.find(args.domain, hint="domain")
    if cand is None:
        print("unknown domain", file=sys.stderr)
        return 1
    for c in store.changes(cand["id"], limit=100):
        print(f"{c['at'][:19]}  {'MEANINGFUL' if c['meaningful'] else 'minor     '} {c['kind']:22} {c['summary']}")
    return 0


def _purge(args, cfg) -> int:
    from .retention import purge
    store, graph, _ = _graph_ctx(cfg)
    print(json.dumps(purge(store, graph, cfg, dry_run=args.dry_run)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hunter")
    ap.add_argument("--config", default="hunter.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brands")
    p = sub.add_parser("permute")
    p.add_argument("--brand"); p.add_argument("--limit", type=int, default=25)
    p = sub.add_parser("score")
    p.add_argument("domain"); p.add_argument("--brand")
    p = sub.add_parser("discover")
    p.add_argument("provider"); p.add_argument("--brand"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("fetch")
    p.add_argument("target"); p.add_argument("--signals", action="store_true"); p.add_argument("--brand")
    p = sub.add_parser("run")
    p.add_argument("--once", action="store_true")
    sub.add_parser("coverage")
    p = sub.add_parser("alerts")
    p.add_argument("--evaluate", action="store_true")
    p = sub.add_parser("changes")
    p.add_argument("domain")
    p = sub.add_parser("purge")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("campaigns")
    p.add_argument("id", nargs="?")
    sub.add_parser("correlate")
    p = sub.add_parser("lineage")
    p.add_argument("value")
    p = sub.add_parser("explain")
    p.add_argument("domain")
    p = sub.add_parser("rescore")
    p.add_argument("domain", nargs="?"); p.add_argument("--all", action="store_true")
    p = sub.add_parser("enrich")
    p.add_argument("--limit", type=int, default=20)
    sub.add_parser("status")
    args = ap.parse_args(argv)
    try:
        cfg = load(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "brands":
        for b in cfg.brands:
            print(f"{b.name}: aliases={b.aliases} official={b.official_domains}")
    elif args.cmd == "permute":
        for perm in generate(cfg.brand(args.brand), cfg, args.limit):
            print(f"{perm.prescore.score:3} {perm.prescore.band:5} {perm.kind:13} {perm.domain}")
    elif args.cmd == "score":
        print(json.dumps(prescore(args.domain, cfg.brand(args.brand), cfg.prescore).dict(), indent=2))
    elif args.cmd == "discover":
        return asyncio.run(_discover(args, cfg))
    elif args.cmd == "fetch":
        return asyncio.run(_fetch(args, cfg))
    elif args.cmd == "run":
        return asyncio.run(_run(args, cfg))
    elif args.cmd == "coverage":
        return _coverage(args, cfg)
    elif args.cmd == "alerts":
        return _alerts(args, cfg)
    elif args.cmd == "changes":
        return _changes(args, cfg)
    elif args.cmd == "purge":
        return _purge(args, cfg)
    elif args.cmd == "campaigns":
        return _campaigns(args, cfg)
    elif args.cmd == "correlate":
        return _correlate_all(args, cfg)
    elif args.cmd == "lineage":
        return _lineage(args, cfg)
    elif args.cmd == "explain":
        return _explain(args, cfg)
    elif args.cmd == "rescore":
        if not (args.all or args.domain):
            print("give a DOMAIN or --all", file=sys.stderr)
            return 2
        return _rescore(args, cfg)
    elif args.cmd == "enrich":
        return asyncio.run(_enrich(args, cfg))
    elif args.cmd == "status":
        store = HuntStore(_db_path())
        print(json.dumps({"queue": store.stats(), "providers": store.provider_health()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
