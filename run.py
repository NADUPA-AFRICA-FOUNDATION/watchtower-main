#!/usr/bin/env python3
"""watchtower — one pipeline, many sources.

    python run.py collect          # ingest from every configured source
    python run.py enrich           # run Claude over unenriched items
    python run.py alert            # match watchlist, write a digest
    python run.py run              # all three, in order (this is your cron job)
    python run.py search "query"   # FTS5 search over the archive
    python run.py stats
    python run.py hunt             # the autonomous hunter (see HUNTER_PLAN.md); --once runs every job once
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))


def load_env(path: Path = None) -> None:
    """Read .env into os.environ without adding a dependency.

    Deliberately does not overwrite anything already exported: a key set in the
    shell or by CI must win over a stale file on disk. Silent when absent —
    every key here is optional and the tool runs without all of them.
    """
    if os.environ.get("WATCHTOWER_SKIP_DOTENV") == "1":
        return
    path = path or Path(__file__).parent / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


load_env()

from core import alerts, report
from core.clean import truncate
from core.enrich import Enricher, digest
from core.fetch import Fetcher
from core.sources import BACKENDS, DEFAULT_BACKENDS
from core.store import Store
from core.sweep import sweep


def load_config(path: str = "config.yaml") -> dict:
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return expand_env(cfg)


def expand_env(cfg: dict) -> dict:
    """Expand ${VAR} in the user agent so a real contact address never has to
    be committed.

    Wikipedia and SEC EDGAR both want a reachable contact and EDGAR answers 403
    without one, so "put a real address in config.yaml" was advice that either
    got ignored or put someone's personal email into version control. The
    address belongs in .env, which is gitignored, and the config just names it.
    """
    fetch = cfg.get("fetch", {})
    ua = fetch.get("user_agent", "")
    if "${" in ua:
        contact = os.environ.get("WATCHTOWER_CONTACT", "")
        fetch["user_agent"] = (os.path.expandvars(ua) if contact
                               else ua.replace("${WATCHTOWER_CONTACT}",
                                               "set WATCHTOWER_CONTACT in .env"))
    return cfg


def make_fetcher(cfg: dict) -> Fetcher:
    f = cfg["fetch"]
    return Fetcher(
        user_agent=f["user_agent"],
        delay=f.get("delay_seconds", 2.0),
        timeout=f.get("timeout_seconds", 20),
        obey_robots=f.get("obey_robots", True),
    )


# ---------------------------------------------------------------- collect

def cmd_collect(cfg: dict, store: Store) -> int:
    # Imported here, not at module scope: the scheduled-mode adapters are the
    # only thing that needs them, and a missing optional adapter shouldn't stop
    # `serve` or `sweep` — which share none of this code — from starting.
    from adapters import gdelt, rss, social, webpage

    fetcher = make_fetcher(cfg)
    sources = cfg.get("sources", {})
    now = datetime.now(timezone.utc).isoformat()
    total = 0

    for feed in sources.get("rss", []) or []:
        print(f"  rss:{feed['name']} ... ", end="", flush=True)
        items = rss.collect(
            feed["url"], feed["name"], feed.get("type", "news"),
            fetcher, store, fetch_body=feed.get("fetch_body", True),
            limit=feed.get("limit", 25),
        )
        n = store.add(items)
        store.mark_seen([i.url for i in items], f"rss:{feed['name']}", now)
        print(f"{len(items)} found, {n} new")
        total += n

    for q in sources.get("gdelt", []) or []:
        label = q["query"][:45]
        print(f"  gdelt:{label} ... ", end="", flush=True)
        items = gdelt.collect(
            q["query"], fetcher, store,
            timespan=q.get("timespan", "24h"),
            max_records=q.get("max_records", 50),
            fetch_body=q.get("fetch_body", False),
        )
        n = store.add(items)
        store.mark_seen([i.url for i in items], "gdelt", now)
        print(f"{len(items)} found, {n} new")
        total += n

    for page in sources.get("webpage", []) or []:
        print(f"  web:{page['name']} ... ", end="", flush=True)
        items = webpage.collect(
            page["url"], page["name"], fetcher, store,
            link_pattern=page.get("link_pattern", ""),
            source_type=page.get("type", "regulatory"),
            limit=page.get("limit", 20),
        )
        n = store.add(items)
        store.mark_seen([i.url for i in items], f"web:{page['name']}", now)
        print(f"{len(items)} found, {n} new")
        total += n

    reddit_cfg = sources.get("reddit", {}) or {}
    if reddit_cfg.get("subreddits"):
        print("  reddit ... ", end="", flush=True)
        items = social.collect_reddit(
            reddit_cfg["subreddits"], store, limit=reddit_cfg.get("limit", 20))
        n = store.add(items)
        store.mark_seen([i.url for i in items], "reddit", now)
        print(f"{len(items)} found, {n} new")
        total += n

    purged = social.purge_expired(store)
    if purged:
        print(f"  retention: purged {purged} expired social item(s)")

    fetcher.close()
    return total


# ---------------------------------------------------------------- enrich

def cmd_enrich(cfg: dict, store: Store) -> int:
    ec = cfg.get("enrichment", {})
    if not ec.get("enabled", True):
        print("  enrichment disabled in config")
        return 0

    enricher = Enricher(
        watchlist=cfg.get("alerts", {}).get("watchlist", []),
        categories=ec.get("categories", []),
        escalate_above=ec.get("escalate_above", 60),
    )
    if not enricher.enabled:
        print("  ANTHROPIC_API_KEY not set — skipping enrichment")
        return 0

    rows = store.pending_enrichment(limit=ec.get("batch_size", 40))
    done = 0
    for row in rows:
        text = truncate(row["text"] or "")
        if not (row["title"] or text):
            store.save_enrichment(row["content_hash"], "", [], [], 0)
            continue
        out = enricher.enrich(row["title"] or "", text)
        if out.get("skipped"):
            print(f"    ! {out['skipped']}")
        store.save_enrichment(
            row["content_hash"],
            out.get("summary", ""),
            out.get("entities", []) or [],
            out.get("categories", []) or [],
            int(out.get("relevance", 0)),
        )
        done += 1
        print(f"    [{out.get('relevance', 0):>3}] {(row['title'] or row['url'])[:70]}")
    return done


# ---------------------------------------------------------------- alert

def cmd_alert(cfg: dict, store: Store) -> int:
    ac = cfg.get("alerts", {})
    selected = alerts.select(store, ac.get("watchlist", []),
                             min_relevance=ac.get("min_relevance", 60))
    brief = digest(selected) if selected else ""
    text = alerts.render(selected, brief)

    out_dir = cfg["storage"].get("output_dir", "out")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    path = alerts.write(text, Path(out_dir) / f"digest-{stamp}.txt")

    store.mark_alerted([s["content_hash"] for s in selected])
    print(text)
    print(f"  written to {path}")
    return len(selected)


# ---------------------------------------------------------------- main

def cmd_sweep(cfg: dict, store: Store, query: str, args) -> int:
    """On-demand: keyword in, ranked findings out."""
    fetcher = make_fetcher(cfg)
    ec = cfg.get("enrichment", {})

    enricher = None
    if not args.no_ai:
        enricher = Enricher(
            watchlist=cfg.get("alerts", {}).get("watchlist", []),
            categories=ec.get("categories", []),
            escalate_above=ec.get("escalate_above", 60),
        )
        if not enricher.enabled:
            print("  (no ANTHROPIC_API_KEY — falling back to keyword ranking)")

    backends = ([b.strip() for b in args.sources.split(",")]
                if args.sources else DEFAULT_BACKENDS)

    print(f'\nsweeping "{query}"  (last {args.hours}h)')
    result = sweep(
        query, fetcher, hours=args.hours, backends=backends,
        limit=args.limit, fetch_bodies=not args.no_fetch,
        enricher=enricher, max_enrich=args.max_ai,
        progress=lambda e: (lambda line: print(line, flush=True) if line else None)(
            report.progress_line(e)),
    )
    fetcher.close()

    print(report.terminal(result, top=args.top))

    if args.save and result.items:
        store.add(result.items)
        print(f"  saved to archive ({cfg['storage']['database']})")

    if result.items:
        path = report.save(result, cfg["storage"].get("output_dir", "out"))
        print(f"  full report: {path}\n")
    return len(result.items)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="watchtower — keyword sweep and scheduled monitoring",
        epilog='example: python run.py sweep "beneficial ownership Kenya" --hours 168',
    )
    ap.add_argument("command",
                    choices=["sweep", "collect", "enrich", "alert", "run",
                             "search", "stats", "sources", "models", "serve", "hunt"])
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--config", default="config.yaml")
    # sweep options
    ap.add_argument("--hours", type=int, default=72, help="lookback window")
    ap.add_argument("--limit", type=int, default=40, help="max hits per source")
    ap.add_argument("--top", type=int, default=20, help="results shown in terminal")
    ap.add_argument("--sources", default="", help="comma-separated backend list")
    ap.add_argument("--no-fetch", action="store_true",
                    help="skip article body fetching (much faster, less accurate)")
    ap.add_argument("--no-ai", action="store_true", help="keyword ranking only")
    ap.add_argument("--max-ai", type=int, default=25,
                    help="cap on items sent to the model")
    ap.add_argument("--save", action="store_true",
                    help="also store results in the archive")
    # hunt options
    ap.add_argument("--once", action="store_true", help="hunt: run every job once, then exit")
    # serve options
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    if args.command == "hunt":
        from hunter.__main__ import main as hunter_main
        sys.exit(hunter_main(["run"] + (["--once"] if args.once else [])))

    if args.command == "serve":
        import uvicorn
        # Make the bind scope explicit to the web layer.  This lets it fail
        # closed for public binds even when the deployment platform does not
        # provide a recognizable hosting environment variable.
        os.environ["WATCHTOWER_BIND_HOST"] = args.host
        print(f"\n  watchtower  ->  http://{args.host}:{args.port}\n")
        uvicorn.run("web.app:app", host=args.host, port=args.port,
                    log_level="warning")
        return

    cfg = load_config(args.config)
    store = Store(cfg["storage"]["database"])

    if args.command == "sources":
        from core.sources import BACKEND_KEYS, RETIRED_BACKENDS, has_credentials
        print("\nAvailable sweep backends:\n")
        for name in BACKENDS:
            if name in RETIRED_BACKENDS:
                continue
            mark = "*" if name in DEFAULT_BACKENDS else " "
            var = BACKEND_KEYS.get(name)
            if not var:
                need = ""
            elif has_credentials(name):
                need = f"  (key set: {var})"
            else:
                # A source that will skip itself is worth saying out loud here:
                # on the CLI it otherwise only surfaces after a 60s sweep.
                need = f"  (NEEDS {var} — will be skipped)"
            print(f"  {mark} {name}{need}")
        print("\n  * = used by default\n")
        store.close()
        return

    if args.command == "models":
        from core.enrich import (DEEP_MODEL, GEMINI_DEEP_MODEL,
                                 GEMINI_TRIAGE_MODEL, TRIAGE_MODEL,
                                 available_provider)
        which = available_provider()
        if not which:
            print("\nNo model API key set. Add GEMINI_API_KEY (free tier) or "
                  "ANTHROPIC_API_KEY to .env.\n")
            store.close()
            return
        print(f"\nprovider: {which}")
        try:
            if which == "gemini":
                from google import genai
                print(f"configured: triage={GEMINI_TRIAGE_MODEL} "
                      f"deep={GEMINI_DEEP_MODEL}\n")
                client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
                for m in client.models.list():
                    actions = getattr(m, "supported_actions", None) or []
                    if not actions or "generateContent" in actions:
                        print(f"  {m.name.replace('models/', ''):42} "
                              f"{getattr(m, 'display_name', '')}")
            else:
                import anthropic
                print(f"configured: triage={TRIAGE_MODEL} deep={DEEP_MODEL}\n")
                for m in anthropic.Anthropic().models.list(limit=20).data:
                    print(f"  {m.id:42} {getattr(m, 'display_name', '')}")
        except Exception as e:
            print(f"  could not list models: {type(e).__name__}: {e}")
        print()
        store.close()
        return

    if args.command == "sweep":
        if not args.query:
            ap.error('sweep needs a query: python run.py sweep "your keywords"')
        cmd_sweep(cfg, store, args.query, args)
        store.close()
        return

    if args.command in ("collect", "run"):
        print("collect:")
        print(f"  -> {cmd_collect(cfg, store)} new item(s)\n")

    if args.command in ("enrich", "run"):
        print("enrich:")
        print(f"  -> {cmd_enrich(cfg, store)} item(s) enriched\n")

    if args.command in ("alert", "run"):
        print("alert:")
        cmd_alert(cfg, store)

    if args.command == "search":
        if not args.query:
            print("usage: python run.py search \"your query\"")
        for row in store.search(args.query):
            print(f"[{row['relevance']:>3}] {row['title'] or '(untitled)'}")
            print(f"      {row['source']}  |  {row['url']}")
            if row["summary"]:
                print(f"      {row['summary']}")
            print()

    if args.command == "stats":
        for k, v in store.stats().items():
            print(f"  {k:<12} {v}")

    store.close()


if __name__ == "__main__":
    main()
