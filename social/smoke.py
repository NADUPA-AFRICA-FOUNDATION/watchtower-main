"""Manual smoke test: one term, end to end, against the live network.

    python -m social.smoke "Fuliza"
    python -m social.smoke "Fuliza" --platforms x,reddit

Uses a throwaway in-memory store, so it never touches real hits. It runs each job once and
does not wait out a retry: a source that is blocked is printed as blocked.
"""
from __future__ import annotations

import argparse

from social.pipeline import Engine
from social.schema import PLATFORMS
from social.store import SQLiteStore


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("term")
    ap.add_argument("--platforms", default=",".join(PLATFORMS))
    args = ap.parse_args()
    store = SQLiteStore()
    engine = Engine(store)
    run_id = engine.submit_search(args.term, "manual smoke test of the pipeline", "smoke",
                                  [p for p in args.platforms.split(",") if p])
    print(f"searching {args.term!r}; requests are paced, expect about 20s per platform\n")
    while engine.work_once():
        pass
    run = store.run_get(run_id)
    latest = {}
    for o in run["outcomes"]:
        latest[(o["platform"], o["source"])] = o
    print("What each source said:")
    for (platform, source), o in latest.items():
        print(f"  {platform:<10} {source:<12} {o['status']:<13} {o['detail']}")
    if run["pending_jobs"]:
        print(f"  ({run['pending_jobs']} job(s) waiting to retry later)")
    hits = store.hits_list(run_id=run_id, limit=200)
    print(f"\n{len(hits)} hit(s):")
    for h in hits[:25]:
        text = (h["content"]["text"] or h.get("title") or "")[:90]
        print(f"  [{h['score']:>3}] {h['platform']:<9} {h['status']:<12} {h['url'][:70]}")
        print(f"        {text}")
        print(f"        missing: {', '.join(h['missing_fields']) or 'nothing'}")
    print("\nSource health:")
    for s in store.source_health(engine.clock()):
        print(f"  {s['source']:<12} breaker {s['breaker']:<6} last status {s['last_status']} ({s['last_detail']})")


if __name__ == "__main__":
    main()
