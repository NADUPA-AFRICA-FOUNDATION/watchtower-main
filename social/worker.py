"""The queue worker: `python -m social.worker` (add --once to drain what is due and exit).

With Convex configured this can be its own service, because web and worker share the data.
With the SQLite fallback it cannot: the database is a file on one machine, so the web process
runs this loop in a thread instead (see web/social_routes.py) and a separate worker service
would be talking to an empty database of its own.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path

from social.pipeline import Engine
from social.store import open_store


def data_dir() -> Path:
    # Same rule as web/app.py and the hunter, so every process agrees where the file is.
    if os.environ.get("WATCHTOWER_DATA_DIR"):
        return Path(os.environ["WATCHTOWER_DATA_DIR"])
    return Path("/tmp/watchtower") if os.environ.get("VERCEL") else Path(__file__).resolve().parent.parent


def run(engine: Engine, stop: threading.Event, once: bool = False, idle_seconds: float = 2.0) -> int:
    done = 0
    while not stop.is_set():
        try:
            engine.tick()
            worked = engine.work_once()
        except Exception as exc:                                   # noqa: BLE001 - keep the loop alive; say why
            print(f"social worker: {type(exc).__name__}: {exc}", file=sys.stderr)
            worked = False
        done += worked
        if not worked:
            if once:
                break
            stop.wait(idle_seconds)
    return done


def main() -> None:
    ap = argparse.ArgumentParser(description="Mnara social discovery worker")
    ap.add_argument("--once", action="store_true", help="run every job that is due, then exit")
    args = ap.parse_args()
    store = open_store(data_dir())
    if not store.shared:
        print("social worker: using the SQLite fallback. A web service on another machine will not see these rows; "
              "set CONVEX_URL to share data between services.", file=sys.stderr)
    n = run(Engine(store), threading.Event(), once=args.once)
    if args.once:
        print(f"ran {n} job(s)")


if __name__ == "__main__":
    main()
