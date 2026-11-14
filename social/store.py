"""Storage for social discovery: watchlist, job queue, HTTP cache, hits, audit, source health.

Two implementations of one contract (the methods of `SQLiteStore`, which the Convex store
mirrors one for one):

  ConvexStore   when CONVEX_URL is set. The primary target: web and worker can run as
                separate services because the data lives outside both.
  SQLiteStore   otherwise. Needs no configuration, so tests and a laptop work out of the
                box. A single file, so the worker must run inside the web process.

All times are integer milliseconds since the epoch, passed in by the caller: nothing here
reads a clock, which is what makes the queue and the purge testable.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path

DAY_MS = 86_400_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS social_watchlist(id TEXT PRIMARY KEY, term TEXT NOT NULL, match_type TEXT NOT NULL,
  platforms TEXT NOT NULL, active INTEGER NOT NULL, created_by TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_jobs(id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, run_after INTEGER NOT NULL, locked_at INTEGER, dedupe_key TEXT, run_id TEXT,
  error TEXT, created_at INTEGER NOT NULL, finished_at INTEGER);
CREATE INDEX IF NOT EXISTS social_jobs_due ON social_jobs(status, run_after);
CREATE TABLE IF NOT EXISTS social_http_cache(key TEXT PRIMARY KEY, body TEXT NOT NULL, status INTEGER NOT NULL,
  fetched_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_hits(id TEXT PRIMARY KEY, platform TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
  author_handle TEXT, text TEXT, published_at TEXT, matched_terms TEXT NOT NULL, engagement TEXT NOT NULL,
  source_method TEXT NOT NULL, confidence REAL NOT NULL, review_status TEXT NOT NULL, first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL, raw TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL,
  reviewed_by TEXT, reviewed_at INTEGER);
CREATE INDEX IF NOT EXISTS social_hits_review ON social_hits(review_status, score);
CREATE TABLE IF NOT EXISTS social_run_hits(run_id TEXT NOT NULL, hit_id TEXT NOT NULL, PRIMARY KEY(run_id, hit_id));
CREATE TABLE IF NOT EXISTS social_audit(id TEXT PRIMARY KEY, user TEXT, action TEXT NOT NULL, query TEXT,
  sources_used TEXT NOT NULL, purpose TEXT, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_sources(source TEXT PRIMARY KEY, last_success_at INTEGER, last_failure_at INTEGER,
  consecutive_failures INTEGER NOT NULL DEFAULT 0, breaker_until INTEGER, last_status TEXT, last_detail TEXT);
CREATE TABLE IF NOT EXISTS social_source_events(source TEXT NOT NULL, ok INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS social_source_events_at ON social_source_events(source, at);
CREATE TABLE IF NOT EXISTS social_runs(id TEXT PRIMARY KEY, kind TEXT NOT NULL, query TEXT NOT NULL, purpose TEXT,
  user TEXT, platforms TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_run_outcomes(run_id TEXT NOT NULL, platform TEXT NOT NULL, source TEXT NOT NULL,
  status TEXT NOT NULL, detail TEXT, count INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _id() -> str:
    return uuid.uuid4().hex


def hit_columns(doc: dict) -> dict:
    """The queryable columns the brief names, derived from the unified hit document."""
    return {"platform": doc["platform"], "url": doc["url"], "author_handle": doc["author"].get("username"),
            "text": doc["content"].get("text"), "published_at": doc["content"].get("published_at"),
            "matched_terms": doc.get("matched_terms", []), "engagement": doc["engagement"],
            "source_method": doc["source_method"], "confidence": float(doc.get("confidence", 0.0)),
            "score": int(doc.get("score", 0)), "status": doc["status"]}


class SQLiteStore:
    backend = "sqlite"
    shared = False        # one file: a separate worker service would not see the web service's rows

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if self.path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def _all(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, args).fetchall()

    def _run(self, sql: str, args=()) -> int:
        with self._lock:
            return self.conn.execute(sql, args).rowcount

    # ------------------------------------------------------------------ watchlist

    @staticmethod
    def _watch(r) -> dict:
        return {"id": r["id"], "term": r["term"], "match_type": r["match_type"], "platforms": json.loads(r["platforms"]),
                "active": bool(r["active"]), "created_by": r["created_by"], "created_at": r["created_at"]}

    def watchlist_add(self, term: str, match_type: str, platforms: list[str], created_by: str, now: int) -> dict:
        wid = _id()
        self._run("INSERT INTO social_watchlist VALUES(?,?,?,?,?,?,?)",
                  (wid, term, match_type, json.dumps(platforms), 1, created_by, now))
        return self._watch(self._all("SELECT * FROM social_watchlist WHERE id=?", (wid,))[0])

    def watchlist_list(self, active_only: bool = False) -> list[dict]:
        rows = self._all("SELECT * FROM social_watchlist" + (" WHERE active=1" if active_only else "") + " ORDER BY created_at")
        return [self._watch(r) for r in rows]

    def watchlist_update(self, wid: str, active: bool) -> bool:
        return self._run("UPDATE social_watchlist SET active=? WHERE id=?", (int(active), wid)) > 0

    def watchlist_delete(self, wid: str) -> bool:
        return self._run("DELETE FROM social_watchlist WHERE id=?", (wid,)) > 0

    # ------------------------------------------------------------------------ jobs

    @staticmethod
    def _job(r) -> dict:
        return {"id": r["id"], "kind": r["kind"], "payload": json.loads(r["payload"]), "status": r["status"],
                "attempts": r["attempts"], "run_after": r["run_after"], "locked_at": r["locked_at"],
                "run_id": r["run_id"], "error": r["error"]}

    def job_enqueue(self, kind: str, payload: dict, now: int, run_after: int | None = None,
                    dedupe_key: str | None = None) -> str | None:
        """None when an unfinished job with the same dedupe_key already exists."""
        with self._lock:
            if dedupe_key and self.conn.execute(
                    "SELECT 1 FROM social_jobs WHERE dedupe_key=? AND status IN ('pending','running')", (dedupe_key,)).fetchone():
                return None
            jid = _id()
            self.conn.execute("INSERT INTO social_jobs(id,kind,payload,status,run_after,dedupe_key,run_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
                              (jid, kind, json.dumps(payload), "pending", now if run_after is None else run_after,
                               dedupe_key, payload.get("run_id"), now))
            return jid

    def job_claim(self, now: int, lock_ms: int = 600_000) -> dict | None:
        """Atomically take the next due job. A job whose worker died is reclaimed after lock_ms."""
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.conn.execute(
                    "SELECT * FROM social_jobs WHERE (status='pending' AND run_after<=?) OR (status='running' AND locked_at<?) "
                    "ORDER BY run_after, created_at LIMIT 1", (now, now - lock_ms)).fetchone()
                if row is None:
                    self.conn.execute("COMMIT")
                    return None
                self.conn.execute("UPDATE social_jobs SET status='running', locked_at=?, attempts=attempts+1 WHERE id=?", (now, row["id"]))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            return self._job(self.conn.execute("SELECT * FROM social_jobs WHERE id=?", (row["id"],)).fetchone())

    def job_finish(self, jid: str, ok: bool, error: str | None, now: int) -> None:
        self._run("UPDATE social_jobs SET status=?, error=?, finished_at=?, locked_at=NULL WHERE id=?",
                  ("done" if ok else "failed", error, now, jid))

    def job_retry(self, jid: str, run_after: int, error: str | None) -> None:
        self._run("UPDATE social_jobs SET status='pending', run_after=?, error=?, locked_at=NULL WHERE id=?", (run_after, error, jid))

    def jobs_pending(self, run_id: str | None = None) -> int:
        sql, args = "SELECT COUNT(*) c FROM social_jobs WHERE status IN ('pending','running')", ()
        if run_id:
            sql, args = sql + " AND run_id=?", (run_id,)
        return self._all(sql, args)[0]["c"]

    # ----------------------------------------------------------------------- cache

    def cache_get(self, key: str, now: int) -> dict | None:
        rows = self._all("SELECT * FROM social_http_cache WHERE key=? AND expires_at>?", (key, now))
        return {"body": rows[0]["body"], "status": rows[0]["status"], "fetched_at": rows[0]["fetched_at"]} if rows else None

    def cache_put(self, key: str, body: str, status: int, now: int, ttl_ms: int) -> None:
        self._run("INSERT OR REPLACE INTO social_http_cache VALUES(?,?,?,?,?)", (key, body, status, now, now + ttl_ms))

    # ------------------------------------------------------------------------ hits

    @staticmethod
    def _hit(r) -> dict:
        doc = json.loads(r["raw"])
        doc.update(id=r["id"], review_status=r["review_status"], first_seen=r["first_seen"], last_seen=r["last_seen"],
                   reviewed_by=r["reviewed_by"], reviewed_at=r["reviewed_at"])
        return doc

    def hit_get(self, hid: str) -> dict | None:
        rows = self._all("SELECT * FROM social_hits WHERE id=?", (hid,))
        return self._hit(rows[0]) if rows else None

    def hit_get_by_url(self, url: str) -> dict | None:
        rows = self._all("SELECT * FROM social_hits WHERE url=?", (url,))
        return self._hit(rows[0]) if rows else None

    def hit_put(self, doc: dict, now: int, run_id: str | None = None) -> dict:
        """Insert, or replace the document of the hit with this URL. Review state and first_seen survive."""
        c = hit_columns(doc)
        body = json.dumps({k: v for k, v in doc.items() if k not in
                           {"id", "review_status", "first_seen", "last_seen", "reviewed_by", "reviewed_at"}})
        with self._lock:
            row = self.conn.execute("SELECT id FROM social_hits WHERE url=?", (c["url"],)).fetchone()
            if row:
                hid, created = row["id"], False
                self.conn.execute(
                    "UPDATE social_hits SET platform=?, author_handle=?, text=?, published_at=?, matched_terms=?, engagement=?, "
                    "source_method=?, confidence=?, last_seen=?, raw=?, score=?, status=? WHERE id=?",
                    (c["platform"], c["author_handle"], c["text"], c["published_at"], json.dumps(c["matched_terms"]),
                     json.dumps(c["engagement"]), c["source_method"], c["confidence"], now, body, c["score"], c["status"], hid))
            else:
                hid, created = _id(), True
                self.conn.execute("INSERT INTO social_hits VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                  (hid, c["platform"], c["url"], c["author_handle"], c["text"], c["published_at"],
                                   json.dumps(c["matched_terms"]), json.dumps(c["engagement"]), c["source_method"], c["confidence"],
                                   "new", now, now, body, c["score"], c["status"], None, None))
            if run_id:
                self.conn.execute("INSERT OR IGNORE INTO social_run_hits VALUES(?,?)", (run_id, hid))
        return {"id": hid, "created": created}

    def hits_list(self, review_status: str | None = None, platform: str | None = None, run_id: str | None = None,
                  limit: int = 100) -> list[dict]:
        where, args = [], []
        if review_status:
            where.append("review_status=?"); args.append(review_status)
        if platform:
            where.append("platform=?"); args.append(platform)
        if run_id:
            where.append("id IN (SELECT hit_id FROM social_run_hits WHERE run_id=?)"); args.append(run_id)
        sql = "SELECT * FROM social_hits" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY score DESC, last_seen DESC LIMIT ?"
        return [self._hit(r) for r in self._all(sql, (*args, max(1, min(int(limit), 500))))]

    def hit_review(self, hid: str, review_status: str, user: str, now: int) -> bool:
        return self._run("UPDATE social_hits SET review_status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                         (review_status, user, now, hid)) > 0

    # ----------------------------------------------------------------------- audit

    def audit(self, user: str, action: str, query: str, sources_used: list[str], purpose: str, now: int) -> None:
        self._run("INSERT INTO social_audit VALUES(?,?,?,?,?,?,?)", (_id(), user, action, query, json.dumps(sources_used), purpose, now))

    def audit_list(self, limit: int = 50) -> list[dict]:
        return [{"user": r["user"], "action": r["action"], "query": r["query"], "sources_used": json.loads(r["sources_used"]),
                 "purpose": r["purpose"], "at": r["at"]}
                for r in self._all("SELECT * FROM social_audit ORDER BY at DESC, rowid DESC LIMIT ?", (max(1, min(int(limit), 500)),))]

    # --------------------------------------------------------------- source health

    def source_event(self, source: str, ok: bool, status: str, detail: str, now: int, breaker_threshold: int = 3,
                     breaker_base_ms: int = 1_800_000, breaker_max_ms: int = 21_600_000) -> dict:
        """Record one attempt. After `breaker_threshold` failures in a row the source is paused, and each
        further failure doubles the pause up to the maximum; one success closes the breaker."""
        with self._lock:
            row = self.conn.execute("SELECT * FROM social_sources WHERE source=?", (source,)).fetchone()
            fails = 0 if ok else (row["consecutive_failures"] if row else 0) + 1
            until = None
            if fails >= breaker_threshold:
                until = now + min(breaker_max_ms, breaker_base_ms * 2 ** (fails - breaker_threshold))
            self.conn.execute(
                "INSERT INTO social_sources(source,last_success_at,last_failure_at,consecutive_failures,breaker_until,last_status,last_detail) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET last_success_at=COALESCE(excluded.last_success_at,last_success_at), "
                "last_failure_at=COALESCE(excluded.last_failure_at,last_failure_at), consecutive_failures=excluded.consecutive_failures, "
                "breaker_until=excluded.breaker_until, last_status=excluded.last_status, last_detail=excluded.last_detail",
                (source, now if ok else None, None if ok else now, fails, until, status, detail[:300]))
            self.conn.execute("INSERT INTO social_source_events VALUES(?,?,?)", (source, int(ok), now))
        return {"consecutive_failures": fails, "breaker_until": until}

    def source_health(self, now: int) -> list[dict]:
        out = []
        for r in self._all("SELECT * FROM social_sources ORDER BY source"):
            ev = self._all("SELECT SUM(ok) s, COUNT(*) n FROM social_source_events WHERE source=? AND at>?", (r["source"], now - 7 * DAY_MS))[0]
            open_ = bool(r["breaker_until"] and r["breaker_until"] > now)
            out.append({"source": r["source"], "last_success_at": r["last_success_at"], "last_failure_at": r["last_failure_at"],
                        "consecutive_failures": r["consecutive_failures"], "breaker": "open" if open_ else "closed",
                        "breaker_until": r["breaker_until"] if open_ else None, "last_status": r["last_status"],
                        "last_detail": r["last_detail"], "attempts_7d": ev["n"],
                        "success_rate_7d": round((ev["s"] or 0) / ev["n"], 3) if ev["n"] else None})
        return out

    # ------------------------------------------------------------------------ runs

    def run_create(self, kind: str, query: str, purpose: str, user: str, platforms: list[str], now: int) -> str:
        rid = _id()
        self._run("INSERT INTO social_runs VALUES(?,?,?,?,?,?,?)", (rid, kind, query, purpose, user, json.dumps(platforms), now))
        return rid

    def run_outcome(self, run_id: str, platform: str, source: str, status: str, detail: str, count: int, now: int) -> None:
        self._run("INSERT INTO social_run_outcomes VALUES(?,?,?,?,?,?,?)", (run_id, platform, source, status, detail[:300], count, now))

    def run_get(self, run_id: str) -> dict | None:
        rows = self._all("SELECT * FROM social_runs WHERE id=?", (run_id,))
        if not rows:
            return None
        r = rows[0]
        outcomes = [{"platform": o["platform"], "source": o["source"], "status": o["status"], "detail": o["detail"],
                     "count": o["count"], "at": o["at"]}
                    for o in self._all("SELECT * FROM social_run_outcomes WHERE run_id=? ORDER BY at", (run_id,))]
        return {"id": r["id"], "kind": r["kind"], "query": r["query"], "purpose": r["purpose"], "user": r["user"],
                "platforms": json.loads(r["platforms"]), "created_at": r["created_at"], "outcomes": outcomes,
                "pending_jobs": self.jobs_pending(run_id)}

    # -------------------------------------------------------------------------- kv

    def kv_get(self, key: str) -> str | None:
        rows = self._all("SELECT value FROM social_kv WHERE key=?", (key,))
        return rows[0]["value"] if rows else None

    def kv_set(self, key: str, value: str) -> None:
        self._run("INSERT OR REPLACE INTO social_kv VALUES(?,?)", (key, value))

    # ----------------------------------------------------------------------- purge

    def purge(self, now: int, retention_ms: int, dismissed_ms: int) -> dict:
        """Retention limit for personal data. Escalated hits are case material and are kept; everything
        else leaves once it has not been seen for the retention period, and dismissed hits leave sooner."""
        with self._lock:
            dismissed = self.conn.execute("DELETE FROM social_hits WHERE review_status='dismissed' AND reviewed_at<?", (now - dismissed_ms,)).rowcount
            expired = self.conn.execute("DELETE FROM social_hits WHERE review_status!='escalated' AND last_seen<?", (now - retention_ms,)).rowcount
            self.conn.execute("DELETE FROM social_run_hits WHERE hit_id NOT IN (SELECT id FROM social_hits)")
            cache = self.conn.execute("DELETE FROM social_http_cache WHERE expires_at<?", (now,)).rowcount
            jobs = self.conn.execute("DELETE FROM social_jobs WHERE status IN ('done','failed') AND finished_at<?", (now - 7 * DAY_MS,)).rowcount
            self.conn.execute("DELETE FROM social_source_events WHERE at<?", (now - 8 * DAY_MS,))
            old_runs = [r["id"] for r in self.conn.execute("SELECT id FROM social_runs WHERE created_at<?", (now - retention_ms,))]
            for rid in old_runs:
                self.conn.execute("DELETE FROM social_run_outcomes WHERE run_id=?", (rid,))
                self.conn.execute("DELETE FROM social_runs WHERE id=?", (rid,))
        return {"dismissed_hits": dismissed, "expired_hits": expired, "cache_rows": cache, "finished_jobs": jobs, "runs": len(old_runs)}


def open_store(data_dir: str | Path | None = None):
    """ConvexStore when CONVEX_URL is set, else SQLite in `data_dir` (in memory when none is given)."""
    if os.environ.get("CONVEX_URL"):
        from social.convex_store import ConvexStore
        return ConvexStore(os.environ["CONVEX_URL"], os.environ.get("CONVEX_SERVER_KEY", ""))
    if data_dir is None:
        return SQLiteStore()
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    return SQLiteStore(Path(data_dir) / "social.db")
