"""Persistent candidate queue with dedup.

One row per (type, canonical) indicator in `hunt_candidates`; every sighting is
kept in `hunt_observations`, so a second source finding the same domain raises
`observation_count` and `sources_seen` instead of creating a second entity. Every
status change is written to `hunt_history`, which answers "what happened to this
candidate and why".

Rejected input is recorded in `hunt_rejections`, never dropped: a discovery
provider that returned 200 junk values must look different from one that
returned nothing.

The queue survives restarts. `claim()` takes rows with BEGIN IMMEDIATE so two
workers (or two processes) cannot claim the same candidate, and `recover_stale()`
returns candidates whose worker died to the retry lane.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, List

from investigation.models import stable_id

from .normalize import InvalidIndicator, is_public, normalize

DISPOSITIONS = ("UNREVIEWED", "BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM", "MONITOR")
CONFIRMED_DISPOSITIONS = {"CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM"}
CLEARED_DISPOSITIONS = {"BENIGN", "FALSE_POSITIVE"}

STATUSES = (
    "NEW", "QUEUED", "INVESTIGATING", "ENRICHED", "SCORED",
    "ESCALATED", "IGNORED", "FAILED", "RETRY",
)

# from -> allowed targets. Re-queueing out of a finished state is how staged
# enrichment (light -> re-score -> deep) and analyst "look again" work.
TRANSITIONS = {
    "NEW": {"QUEUED", "IGNORED"},
    "QUEUED": {"INVESTIGATING", "IGNORED"},
    "INVESTIGATING": {"ENRICHED", "SCORED", "ESCALATED", "IGNORED", "FAILED", "RETRY", "QUEUED"},
    "RETRY": {"INVESTIGATING", "IGNORED", "QUEUED"},
    "ENRICHED": {"SCORED", "ESCALATED", "QUEUED", "IGNORED"},
    "SCORED": {"ESCALATED", "QUEUED", "IGNORED"},
    "ESCALATED": {"QUEUED", "IGNORED"},
    "IGNORED": {"QUEUED"},
    "FAILED": {"QUEUED", "IGNORED"},
}
TERMINAL_RESULTS = {"ENRICHED", "SCORED", "ESCALATED", "IGNORED"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS hunt_candidates(
  id TEXT PRIMARY KEY,
  indicator_type TEXT NOT NULL,
  canonical TEXT NOT NULL,
  original TEXT,
  brand TEXT,
  discovery_source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'NEW',
  priority REAL NOT NULL DEFAULT 0,
  risk_score REAL,
  depth INTEGER NOT NULL DEFAULT 0,
  parent_id TEXT,
  campaign_id TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  observation_count INTEGER NOT NULL DEFAULT 1,
  sources_seen TEXT NOT NULL DEFAULT '[]',
  last_investigated TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  error_state TEXT,
  next_attempt_at TEXT,
  deferred_reason TEXT,
  claimed_at TEXT,
  stage TEXT NOT NULL DEFAULT 'none',
  market TEXT,
  market_confidence REAL,
  classification TEXT,
  root_id TEXT,
  disposition TEXT,
  UNIQUE(indicator_type, canonical)
);
CREATE TABLE IF NOT EXISTS hunt_observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  source TEXT NOT NULL,
  query TEXT,
  original TEXT,
  parent_id TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  confidence REAL,
  metadata TEXT,
  observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  event TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT,
  detail TEXT,
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_rejections(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original TEXT,
  source TEXT,
  reason TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_state(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_discovery_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL,
  brand TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_ms INTEGER,
  found INTEGER NOT NULL DEFAULT 0,
  submitted INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL DEFAULT 0,
  queued INTEGER NOT NULL DEFAULT 0,
  stored_only INTEGER NOT NULL DEFAULT 0,
  rejected INTEGER NOT NULL DEFAULT 0,
  skipped_official INTEGER NOT NULL DEFAULT 0,
  noise_filtered INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0,
  detail TEXT,
  error TEXT
);
CREATE TABLE IF NOT EXISTS hunt_provider_health(
  provider TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  last_attempt TEXT,
  last_success TEXT,
  last_failure TEXT,
  last_error TEXT,
  last_result_count INTEGER,
  avg_latency_ms REAL,
  runs INTEGER NOT NULL DEFAULT 0,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  rate_limit TEXT
);
CREATE TABLE IF NOT EXISTS hunt_scores(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  scored_at TEXT NOT NULL,
  trigger TEXT NOT NULL,
  score INTEGER NOT NULL,
  classification TEXT NOT NULL,
  assessment TEXT NOT NULL,
  scoring_version TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  reasons TEXT NOT NULL,
  coverage TEXT NOT NULL,
  previous_score INTEGER,
  delta INTEGER,
  changes TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunt_scores ON hunt_scores(candidate_id, id);
CREATE TABLE IF NOT EXISTS hunt_campaign_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id TEXT NOT NULL,
  at TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunt_campaign_events ON hunt_campaign_events(campaign_id, id);
CREATE TABLE IF NOT EXISTS hunt_changes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  meaningful INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL,
  before TEXT,
  after TEXT,
  evidence_id TEXT,
  UNIQUE(candidate_id, kind, evidence_id)
);
CREATE TABLE IF NOT EXISTS hunt_alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT,
  candidate_id TEXT,
  campaign_id TEXT,
  delivered TEXT,
  acknowledged_by TEXT,
  acknowledged_at TEXT
);
CREATE TABLE IF NOT EXISTS hunt_purges(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  original_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunt_changes ON hunt_changes(candidate_id, id);
CREATE INDEX IF NOT EXISTS idx_hunt_alerts ON hunt_alerts(dedupe_key, id);
CREATE TABLE IF NOT EXISTS hunt_dispositions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT,
  campaign_id TEXT,
  disposition TEXT NOT NULL,
  previous TEXT,
  analyst TEXT NOT NULL,
  identity_source TEXT NOT NULL,
  reason TEXT,
  notes TEXT,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_disp ON hunt_dispositions(candidate_id, id);
CREATE INDEX IF NOT EXISTS idx_hunt_claim ON hunt_candidates(status, priority DESC, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_hunt_obs ON hunt_observations(candidate_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_hunt_hist ON hunt_history(candidate_id, at);
"""


class InvalidTransition(ValueError):
    pass


class Submission:
    """Outcome of one submit(). `accepted` False always carries a `reason`."""

    __slots__ = ("accepted", "created", "candidate_id", "canonical", "indicator_type", "reason")

    def __init__(self, accepted, created=False, candidate_id=None, canonical=None,
                 indicator_type=None, reason=None):
        self.accepted, self.created, self.candidate_id = accepted, created, candidate_id
        self.canonical, self.indicator_type, self.reason = canonical, indicator_type, reason

    def __repr__(self):
        return (f"Submission(accepted={self.accepted}, created={self.created}, "
                f"id={self.candidate_id}, reason={self.reason})")


class HuntStore:
    def __init__(self, path: str | Path = ":memory:", clock: Callable[[], datetime] | None = None):
        self.path = str(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._ensure_column("hunt_candidates", "stage", "TEXT NOT NULL DEFAULT 'none'")
        self._ensure_column("hunt_candidates", "market", "TEXT")
        self._ensure_column("hunt_candidates", "market_confidence", "REAL")
        self._ensure_column("hunt_candidates", "classification", "TEXT")
        self._ensure_column("hunt_candidates", "root_id", "TEXT")
        self._ensure_column("hunt_candidates", "disposition", "TEXT")

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        """Add a column to a table created by an earlier version of the schema."""
        have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in have:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    # -- plumbing -------------------------------------------------------------

    def _iso(self, dt: datetime | None = None) -> str:
        # Fixed-width microseconds keep string comparison equal to time comparison.
        return (dt or self.clock()).astimezone(timezone.utc).isoformat(timespec="microseconds")

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def _log(self, c, cid, event, from_status=None, to_status=None, detail=None):
        c.execute(
            "INSERT INTO hunt_history(candidate_id,event,from_status,to_status,detail,at) VALUES(?,?,?,?,?,?)",
            (cid, event, from_status, to_status, detail, self._iso()),
        )

    def _row(self, c, cid):
        row = c.execute("SELECT * FROM hunt_candidates WHERE id=?", (cid,)).fetchone()
        if row is None:
            raise KeyError(f"unknown candidate: {cid}")
        return row

    def _move(self, c, row, to_status, event, detail=None, **fields):
        if to_status not in TRANSITIONS.get(row["status"], set()):
            raise InvalidTransition(f"{row['status']} -> {to_status} is not allowed")
        fields["status"] = to_status
        sets = ", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE hunt_candidates SET {sets} WHERE id=?", (*fields.values(), row["id"]))
        self._log(c, row["id"], event, row["status"], to_status, detail)

    @staticmethod
    def _dict(row) -> dict[str, Any]:
        d = dict(row)
        d["sources_seen"] = json.loads(d.get("sources_seen") or "[]")
        return d

    # -- submit / dedup ---------------------------------------------------------

    def reject(self, original, source, reason) -> Submission:
        with self._tx() as c:
            c.execute("INSERT INTO hunt_rejections(original,source,reason,at) VALUES(?,?,?,?)",
                      (str(original)[:500], source, reason, self._iso()))
        return Submission(False, reason=reason)

    def submit(
        self,
        value: str,
        source: str,
        *,
        hint: str | None = None,
        region: str | None = "KE",
        query: str | None = None,
        brand: str | None = None,
        parent_id: str | None = None,
        depth: int = 0,
        priority: float = 0.0,
        confidence: float = 0.5,
        metadata: dict | None = None,
        enqueue: bool = True,
        indicator=None,
    ) -> Submission:
        """`indicator` skips parsing: pivots already hold a canonical Indicator, and some canonical
        forms (`x:handle`, `google_analytics:g-1`) are not parseable back from text."""
        try:
            ind = indicator if indicator is not None else normalize(value, hint=hint, region=region)
        except InvalidIndicator as exc:
            return self.reject(value, source, str(exc))
        if not is_public(ind):
            return self.reject(value, source, f"non-public target: {ind.canonical}")

        cid = stable_id(ind.type, ind.canonical)
        now = self._iso()
        with self._tx() as c:
            row = c.execute("SELECT * FROM hunt_candidates WHERE id=?", (cid,)).fetchone()
            created = row is None
            if created:
                parent = c.execute("SELECT root_id FROM hunt_candidates WHERE id=?", (parent_id,)).fetchone() if parent_id else None
                root = (parent["root_id"] or parent_id) if parent else cid
                c.execute(
                    """INSERT INTO hunt_candidates(id,indicator_type,canonical,original,brand,
                       discovery_source,priority,depth,parent_id,first_seen,last_seen,sources_seen,root_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (cid, ind.type, ind.canonical, ind.original, brand, source, priority,
                     depth, parent_id, now, now, json.dumps([source]), root),
                )
                self._log(c, cid, "discovered", None, "NEW", f"{source}: {query or ''}".strip(": "))
                row = self._row(c, cid)
            else:
                sources = json.loads(row["sources_seen"] or "[]")
                if source not in sources:
                    sources.append(source)
                # Shallowest depth and highest priority win: a direct discovery
                # outranks the same indicator reached by a long pivot chain.
                c.execute(
                    """UPDATE hunt_candidates SET last_seen=?, observation_count=observation_count+1,
                       sources_seen=?, priority=MAX(priority,?), depth=MIN(depth,?),
                       brand=COALESCE(brand,?) WHERE id=?""",
                    (now, json.dumps(sources), priority, depth, brand, cid),
                )
                row = self._row(c, cid)
            c.execute(
                """INSERT INTO hunt_observations(candidate_id,source,query,original,parent_id,
                   depth,confidence,metadata,observed_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (cid, source, query, ind.original, parent_id, depth, confidence,
                 json.dumps(metadata or {}), now),
            )
            if enqueue and row["status"] == "NEW":
                self._move(c, row, "QUEUED", "queued")
        return Submission(True, created, cid, ind.canonical, ind.type)

    # -- claiming ---------------------------------------------------------------

    def claim(self, limit: int = 1) -> List[dict[str, Any]]:
        now = self._iso()
        with self._tx() as c:
            rows = c.execute(
                """SELECT * FROM hunt_candidates
                   WHERE status IN ('QUEUED','RETRY') AND (next_attempt_at IS NULL OR next_attempt_at<=?)
                   ORDER BY priority DESC, depth ASC, first_seen ASC LIMIT ?""",
                (now, limit),
            ).fetchall()
            for row in rows:
                self._move(c, row, "INVESTIGATING", "claimed", f"attempt {row['attempts'] + 1}",
                           attempts=row["attempts"] + 1, claimed_at=now, deferred_reason=None,
                           next_attempt_at=None)
            return [self._dict(self._row(c, r["id"])) for r in rows]

    def complete(self, cid: str, status: str, *, risk_score: float | None = None,
                 note: str | None = None, campaign_id: str | None = None,
                 stage: str | None = None, priority: float | None = None) -> None:
        if status not in TERMINAL_RESULTS:
            raise InvalidTransition(f"{status} is not a completion status")
        with self._tx() as c:
            row = self._row(c, cid)
            fields: dict[str, Any] = {"last_investigated": self._iso(), "error_state": None,
                                      "next_attempt_at": None, "claimed_at": None}
            if risk_score is not None:
                fields["risk_score"] = risk_score
            if campaign_id is not None:
                fields["campaign_id"] = campaign_id
            if stage is not None:
                fields["stage"] = stage
            if priority is not None:
                fields["priority"] = priority
            self._move(c, row, status, "completed", note, **fields)

    def fail(self, cid: str, error: str, *, max_attempts: int = 3,
             backoff_base: float = 60.0, backoff_cap: float = 3600.0) -> str:
        """Record a failed attempt. Returns RETRY, or FAILED once attempts run out.

        The error is kept on the row: a candidate that could not be investigated
        must not read as one that was investigated and found clean.
        """
        with self._tx() as c:
            row = self._row(c, cid)
            error = str(error)[:500]
            if row["attempts"] >= max_attempts:
                self._move(c, row, "FAILED", "failed", error, error_state=error,
                           claimed_at=None, next_attempt_at=None)
                return "FAILED"
            delay = min(backoff_base * (2 ** max(row["attempts"] - 1, 0)), backoff_cap)
            self._move(c, row, "RETRY", "retry", error, error_state=error, claimed_at=None,
                       next_attempt_at=self._iso(self.clock() + timedelta(seconds=delay)))
            return "RETRY"

    def defer(self, cid: str, reason: str, until: datetime) -> None:
        """Put a candidate back until `until` for a stated reason (budget, rate limit).

        A deferral is not an attempt, so the attempt counter is given back.
        """
        with self._tx() as c:
            row = self._row(c, cid)
            if row["status"] not in {"INVESTIGATING", "QUEUED"}:
                raise InvalidTransition(f"cannot defer a {row['status']} candidate")
            attempts = max(row["attempts"] - 1, 0) if row["status"] == "INVESTIGATING" else row["attempts"]
            c.execute(
                "UPDATE hunt_candidates SET status='QUEUED', attempts=?, next_attempt_at=?, deferred_reason=?, claimed_at=NULL WHERE id=?",
                (attempts, self._iso(until), reason, cid),
            )
            self._log(c, cid, "deferred", row["status"], "QUEUED", reason)

    def recover_stale(self, max_age_seconds: float = 900, max_attempts: int = 3) -> int:
        cutoff = self._iso(self.clock() - timedelta(seconds=max_age_seconds))
        n = 0
        with self._tx() as c:
            for row in c.execute("SELECT * FROM hunt_candidates WHERE status='INVESTIGATING' AND claimed_at<=?",
                                 (cutoff,)).fetchall():
                msg = "claim expired; worker presumed dead"
                target = "FAILED" if row["attempts"] >= max_attempts else "RETRY"
                self._move(c, row, target, "recovered", msg, error_state=msg, claimed_at=None,
                           next_attempt_at=None)
                n += 1
        return n

    def requeue(self, cid: str, *, priority: float | None = None, reason: str = "requeued",
                stage: str | None = None, exact_priority: bool = False) -> None:
        with self._tx() as c:
            row = self._row(c, cid)
            fields: dict[str, Any] = {"next_attempt_at": None, "deferred_reason": None, "attempts": 0,
                                      "error_state": None, "claimed_at": None}
            if priority is not None:
                fields["priority"] = priority if exact_priority else max(row["priority"], priority)
            if stage is not None:
                fields["stage"] = stage
            self._move(c, row, "QUEUED", "requeued", reason, **fields)

    def ignore(self, cid: str, reason: str) -> None:
        with self._tx() as c:
            self._move(c, self._row(c, cid), "IGNORED", "ignored", reason, claimed_at=None)

    def latest_score(self, cid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM hunt_scores WHERE candidate_id=? ORDER BY id DESC LIMIT 1",
                                    (cid,)).fetchone()
        return self._score_row(row) if row else None

    def score_history(self, cid: str) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_scores WHERE candidate_id=? ORDER BY id", (cid,)).fetchall()
        return [self._score_row(r) for r in rows]

    @staticmethod
    def _score_row(row) -> dict[str, Any]:
        d = dict(row)
        for k in ("reasons", "coverage", "changes"):
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k != "coverage" else {})
        return d

    def record_score(self, cid: str, *, trigger: str, score: int, classification: str, assessment: str,
                     version: str, config_hash: str, content_hash: str, reasons: list, coverage: dict) -> dict[str, Any]:
        """Append a score row unless it is identical to the latest (same content, same config).

        History is append-only: a change in score, reasons, evidence or weights adds a row with the
        delta and what changed; an unchanged re-score adds nothing and says so. The candidate's
        current risk_score/classification always follow the newest row.
        """
        with self._tx() as c:
            self._row(c, cid)
            prev = c.execute("SELECT * FROM hunt_scores WHERE candidate_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
            if prev is not None and prev["content_hash"] == content_hash:
                return {"recorded": False, "score": score, "previous_score": prev["score"], "delta": 0, "changes": []}
            prior = {r["signal"]: r for r in json.loads(prev["reasons"])} if prev else {}
            now_by = {r["signal"]: r for r in reasons}
            changes = ([{"signal": k, "change": "added", "weight": v["weight"]} for k, v in sorted(now_by.items()) if k not in prior]
                       + [{"signal": k, "change": "removed", "weight": v["weight"]} for k, v in sorted(prior.items()) if k not in now_by]
                       + [{"signal": k, "change": "reweighted", "from": prior[k]["weight"], "to": v["weight"]}
                          for k, v in sorted(now_by.items()) if k in prior and prior[k]["weight"] != v["weight"]])
            delta = score - prev["score"] if prev else None
            c.execute(
                """INSERT INTO hunt_scores(candidate_id,scored_at,trigger,score,classification,assessment,scoring_version,
                   config_hash,content_hash,reasons,coverage,previous_score,delta,changes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, self._iso(), trigger, score, classification, assessment, version, config_hash, content_hash,
                 json.dumps(reasons), json.dumps(coverage), prev["score"] if prev else None, delta, json.dumps(changes)))
            c.execute("UPDATE hunt_candidates SET risk_score=?, classification=? WHERE id=?", (score, classification, cid))
            self._log(c, cid, "scored", None, None,
                      f"{score} {classification} ({trigger})" + (f", {delta:+d}" if delta is not None else ""))
        return {"recorded": True, "score": score, "previous_score": prev["score"] if prev else None,
                "delta": delta, "changes": changes}

    # -- lineage and pivot budgets ---------------------------------------------------------------

    def count_children(self, parent_id: str) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM hunt_candidates WHERE parent_id=?", (parent_id,)).fetchone()[0]

    def count_lineage(self, key: str) -> int:
        """Candidates in a campaign, or (before one exists) under one originating candidate."""
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM hunt_candidates WHERE campaign_id=? OR COALESCE(root_id,id)=?",
                                     (key, key)).fetchone()[0]

    def count_observations_since(self, source_prefix: str, seconds: float) -> int:
        cutoff = self._iso(self.clock() - timedelta(seconds=seconds))
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM hunt_observations WHERE substr(source,1,?)=? AND observed_at>=?",
                                     (len(source_prefix), source_prefix, cutoff)).fetchone()[0]

    def lineage(self, cid: str) -> List[dict[str, Any]]:
        """Root -> ... -> cid: how the hunter came to look at this candidate, one hop per entry."""
        chain: List[dict[str, Any]] = []
        seen: set = set()
        cur: str | None = cid
        while cur and cur not in seen and len(chain) < 12:
            seen.add(cur)
            row = self.get(cur)
            if row is None:
                break
            with self._lock:
                obs = self.conn.execute("SELECT * FROM hunt_observations WHERE candidate_id=? ORDER BY id LIMIT 1", (cur,)).fetchone()
            meta = json.loads(obs["metadata"] or "{}") if obs else {}
            chain.append({"id": cur, "type": row["indicator_type"], "canonical": row["canonical"], "depth": row["depth"],
                          "source": row["discovery_source"], "query": obs["query"] if obs else None,
                          "via": {k: meta[k] for k in ("pivot_from", "where", "snippet", "evidence_id", "pivot_value") if k in meta},
                          "first_seen": row["first_seen"]})
            cur = row["parent_id"]
        return chain[::-1]

    def ancestor_risk(self, cid: str) -> float:
        """Highest risk score among a candidate's ancestors (0 when none has been scored)."""
        best: float = 0.0
        seen: set = set()
        cur = (self.get(cid) or {}).get("parent_id")
        while cur and cur not in seen and len(seen) < 12:
            seen.add(cur)
            row = self.get(cur)
            if row is None:
                break
            best = max(best, row.get("risk_score") or 0.0)
            cur = row["parent_id"]
        return best

    def set_market(self, cid: str, market: str, confidence: float) -> None:
        with self._tx() as c:
            self._row(c, cid)
            c.execute("UPDATE hunt_candidates SET market=?, market_confidence=? WHERE id=?", (market, confidence, cid))

    def add_change(self, cid: str, kind: str, summary: str, *, meaningful: bool, before=None, after=None, evidence_id=None) -> bool:
        with self._tx() as c:
            cur = c.execute("INSERT OR IGNORE INTO hunt_changes(candidate_id,at,kind,meaningful,summary,before,after,evidence_id) VALUES(?,?,?,?,?,?,?,?)",
                            (cid, self._iso(), kind, int(meaningful), summary, json.dumps(before, sort_keys=True, default=str) if before is not None else None,
                             json.dumps(after, sort_keys=True, default=str) if after is not None else None, evidence_id))
            if cur.rowcount:
                self._log(c, cid, "changed", None, None, f"{kind}: {summary}")
            return bool(cur.rowcount)

    def changes(self, cid: str | None = None, *, meaningful_only: bool = False, limit: int = 100) -> List[dict[str, Any]]:
        sql, args = "SELECT * FROM hunt_changes WHERE 1=1", []
        if cid:
            sql += " AND candidate_id=?"
            args.append(cid)
        if meaningful_only:
            sql += " AND meaningful=1"
        with self._lock:
            rows = self.conn.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [dict(r) for r in rows]

    # -- analyst dispositions (append-only; nothing is ever deleted) --------------------------------------------

    def add_disposition(self, *, disposition: str, analyst: str, identity_source: str, reason: str = "", notes: str = "",
                        candidate_id: str | None = None, campaign_id: str | None = None) -> dict[str, Any]:
        if disposition not in DISPOSITIONS:
            raise ValueError(f"unknown disposition: {disposition!r} (choose from {', '.join(DISPOSITIONS)})")
        if bool(candidate_id) == bool(campaign_id):
            raise ValueError("a disposition applies to exactly one candidate or one campaign")
        if not analyst.strip():
            raise ValueError("an analyst name is required")
        if disposition != "UNREVIEWED" and not reason.strip():
            raise ValueError("a reason is required")
        with self._tx() as c:
            if candidate_id:
                self._row(c, candidate_id)
                prev = c.execute("SELECT disposition FROM hunt_dispositions WHERE candidate_id=? ORDER BY id DESC LIMIT 1", (candidate_id,)).fetchone()
            else:
                prev = c.execute("SELECT disposition FROM hunt_dispositions WHERE campaign_id=? ORDER BY id DESC LIMIT 1", (campaign_id,)).fetchone()
            at = self._iso()
            rid = c.execute(
                "INSERT INTO hunt_dispositions(candidate_id,campaign_id,disposition,previous,analyst,identity_source,reason,notes,at) VALUES(?,?,?,?,?,?,?,?,?)",
                (candidate_id, campaign_id, disposition, prev["disposition"] if prev else None, analyst.strip()[:100], identity_source,
                 reason.strip()[:2000], notes.strip()[:4000], at)).lastrowid
            if candidate_id:
                c.execute("UPDATE hunt_candidates SET disposition=? WHERE id=?", (disposition, candidate_id))
                self._log(c, candidate_id, "disposition", prev["disposition"] if prev else None, disposition, f"{analyst.strip()[:100]} ({identity_source})")
        return {"id": rid, "disposition": disposition, "previous": prev["disposition"] if prev else None, "at": at}

    def dispositions(self, candidate_id: str | None = None, campaign_id: str | None = None) -> List[dict[str, Any]]:
        col, val = ("candidate_id", candidate_id) if candidate_id else ("campaign_id", campaign_id)
        with self._lock:
            rows = self.conn.execute(f"SELECT * FROM hunt_dispositions WHERE {col}=? ORDER BY id", (val,)).fetchall()
        return [dict(r) for r in rows]

    def disposition_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self.conn.execute("SELECT COALESCE(disposition,'UNREVIEWED') d, COUNT(*) n FROM hunt_candidates WHERE indicator_type='domain' GROUP BY d").fetchall()
        out = dict.fromkeys(DISPOSITIONS, 0)
        out.update({r["d"]: r["n"] for r in rows})
        return out

    # -- administrator-approved trust (a classification, never an automatic weight change) -----------------------

    def admin_trusted(self) -> List[dict[str, Any]]:
        raw = self.get_state("admin:trusted").get("admin:trusted")
        return json.loads(raw) if raw else []

    def set_admin_trusted(self, items: List[dict[str, Any]]) -> None:
        self.set_state({"admin:trusted": json.dumps(items, sort_keys=True)})

    def log_campaign_event(self, campaign_id: str, event: str, detail: dict) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO hunt_campaign_events(campaign_id,at,event,detail) VALUES(?,?,?,?)",
                      (campaign_id, self._iso(), event, json.dumps(detail, sort_keys=True)))

    def campaign_events(self, campaign_id: str | None = None, limit: int = 100) -> List[dict[str, Any]]:
        sql, args = "SELECT * FROM hunt_campaign_events", []
        if campaign_id:
            sql += " WHERE campaign_id=?"
            args.append(campaign_id)
        with self._lock:
            rows = self.conn.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]

    def set_campaign(self, cid: str, campaign_id: str | None) -> None:
        with self._tx() as c:
            c.execute("UPDATE hunt_candidates SET campaign_id=? WHERE id=?", (campaign_id, cid))

    def escalate(self, cid: str, note: str) -> bool:
        """SCORED/ENRICHED -> ESCALATED after a rescore pushes a candidate over the line."""
        with self._tx() as c:
            row = self._row(c, cid)
            if row["status"] not in {"SCORED", "ENRICHED"}:
                return False
            self._move(c, row, "ESCALATED", "escalated", note)
            return True

    def log_event(self, cid: str, event: str, detail: str | None = None) -> None:
        """Append a history event that is not a status change (e.g. a budget-counted step)."""
        with self._tx() as c:
            self._log(c, cid, event, None, None, detail)

    SEARCH_EVENTS = ("pivot_search", "discovery_search")

    def search_events_24h(self) -> List[str]:
        """Timestamps of every public search query in the last day, pivots and discovery together:
        they draw on one budget because they hit the same rate-limited service."""
        return sorted(t for e in self.SEARCH_EVENTS for t in self.recent_events(e, 86400))

    def count_events(self, cid: str, event: str) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM hunt_history WHERE candidate_id=? AND event=?",
                                     (cid, event)).fetchone()[0]

    def recent_events(self, event: str, seconds: float) -> List[str]:
        """Timestamps (oldest first) of `event` across all candidates in the last `seconds`."""
        cutoff = self._iso(self.clock() - timedelta(seconds=seconds))
        with self._lock:
            rows = self.conn.execute("SELECT at FROM hunt_history WHERE event=? AND at>=? ORDER BY at",
                                     (event, cutoff)).fetchall()
        return [r["at"] for r in rows]

    # -- reading ----------------------------------------------------------------

    def get(self, cid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM hunt_candidates WHERE id=?", (cid,)).fetchone()
        return self._dict(row) if row else None

    def find(self, value: str, hint: str | None = None, region: str | None = "KE") -> dict[str, Any] | None:
        ind = normalize(value, hint=hint, region=region)
        return self.get(stable_id(ind.type, ind.canonical))

    def list(self, status: str | None = None, limit: int = 100, offset: int = 0) -> List[dict[str, Any]]:
        sql, args = "SELECT * FROM hunt_candidates", []
        if status:
            sql += " WHERE status=?"
            args.append(status)
        sql += " ORDER BY last_seen DESC, id LIMIT ? OFFSET ?"
        with self._lock:
            rows = self.conn.execute(sql, (*args, limit, offset)).fetchall()
        return [self._dict(r) for r in rows]

    def observations(self, cid: str) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_observations WHERE candidate_id=? ORDER BY id", (cid,)).fetchall()
        return [dict(r) for r in rows]

    def history(self, cid: str) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_history WHERE candidate_id=? ORDER BY id", (cid,)).fetchall()
        return [dict(r) for r in rows]

    def rejections(self, limit: int = 100) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_rejections ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        now = self._iso()
        with self._lock:
            by_status = dict.fromkeys(STATUSES, 0)
            for r in self.conn.execute("SELECT status, COUNT(*) n FROM hunt_candidates GROUP BY status"):
                by_status[r["status"]] = r["n"]
            deferred = self.conn.execute(
                "SELECT COUNT(*) FROM hunt_candidates WHERE status='QUEUED' AND deferred_reason IS NOT NULL AND next_attempt_at>?",
                (now,)).fetchone()[0]
            rejected = self.conn.execute("SELECT COUNT(*) FROM hunt_rejections").fetchone()[0]
        return {"by_status": by_status, "total": sum(by_status.values()),
                "deferred": deferred, "rejected": rejected}

    # -- cursors, runs, provider health ------------------------------------------

    def get_state(self, prefix: str = "") -> dict[str, str]:
        with self._lock:
            rows = self.conn.execute("SELECT key,value FROM hunt_state WHERE substr(key,1,?)=?",
                                     (len(prefix), prefix)).fetchall()
        return {r["key"]: r["value"] for r in rows}

    def set_state(self, updates: dict[str, str]) -> None:
        if not updates:
            return
        with self._tx() as c:
            for key, value in updates.items():
                c.execute("INSERT INTO hunt_state(key,value,updated_at) VALUES(?,?,?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                          (key, value, self._iso()))

    def record_run(self, provider: str, brand: str | None, *, status: str, started_at: str,
                   duration_ms: int | None, found: int = 0, submitted: int = 0, created: int = 0,
                   queued: int = 0, stored_only: int = 0, rejected: int = 0, skipped_official: int = 0,
                   noise_filtered: int = 0, truncated: bool = False, detail: str | None = None,
                   error: str | None = None, last_success: str | None = None,
                   rate_limit: dict | None = None) -> int:
        """Log one discovery run and fold it into the provider's rolling health.

        Anything but `operational` counts as a failure for the streak, including
        `partial`: a provider that lost half its terms is not healthy.
        """
        now = self._iso()
        with self._tx() as c:
            run_id = c.execute(
                """INSERT INTO hunt_discovery_runs(provider,brand,started_at,finished_at,status,duration_ms,
                   found,submitted,created,queued,stored_only,rejected,skipped_official,noise_filtered,
                   truncated,detail,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (provider, brand, started_at, now, status, duration_ms, found, submitted, created, queued,
                 stored_only, rejected, skipped_official, noise_filtered, int(truncated), detail, error),
            ).lastrowid
            prev = c.execute("SELECT * FROM hunt_provider_health WHERE provider=?", (provider,)).fetchone()
            ok = status == "operational"
            succeeded = status in {"operational", "partial"}
            avg = duration_ms
            if prev and prev["avg_latency_ms"] is not None and duration_ms is not None:
                avg = 0.7 * prev["avg_latency_ms"] + 0.3 * duration_ms  # smoothed, recent runs weigh more
            c.execute(
                """INSERT INTO hunt_provider_health(provider,status,last_attempt,last_success,last_failure,
                   last_error,last_result_count,avg_latency_ms,runs,consecutive_failures,rate_limit)
                   VALUES(?,?,?,?,?,?,?,?,1,?,?)
                   ON CONFLICT(provider) DO UPDATE SET status=excluded.status, last_attempt=excluded.last_attempt,
                     last_success=COALESCE(excluded.last_success, hunt_provider_health.last_success),
                     last_failure=COALESCE(excluded.last_failure, hunt_provider_health.last_failure),
                     last_error=excluded.last_error, last_result_count=excluded.last_result_count,
                     avg_latency_ms=excluded.avg_latency_ms, runs=hunt_provider_health.runs+1,
                     consecutive_failures=CASE WHEN ?=1 THEN 0 ELSE hunt_provider_health.consecutive_failures+1 END,
                     rate_limit=excluded.rate_limit""",
                (provider, status, now, (last_success or now) if succeeded else None,
                 None if ok else now, error, found, avg, 0 if ok else 1,
                 json.dumps(rate_limit or {}), int(ok)),
            )
        return int(run_id or 0)

    def provider_health_row(self, provider: str) -> dict[str, Any] | None:
        return next((h for h in self.provider_health() if h["provider"] == provider), None)

    def settled_domains(self, limit: int = 1000) -> List[dict[str, Any]]:
        """Domain candidates that finished a pass, oldest investigation first: the refresh queue's source."""
        with self._lock:
            rows = self.conn.execute(
                """SELECT * FROM hunt_candidates WHERE indicator_type='domain' AND status IN ('SCORED','ENRICHED','ESCALATED')
                   AND last_investigated IS NOT NULL ORDER BY last_investigated LIMIT ?""", (limit,)).fetchall()
        return [self._dict(r) for r in rows]

    def provider_health(self) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_provider_health ORDER BY provider").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rate_limit"] = json.loads(d.get("rate_limit") or "{}")
            out.append(d)
        return out

    def discovery_runs(self, limit: int = 50) -> List[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hunt_discovery_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self.conn.close()
