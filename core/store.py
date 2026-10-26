"""SQLite store. Archive + search + the queue that feeds alerts and summaries.

SQLite is the right call here until you're past a few million rows. FTS5 gives
you the searchable archive with no extra service to run.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from .models import Item

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    content_hash  TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    source        TEXT NOT NULL,
    source_type   TEXT NOT NULL,
    title         TEXT,
    text          TEXT,
    author        TEXT,
    published_at  TEXT,
    fetched_at    TEXT,
    lang          TEXT,
    raw_meta      TEXT,
    summary       TEXT,
    entities      TEXT,
    categories    TEXT,
    relevance     INTEGER DEFAULT 0,
    enriched      INTEGER DEFAULT 0,
    alerted       INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_fetched  ON items(fetched_at);
CREATE INDEX IF NOT EXISTS idx_source   ON items(source);
CREATE INDEX IF NOT EXISTS idx_enriched ON items(enriched);
CREATE INDEX IF NOT EXISTS idx_alerted  ON items(alerted);

CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5(
    title, text, entities,
    content='items', content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS items_ai AFTER INSERT ON items BEGIN
    INSERT INTO items_fts(rowid, title, text, entities)
    VALUES (new.rowid, new.title, new.text, new.entities);
END;

CREATE TRIGGER IF NOT EXISTS items_au AFTER UPDATE ON items BEGIN
    INSERT INTO items_fts(items_fts, rowid, title, text, entities)
    VALUES('delete', old.rowid, old.title, old.text, old.entities);
    INSERT INTO items_fts(rowid, title, text, entities)
    VALUES (new.rowid, new.title, new.text, new.entities);
END;

-- Without this, a deleted row leaves its title and body in the FTS index and
-- stays findable through `run.py search`. That is a correctness bug for any
-- delete, and a compliance one for the retention purge in adapters/social.py:
-- the point of RETENTION_DAYS is that someone's post is actually gone, not
-- that one of the two places holding it forgot about it.
CREATE TRIGGER IF NOT EXISTS items_ad AFTER DELETE ON items BEGIN
    INSERT INTO items_fts(items_fts, rowid, title, text, entities)
    VALUES('delete', old.rowid, old.title, old.text, old.entities);
END;

-- Tracks what each adapter has already seen, so re-runs are cheap.
CREATE TABLE IF NOT EXISTS seen_urls (
    url        TEXT PRIMARY KEY,
    source     TEXT,
    first_seen TEXT
);
"""

COLUMNS = [
    "content_hash", "url", "source", "source_type", "title", "text", "author",
    "published_at", "fetched_at", "lang", "raw_meta", "summary", "entities",
    "categories", "relevance", "enriched",
]


class Store:
    def __init__(self, path: str | Path = "watchtower.db"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------- writes ----------

    def add(self, items: Iterable[Item]) -> int:
        """Insert, skipping anything we've already stored. Returns new count."""
        rows = [i.to_row() for i in items]
        if not rows:
            return 0
        placeholders = ", ".join("?" for _ in COLUMNS)
        sql = (f"INSERT OR IGNORE INTO items ({', '.join(COLUMNS)}) "
               f"VALUES ({placeholders})")
        # Count rows directly. total_changes would also pick up the writes the
        # FTS triggers make, which inflates the number several times over.
        count = lambda: self.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        before = count()
        self.conn.executemany(sql, [[r[c] for c in COLUMNS] for r in rows])
        self.conn.commit()
        return count() - before

    def mark_seen(self, urls: Iterable[str], source: str, when: str) -> None:
        self.conn.executemany(
            "INSERT OR IGNORE INTO seen_urls (url, source, first_seen) VALUES (?,?,?)",
            [(u, source, when) for u in urls],
        )
        self.conn.commit()

    def is_seen(self, url: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM seen_urls WHERE url = ?", (url,))
        return cur.fetchone() is not None

    def save_enrichment(self, content_hash: str, summary: str,
                        entities: list[str], categories: list[str],
                        relevance: int) -> None:
        self.conn.execute(
            """UPDATE items SET summary=?, entities=?, categories=?,
                                relevance=?, enriched=1
               WHERE content_hash=?""",
            (summary, "\n".join(entities), "\n".join(categories),
             relevance, content_hash),
        )
        self.conn.commit()

    def mark_alerted(self, hashes: Iterable[str]) -> None:
        self.conn.executemany(
            "UPDATE items SET alerted=1 WHERE content_hash=?",
            [(h,) for h in hashes],
        )
        self.conn.commit()

    # ---------- reads ----------

    def pending_enrichment(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM items WHERE enriched=0 ORDER BY fetched_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def pending_alerts(self, min_relevance: int = 0) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM items WHERE alerted=0 AND relevance >= ? "
            "ORDER BY relevance DESC, fetched_at DESC",
            (min_relevance,),
        ).fetchall()

    def search(self, query: str, limit: int = 20) -> list[sqlite3.Row]:
        """Full-text search over the archive. Supports FTS5 syntax:
        'kenya AND (fraud OR laundering)', '"beneficial ownership"', 'crypto*'
        """
        return self.conn.execute(
            """SELECT i.*, bm25(items_fts) AS rank
               FROM items_fts JOIN items i ON i.rowid = items_fts.rowid
               WHERE items_fts MATCH ? ORDER BY rank LIMIT ?""",
            (query, limit),
        ).fetchall()

    def stats(self) -> dict[str, int]:
        q = lambda s: self.conn.execute(s).fetchone()[0]
        return {
            "total": q("SELECT COUNT(*) FROM items"),
            "enriched": q("SELECT COUNT(*) FROM items WHERE enriched=1"),
            "unalerted": q("SELECT COUNT(*) FROM items WHERE alerted=0"),
            "sources": q("SELECT COUNT(DISTINCT source) FROM items"),
        }

    def close(self) -> None:
        self.conn.close()
