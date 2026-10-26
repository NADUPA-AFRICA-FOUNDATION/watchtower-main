from __future__ import annotations
import json
import sqlite3
import uuid
from pathlib import Path
from .models import now

MIGRATION = """
CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY, brand TEXT NOT NULL, query TEXT, status TEXT, started_at TEXT, completed_at TEXT, requested_sources TEXT, successful_sources TEXT, limited_sources TEXT, failed_sources TEXT, unavailable_sources TEXT, coverage_percentage REAL, config_snapshot TEXT, budget_note TEXT);
CREATE TABLE IF NOT EXISTS investigation_entities(investigation_id TEXT, entity_id TEXT, PRIMARY KEY(investigation_id,entity_id));
CREATE TABLE IF NOT EXISTS entities(id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, canonical_value TEXT NOT NULL, display_value TEXT, platform TEXT, metadata TEXT, confidence REAL, first_seen TEXT, last_seen TEXT, created_at TEXT, updated_at TEXT, UNIQUE(entity_type,canonical_value));
CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, entity_id TEXT NOT NULL, source TEXT NOT NULL, evidence_type TEXT NOT NULL, source_url TEXT, observed_value TEXT, raw_metadata TEXT, observed_at TEXT, confidence REAL);
CREATE TABLE IF NOT EXISTS relationships(id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, source_entity_id TEXT NOT NULL, target_entity_id TEXT NOT NULL, relationship_type TEXT NOT NULL, confidence REAL, evidence_id TEXT NOT NULL, first_seen TEXT, last_seen TEXT, UNIQUE(investigation_id,source_entity_id,target_entity_id,relationship_type,evidence_id));
CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, public_id TEXT UNIQUE, brand TEXT, correlation_score REAL, correlation_label TEXT, threat_score REAL, system_classification TEXT, status TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS campaign_entities(campaign_id TEXT, entity_id TEXT, relationship_strength REAL, PRIMARY KEY(campaign_id,entity_id));
CREATE TABLE IF NOT EXISTS scores(id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT, heuristic_score REAL, model_score REAL, combined_threat_score REAL, scoring_version TEXT, model_provider TEXT, model_name TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS analyst_verdicts(id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT, campaign_id TEXT, verdict TEXT NOT NULL, analyst_comment TEXT, analyst_identifier TEXT, created_at TEXT, previous_verdict TEXT, evidence_snapshot TEXT);
CREATE TABLE IF NOT EXISTS source_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, source TEXT, status TEXT, started_at TEXT, completed_at TEXT, results_returned INTEGER, error_code TEXT, error_message TEXT, rate_limit_metadata TEXT);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, entity_id TEXT, provider TEXT, observation_type TEXT, raw_value TEXT, normalized_value TEXT, source_url TEXT, observed_at TEXT, metadata TEXT);
CREATE INDEX IF NOT EXISTS idx_observation_entity ON observations(entity_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence(entity_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_rel_investigation ON relationships(investigation_id);
"""
VERDICTS = {
    "confirmed_malicious",
    "likely_malicious",
    "suspicious",
    "needs_review",
    "needs_investigation",
    "benign",
    "legitimate",
    "false_positive",
    "duplicate",
    "monitor",
    # hunter dispositions (HUNTER_PLAN.md, Milestone 11)
    "confirmed_scam",
    "confirmed_impersonation",
    "unreviewed",
}


class InvestigationStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(MIGRATION)
        self.conn.commit()

    def create(self, brand, query, requested, snapshot):
        iid = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO investigations(id,brand,query,status,started_at,requested_sources,config_snapshot) VALUES(?,?,?,?,?,?,?)",
            (
                iid,
                brand,
                query,
                "running",
                now(),
                json.dumps(requested),
                json.dumps(snapshot),
            ),
        )
        self.conn.commit()
        return iid

    def persist(self, iid, entities, evidence, relationships):
        with self.conn:
            for e in entities:
                self.conn.execute(
                    "INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity_type,canonical_value) DO UPDATE SET last_seen=excluded.last_seen,metadata=excluded.metadata",
                    (
                        e.id,
                        e.entity_type,
                        e.canonical_value,
                        e.display_value,
                        e.platform,
                        json.dumps(e.metadata),
                        e.confidence,
                        e.first_seen,
                        e.last_seen,
                        now(),
                        now(),
                    ),
                )
                self.conn.execute(
                    "INSERT OR IGNORE INTO investigation_entities VALUES(?,?)",
                    (iid, e.id),
                )
            for x in evidence:
                inserted = self.conn.execute(
                    "INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        x.id,
                        x.investigation_id,
                        x.entity_id,
                        x.source,
                        x.evidence_type,
                        x.source_url,
                        x.observed_value,
                        json.dumps(x.raw_metadata),
                        x.observed_at,
                        x.confidence,
                    ),
                )
                if inserted.rowcount:
                    self.conn.execute(
                        """INSERT INTO observations(
                           investigation_id,entity_id,provider,observation_type,
                           raw_value,normalized_value,source_url,observed_at,metadata)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (iid, x.entity_id, x.source, x.evidence_type,
                         x.raw_metadata.get("raw_value", x.observed_value),
                         x.raw_metadata.get("normalized_value", x.observed_value),
                         x.source_url, x.observed_at, json.dumps(x.raw_metadata)),
                    )
            for r in relationships:
                self.conn.execute(
                    "INSERT OR IGNORE INTO relationships VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        r.id,
                        r.investigation_id,
                        r.source_entity_id,
                        r.target_entity_id,
                        r.relationship_type,
                        r.confidence,
                        r.evidence_id,
                        r.first_seen,
                        r.last_seen,
                    ),
                )

    def finish(self, iid, successful, limited, failed, unavailable, note=""):
        req = json.loads(
            self.conn.execute(
                "SELECT requested_sources FROM investigations WHERE id=?", (iid,)
            ).fetchone()[0]
        )
        coverage = round(100 * len(successful) / len(req), 1) if req else 0
        self.conn.execute(
            "UPDATE investigations SET status='completed',completed_at=?,successful_sources=?,limited_sources=?,failed_sources=?,unavailable_sources=?,coverage_percentage=?,budget_note=? WHERE id=?",
            (
                now(),
                json.dumps(successful),
                json.dumps(limited),
                json.dumps(failed),
                json.dumps(unavailable),
                coverage,
                note,
                iid,
            ),
        )
        self.conn.commit()

    def record_source_run(self, iid, health):
        self.conn.execute(
            """INSERT INTO source_runs(
               investigation_id,source,status,started_at,completed_at,
               results_returned,error_code,error_message,rate_limit_metadata)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (iid, health.provider, health.status, health.last_attempt, now(),
             health.results, health.status if health.error else None,
             health.error, json.dumps({**health.rate_limit,
                                       "duration_ms": health.duration_ms})),
        )
        self.conn.commit()

    def save_score(self, entity_id, scored):
        self.conn.execute(
            """INSERT INTO scores(entity_id,heuristic_score,model_score,
               combined_threat_score,scoring_version,model_provider,model_name,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (entity_id, scored.risk_score, None, scored.risk_score,
             scored.scoring_version, "none", "evidence-rules", now()),
        )
        self.conn.execute(
            "UPDATE entities SET metadata=json_set(COALESCE(metadata,'{}'), '$.risk', json(?)) WHERE id=?",
            (json.dumps(scored.dict()), entity_id),
        )
        self.conn.commit()

    def source_runs(self, iid):
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM source_runs WHERE investigation_id=? ORDER BY id", (iid,)
        )]

    def create_campaign(self, brand, entity_ids, correlation, label, threat_score=None):
        year = now()[:4]
        sequence = (
            self.conn.execute(
                "SELECT COUNT(*) FROM campaigns WHERE public_id LIKE ?",
                (f"WT-CMP-{year}-%",),
            ).fetchone()[0]
            + 1
        )
        cid = str(uuid.uuid4())
        public = f"WT-CMP-{year}-{sequence:04d}"
        with self.conn:
            self.conn.execute(
                "INSERT INTO campaigns VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    cid,
                    public,
                    brand,
                    correlation,
                    label,
                    threat_score,
                    "needs_review",
                    "active",
                    now(),
                    now(),
                ),
            )
            self.conn.executemany(
                "INSERT OR IGNORE INTO campaign_entities VALUES(?,?,?)",
                [(cid, eid, correlation / 100) for eid in entity_ids],
            )
        return {
            "id": cid,
            "public_id": public,
            "correlation_score": correlation,
            "correlation_label": label,
            "threat_score": threat_score,
        }

    def get(self, table, key):
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (key,)).fetchone()
        return dict(row) if row else None

    def graph(self, iid):
        nodes = [
            dict(r)
            for r in self.conn.execute(
                "SELECT e.* FROM entities e JOIN investigation_entities ie ON ie.entity_id=e.id WHERE ie.investigation_id=?",
                (iid,),
            )
        ]
        edges = [
            dict(r)
            for r in self.conn.execute(
                "SELECT r.*,ev.source,ev.source_url,ev.observed_value,ev.observed_at FROM relationships r JOIN evidence ev ON ev.id=r.evidence_id WHERE r.investigation_id=?",
                (iid,),
            )
        ]
        for n in nodes:
            n["metadata"] = json.loads(n["metadata"] or "{}")
        return {"nodes": nodes, "edges": edges}

    def verdict(self, entity_id, verdict, comment, analyst):
        if verdict not in VERDICTS:
            raise ValueError("invalid verdict")
        prior = self.conn.execute(
            "SELECT verdict FROM analyst_verdicts WHERE entity_id=? ORDER BY id DESC LIMIT 1",
            (entity_id,),
        ).fetchone()
        snapshot = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM evidence WHERE entity_id=?", (entity_id,)
            )
        ]
        self.conn.execute(
            "INSERT INTO analyst_verdicts(entity_id,verdict,analyst_comment,analyst_identifier,created_at,previous_verdict,evidence_snapshot) VALUES(?,?,?,?,?,?,?)",
            (
                entity_id,
                verdict,
                comment,
                analyst,
                now(),
                prior[0] if prior else None,
                json.dumps(snapshot),
            ),
        )
        self.conn.commit()
        return {
            "entity_id": entity_id,
            "analyst_verdict": verdict,
            "system_classification_unchanged": True,
        }
