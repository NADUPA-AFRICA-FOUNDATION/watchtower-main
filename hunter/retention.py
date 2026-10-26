"""Retention: personal data is kept for a stated purpose and a stated time, then removed.

What counts: page text snapshots, contact identifiers extracted from pages (phone, WhatsApp, email,
Telegram, social profile), visible RDAP registrant data, and rejected raw input. Kenya's Data
Protection Act 2019 requires a lawful basis, a purpose and a retention limit; confirm them before
running against live traffic. This module enforces the limit, it does not supply the lawful basis.

Evidence is otherwise immutable, so a purge is deliberate and leaves a trace: the row stays (id, type,
timestamps, source) but its content is replaced, and `hunt_purges` records what was removed and the
SHA-256 of the original, so that its existence and integrity can be shown without keeping the data.
Indicators tied to an active campaign are kept when `keep_campaign_indicators` is true.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

PERSONAL_ENTITY_TYPES = ("phone_number", "whatsapp", "email", "telegram", "social_account")
PLACEHOLDER = "[purged: retention]"


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def purge(store, graph, cfg, now: datetime | None = None, *, dry_run: bool = False) -> dict:
    rc, conn = cfg.retention, graph.conn
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=rc.personal_data_days)).isoformat()
    rej_cutoff = (now - timedelta(days=rc.rejection_days)).isoformat(timespec="microseconds")
    counts = {"evidence_redacted": 0, "entities_deleted": 0, "candidates_deleted": 0, "rejections_deleted": 0, "kept_campaign": 0}

    # 1. evidence content flagged as personal data
    redact = []
    for r in conn.execute("SELECT id, evidence_type, observed_value, raw_metadata FROM evidence WHERE observed_at<?", (cutoff,)):
        try:
            meta = json.loads(r["raw_metadata"] or "{}")
        except ValueError:
            meta = {}
        if (r["evidence_type"] == "page_text" or meta.get("personal_data")) and r["observed_value"] != PLACEHOLDER:
            redact.append(r)
    counts["evidence_redacted"] = len(redact)

    # 2. personal indicators with no reason to keep them
    q = ",".join("?" * len(PERSONAL_ENTITY_TYPES))
    doomed, keep = [], 0
    for e in conn.execute(f"SELECT id, entity_type, canonical_value FROM entities WHERE entity_type IN ({q}) AND last_seen<?",
                          (*PERSONAL_ENTITY_TYPES, cutoff)):
        if rc.keep_campaign_indicators and conn.execute(
                """SELECT 1 FROM relationships r JOIN campaign_entities ce ON ce.entity_id=r.source_entity_id
                   JOIN campaigns c ON c.id=ce.campaign_id WHERE r.target_entity_id=? AND c.status='active' LIMIT 1""", (e["id"],)).fetchone():
            keep += 1
            continue
        doomed.append(e)
    counts["kept_campaign"] = keep
    counts["entities_deleted"] = len(doomed)
    counts["candidates_deleted"] = sum(1 for e in doomed if store.get(e["id"]))
    with store._lock:
        counts["rejections_deleted"] = store.conn.execute("SELECT COUNT(*) FROM hunt_rejections WHERE at<?", (rej_cutoff,)).fetchone()[0]
    if dry_run:
        return {**counts, "dry_run": True}

    at = now.isoformat()
    with conn:
        for r in redact:
            conn.execute("UPDATE evidence SET observed_value=?, raw_metadata=? WHERE id=?",
                         (PLACEHOLDER, json.dumps({"purged": True, "reason": "retention", "evidence_type": r["evidence_type"]}), r["id"]))
    with store._tx() as c:
        for r in redact:
            c.execute("INSERT INTO hunt_purges(at,kind,target,reason,original_sha256) VALUES(?,?,?,?,?)",
                      (at, "evidence", r["id"], "retention", _sha(r["observed_value"])))
        for e in doomed:
            c.execute("INSERT INTO hunt_purges(at,kind,target,reason,original_sha256) VALUES(?,?,?,?,?)",
                      (at, "entity", e["entity_type"], "retention", _sha(e["canonical_value"])))   # the value itself is not kept
            c.execute("DELETE FROM hunt_observations WHERE candidate_id=?", (e["id"],))
            c.execute("DELETE FROM hunt_history WHERE candidate_id=?", (e["id"],))
            c.execute("DELETE FROM hunt_scores WHERE candidate_id=?", (e["id"],))
            c.execute("DELETE FROM hunt_changes WHERE candidate_id=?", (e["id"],))
            c.execute("DELETE FROM hunt_candidates WHERE id=?", (e["id"],))
        c.execute("DELETE FROM hunt_rejections WHERE at<?", (rej_cutoff,))
    with conn:
        for e in doomed:
            conn.execute("DELETE FROM relationships WHERE source_entity_id=? OR target_entity_id=?", (e["id"], e["id"]))
            conn.execute("DELETE FROM evidence WHERE entity_id=?", (e["id"],))
            conn.execute("DELETE FROM observations WHERE entity_id=?", (e["id"],))
            conn.execute("DELETE FROM investigation_entities WHERE entity_id=?", (e["id"],))
            conn.execute("DELETE FROM entities WHERE id=?", (e["id"],))
    return {**counts, "dry_run": False}
