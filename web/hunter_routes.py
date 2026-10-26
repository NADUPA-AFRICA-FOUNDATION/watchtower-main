"""HTTP API for the autonomous hunter: /api/hunter/*.

Built by `build_router(...)` so the web app injects what only it knows (where the data lives, whether
storage is durable, who the caller is) and this module stays testable on its own.

Principles carried over from the rest of the app:
  * Nothing here exposes configuration, environment variables, file paths or credentials.
  * Authentication is the app's middleware (HTTP Basic once off localhost); this layer never weakens it.
  * Analyst identity is the authenticated user when auth is on, otherwise a free-text name that is stored
    as `self_asserted`, so a later reader can tell the two apart.
  * Writes (dispositions, alert acknowledgements, trust approvals) need durable storage and refuse on an
    ephemeral deployment rather than appearing to work.
  * Lists are bounded; ids are validated; payloads are length-limited.
"""
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Callable, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request

_ID = re.compile(r"^[A-Za-z0-9:_.\-]{1,120}$")
_CLASSES = {"LOW", "WATCH", "SUSPICIOUS", "HIGH_PRIORITY", "UNASSESSED"}


def build_router(db_path: Callable[[], Path], load_config: Callable[[], object], identity: Callable[[Request, str], tuple],
                 ephemeral: Callable[[], bool] = lambda: False, clock: Optional[Callable] = None) -> APIRouter:
    from hunter.alerts import AlertEngine
    from hunter.config import ConfigError
    from hunter.coverage import source_coverage
    from hunter.dispositions import apply_disposition, approve_trusted, insights, remove_trusted
    from hunter.graphq import GraphQueries
    from hunter.store import DISPOSITIONS, HuntStore
    from investigation.storage import InvestigationStore

    router = APIRouter(prefix="/api/hunter", tags=["hunter"])

    def ctx():
        path = str(db_path())
        try:
            cfg = load_config()
        except ConfigError as exc:                       # a broken config must be visible, not an empty dashboard
            detail = "the hunter configuration file is missing" if "not found" in str(exc) else f"hunter configuration error: {exc}"
            raise HTTPException(503, detail)             # (never echoes a filesystem path)
        store, graph = HuntStore(path, clock=clock), InvestigationStore(path)
        return cfg, store, graph, GraphQueries(store, graph)

    def check_id(value: str) -> str:
        if not _ID.match(value or ""):
            raise HTTPException(400, "invalid id")
        return value

    def candidate_or_404(store, cid: str) -> dict:
        row = store.get(check_id(cid))
        if row is None:
            raise HTTPException(404, "unknown candidate")
        return row

    def durable():
        if ephemeral():
            raise HTTPException(409, "this action needs durable storage; set WATCHTOWER_DATA_DIR")

    def brief(row: dict, store, graph) -> dict:
        camp = None
        if row.get("campaign_id"):
            c = graph.conn.execute("SELECT public_id FROM campaigns WHERE id=?", (row["campaign_id"],)).fetchone()
            camp = c["public_id"] if c else None
        return {"id": row["id"], "indicator": row["canonical"], "type": row["indicator_type"], "brand": row["brand"],
                "market": row.get("market"), "source": row["discovery_source"], "status": row["status"], "stage": row.get("stage"),
                "risk_score": row.get("risk_score"), "classification": row.get("classification"), "priority": row["priority"],
                "depth": row["depth"], "campaign": camp, "disposition": row.get("disposition"),
                "first_seen": row["first_seen"], "last_seen": row["last_seen"], "last_investigated": row.get("last_investigated"),
                "sightings": row["observation_count"], "sources_seen": row["sources_seen"],
                "error": row.get("error_state"), "deferred_reason": row.get("deferred_reason")}

    # ----------------------------------------------------------------------------------------- overview
    @router.get("/status")
    def status():
        cfg, store, graph, q = ctx()
        since = store._iso(store.clock() - timedelta(hours=24))
        with store._lock:
            one = lambda sql, *a: store.conn.execute(sql, a).fetchone()[0]   # noqa: E731
            discovered = one("SELECT COUNT(*) FROM hunt_candidates WHERE first_seen>=? AND depth=0", since)
            pivoted = one("SELECT COUNT(*) FROM hunt_candidates WHERE first_seen>=? AND depth>0", since)
            investigated = one("SELECT COUNT(*) FROM hunt_candidates WHERE last_investigated>=?", since)
            new_domains = one("SELECT COUNT(*) FROM hunt_candidates WHERE first_seen>=? AND indicator_type='domain'", since)
            new_indicators = one("SELECT COUNT(*) FROM hunt_candidates WHERE first_seen>=? AND indicator_type!='domain'", since)
            suspicious = one("SELECT COUNT(*) FROM hunt_candidates WHERE indicator_type='domain' AND classification IN ('SUSPICIOUS','HIGH_PRIORITY') AND last_investigated>=?", since)
            high = one("SELECT COUNT(*) FROM hunt_candidates WHERE indicator_type='domain' AND classification='HIGH_PRIORITY' AND last_investigated>=?", since)
            pending = one("SELECT COUNT(*) FROM hunt_candidates WHERE indicator_type='domain' AND status='ESCALATED' AND disposition IS NULL")
            unreviewed_suspicious = one("SELECT COUNT(*) FROM hunt_candidates WHERE indicator_type='domain' AND classification IN ('SUSPICIOUS','HIGH_PRIORITY') AND (disposition IS NULL OR disposition='UNREVIEWED')")
        new_campaigns = graph.conn.execute("SELECT COUNT(*) FROM campaigns WHERE created_at>=? AND status!='merged'", (since,)).fetchone()[0]
        cov = source_coverage(store, cfg)
        counts = store.disposition_counts()
        return {
            "window_hours": 24, "persistent_storage": not ephemeral(),
            "metrics": {"candidates_discovered": discovered, "pivoted_candidates": pivoted, "candidates_investigated": investigated,
                        "suspicious": suspicious, "high_priority": high, "new_campaigns": new_campaigns, "new_domains": new_domains,
                        "new_indicators": new_indicators, "pending_review": pending, "suspicious_unreviewed": unreviewed_suspicious,
                        "false_positives": counts["FALSE_POSITIVE"]},
            "queue": store.stats(),
            "providers": {"healthy": sum(r["status"] == "healthy" for r in cov), "degraded": sum(r["status"] in {"degraded", "rate_limited"} for r in cov),
                          "failing": sum(r["status"] in {"failing", "circuit_open"} for r in cov),
                          "not_run": sum(r["status"] == "not_run" for r in cov), "disabled": sum(r["status"] == "disabled" for r in cov)},
            "dispositions": counts,
            "unacknowledged_alerts": len(AlertEngine(store, graph, cfg).list(200, unacknowledged_only=True)),
        }

    # ------------------------------------------------------------------------------------------ feed
    @router.get("/candidates")
    def candidates(status: Optional[str] = None, classification: Optional[str] = None, source: Optional[str] = None,
                   market: Optional[str] = None, campaign: Optional[str] = None, disposition: Optional[str] = None,
                   type: Optional[str] = None, q: Optional[str] = Query(None, max_length=100), min_score: Optional[float] = None,
                   limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
        cfg, store, graph, _ = ctx()
        where: list = ["1=1"]
        args: list = []
        if status:
            where.append("status=?"); args.append(status.upper())
        if classification:
            if classification.upper() not in _CLASSES:
                raise HTTPException(400, "unknown classification")
            where.append("classification=?"); args.append(classification.upper())
        if source:
            where.append("(discovery_source=? OR sources_seen LIKE ?)"); args += [source, f'%"{source}"%']
        if market:
            where.append("market=?"); args.append(market)
        if disposition:
            where.append("COALESCE(disposition,'UNREVIEWED')=?"); args.append(disposition.upper())
        if type:
            where.append("indicator_type=?"); args.append(type)
        if q:
            where.append("canonical LIKE ? ESCAPE '\\'"); args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if min_score is not None:
            where.append("risk_score>=?"); args.append(min_score)
        if campaign:
            row = graph.conn.execute("SELECT id FROM campaigns WHERE id=? OR public_id=?", (campaign, campaign)).fetchone()
            where.append("campaign_id=?"); args.append(row["id"] if row else "")
        sql = " AND ".join(where)
        with store._lock:
            total = store.conn.execute(f"SELECT COUNT(*) FROM hunt_candidates WHERE {sql}", args).fetchone()[0]
            rows = store.conn.execute(f"SELECT * FROM hunt_candidates WHERE {sql} ORDER BY COALESCE(risk_score,-1) DESC, last_seen DESC LIMIT ? OFFSET ?",
                                      (*args, limit, offset)).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "items": [brief(store._dict(r), store, graph) for r in rows]}

    @router.get("/investigations/{cid}")
    def investigation(cid: str):
        cfg, store, graph, q = ctx()
        row = candidate_or_404(store, cid)
        score = store.latest_score(cid)
        view = q.entity_view(cid) or {"evidence": [], "outgoing": [], "incoming": []}
        camp = q.campaign(row["campaign_id"]) if row.get("campaign_id") else None
        return {
            "candidate": brief(row, store, graph), "score": score,
            "why_flagged": [r for r in (score["reasons"] if score else []) if r["weight"] != 0],
            "coverage": (score or {}).get("coverage", {}),
            "how_found": q.what_led_to(cid), "first_discovered": q.first_discovered(cid),
            "observations": store.observations(cid)[-20:],
            "indicators": q.indicators_of(cid), "relationships": view["outgoing"][:300],
            "evidence": [{**e, "raw_metadata": json.loads(e["raw_metadata"] or "{}")} for e in view["evidence"][-120:]],
            "score_history": store.score_history(cid), "changes": store.changes(cid, limit=50),
            "history": store.history(cid)[-60:], "dispositions": store.dispositions(candidate_id=cid),
            "campaign": ({k: camp[k] for k in ("id", "public_id", "name", "theme", "correlation_score", "correlation_label", "infrastructure")} if camp else None),
        }

    @router.get("/indicators/{entity_id}")
    def indicator(entity_id: str):
        cfg, store, graph, q = ctx()
        view = q.entity_view(check_id(entity_id))
        if view is None:
            raise HTTPException(404, "unknown entity")
        ent = view["entity"]
        return {"entity": ent, "evidence": view["evidence"][-60:], "used_by": q.domains_using(ent["entity_type"], ent["canonical_value"]),
                "campaigns": q.campaigns_for_indicator(ent["entity_type"], ent["canonical_value"]),
                "incoming": view["incoming"][:200], "outgoing": view["outgoing"][:200]}

    @router.get("/relationships")
    def relationships(entity: Optional[str] = None, type: Optional[str] = None, limit: int = Query(100, ge=1, le=500)):
        cfg, store, graph, _ = ctx()
        where, args = ["1=1"], []
        if entity:
            where.append("(r.source_entity_id=? OR r.target_entity_id=?)"); args += [check_id(entity)] * 2
        if type:
            where.append("r.relationship_type=?"); args.append(type)
        rows = graph.conn.execute(
            f"""SELECT r.id, r.relationship_type AS type, r.confidence, r.evidence_id, r.first_seen, r.last_seen,
                       s.entity_type AS source_type, s.canonical_value AS source, t.entity_type AS target_type, t.canonical_value AS target,
                       ev.source AS evidence_source, ev.observed_at
                FROM relationships r JOIN entities s ON s.id=r.source_entity_id JOIN entities t ON t.id=r.target_entity_id
                LEFT JOIN evidence ev ON ev.id=r.evidence_id WHERE {' AND '.join(where)} ORDER BY r.last_seen DESC LIMIT ?""", (*args, limit)).fetchall()
        return {"items": [dict(r) for r in rows]}

    # ------------------------------------------------------------------------------------- operations
    @router.get("/queue")
    def queue():
        cfg, store, graph, _ = ctx()
        stats = store.stats()
        by = stats["by_status"]
        now = store._iso()
        with store._lock:
            deferred = store.conn.execute(
                "SELECT deferred_reason AS reason, COUNT(*) AS n, MIN(next_attempt_at) AS next FROM hunt_candidates "
                "WHERE status='QUEUED' AND deferred_reason IS NOT NULL AND next_attempt_at>? GROUP BY deferred_reason ORDER BY n DESC LIMIT 20", (now,)).fetchall()
            failed = store.conn.execute("SELECT canonical, indicator_type, error_state, attempts FROM hunt_candidates WHERE status IN ('FAILED','RETRY') ORDER BY last_seen DESC LIMIT 20").fetchall()
        return {"queued": by["QUEUED"] - stats["deferred"], "stored_only": by["NEW"], "running": by["INVESTIGATING"], "completed": by["ENRICHED"] + by["SCORED"] + by["ESCALATED"],
                "failed": by["FAILED"], "retrying": by["RETRY"], "ignored": by["IGNORED"], "deferred": stats["deferred"],
                "deferred_reasons": [dict(r) for r in deferred], "recent_failures": [dict(r) for r in failed], "rejected_inputs": stats["rejected"],
                "by_status": by}

    @router.get("/providers")
    def providers():
        cfg, store, graph, _ = ctx()
        prefix = "schedule:last:"
        jobs = [{"job": k[len(prefix):], "last_run": v} for k, v in sorted(store.get_state(prefix).items())]
        return {"sources": source_coverage(store, cfg), "recent_runs": store.discovery_runs(30), "jobs": jobs}

    @router.get("/alerts")
    def alerts(limit: int = Query(50, ge=1, le=200), unacknowledged: bool = False):
        cfg, store, graph, _ = ctx()
        return {"items": AlertEngine(store, graph, cfg).list(limit, unacknowledged)}

    @router.post("/alerts/{alert_id}/ack")
    def ack(request: Request, alert_id: int, payload: dict = Body(default={})):
        durable()
        cfg, store, graph, _ = ctx()
        who, source = identity(request, str(payload.get("analyst", "")))
        if not who:
            raise HTTPException(400, "an analyst name is required")
        if not AlertEngine(store, graph, cfg).acknowledge(alert_id, f"{who} ({source})"):
            raise HTTPException(404, "alert not found or already acknowledged")
        return {"acknowledged": alert_id, "by": who, "identity_source": source}

    # ---------------------------------------------------------------------------------------- campaigns
    @router.get("/campaigns")
    def campaigns(limit: int = Query(50, ge=1, le=200)):
        cfg, store, graph, q = ctx()
        items = q.campaigns(limit)
        for c in items:
            c["members"] = c["members"][:50]
            c.pop("why_related", None)
        return {"items": items}

    @router.get("/campaigns/{campaign_id}")
    def campaign(campaign_id: str):
        cfg, store, graph, q = ctx()
        c = q.campaign(check_id(campaign_id))
        if c is None:
            raise HTTPException(404, "unknown campaign")
        c["dispositions"] = store.dispositions(campaign_id=c["id"])
        return c

    @router.get("/campaigns/{campaign_id}/graph")
    def campaign_graph(campaign_id: str):
        cfg, store, graph, q = ctx()
        g = q.subgraph(check_id(campaign_id))
        if not g["nodes"]:
            raise HTTPException(404, "unknown campaign")
        return g

    # ----------------------------------------------------------------------------------- dispositions
    def disposition_payload(request: Request, payload: dict) -> dict:
        d = str(payload.get("disposition", "")).upper()
        if d not in DISPOSITIONS:
            raise HTTPException(400, f"disposition must be one of: {', '.join(DISPOSITIONS)}")
        who, source = identity(request, str(payload.get("analyst", "")))
        if not who:
            raise HTTPException(400, "an analyst name is required")
        return {"disposition": d, "analyst": who, "identity_source": source, "reason": str(payload.get("reason", ""))[:2000],
                "notes": str(payload.get("notes", ""))[:4000]}

    @router.post("/candidates/{cid}/disposition")
    def set_disposition(request: Request, cid: str, payload: dict = Body(...)):
        durable()
        cfg, store, graph, _ = ctx()
        candidate_or_404(store, cid)
        body = disposition_payload(request, payload)
        try:
            return apply_disposition(store, graph, cfg, {b.name: b for b in cfg.brands}, candidate_id=cid, **body)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/campaigns/{campaign_id}/disposition")
    def set_campaign_disposition(request: Request, campaign_id: str, payload: dict = Body(...)):
        durable()
        cfg, store, graph, q = ctx()
        c = q.campaign(check_id(campaign_id))
        if c is None:
            raise HTTPException(404, "unknown campaign")
        body = disposition_payload(request, payload)
        try:
            return apply_disposition(store, graph, cfg, {b.name: b for b in cfg.brands}, campaign_id=c["id"], **body)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/insights")
    def get_insights():
        cfg, store, graph, _ = ctx()
        out = insights(store, graph, cfg)
        out["approved_trusted"] = store.admin_trusted()
        return out

    @router.post("/trusted-domains")
    def trust(request: Request, payload: dict = Body(...)):
        durable()
        cfg, store, graph, _ = ctx()
        who, source = identity(request, str(payload.get("analyst", "")))
        domain = str(payload.get("domain", "")).strip()
        if not who or not domain:
            raise HTTPException(400, "domain and an analyst name are required")
        try:
            return approve_trusted(store, graph, cfg, {b.name: b for b in cfg.brands}, domain, by=who, identity_source=source,
                                   reason=str(payload.get("reason", "")))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.delete("/trusted-domains/{domain}")
    def untrust(domain: str):
        durable()
        cfg, store, graph, _ = ctx()
        try:
            return remove_trusted(store, graph, cfg, {b.name: b for b in cfg.brands}, domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return router
