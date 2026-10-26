"""Web server for watchtower.

A sweep takes 30-60 seconds. Making someone watch a spinner for that long is a
design failure, so results stream: the browser opens an SSE connection and each
source reports in as it lands. The sweep itself runs in a worker thread and
pushes events onto a queue that the response generator drains.

    python run.py serve            # http://127.0.0.1:8000

Now with async support for fast OSINT discovery using watchtower_async module.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import queue
import secrets
import threading
from dataclasses import asdict
from pathlib import Path

import yaml
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from core import report
from core.enrich import Enricher
from core.fetch import Fetcher
from core.sources import (BACKEND_KEYS, BACKEND_REQUIREMENTS, BACKENDS,
                          DEFAULT_BACKENDS, RETIRED_BACKENDS, has_credentials)
from core.store import Store
from core.sweep import sweep
from investigation.storage import InvestigationStore

# The two tools stay independent of each other; only this layer knows about
# both. scamscan still imports nothing from core/, and core/ imports nothing
# from scamscan — a shared front door is not a shared engine, and the moment
# one starts reaching into the other's store or config that stops being true.
import scamscan

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"

# On a serverless host the deployment bundle is read-only and only /tmp can be
# written. The archive and the generated reports both write, so they have to
# move — but /tmp does not survive between invocations, so anything "saved"
# there is gone by the next request. That is a real limitation, not a detail:
# EPHEMERAL is surfaced through /api/sources so the UI can say so out loud
# rather than letting someone believe they have an archive they don't.
_EXPLICIT_DATA_DIR = os.environ.get("WATCHTOWER_DATA_DIR")
SERVERLESS = bool(
    os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
)
HOSTED = bool(
    SERVERLESS
    or os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("RENDER")
    or os.environ.get("K_SERVICE")
    or os.environ.get("FLY_APP_NAME")
    or os.environ.get("DYNO")
)


def _is_loopback_bind(value: str) -> bool:
    """Return whether a bind address is unquestionably local-only."""
    value = (value or "").strip().lower().strip("[]")
    if value in {"localhost", "localhost.localdomain", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        # Hostnames cannot be trusted to remain local (DNS can change), so an
        # unknown bind name is treated as public and requires authentication.
        return False


_EXPLICIT_AUTH = os.environ.get("WATCHTOWER_REQUIRE_AUTH", "").lower() in {
    "1", "true", "yes", "on"
}
# ``run.py`` records the requested bind address before importing this module.
# The middleware also checks the ASGI server address for callers that launch
# uvicorn directly.  Authentication must not depend on recognizing a hosting
# provider's brand-specific environment variable.
BIND_HOST = os.environ.get("WATCHTOWER_BIND_HOST", "")
REQUIRE_AUTH = HOSTED or _EXPLICIT_AUTH or (
    bool(BIND_HOST) and not _is_loopback_bind(BIND_HOST)
)
DATA_DIR = (
    Path(_EXPLICIT_DATA_DIR)
    if _EXPLICIT_DATA_DIR
    else (Path("/tmp/watchtower") if SERVERLESS else ROOT)
)
EPHEMERAL = SERVERLESS and not _EXPLICIT_DATA_DIR

# Wall-clock ceiling for an interactive sweep. A retrying source must not hold
# the browser open for a minute. Deep CLI research remains unbounded, and a
# deployment can raise this explicitly when coverage matters more than speed.
SWEEP_BUDGET = (
    float(os.environ.get("WATCHTOWER_SWEEP_BUDGET", "30"))
    or None
)

app = FastAPI(title="Mnara", docs_url="/api/docs")
# JSON and the 200KB of JS/CSS compress ~5x. Starlette's gzip leaves text/event-stream alone, so the live
# sweep trace is still delivered frame by frame.
app.add_middleware(GZipMiddleware, minimum_size=800)


def investigation_store() -> InvestigationStore:
    cfg = config()
    return InvestigationStore(
        data_path(cfg["storage"].get("investigations_database", "investigations.db"))
    )


_CONFIG_CACHE: dict = {}


def config() -> dict:
    """Parsed config.yaml, re-read only when the file changes (it was re-parsed on every request).
    Returned as a copy so a caller editing it cannot leak into the next request."""
    import copy
    from run import expand_env

    path = ROOT / "config.yaml"
    stamp = (path.stat().st_mtime_ns, tuple(sorted(os.environ.items())))
    hit = _CONFIG_CACHE.get("v")
    if hit is None or hit[0] != stamp:
        hit = _CONFIG_CACHE["v"] = (stamp, expand_env(yaml.safe_load(path.read_text(encoding="utf-8"))))
    return copy.deepcopy(hit[1])


def data_path(relative) -> Path:
    """Resolve a configured storage path against the writable data directory."""
    p = Path(relative)
    if p.is_absolute():
        return p
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / p


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ------------------------------------------------------------------ auth

WT_PASSWORD = os.environ.get("WATCHTOWER_PASSWORD", "")
WT_USER = os.environ.get("WATCHTOWER_USER", "watchtower")


def _request_requires_auth(request) -> bool:
    if REQUIRE_AUTH:
        return True
    configured = os.environ.get("WATCHTOWER_BIND_HOST", "")
    if configured:
        return not _is_loopback_bind(configured)
    # Uvicorn exposes its configured bind address in the ASGI scope.  This
    # catches direct ``uvicorn web.app:app --host 0.0.0.0`` launches too.
    server = request.scope.get("server") or ()
    server_host = server[0] if server else ""
    if server_host == "testserver" and request.client and request.client.host == "testclient":
        # Starlette's in-process TestClient is not a network listener.
        return False
    # An absent server address is not proof that the listener is local.
    return True if not server_host else not _is_loopback_bind(server_host)


@app.middleware("http")
async def require_password(request, call_next):
    """HTTP Basic, but only once the app is off localhost.

    Locally this is a no-op, because `python run.py serve` binding to 127.0.0.1
    with no password is the documented design and adding a login to it would be
    friction for nothing.

    On a public host it is the opposite: /api/sweep and /api/scamscan/hunt
    spend real money against whichever model key is set, so an unauthenticated
    public deployment is someone else's budget to burn — and the scamscan queue
    it exposes holds personal data scraped off live pages. With no password set we therefore fail *closed* and
    serve 503 rather than quietly exposing it — a deployment that refuses to
    work is recoverable, one that silently runs up a bill is not.
    """
    if request.url.path == "/api/healthz":
        return await call_next(request)

    if not _request_requires_auth(request):
        return await call_next(request)

    if not WT_PASSWORD:
        return JSONResponse(
            {
                "detail": "WATCHTOWER_PASSWORD is not set. Refusing to serve a "
                "public instance without authentication — /api/sweep "
                "and /api/scamscan/hunt spend real API credits and the "
                "review queue holds personal data. Set it in the host's "
                "environment variables and redeploy."
            },
            status_code=503,
        )

    supplied = request.headers.get("authorization", "")
    expected = "Basic " + base64.b64encode(f"{WT_USER}:{WT_PASSWORD}".encode()).decode()
    # Constant-time compare: a plain != leaks the password a byte at a time.
    if not secrets.compare_digest(supplied, expected):
        return JSONResponse(
            {"detail": "authentication required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="watchtower"'},
        )
    return await call_next(request)


@app.get("/api/healthz", include_in_schema=False)
def healthz():
    """Credential-free liveness only; exposes no configuration or data."""
    return {"status": "ok"}


# ------------------------------------------------------------------ meta


@app.get("/api/sources")
def list_sources():
    cfg = config()
    enricher = Enricher([], cfg.get("enrichment", {}).get("categories", []))
    from core.enrich import available_provider

    # `available` is about credentials actually being present, which is not the
    # same question as `default`. opensanctions is both a default and key-gated,
    # so keying the UI off `default` left it selected and silently returning
    # nothing — the worst possible failure for a sanctions check.
    from watchtower.discovery.providers import default_providers
    free_sources = [
        {
            "name": provider.name,
            "default": True,
            "needs_key": False,
            "available": True,
            "key_name": "",
            "capabilities": list(provider.capabilities()),
            "status": "configured",
            "detail": "No commercial API key required; verified when queried",
            "surface": "investigation",
        }
        for provider in default_providers()
    ]
    legacy = [
        {
            "name": n,
            "default": n in DEFAULT_BACKENDS,
            "needs_key": n in BACKEND_KEYS,
            "available": has_credentials(n),
            "key_name": ", ".join(BACKEND_REQUIREMENTS.get(n, (BACKEND_KEYS.get(n, ""),))),
            "surface": "monitor",
            "description": {
                "gdelt": "Global news and broadcasts with a short delay",
                "google_news": "Broad local and international news coverage",
                "wikipedia": "Entity background and disambiguation context",
                "hackernews": "Technology and fintech community discussions",
                "social_web_index": "Free public social links found through web indexing",
                "gleif": "Legal entity identifiers and ownership records",
                "sec_edgar": "US company filings and regulatory disclosures",
                "opensanctions": "Sanctions, PEP and watchlist records",
                "opencorporates": "Global company registry records",
                "reddit": "Subreddit search through the official Reddit API",
                "x": "Posts through X's official API (paid access)",
                "socialcrawl": "Cross-platform social discovery (paid credits)",
            }.get(n, "Public source adapter"),
        }
        for n in BACKENDS if n not in RETIRED_BACKENDS
    ]
    return {
        "sources": [
            *free_sources,
            *(item for item in legacy if item["name"] not in
              {source["name"] for source in free_sources}),
        ],
        "ai_available": enricher.enabled,
        "ai_provider": available_provider() or "none",
        "ephemeral_storage": EPHEMERAL,
        "zero_key_mode": not any(os.environ.get(key) for key in BACKEND_KEYS.values()),
    }


@app.get("/api/system/health")
def system_health():
    """Capability report: configuration is not misrepresented as live health."""
    from core.enrich import available_provider

    def configured(key: str) -> bool:
        return bool(os.environ.get(key))

    sources = {
        "reddit": {
            "configured": configured("REDDIT_CLIENT_ID")
            and configured("REDDIT_CLIENT_SECRET"),
            "status": "degraded"
            if configured("REDDIT_CLIENT_ID") and configured("REDDIT_CLIENT_SECRET")
            else "missing_credentials",
        },
        "x": {
            "configured": configured("X_BEARER_TOKEN"),
            "status": "degraded"
            if configured("X_BEARER_TOKEN")
            else "subscription_limited",
        },
        "tiktok": {
            "configured": configured("TIKTOK_ACCESS_TOKEN"),
            "status": "direct_api"
            if configured("TIKTOK_ACCESS_TOKEN")
            else "web_index_only",
            "detail": "Public index discovery only; direct crawling is not attempted",
        },
        "duckduckgo": {
            "configured": True,
            "status": "degraded",
            "detail": "unauthenticated provider; verified per investigation",
        },
    }
    store = investigation_store()
    try:
        latest = store.conn.execute(
            """SELECT sr.*,
               (SELECT MAX(ok.completed_at) FROM source_runs ok
                WHERE ok.source=sr.source AND ok.status='operational') AS last_ok
               FROM source_runs sr JOIN (
               SELECT source,MAX(id) AS max_id FROM source_runs GROUP BY source
               ) newest ON newest.max_id=sr.id"""
        ).fetchall()
    finally:
        store.conn.close()
    from watchtower.discovery.providers import default_providers
    for provider in default_providers():
        sources[provider.name] = {
            "configured": True,
            "status": "configured",
            "detail": "No key required; live availability not yet checked",
            "capabilities": list(provider.capabilities()),
        }
    for row in latest:
        sources[row["source"]] = {
            **sources.get(row["source"], {}),
            "configured": True,
            "status": row["status"],
            "last_attempt": row["started_at"],
            "last_success": row["last_ok"],
            "results": row["results_returned"],
            "error": row["error_message"],
        }
    return {
        "storage": {
            "persistent": not EPHEMERAL,
            "status": "operational" if not EPHEMERAL else "limited",
            "backend": "sqlite",
        },
        "model": {
            "provider": available_provider() or "none",
            "status": "degraded" if available_provider() else "missing_credentials",
            "detail": "verified when scoring runs",
        },
        "sources": sources,
        "analyst_verdicts": {"enabled": not EPHEMERAL},
    }


@app.post("/api/investigations")
async def create_investigation(payload: dict = Body(...)):
    brand = str(payload.get("brand", "")).strip()
    if not 2 <= len(brand) <= 100:
        raise HTTPException(400, "brand must be between 2 and 100 characters")
    try:
        requested_limit = int(payload.get("limit", 20))
    except (TypeError, ValueError):
        raise HTTPException(400, "limit must be a number")
    requested_limit = max(1, min(requested_limit, 75))
    from watchtower.discovery.cache import ProviderCache
    from watchtower.discovery.orchestrator import DiscoveryOrchestrator
    from watchtower.discovery.providers import default_providers
    from watchtower.discovery.safe_fetch import SafeFetcher

    store = investigation_store()
    try:
        scam_cfg = scamscan_config()
        configured_brand = scam_cfg.get("brand", {})
        configured_terms = {
            configured_brand.get("name", "").lower(),
            *(str(x).lower() for x in configured_brand.get("aliases", [])),
            *(str(x).lower() for x in configured_brand.get("products", [])),
        }
        # Product/campaign searches such as ``Fuliza Increase`` should inherit
        # the configured M-PESA profile instead of becoming an isolated brand
        # with no aliases. This preserves the parent brand context while
        # keeping unrelated financial institutions out of the query.
        brand_lower = brand.lower()
        matched_terms = [term for term in configured_terms
                         if term and (term in brand_lower or brand_lower in term)]
        if not matched_terms:
            configured_brand = {
                "name": brand, "aliases": [brand], "official_domains": [],
                "products": [], "related_organizations": [],
            }
        else:
            configured_brand = dict(configured_brand)
            configured_brand["aliases"] = list(dict.fromkeys([
                *configured_brand.get("aliases", []),
                *configured_brand.get("products", []),
                *matched_terms,
                brand,
            ]))
        inv_cfg = config().get("investigation", {})
        cache = ProviderCache(data_path("provider-cache.db"))
        engine = DiscoveryOrchestrator(
            store,
            default_providers(cache),
            fetcher=SafeFetcher(cache=cache),
            max_domains=min(requested_limit, int(inv_cfg.get("max_domains", 40))),
            max_fetches=int(inv_cfg.get("max_page_fetches", 20)),
            max_pivot_depth=int(inv_cfg.get("max_pivot_depth", 2)),
            max_global_requests=int(inv_cfg.get("max_global_requests", 8)),
            max_external_requests=int(inv_cfg.get("max_external_requests", 500)),
        )
        return await engine.investigate(
            brand, str(payload.get("query") or brand), configured_brand
        )
    finally:
        store.conn.close()


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    store = investigation_store()
    try:
        row = store.get("investigations", investigation_id)
        runs = store.source_runs(investigation_id) if row else []
    finally:
        store.conn.close()
    if not row:
        raise HTTPException(404, "investigation not found")
    for key in (
        "requested_sources",
        "successful_sources",
        "limited_sources",
        "failed_sources",
        "unavailable_sources",
        "config_snapshot",
    ):
        if row.get(key):
            row[key] = json.loads(row[key])
    row["source_runs"] = runs
    row["zero_key_mode"] = not any(os.environ.get(key) for key in BACKEND_KEYS.values())
    return row


@app.get("/api/investigations/{investigation_id}/graph")
def get_investigation_graph(investigation_id: str):
    store = investigation_store()
    try:
        if not store.get("investigations", investigation_id):
            raise HTTPException(404, "investigation not found")
        return store.graph(investigation_id)
    finally:
        store.conn.close()


@app.get("/api/entities/{entity_id}")
def get_entity(entity_id: str):
    store = investigation_store()
    try:
        row = store.get("entities", entity_id)
    finally:
        store.conn.close()
    if not row:
        raise HTTPException(404, "entity not found")
    row["metadata"] = json.loads(row.get("metadata") or "{}")
    return row


@app.get("/api/campaigns/{campaign_id}")
def get_campaign(campaign_id: str):
    store = investigation_store()
    try:
        row = store.get("campaigns", campaign_id)
        if not row:
            raise HTTPException(404, "campaign not found")
        row["entities"] = [
            dict(r)
            for r in store.conn.execute(
                "SELECT e.*,ce.relationship_strength FROM campaign_entities ce JOIN entities e ON e.id=ce.entity_id WHERE ce.campaign_id=?",
                (campaign_id,),
            )
        ]
        return row
    finally:
        store.conn.close()


@app.get("/api/entities/{entity_id}/evidence")
def get_entity_evidence(entity_id: str):
    store = investigation_store()
    try:
        return {
            "evidence": [
                dict(r)
                for r in store.conn.execute(
                    "SELECT * FROM evidence WHERE entity_id=? ORDER BY observed_at",
                    (entity_id,),
                )
            ]
        }
    finally:
        store.conn.close()


@app.post("/api/entities/{entity_id}/verdict")
def submit_verdict(entity_id: str, payload: dict = Body(...)):
    if EPHEMERAL:
        raise HTTPException(
            409, "analyst verdicts require durable storage; set WATCHTOWER_DATA_DIR"
        )
    store = investigation_store()
    try:
        if not store.get("entities", entity_id):
            raise HTTPException(404, "entity not found")
        try:
            return store.verdict(
                entity_id,
                str(payload.get("verdict", "")),
                str(payload.get("comment", ""))[:2000],
                str(payload.get("analyst_identifier", "analyst"))[:100],
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    finally:
        store.conn.close()


@app.get("/api/stats")
def stats():
    cfg = config()
    store = Store(data_path(cfg["storage"]["database"]))
    try:
        return store.stats()
    finally:
        store.close()


# ----------------------------------------------------------------- sweep


@app.get("/api/sweep")
def run_sweep(
    q: str = Query(..., min_length=2, max_length=200),
    hours: int = Query(72, ge=1, le=8760),
    sources: str = Query(""),
    use_ai: bool = Query(True),
    fetch_bodies: bool = Query(True),
    save: bool = Query(False),
    limit: int = Query(40, ge=1, le=250),
    max_ai: int = Query(25, ge=0, le=100),
):
    if save and EPHEMERAL:
        raise HTTPException(
            409, "saved results require durable storage; set WATCHTOWER_DATA_DIR"
        )
    cfg = config()
    backends = [s.strip() for s in sources.split(",") if s.strip()] or DEFAULT_BACKENDS
    unknown = [b for b in backends if b not in BACKENDS]
    if unknown:
        raise HTTPException(400, f"unknown source(s): {', '.join(unknown)}")

    events: queue.Queue = queue.Queue()
    holder: dict = {}

    def work():
        fetcher = None
        try:
            f = cfg["fetch"]
            fetcher = Fetcher(
                user_agent=f["user_agent"],
                delay=f.get("delay_seconds", 2.0),
                timeout=f.get("timeout_seconds", 20),
                obey_robots=f.get("obey_robots", True),
            )
            ec = cfg.get("enrichment", {})
            enricher = None
            if use_ai:
                enricher = Enricher(
                    watchlist=cfg.get("alerts", {}).get("watchlist", []),
                    categories=ec.get("categories", []),
                    escalate_above=ec.get("escalate_above", 60),
                )
            result = sweep(
                q,
                fetcher,
                hours=hours,
                backends=backends,
                limit=limit,
                fetch_bodies=fetch_bodies,
                enricher=enricher,
                max_enrich=max_ai,
                budget=SWEEP_BUDGET,
                # Do not discard a paid call after it starts. Only this future
                # may exceed the deadline; all other work remains bounded.
                protected_backends={"socialcrawl"} & set(backends),
                progress=events.put,
            )
            holder["result"] = result
        except Exception as e:
            holder["error"] = f"{type(e).__name__}: {e}"
        finally:
            if fetcher:
                fetcher.close()
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        yield _sse("start", {"query": q, "sources": backends, "hours": hours})
        while True:
            event = events.get()
            if event is None:
                break
            yield _sse(event.get("type", "progress"), event)

        if "error" in holder:
            yield _sse("failed", {"message": holder["error"]})
            return

        result = holder["result"]
        payload = {
            "query": result.query,
            "enriched": result.enriched,
            "per_source": result.per_source,
            "entities": [{"name": n, "count": c} for n, c in result.entities],
            "errors": result.errors,
            # The frontend needs to tell "searched, found nothing" apart from
            # "could not search" — rendering those the same way is the bug.
            "failed": result.failed,
            "skipped": result.skipped,
            "complete": result.complete,
            "scoring_error": result.scoring_error,
            "items": [
                {**asdict(i), "band": report.band(i.relevance), "text": i.text[:600]}
                for i in result.items
            ],
        }

        if result.items:
            out_dir = data_path(cfg["storage"].get("output_dir", "out"))
            payload["report"] = report.save(result, out_dir).name
            payload["report_html"] = Path(payload["report"]).with_suffix(".html").name
            if save:
                store = Store(data_path(cfg["storage"]["database"]))
                payload["saved"] = store.add(result.items)
                store.close()

        yield _sse("done", payload)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --------------------------------------------------------------- archive


@app.get("/api/archive")
def archive(q: str = Query(..., min_length=1), limit: int = Query(30, le=100)):
    cfg = config()
    store = Store(data_path(cfg["storage"]["database"]))
    try:
        rows = store.search(q, limit=limit)
    except Exception as e:
        # FTS5 rejects malformed match syntax; say so rather than 500ing.
        raise HTTPException(400, f"invalid search syntax: {e}")
    finally:
        store.close()
    return {
        "items": [
            {
                "title": r["title"],
                "url": r["url"],
                "source": r["source"],
                "summary": r["summary"],
                "relevance": r["relevance"],
                "band": report.band(r["relevance"]),
                "published_at": r["published_at"],
            }
            for r in rows
        ]
    }


# -------------------------------------------------------------- scamscan

SCAMSCAN_CONFIG = ROOT / "config.json"


def scamscan_config() -> dict:
    try:
        return json.loads(SCAMSCAN_CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HTTPException(503, "config.json is missing — scamscan is not configured")
    except json.JSONDecodeError as e:
        raise HTTPException(503, f"config.json is not valid JSON: {e}")


def scam_band(score, cfg) -> str:
    """Map a score onto the shared relevance ramp.

    The thresholds already mean something — review_threshold is "an analyst
    should look", auto_escalate_threshold is "look now" — so the colour carries
    the same meaning it does on the watchtower side rather than being decoration.
    """
    sc = cfg["scoring"]
    if score >= sc["auto_escalate_threshold"]:
        return "HIGH"
    if score >= sc["review_threshold"]:
        return "MED"
    if score >= sc["review_threshold"] / 2:
        return "LOW"
    return "WEAK"


@app.get("/api/scamscan/status")
def scamscan_status():
    cfg = scamscan_config()
    _, tool_note = scamscan.web_search_tool(cfg)
    lex = cfg["lexicon"]
    unverified = sum(
        1
        for group in lex.values()
        for entry in group.values()
        if scamscan.term_weight(entry)[1] in ("", "UNVERIFIED")
    )
    which = scamscan.provider(cfg)
    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        rows = dict(
            con.execute(
                "SELECT disposition, COUNT(*) FROM findings GROUP BY disposition"
            ).fetchall()
        )
    finally:
        con.close()
    return {
        "brand": cfg["brand"]["name"],
        "topics": len(cfg["seed_topics"]),
        "queries_per_topic": cfg["search"]["queries_per_topic"],
        "max_uses_per_query": cfg["search"]["max_uses_per_query"],
        "provider": which or "none",
        "model": scamscan.model_for(cfg),
        "search_tool": tool_note,
        "structured_outputs": bool(cfg["search"].get("structured_outputs", True)),
        "review_threshold": cfg["scoring"]["review_threshold"],
        "escalate_threshold": cfg["scoring"]["auto_escalate_threshold"],
        "lexicon_terms": sum(len(g) for g in lex.values()),
        "counter_terms": len(cfg.get("counter_terms", {})),
        "unverified_terms": unverified,
        # hunt spends money; the UI disables the button rather than letting
        # someone click it and read a 500 as "no scams found".
        "api_available": bool(which and scamscan.provider_key(which)),
        "ephemeral_storage": EPHEMERAL,
        "queue": rows,
        "total": sum(rows.values()),
    }


@app.get("/api/scamscan/queue")
def scamscan_queue(
    min_score: float = Query(0, ge=0, le=100),
    disposition: str = Query("new"),
    limit: int = Query(50, ge=1, le=200),
):
    cfg = scamscan_config()
    allowed = {"new", "confirmed", "false_positive", "unclear", "escalated", "all"}
    if disposition not in allowed:
        raise HTTPException(400, f"disposition must be one of {sorted(allowed)}")

    sql = (
        "SELECT fingerprint, score, scam_type, url, title, summary, evidence, "
        "times_seen, disposition, analyst_note, first_seen, last_seen, breakdown "
        "FROM findings WHERE score >= ?"
    )
    params = [min_score]
    if disposition != "all":
        sql += " AND disposition = ?"
        params.append(disposition)
    sql += " ORDER BY score DESC LIMIT ?"
    params.append(limit)

    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()

    items = []
    for (
        fp,
        score,
        stype,
        url,
        title,
        summary,
        evidence,
        seen,
        disp,
        note,
        first,
        last,
        breakdown,
    ) in rows:
        try:
            detail = json.loads(breakdown or "{}")
        except json.JSONDecodeError:
            detail = {}
        items.append(
            {
                "fingerprint": fp,
                "score": score,
                "band": scam_band(score or 0, cfg),
                "scam_type": stype,
                "url": url,
                "title": title,
                "summary": summary,
                "evidence": evidence,
                "times_seen": seen,
                "disposition": disp,
                "analyst_note": note,
                "first_seen": first,
                "last_seen": last,
                "breakdown": detail,
            }
        )
    return {"items": items, "ephemeral_storage": EPHEMERAL}


@app.post("/api/scamscan/dispose")
def scamscan_dispose(payload: dict = Body(...)):
    if EPHEMERAL:
        raise HTTPException(
            409, "analyst verdicts require durable storage; set WATCHTOWER_DATA_DIR"
        )
    verdicts = {"confirmed", "false_positive", "unclear", "escalated", "new"}
    fingerprint = str(payload.get("fingerprint", "")).strip()
    verdict = str(payload.get("verdict", "")).strip()
    note = str(payload.get("note", ""))[:2000]
    if not fingerprint:
        raise HTTPException(400, "fingerprint is required")
    if verdict not in verdicts:
        raise HTTPException(400, f"verdict must be one of {sorted(verdicts)}")

    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        cur = con.execute(
            "UPDATE findings SET disposition=?, analyst_note=? WHERE fingerprint=?",
            (verdict, note, fingerprint),
        )
        con.commit()
        if not cur.rowcount:
            raise HTTPException(404, "no finding with that fingerprint")
    finally:
        con.close()
    return {"fingerprint": fingerprint, "verdict": verdict, "note": note}


@app.post("/api/scamscan/score")
def scamscan_score(payload: dict = Body(...)):
    """Score pasted text with no API call at all — the `test` command, in a page.

    Free and deterministic, which makes it the right place to tune weights and
    to see why a page scored what it did before spending anything on a hunt.
    """
    cfg = scamscan_config()
    text = str(payload.get("text", ""))[:20000]
    url = str(payload.get("url", ""))[:2000]
    if not text.strip() and not url.strip():
        raise HTTPException(400, "give it some text or a URL to score")

    finding = {"url": url, "title": "", "summary": text, "quoted_evidence": text}
    raw = payload.get("model_confidence")
    if raw not in (None, ""):
        finding["model_confidence"] = raw

    scored = scamscan.score_finding(finding, cfg)
    return {
        **scored,
        "band": scam_band(scored["score"], cfg),
        "review_threshold": cfg["scoring"]["review_threshold"],
        "escalate_threshold": cfg["scoring"]["auto_escalate_threshold"],
    }


@app.get("/api/scamscan/hunt")
def scamscan_hunt(topics: int = Query(1, ge=1, le=20),
                  dry_run: bool = Query(False)):
    """Run a discovery pass, streaming the same progress dicts the CLI prints.

    Costs real money per query — web search is billed separately from tokens —
    so `topics` is capped and the UI states the ceiling before you click.
    `dry_run=true` expands and streams the planned queries without searching,
    saving findings, or spending search credits.
    """
    if EPHEMERAL and not dry_run:
        raise HTTPException(
            409, "hunts require durable storage so findings and verdicts are retained"
        )
    cfg = scamscan_config()
    which = scamscan.provider(cfg)
    if not which:
        raise HTTPException(
            503,
            "No model API key — set GEMINI_API_KEY (free tier) or ANTHROPIC_API_KEY",
        )

    events: queue.Queue = queue.Queue()
    holder: dict = {}

    def work():
        con = None
        try:
            # A plan-only run must not create or mutate the persistent queue,
            # including on ephemeral deployments where the disk is temporary.
            con = scamscan.db_connect(":memory:" if dry_run
                                      else str(data_path("scamscan.db")))
            holder["summary"] = scamscan.hunt(
                scamscan.make_client(which), cfg, con, topics, events.put,
                dry_run=dry_run,
            )
        except Exception as e:
            holder["error"] = f"{type(e).__name__}: {e}"
        finally:
            if con:
                con.close()
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            event = events.get()
            if event is None:
                break
            # `done` is emitted by hunt() itself; hold it back so the browser
            # only ever sees one terminal frame, from whichever path ends first.
            if event.get("type") == "done":
                holder.setdefault("summary", event)
                continue
            yield _sse(event.get("type", "progress"), event)

        if "error" in holder:
            yield _sse("failed", {"message": holder["error"]})
            return
        summary = dict(holder.get("summary", {}))
        summary["ephemeral_storage"] = EPHEMERAL
        yield _sse("done", summary)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/scan")
def scan_url(payload: dict = Body(...)):
    """Scan a single URL and return structured results for the new UI."""
    import osint_discovery

    url = str(payload.get("url", "")).strip()
    if not url:
        raise HTTPException(400, "URL is required")
    # Accept the form users actually paste (example.com) while keeping the
    # scanner contract explicit for direct API callers as well.
    from urllib.parse import urlparse
    if "://" not in url:
        url = f"https://{url}"
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise HTTPException(422, "Enter a valid public http:// or https:// URL")

    cfg = scamscan_config()

    def _compute_confidence(scored: dict) -> float:
        """Compute confidence based on evidence completeness."""
        signals_present = 0
        total_signals = 5

        if scored.get("lexicon_score", 0) > 0:
            signals_present += 1
        if scored.get("impersonation_score", 0) > 0:
            signals_present += 1
        if scored.get("artifact_score", 0) > 0:
            signals_present += 1
        if scored.get("model_score") is not None:
            signals_present += 1

        # Infrastructure flags count as evidence
        infra = scored.get("infrastructure_flags", {})
        if infra:
            signals_present += 0.5

        # Base confidence from signal coverage
        base_conf = signals_present / total_signals

        # Boost confidence when strong signals are present
        imp_score = scored.get("impersonation_score", 0)
        if imp_score >= 70:
            base_conf = max(base_conf, 0.8)  # High confidence in strong impersonation

        return min(1.0, base_conf)

    # Fetch and analyze the URL using existing scamscan logic
    try:
        finding = osint_discovery.fetch_and_analyze_url(url, cfg)

        fetch_error = str(finding.get("summary", ""))
        if fetch_error.startswith("Error fetching URL:"):
            raise HTTPException(422, fetch_error.removeprefix("Error fetching URL: "))

        # Check for official domain (INSTANT SAFE)
        if finding.get("_is_official"):
            return {
                "url": url,
                "score": 0,
                "classification": "SAFE",
                "verdict": "VERIFIED_OFFICIAL",
                "findings": [
                    f"Verified official domain ({finding.get('_official_domain')})"
                ],
                "breakdown": {"official_domain": finding.get("_official_domain")},
            }

        # Check for smoking gun (INSTANT SCAM)
        if finding.get("_smoking_gun"):
            return {
                "url": url,
                "score": 100,
                "classification": "ADVANCE_FEE_SCAM",
                "verdict": "CONFIRMED_SCAM",
                "findings": [finding["_smoking_gun_reason"]],
                "breakdown": {"smoking_gun": True},
            }

        # Score the finding normally if no override
        scored = scamscan.score_finding(finding, cfg)

        # Format findings list with explainable evidence
        findings_list = []
        if scored.get("lexicon_score", 0) > 0:
            findings_list.append(f"Lexicon match: +{scored['lexicon_score']} points")
        if scored.get("impersonation_score", 0) > 0:
            findings_list.append(
                f"Impersonation detected: +{scored['impersonation_score']} points"
            )
        if scored.get("artifact_score", 0) > 0:
            findings_list.append(
                f"Suspicious artifacts: +{scored['artifact_score']} points"
            )

        # Add infrastructure flags as evidence
        infra_flags = scored.get("infrastructure_flags", {})
        if infra_flags.get("on_free_host"):
            findings_list.append(
                "Hosted on free platform commonly used for scams (Vercel/Netlify/etc)"
            )

        # Add specific evidence
        if finding.get("quoted_evidence"):
            evidence_text = finding["quoted_evidence"][:500]
            if evidence_text:
                findings_list.append(f"Evidence: {evidence_text}")

        # Add impersonation reason
        if scored.get("impersonation_reason"):
            findings_list.append(f"Why: {scored['impersonation_reason']}")

        # Determine verdict based on score with improved thresholds
        # Using evidence-based categories instead of simple thresholds
        score = scored["score"]
        imp_score = scored.get("impersonation_score", 0)

        # Verdict logic based on evidence strength
        if score >= 80 or imp_score >= 85:
            verdict = "HIGH_RISK"
            classification = "Brand Impersonation / Advance Fee Scam"
        elif score >= 60 or imp_score >= 70:
            verdict = "SUSPICIOUS"
            classification = "Suspected Brand Impersonation"
        elif score >= 40:
            verdict = "SUSPICIOUS"
            classification = scored.get("scam_type", "Suspicious Activity")
        elif score >= 20:
            verdict = "LOW_RISK"
            classification = "Low Risk Indicators"
        else:
            verdict = "UNKNOWN"
            classification = "Insufficient Evidence"

        return {
            "url": url,
            "score": score,
            "classification": classification,
            "verdict": verdict,
            "findings": findings_list,
            "breakdown": scored,
            "confidence": _compute_confidence(scored),  # Add confidence metric
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {str(e)}")


@app.post("/api/discover")
def discover_scams(payload: dict = Body(...)):
    """OSINT discovery endpoint for hunting scam sites - uses proven DuckDuckGo search."""
    import osint_discovery

    brand = str(payload.get("brand", "fuliza")).strip().lower()
    if len(brand) < 2 or len(brand) > 80:
        raise HTTPException(400, "brand must be between 2 and 80 characters")
    try:
        limit = int(payload.get("limit", 10))
    except (TypeError, ValueError):
        raise HTTPException(400, "limit must be a number")
    limit = max(1, min(limit, 20))  # Cap between 1-20

    cfg = scamscan_config()

    try:
        # Use the proven OSINT discovery module with DuckDuckGo
        results = osint_discovery.discover_and_score(brand, limit, cfg)

        # Format results for UI with enhanced data
        formatted_results = []
        review = cfg.get("scoring", {}).get("review_threshold", 45)
        escalate = cfg.get("scoring", {}).get("auto_escalate_threshold", 80)
        for item in results:
            score = item.get("score", 0)
            if score >= escalate:
                classification = "High risk"
            elif score >= review:
                classification = "Needs review"
            else:
                classification = "Weak signal"
            formatted_results.append(
                {
                    "url": item.get("url", ""),
                    "brand": brand,
                    "score": score,
                    "classification": classification,
                    "title": item.get("title", ""),
                    "summary": item.get("summary", ""),
                    "source": item.get("source", "duckduckgo"),
                    "findings": [
                        f"Score: {score:.1f}/100",
                        f"Found via: {item.get('source', 'search')}",
                    ],
                    "breakdown": item.get("breakdown", {}),
                }
            )

        return {
            "results": formatted_results,
            "count": len(formatted_results),
            "method": "duckduckgo_search",
        }

    except Exception as e:
        logger.error(f"Discovery error: {e}")
        raise HTTPException(500, f"Discovery failed: {str(e)}")


@app.post("/api/discover_async")
async def discover_scams_experimental(payload: dict = Body(...)):
    """Experimental async OSINT discovery - faster but may be blocked by search engines."""
    import watchtower_async

    brand = str(payload.get("brand", "fuliza")).strip().lower()
    limit = int(payload.get("limit", 10))
    timeout = int(payload.get("timeout", 20))

    cfg = scamscan_config()

    try:
        wt_config = {
            "brand_aliases": cfg.get("brand", {}).get("aliases", [brand]),
            "suspicious_keywords": list(
                cfg.get("lexicon", {}).get("advance_fee_scam", {}).keys()
            )[:3],
            "free_hosting_domains": [
                "vercel.app",
                "netlify.app",
                "firebaseapp.com",
                "github.io",
            ],
        }

        engine = watchtower_async.WatchtowerEngine(wt_config)
        raw_results = await engine.run_sweep(
            max_results=limit * 2, timeout_seconds=timeout
        )

        # Score discovered URLs
        scored_results = []
        for item in raw_results.get("results", []):
            url = item.get("url", "")
            if not url:
                continue
            scored_results.append(
                {
                    "url": url,
                    "brand": brand,
                    "score": item.get("confidence", 0) * 100,
                    "title": item.get("title", ""),
                    "source": item.get("source", "unknown"),
                    "confidence": item.get("confidence", 0),
                }
            )

        scored_results.sort(key=lambda x: x["score"], reverse=True)

        return {
            "results": scored_results[:limit],
            "count": len(scored_results[:limit]),
            "time_taken": raw_results.get("time_taken", 0),
            "method": "async_multi_source",
        }

    except Exception as e:
        logger.error(f"Async discovery error: {e}")
        raise HTTPException(500, f"Discovery failed: {str(e)}")


@app.get("/api/report/{name}")
def get_report(name: str):
    cfg = config()
    out_dir = data_path(cfg["storage"].get("output_dir", "out")).resolve()
    path = (out_dir / name).resolve()
    # Contain path traversal: the resolved path must stay inside out_dir.
    if (path == out_dir or out_dir not in path.parents or not path.is_file()
            or path.suffix.lower() not in {".md", ".html"}):
        raise HTTPException(404, "report not found")
    media_type = "text/html" if path.suffix.lower() == ".html" else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=name)


_HUNTER_CFG: dict = {}


def _hunter_config():
    """hunter.yaml, parsed once per edit. Config objects are never mutated, so sharing one is safe."""
    from hunter.config import load as load_hunter_config
    path = ROOT / "hunter.yaml"
    stamp = path.stat().st_mtime_ns
    if _HUNTER_CFG.get("stamp") != stamp:
        _HUNTER_CFG.update(stamp=stamp, cfg=load_hunter_config(path))
    return _HUNTER_CFG["cfg"]


def _analyst_identity(request: Request, claimed: str) -> tuple[str, str]:
    """Who is acting. With auth on, the authenticated account; otherwise the name typed in, labelled as such."""
    if _request_requires_auth(request):
        return WT_USER, "authenticated"
    return (claimed or "").strip()[:100], "self_asserted"


from web.hunter_routes import build_router  # noqa: E402  (kept next to the mount: routes must precede it)

app.include_router(build_router(lambda: data_path("hunter.db"), _hunter_config, _analyst_identity, lambda: EPHEMERAL))

class _RevalidatingStatic(StaticFiles):
    """Static files carry an ETag already; `no-cache` makes the browser revalidate (a 304, no body) instead of
    guessing a freshness window, so edits still show immediately and repeat loads cost almost nothing."""

    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        resp.headers.setdefault("Cache-Control", "no-cache")
        return resp


app.mount("/", _RevalidatingStatic(directory=STATIC, html=True), name="static")
