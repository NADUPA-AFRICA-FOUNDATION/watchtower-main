"""Web layer test. Real FastAPI app, real SSE code path, mocked network.

Runs the actual endpoints through Starlette's TestClient with the same canned
responses sweep_test.py uses. Verifies the SSE event contract the frontend
depends on, which is the part most likely to break silently: rename an event
and the browser just sits there showing nothing.

    python web_test.py
"""

import json
import os
import shutil
import sys
import warnings

warnings.filterwarnings("ignore")
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient

# Same reason as scamscan_test: the app now imports scamscan, which loads .env,
# so pin the provider or the assertions below depend on whose keys are present.
os.environ["SCAMSCAN_PROVIDER"] = "anthropic"
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-used-offline")

import web.app as webapp
from core.fetch import Fetcher
from sweep_test import handler

# Swap the network out from under the app. Everything else is the real thing.
webapp.Fetcher = lambda **kw: Fetcher(
    **{**kw, "delay": 0.0}, transport=httpx.MockTransport(handler))

client = TestClient(webapp.app)


def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    return bool(cond)


def parse_sse(text):
    """Turn a raw SSE body into [(event, data), ...]."""
    events = []
    name, data = None, None
    for line in text.splitlines():
        if line.startswith("event: "):
            name = line[7:]
        elif line.startswith("data: "):
            data = json.loads(line[6:])
        elif not line.strip() and name:
            events.append((name, data))
            name, data = None, None
    if name:
        events.append((name, data))
    return events


def main():
    ok = True

    print("\nstatic and meta")
    r = client.get("/")
    ok &= check("index serves", r.status_code == 200 and "Mnara" in r.text)
    ok &= check("stylesheet serves", client.get("/style.css").status_code == 200)
    ok &= check("script serves", client.get("/app.js").status_code == 200)
    ok &= check("OpenSanctions has a visible screening section",
                'id="sanctions-section"' in r.text
                and 'id="sanctions-source"' in r.text)
    ok &= check("site discovery is a first-class view",
                'data-view="discover"' in r.text
                and 'id="discover-form"' in r.text
                and 'id="discover-results"' in r.text)
    ok &= check("live URL scanning is available from the UI",
                'id="scan-form"' in r.text and 'id="scan-url"' in r.text)
    ok &= check("investigation evidence has an accessible detail surface",
                'id="detail-dialog"' in r.text
                and 'aria-labelledby="detail-title"' in r.text)
    ok &= check("archive metrics are visible",
                all(f'id="stat-{key}"' in r.text
                    for key in ("total", "enriched", "unalerted", "sources")))

    r = client.get("/api/sources")
    body = r.json()
    # Compare against the registry, not a hardcoded number — the last count
    # here drifted silently and told us 33 checks when there were 36.
    from core.sources import BACKENDS, DEFAULT_BACKENDS, RETIRED_BACKENDS
    names = {source["name"] for source in body["sources"]}
    ok &= check("lists every active backend",
                (set(BACKENDS) - set(RETIRED_BACKENDS)) <= names
                and not (set(RETIRED_BACKENDS) & names))
    ok &= check("marks defaults", all(
        next(source for source in body["sources"] if source["name"] == name)["default"]
        for name in DEFAULT_BACKENDS
    ))
    ok &= check("lists the free investigation providers",
                {"certificate_transparency", "common_crawl", "rdap", "dns",
                 "tls", "urlhaus", "threatfox"} <= names)
    ok &= check("every key-gated source names its key",
                all(s["key_name"] for s in body["sources"] if s["needs_key"]))
    ok &= check("flags the one needing a key",
                any(s["needs_key"] for s in body["sources"]))
    # A key-gated source that is also a default used to ship selected and dead.
    # `available` is what the UI must gate on.
    osrc = next(s for s in body["sources"] if s["name"] == "opensanctions")
    ok &= check("a key-gated source reports whether the key is actually set",
                osrc["available"] == bool(os.environ.get("OPENSANCTIONS_API_KEY")))
    ok &= check("and names the key it wants",
                osrc["key_name"] == "OPENSANCTIONS_API_KEY")
    ok &= check("reports whether scoring is available",
                isinstance(body["ai_available"], bool))
    ok &= check("stats respond", client.get("/api/stats").status_code == 200)

    print("\nvalidation")
    ok &= check("rejects unknown source",
                client.get("/api/sweep?q=test&sources=bogus").status_code == 400)
    ok &= check("rejects a too-short query",
                client.get("/api/sweep?q=a").status_code == 422)
    ok &= check("rejects an absurd window",
                client.get("/api/sweep?q=test&hours=999999").status_code == 422)
    ok &= check("discovery rejects an empty brand",
                client.post("/api/discover", json={"brand": ""}).status_code == 400)
    ok &= check("discovery rejects a malformed limit",
                client.post("/api/discover",
                            json={"brand": "fuliza", "limit": "many"}).status_code == 400)
    scan = client.post("/api/scan", json={"url": "http://127.0.0.1/private"})
    ok &= check("live scan rejects private-network targets", scan.status_code == 422)
    ok &= check("blocks path traversal on reports",
                client.get("/api/report/../config.yaml").status_code == 404)
    r = client.get("/api/archive?q=AND OR")
    ok &= check("bad search syntax returns 400, not 500", r.status_code == 400)
    ok &= check("and explains itself", "syntax" in r.json()["detail"].lower())

    print("\nsweep over SSE")
    r = client.get("/api/sweep?q=beneficial ownership Kenya&hours=72"
                   "&sources=gdelt,google_news,wikipedia&use_ai=false")
    ok &= check("streams as event-stream",
                "text/event-stream" in r.headers["content-type"])
    ok &= check("disables proxy buffering",
                r.headers.get("x-accel-buffering") == "no")

    events = parse_sse(r.text)
    names = [n for n, _ in events]
    ok &= check("opens with start", names[0] == "start")
    ok &= check("closes with done", names[-1] == "done")
    ok &= check("reports each source", names.count("source") == 3)
    ok &= check("reports the dedupe stage", "stage" in names)

    per_source = {d["name"]: d["count"] for n, d in events if n == "source"}
    ok &= check("gdelt lane gets its count", per_source["gdelt"] == 5)
    ok &= check("wikipedia lane gets its count", per_source["wikipedia"] == 1)

    done = events[-1][1]
    ok &= check("payload carries items", len(done["items"]) > 0)
    ok &= check("every item has a band the CSS knows",
                all(i["band"] in ("HIGH", "MED", "LOW", "WEAK")
                    for i in done["items"]))
    ok &= check("items are sorted by score",
                all(done["items"][i]["relevance"] >= done["items"][i + 1]["relevance"]
                    for i in range(len(done["items"]) - 1)))
    ok &= check("body text is capped for transport",
                all(len(i["text"]) <= 600 for i in done["items"]))
    ok &= check("marks keyword-only mode", done["enriched"] is False)
    ok &= check("names the written report", done.get("report", "").endswith(".md"))
    ok &= check("names the print-ready HTML report", done.get("report_html", "").endswith(".html"))

    print("\nreport download")
    r2 = client.get(f"/api/report/{done['report']}")
    ok &= check("report downloads", r2.status_code == 200)
    ok &= check("report has content", r2.text.startswith("# Sweep:"))
    (Path(__file__).parent / "out" / done["report"]).unlink(missing_ok=True)
    r3 = client.get(f"/api/report/{done['report_html']}")
    ok &= check("styled report downloads as HTML", r3.status_code == 200
                and "@media print" in r3.text and "MNARA" in r3.text)
    (Path(__file__).parent / "out" / done["report_html"]).unlink(missing_ok=True)

    print("\nno results path")
    r3 = client.get("/api/sweep?q=zzzz nothing&sources=sec_edgar&use_ai=false")
    ev = parse_sse(r3.text)
    ok &= check("still closes with done", ev[-1][0] == "done")
    ok &= check("returns an empty list rather than erroring",
                ev[-1][1]["items"] == [])

    print("\nkeeping results")
    # The Archive tab is dead weight unless the browser can ask for save=true,
    # so assert the round trip rather than just the checkbox existing. Point
    # the store at a scratch DB first — a test must never write fixture rows
    # into the archive the user actually reads.
    import tempfile
    real_config = webapp.config
    tmpdir = tempfile.mkdtemp()
    webapp.config = lambda: {**real_config(),
                             "storage": {"database": f"{tmpdir}/test.db",
                                         "output_dir": tmpdir}}
    try:
        r4 = client.get("/api/sweep?q=beneficial ownership Kenya&sources=gdelt"
                        "&use_ai=false&fetch_bodies=false&save=true")
        kept = parse_sse(r4.text)[-1][1]
        ok &= check("save=true reports how many rows it stored",
                    isinstance(kept.get("saved"), int))
        r5 = client.get("/api/sweep?q=beneficial ownership Kenya&sources=gdelt"
                        "&use_ai=false&fetch_bodies=false")
        ok &= check("and stores nothing without it",
                    "saved" not in parse_sse(r5.text)[-1][1])
    finally:
        webapp.config = real_config
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nserverless deployment guards")
    import importlib
    # Re-import the app as if it were running on Vercel with no password set.
    saved = dict(os.environ)
    os.environ["VERCEL"] = "1"
    os.environ.pop("WATCHTOWER_PASSWORD", None)
    try:
        prod = importlib.reload(webapp)
        pc = TestClient(prod.app)
        ok &= check("storage moves off the read-only bundle",
                    str(prod.DATA_DIR).startswith("/tmp"))
        ok &= check("and knows that storage is ephemeral", prod.EPHEMERAL is True)
        ok &= check("a sweep gets a time budget under the platform timeout",
                    0 < prod.SWEEP_BUDGET < 300)
        # Fail closed: no password on a public host must not serve the app.
        ok &= check("refuses to serve publicly with no password set",
                    pc.get("/api/sources").status_code == 503)
        ok &= check("and says why", "WATCHTOWER_PASSWORD"
                    in pc.get("/api/sources").json()["detail"])

        os.environ["WATCHTOWER_PASSWORD"] = "hunter2"
        prod = importlib.reload(webapp)
        pc = TestClient(prod.app)
        ok &= check("still refuses without credentials",
                    pc.get("/api/sources").status_code == 401)
        ok &= check("challenges with Basic",
                    "Basic" in pc.get("/api/sources").headers.get("www-authenticate", ""))
        ok &= check("rejects a wrong password",
                    pc.get("/api/sources", auth=("watchtower", "wrong")).status_code == 401)
        ok &= check("accepts the right one",
                    pc.get("/api/sources", auth=("watchtower", "hunter2")).status_code == 200)
        ok &= check("and tells the UI storage is ephemeral",
                    pc.get("/api/sources", auth=("watchtower", "hunter2"))
                      .json()["ephemeral_storage"] is True)
        ok &= check("ephemeral storage rejects misleading save requests",
                    pc.get("/api/sweep?q=test&save=true",
                           auth=("watchtower", "hunter2")).status_code == 409)
        ok &= check("ephemeral storage rejects analyst verdicts",
                    pc.post("/api/scamscan/dispose",
                            auth=("watchtower", "hunter2"),
                            json={"fingerprint": "x", "verdict": "confirmed"})
                      .status_code == 409)
        ok &= check("ephemeral storage also rejects entity verdicts",
                    pc.post("/api/entities/entity-x/verdict",
                            auth=("watchtower", "hunter2"),
                            json={"verdict": "needs_review"}).status_code == 409)
        ok &= check("ephemeral storage rejects hunts whose findings would be lost",
                    pc.get("/api/scamscan/hunt?topics=1",
                           auth=("watchtower", "hunter2")).status_code == 409)

        os.environ.pop("VERCEL", None)
        os.environ.pop("WATCHTOWER_PASSWORD", None)
        os.environ["RAILWAY_ENVIRONMENT"] = "production"
        prod = importlib.reload(webapp)
        pc = TestClient(prod.app)
        ok &= check("Railway deployments also fail closed without a password",
                    pc.get("/").status_code == 503)
        ok &= check("host health checks remain credential-free and data-free",
                    pc.get("/api/healthz").status_code == 200
                    and pc.get("/api/healthz").json() == {"status": "ok"})
    finally:
        os.environ.clear()
        os.environ.update(saved)
        webapp_reloaded = importlib.reload(webapp)
        ok &= check("local runs keep no-auth, on-disk storage",
                    not webapp_reloaded.SERVERLESS
                    and webapp_reloaded.EPHEMERAL is False)

    print("\nscamscan side — read-only surface")
    import tempfile
    import types

    import scamscan
    from scamscan_test import Block, FakeClient, Resp, text_resp

    scam_dir = Path(tempfile.mkdtemp(prefix="scamscan_test_"))
    saved_dir = webapp.DATA_DIR
    webapp.DATA_DIR = scam_dir
    try:
        r = client.get("/api/scamscan/status")
        st = r.json()
        ok &= check("status serves", r.status_code == 200)
        ok &= check("it names the brand it is configured for", bool(st["brand"]))
        ok &= check("and reports the lexicon it will score with",
                    st["lexicon_terms"] > 0 and st["counter_terms"] > 0)
        ok &= check("and which search tool the model actually gets",
                    "web_search_20" in st["search_tool"])
        ok &= check("it names the provider it will call",
                    st["provider"] == "anthropic")
        ok &= check("and whether a hunt can run at all",
                    st["api_available"] is True)

        r = client.get("/api/scamscan/queue")
        ok &= check("an empty queue is an empty list, not an error",
                    r.status_code == 200 and r.json()["items"] == [])
        ok &= check("an unknown disposition is rejected",
                    client.get("/api/scamscan/queue?disposition=hax").status_code == 400)

        # Seed one finding through scamscan's own writer, so the test exercises
        # the same rows a real hunt produces rather than a hand-built fixture.
        cfg = json.loads((Path(__file__).parent / "config.json").read_text())
        finding = {"url": "http://mpesa-verify.co.ke/login", "title": "verify now",
                   "scam_type": "phishing", "summary": "Send your PIN to unlock",
                   "quoted_evidence": "send your pin", "model_confidence": 0.9}
        con = scamscan.db_connect(str(scam_dir / "scamscan.db"))
        scored = scamscan.score_finding(finding, cfg)
        scamscan.upsert(con, finding, scored, "q")
        con.commit()
        con.close()
        fp = scamscan.fingerprint(finding)

        d = client.get("/api/scamscan/queue?min_score=0").json()
        ok &= check("a stored finding comes back", len(d["items"]) == 1)
        item = d["items"][0]
        ok &= check("with a band on the shared relevance ramp",
                    item["band"] in {"HIGH", "MED", "LOW", "WEAK"})
        ok &= check("and the breakdown, so the score can be explained",
                    item["breakdown"]["lexicon_hits"]
                    and "scored_on" in item["breakdown"])
        ok &= check("min_score filters it out when set above the score",
                    client.get("/api/scamscan/queue?min_score=99").json()["items"] == [])

        r = client.post("/api/scamscan/dispose",
                        json={"fingerprint": fp, "verdict": "confirmed",
                              "note": "checked"})
        ok &= check("a verdict saves", r.status_code == 200)
        after = client.get("/api/scamscan/queue?min_score=0&disposition=confirmed").json()
        ok &= check("and moves the finding out of the new queue",
                    len(after["items"]) == 1
                    and after["items"][0]["analyst_note"] == "checked"
                    and client.get("/api/scamscan/queue?min_score=0").json()["items"] == [])
        ok &= check("an invalid verdict is rejected",
                    client.post("/api/scamscan/dispose",
                                json={"fingerprint": fp, "verdict": "drop"}
                                ).status_code == 400)
        # Silently accepting a verdict for a row that isn't there would tell an
        # analyst their decision was recorded when nothing was written.
        ok &= check("a verdict for an unknown finding is a 404, not a no-op",
                    client.post("/api/scamscan/dispose",
                                json={"fingerprint": "nope", "verdict": "confirmed"}
                                ).status_code == 404)

        print("\nscoring in the browser costs nothing and calls nothing")
        r = client.post("/api/scamscan/score",
                        json={"text": "New M-PESA balance is Ksh(*LOCKED*). Pay to POCHI.",
                              "url": "http://mpesa-verify.co.ke/login"})
        s = r.json()
        ok &= check("it scores", r.status_code == 200 and s["score"] > 0)
        ok &= check("every hit carries the source it came from",
                    all("[" in h for h in s["lexicon_hits"]))
        ok &= check("an absent model confidence is reported as absent, not zero",
                    s["model_score"] is None and "model" not in s["scored_on"])
        ok &= check("and an explicit one is included",
                    "model" in client.post("/api/scamscan/score",
                                           json={"text": "x", "url": "y",
                                                 "model_confidence": 0.5}
                                           ).json()["scored_on"])
        ok &= check("an empty request is rejected rather than scored as clean",
                    client.post("/api/scamscan/score",
                                json={"text": "", "url": ""}).status_code == 400)

        print("\nhunt streams, and a query that never ran says so")
        saved_key = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        saved_anthropic = scamscan.anthropic

        class Err:
            type = "web_search_tool_result_error"
            error_code = "too_many_requests"

        script = [
            Resp([Block("text", text='{"queries": ["one", "two"]}')]),
            text_resp({"findings": [finding]}),
            Resp([Block("web_search_tool_result", content=Err()),
                  Block("text", text='{"findings": []}')]),
        ]
        scamscan.anthropic = types.SimpleNamespace(Anthropic=lambda: FakeClient(*script))
        try:
            with client.stream("GET", "/api/scamscan/hunt?topics=1") as resp:
                events = parse_sse("".join(resp.iter_text()))
        finally:
            scamscan.anthropic = saved_anthropic
            if saved_key is None:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            else:
                os.environ["ANTHROPIC_API_KEY"] = saved_key

        names = [n for n, _ in events]
        ok &= check("the stream opens with what it is about to spend on",
                    names[0] == "start")
        ok &= check("topics and queries stream as they run",
                    "topic" in names and "query" in names)
        ok &= check("findings stream one at a time", "finding" in names)
        # The whole point: a rate-limited query and a clean query must not
        # arrive on the same event.
        ok &= check("a query that could not be searched gets its own event",
                    "unsearched" in names)
        ok &= check("exactly one terminal frame closes the stream",
                    names.count("done") == 1 and names[-1] == "done")
        done = dict(events)["done"]
        ok &= check("the summary carries the failures, not just the count",
                    len(done["failures"]) == 1 and done["complete"] is False)
        ok &= check("and enough to state the cost that was incurred",
                    done["queries_run"] == 1 and "model" in done)

        r = client.get("/api/scamscan/hunt?topics=99")
        ok &= check("topics is capped so one click cannot spend unboundedly",
                    r.status_code == 422)
    finally:
        webapp.DATA_DIR = saved_dir
        shutil.rmtree(scam_dir, ignore_errors=True)

    print("\nfrontend wiring")
    import re
    static = Path(__file__).parent / "web" / "static"
    html = (static / "index.html").read_text()
    js = (static / "app.js").read_text()
    css = (static / "style.css").read_text()

    html_ids = set(re.findall(r'id="([^"]+)"', html))
    js_ids = set(re.findall(r'\$\("#([a-zA-Z0-9_-]+)"\)', js))
    ok &= check("every element the script reaches for exists",
                not (js_ids - html_ids))

    js_classes = set(re.findall(r'el\("[a-z0-9]+", "([a-z-]+)"', js))
    js_classes |= set(re.findall(r'classList\.(?:add|toggle)\("([a-z-]+)"\)', js))
    css_classes = set(re.findall(r'\.([a-zA-Z][\w-]*)', css))
    ok &= check("every class the script applies is styled",
                not (js_classes - css_classes))

    js_events = set(re.findall(r'addEventListener\("(\w+)"', js))
    ok &= check("the script handles every event the server sends",
                {"source", "stage", "scored", "done", "failed"} <= js_events)

    ok &= check("the sweep request carries the save flag", "save:" in js)
    ok &= check("interactive sweeps use fast defaults",
                not re.search(r'id="fetch-bodies"[^>]*checked', html)
                and "limit: 20" in js)
    ok &= check("monitor exposes the complete lookback range",
                all(f'data-h="{hours}"' in html for hours in ("24", "72", "168", "720", "2160", "4320", "8760")))
    ok &= check("monitor exposes result and model budgets",
                all(identifier in html for identifier in ('id="sweep-limit"', 'id="max-ai"'))
                and "sweepLimit" in js and "maxAi" in js)
    ok &= check("source presets and preference persistence are wired",
                all(identifier in html for identifier in ('id="sources-default"', 'id="sources-all"', 'id="sources-none"', 'id="reset-controls"'))
                and "mnara-monitor-preferences" in js)
    ok &= check("investigation exposes a no-cost plan-only run",
                'id="dry-run-hunt"' in html and "dry_run=${dryRun}" in js
                and "PLAN ONLY" in js)
    # Source-controlled text (titles, URL slugs, entity names) has no spaces to
    # wrap at. Without these the longest token sets the column width and the
    # whole page scrolls sideways — worst at 380px. See the note in style.css.
    for sel in (".card h3", ".card p.body", ".tag", ".panel li span"):
        ok &= check(f"{sel} can break an unbreakable string",
                    re.search(re.escape(sel) + r"[^{]*\{[^}]*overflow-wrap:\s*anywhere",
                              css) is not None)
    ok &= check("the favicon is inline, so a clean load logs no 404",
                'rel="icon"' in html)
    # showEmpty() hides #results, which is where the Problems panel lives, so a
    # zero-hit sweep caused by six broken sources would otherwise explain
    # nothing. The rendering itself needs a browser; this checks the wiring.
    ok &= check("a zero-result sweep passes the coverage reasons through",
                re.search(r"showEmpty\([^;]*notes\)", js) is not None)
    ok &= check("and the empty-state error block is styled",
                ".empty-errs" in css)
    # The whole point of task 02: an empty sweep with a broken source must not
    # render the same as an empty sweep where everything answered.
    ok &= check("the empty state branches on whether coverage was complete",
                "d.complete === false" in js)
    ok &= check("a failed lane is labelled, not shown as 0",
                'd.error ? "failed"' in js)
    ok &= check("an unsearched lane is labelled too", 'd.skipped ? "off"' in js)
    ok &= check("chips gate on the key being present, not on being a default",
                "s.available !== false" in js)
    # The label said "Score with Claude" while a Gemini key was driving it.
    ok &= check("the scoring toggle names the provider actually in use",
                'id="ai-label"' in html and "data.ai_provider" in js)
    ok &= check("and /api/sources reports which one that is",
                "ai_provider" in client.get("/api/sources").json())
    for cls in (".lane.skipped", ".summary .warn"):
        ok &= check(f"{cls} is styled", cls in css)
    ok &= check("every investigation detail endpoint is wired into the UI",
                all(path in js for path in (
                    "/api/investigations/${encodeURIComponent(id)}",
                    "/api/entities/${encodeURIComponent(id)}",
                    "/api/entities/${encodeURIComponent(id)}/evidence",
                    "/api/entities/${encodeURIComponent(id)}/verdict",
                    "/api/campaigns/${encodeURIComponent(id)}",
                    "/api/scan",
                    "/api/stats",
                )))
    ok &= check("investigation expansion rounds are visible",
                'id="discover-expansion"' in html
                and "renderInvestigationExpansion" in js
                and "termination_reason" in js)
    ok &= check("terminal active navigation labels keep contrast",
                re.search(r'\[data-theme="terminal"\] \.tab\.is-on\s*\{[^}]*color:\s*#0a0a0a;[^}]*background:\s*var\(--ink\)', css) is not None)

    print("\ntwo sides, one page")
    sides = set(re.findall(r'data-side="(\w+)"', html))
    ok &= check("the nav declares all three workspaces", sides == {"watchtower", "scamscan", "hunter"})
    tab_views = set(re.findall(r'class="tab[^"]*" data-view="(\w+)"', html))
    ok &= check("every tab has a section to show",
                all(f"view-{v}" in html_ids for v in tab_views))
    ok &= check("and the switcher knows all four",
                re.search(r'VIEWS\s*=\s*\[([^\]]+)\]', js)
                and tab_views <= set(re.findall(
                    r'"(\w+)"', re.search(r'VIEWS\s*=\s*\[([^\]]+)\]', js).group(1))))
    print("\nautonomous hunting frontend")
    hjs = (static / "hunter.js").read_text()
    hcss = (static / "hunter.css").read_text()
    ok &= check("hunter script and stylesheet are linked and served",
                '/hunter.js' in html and '/hunter.css' in html
                and client.get("/hunter.js").status_code == 200 and client.get("/hunter.css").status_code == 200)
    used_ids = set(re.findall(r'\$h\("#(hx-[\w-]+)"', hjs))
    ok &= check("every element hunter.js looks up is defined by the page or by the script's own templates",
                used_ids and all(f'id="{i}"' in html or f'id="{i}"' in hjs for i in used_ids)
                and {"hx-metrics", "hx-feed", "hx-detail", "hx-campaigns", "hx-queue", "hx-sources", "hx-alerts"} <= used_ids)
    ok &= check("the hunt workspace has a mode tab, three tabs, and sections for each",
                'data-mode="hunt"' in html
                and all(f'data-view="{v}" data-side="hunter"' in html and f'id="view-{v}"' in html
                        for v in ("hunt", "campaigns", "huntops"))
                and "hunt: [" in js and "SIDE_MODE" in js and "hunterOnView" in js)
    # The OpenAPI schema, not app.routes: newer FastAPI wraps include_router() output in an object with no .path.
    api_paths = set(webapp.app.openapi()["paths"])
    used_api = {"/api/hunter" + p for p in re.findall(r'api\(`?"?(/[\w/-]+)', hjs)}
    ok &= check("every hunter API path the script calls is routed",
                used_api and all(any(re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", route), path.split("?")[0].rstrip("/"))
                                     or route.startswith(path.split("?")[0].rstrip("/"))
                                     for route in api_paths if route.startswith("/api/hunter"))
                                 for path in used_api))
    ok &= check("hunter.js escapes everything it renders and builds no dynamic URLs or code",
                "const esc =" in hjs and hjs.count("esc(") > 80
                and "eval(" not in hjs and "document.write" not in hjs and 'href="${' not in hjs
                and not re.search(r"innerHTML\s*=\s*[a-z]+\.[a-z_]+\s*;", hjs))
    ok &= check("hunter.css uses the app's relevance colours for classification chips",
                all(c in hcss for c in (".hx-HIGH_PRIORITY", ".hx-SUSPICIOUS", ".hx-UNASSESSED", "var(--high", "var(--med")))
    ok &= check("the rail names the side you are on",
                'id="rail-name"' in html and "#rail-name" in js)
    ok &= check("navigation uses task-oriented labels",
                all(label in html for label in
                    ("Monitor", "Saved results", "Find scam sites",
                     "Review queue", "Quick score")))
    ok &= check("system status is visible and expandable",
                'id="system-status"' in html and 'id="status-details"' in html
                and 'id="status-toggle"' in html)
    ok &= check("optional integrations are summarized instead of listed as failures",
                "optional integration" in js
                and "unavailable.map" not in js
                and "Ready ·" in js)
    radios = re.findall(r'<button[^>]+role="radio"[^>]*>', html)
    ok &= check("every custom radio declares its accessibility state",
                radios and all('aria-checked=' in radio for radio in radios))
    ok &= check("custom radios support arrow-key navigation",
                "function radioKeys" in js and "ArrowRight" in js)
    ok &= check("long-running views offer a stop-updates control",
                'id="cancel-sweep"' in html and 'id="cancel-hunt"' in html
                and "Requests already sent" in js)
    for cls in (".side-group", ".side-label"):
        ok &= check(f"{cls} is styled", cls in css)

    # The hunt stream has its own event vocabulary; a rename here fails the same
    # silent way a sweep rename would — the log just stays empty.
    for ev in ("start", "topic", "query", "finding", "unsearched", "note"):
        ok &= check(f"the hunt log handles the {ev!r} event",
                    f'addEventListener("{ev}"' in js)
    ok &= check("an unsearched query is styled apart from a finding",
                ".log-fail" in css and ".log-find" in css)
    # Same argument as the sweep's failed lane, one screen over: an absent
    # family must not be drawn as a zero-width bar that reads as a zero score.
    ok &= check("an absent scoring family is drawn as absent, not as zero",
                ".fam.absent" in css and '"absent"' in js
                and "No fill element at all" in js)
    ok &= check("lexicon provenance reaches the page", ".hit-src" in css)
    ok &= check("counter terms are visually distinct from hits",
                ".hit.is-counter" in css)
    ok &= check("a failed verdict save is surfaced on the card",
                re.search(r"Not saved", js) is not None)
    ok &= check("an empty queue does not read as a clean brand",
                "not about the brand" in js and ".empty-inline" in css)
    ok &= check("the hunt states its cost before it is clicked",
                "searches per topic" in js)
    for sel in (".evidence", ".reason", ".hit"):
        ok &= check(f"{sel} can break an unbreakable string",
                    re.search(re.escape(sel) + r"[^{]*\{[^}]*overflow-wrap:\s*anywhere",
                              css) is not None)

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
