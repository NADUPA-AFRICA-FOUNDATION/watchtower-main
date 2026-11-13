import asyncio
import datetime as dt

import httpx

from hunter.enrich.threat import ThreatFeeds, ThreatResult
from hunter.scoring import gather_inputs, score
from test_hunter_enrich import Harness, NOW, registry_handler  # shared offline harness

LIST = "\n".join(f"filler-{i}.example" for i in range(1200))


def feeds(handler, **kw):
    return ThreatFeeds(httpx.AsyncClient(transport=httpx.MockTransport(handler)), **kw)


def test_hit_miss_and_url_feed_hostnames_match_exactly():
    def handler(request):
        if "Phishing.Database" in str(request.url):
            return httpx.Response(200, text=LIST + "\nmpesa-verify.com\n")
        return httpx.Response(200, text="\n".join(f"http://u{i}.example/x" for i in range(30)) + "\nhttps://www.fuliza-boost.example/login\n")
    tf = feeds(handler)
    hit = asyncio.run(tf.check("MPESA-VERIFY.com"))
    assert hit.status == "checked" and hit.hits == ["phishing_database"] and len(hit.feeds_checked) == 2
    assert asyncio.run(tf.check("fuliza-boost.example")).hits == ["openphish"]            # URL feed, www. ignored
    miss = asyncio.run(tf.check("sub.mpesa-verify.com"))
    assert miss.status == "checked" and miss.hits == []                                   # no parent-domain matching


def test_a_feed_that_cannot_be_read_is_never_a_clean_result():
    down = asyncio.run(feeds(lambda r: httpx.Response(503)).check("mpesa-verify.com"))
    assert down.status == "error" and down.hits == [] and len(down.errors) == 2

    def half(request):
        return httpx.Response(200, text=LIST) if "Phishing.Database" in str(request.url) else httpx.Response(500)
    partial = asyncio.run(feeds(half).check("mpesa-verify.com"))
    assert partial.status == "partial" and partial.feeds_checked == ["phishing_database"] and "openphish" in partial.errors
    # a truncated body is an error, not a short list
    short = asyncio.run(feeds(lambda r: httpx.Response(200, text="one.example\n")).check("one.example"))
    assert short.status == "error" and short.hits == []


def test_failed_refresh_keeps_the_previous_list_and_says_stale():
    now, ok = [0.0], [True]

    def handler(request):
        return httpx.Response(200, text=LIST + "\nhttp://bad.example/\n") if ok[0] else httpx.Response(502)
    tf = feeds(handler, cache_hours=1, clock=lambda: now[0])
    assert asyncio.run(tf.check("bad.example")).hits
    ok[0], now[0] = False, 7200.0
    later = asyncio.run(tf.check("bad.example"))
    assert later.hits and set(later.stale) == set(later.feeds_checked) and later.errors and later.status == "checked"


class FakeThreat:
    def __init__(self, result):
        self.result = result

    async def check(self, domain):
        return self.result


def _scored(h, cid):
    cand = h.store.get(cid)
    brand = h.ctx.brands["M-PESA"]
    return score(gather_inputs(h.graph, cid, cand["canonical"], brand, h.cfg, NOW, h.store), h.cfg)


def test_pipeline_records_the_check_and_a_hit_raises_the_score_with_the_feed_named():
    dns = {("mpesa-verify.com", "A"): ["8.8.8.8"]}
    base = Harness(dns, registry_handler())
    cid0 = base.add("mpesa-verify.com")
    base.batch()
    assert base.evidence(cid0, "threat_feed_check") == []                                 # not consulted, nothing claimed

    h = Harness(dns, registry_handler())
    h.ctx.en.threat = FakeThreat(ThreatResult("mpesa-verify.com", "checked", ["phishing_database"],
                                              ["phishing_database", "openphish"]))
    cid = h.add("mpesa-verify.com")
    h.batch()
    assert len(h.evidence(cid, "threat_feed_check")) == 1 and len(h.evidence(cid, "threat_feed_hit")) == 1
    res = _scored(h, cid)
    reason = next(r for r in res.reasons if r.signal == "known_malicious_infrastructure")
    assert "phishing_database" in reason.evidence and reason.evidence_ids
    assert res.score > _scored(base, cid0).score


def test_a_later_complete_clean_check_supersedes_a_hit_but_a_failed_one_does_not():
    dns = {("mpesa-verify.com", "A"): ["8.8.8.8"]}
    for later, still_listed in ((ThreatResult("mpesa-verify.com", "checked", [], ["phishing_database", "openphish"]), False),
                                (ThreatResult("mpesa-verify.com", "error", [], [], [], {"openphish": "HTTP 503"}), True),
                                (ThreatResult("mpesa-verify.com", "partial", [], ["openphish"], [], {"phishing_database": "x"}), True)):
        h = Harness(dns, registry_handler())
        h.ctx.en.threat = FakeThreat(ThreatResult("mpesa-verify.com", "checked", ["phishing_database"], ["phishing_database", "openphish"]))
        cid = h.add("mpesa-verify.com")
        h.batch()
        h.now[0] = NOW + dt.timedelta(hours=2)
        h.ctx.en.threat = FakeThreat(later)
        if h.store.get(cid)["status"] != "QUEUED":
            h.store.requeue(cid, stage="light")
        h.batch()                                                # the deep pass consults the feeds again
        assert len(h.evidence(cid, "threat_feed_check")) == 2
        listed = any(r.signal == "known_malicious_infrastructure" for r in _scored(h, cid).reasons)
        assert listed is still_listed, later.status
