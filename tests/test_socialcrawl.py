from __future__ import annotations

import httpx
import pytest

from core.fetch import Fetcher
from core.sources import (SourceError, SourceSkipped, social_web_index,
                          socialcrawl)


def _fetcher(handler) -> Fetcher:
    return Fetcher("watchtower-test/0.1", delay=0,
                   transport=httpx.MockTransport(handler))


def test_socialcrawl_maps_unified_results(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "sc_test"
        assert request.url.params["query"] == "mpesa scam"
        assert request.url.params["lookback_days"] == "7"
        return httpx.Response(200, json={
            "success": True,
            "credits_used": 20,
            "credits_remaining": 80,
            "request_id": "req_1",
            "cached": False,
            "data": {"items": [{
                "id": "123",
                "platform": "tiktok",
                "url": "https://www.tiktok.com/@watch/video/123",
                "text": "Fake M-Pesa promotion",
                "author": {"username": "watch"},
                "engagement": {"likes": 10},
                "computed": {"language": "en"},
                "created_at": "2026-08-20T12:00:00Z",
            }]},
            "pagination": {"has_more": True, "next_cursor": "next-1"},
        })

    items = socialcrawl("mpesa scam", _fetcher(handler), hours=168)
    assert len(items) == 1
    assert items[0].source == "socialcrawl:tiktok"
    assert items[0].source_type == "social"
    assert items[0].author == "watch"
    assert items[0].lang == "en"
    assert items[0].raw_meta["credits_used"] == 20
    assert items[0].raw_meta["engagement"] == {"likes": 10}
    assert items[0].raw_meta["pagination"]["next_cursor"] == "next-1"


def test_socialcrawl_requires_key(monkeypatch):
    monkeypatch.delenv("SOCIALCRAWL_API_KEY", raising=False)
    with pytest.raises(SourceSkipped, match="SOCIALCRAWL_API_KEY"):
        socialcrawl("query", _fetcher(lambda request: httpx.Response(500)))


def test_socialcrawl_preflights_before_spending_credits(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"success": True, "data": {"items": []}})

    fetcher = _fetcher(handler)
    with pytest.raises(SourceError, match="at least 2 characters"):
        socialcrawl(" ", fetcher)
    with pytest.raises(SourceError, match="positive integer"):
        socialcrawl("valid query", fetcher, limit=0)
    assert calls == 0


def test_socialcrawl_rejects_non_object_json_envelope(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(200, json=[]))
    with pytest.raises(SourceError, match="JSON object"):
        socialcrawl("query", fetcher)


def test_socialcrawl_rejects_bad_payload(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(200, text="not json"))
    with pytest.raises(SourceError, match="not valid JSON"):
        socialcrawl("query", fetcher)


def test_socialcrawl_does_not_retry_a_paid_request(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="upstream unavailable")

    with pytest.raises(SourceError):
        socialcrawl("query", _fetcher(handler))
    assert calls == 1


def test_socialcrawl_reports_unusable_paid_results(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(200, json={
        "success": True,
        "credits_used": 20,
        "data": {"items": [{"source": "reddit", "title": "missing URL"}]},
    }))
    with pytest.raises(SourceError, match="none had a usable URL"):
        socialcrawl("query", fetcher)


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    monkeypatch.setattr("core.sources.SOCIAL_PACE", 0)


def test_free_social_index_maps_public_platform_results(monkeypatch):
    def search(query, max_results):
        if "site:tiktok.com" not in query:
            return []
        return [
            {"title": "M-Pesa scam alert", "url": "https://www.tiktok.com/@watch/video/1#comments",
             "summary": "Fake M-Pesa offer"},
            {"title": "Duplicate", "url": "http://www.tiktok.com/@watch/video/1",
             "summary": "same post"},
            {"title": "Unrelated", "url": "https://example.com/page", "summary": ""},
            "malformed row",
        ]

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("M-Pesa scam", _fetcher(lambda request: httpx.Response(500)))
    assert len(items) == 1
    assert items[0].source == "social_web_index"
    assert items[0].raw_meta["platform"] == "tiktok.com"
    assert items[0].url == "https://www.tiktok.com/@watch/video/1"
    assert items[0].raw_meta["kind"] == "post" and items[0].raw_meta["account"] == "watch"
    assert items[0].raw_meta["term_match"] is True
    assert items[0].raw_meta["requests_failed"] == 0


def test_free_social_index_queries_each_platform_separately(monkeypatch):
    """The single OR-of-sites query returned nothing for real topics; one query per site must not."""
    queries = []
    monkeypatch.setattr("osint_discovery.search_duckduckgo",
                        lambda q, max_results: queries.append(q) or [])
    social_web_index("Fuliza limit increase", _fetcher(lambda request: httpx.Response(500)))
    assert len(queries) == 14 and len(set(queries)) == 14
    assert all(q.count("site:") == 1 for q in queries)
    assert any(q.startswith('"Fuliza limit increase" site:t.me') for q in queries)
    assert any(q == "Fuliza limit increase site:t.me" for q in queries)


def test_free_social_index_canonicalises_telegram_and_interleaves_platforms(monkeypatch):
    def search(query, max_results):
        if "site:t.me" in query:
            return [{"title": "Fuliza", "url": "https://t.me/s/fulizaagent01?before=30", "summary": "x"},
                    {"title": "Fuliza", "url": "https://t.me/fulizaagent01", "summary": "x"},
                    {"title": "Fuliza2", "url": "https://t.me/s/other", "summary": "fuliza"},
                    {"title": "Invite", "url": "https://t.me/+abcdef", "summary": "fuliza"}]
        if "site:tiktok.com" in query:
            return [{"title": "Fuliza topic", "url": "https://www.tiktok.com/discover/fuliza", "summary": "fuliza"},
                    {"title": "Fuliza boost", "url": "https://www.tiktok.com/@boost", "summary": "fuliza"}]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("Fuliza", _fetcher(lambda request: httpx.Response(500)), limit=3)
    urls = [i.url for i in items]
    assert "https://t.me/fulizaagent01" in urls and len([u for u in urls if "fulizaagent01" in u]) == 1
    assert {i.raw_meta["platform"] for i in items} == {"t.me", "tiktok.com"}
    topic = next(i for i in items if i.raw_meta["kind"] == "topic_page") if any(
        i.raw_meta["kind"] == "topic_page" for i in items) else None
    profile = next(i for i in items if i.url.endswith("/@boost"))
    assert profile.raw_meta["kind"] == "profile"
    assert topic is None or items.index(profile) < items.index(topic)
    assert next(i for i in items if i.url.endswith("/fulizaagent01")).raw_meta["kind"] == "channel"


def test_free_social_index_never_reports_partial_failure_as_clean(monkeypatch):
    def search(query, max_results):
        if "site:tiktok.com" in query:
            raise RuntimeError("throttled")
        if "site:t.me" in query:
            return [{"title": "watch tower", "url": "https://t.me/chan", "summary": "x"}]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))
    assert items and all(i.raw_meta["requests_failed"] == 2 for i in items)   # tiktok, exact + loose phrasing

    # Some failed and the rest found nothing: that is "could not look", not "nothing there".
    monkeypatch.setattr("osint_discovery.search_duckduckgo",
                        lambda q, max_results: (_ for _ in ()).throw(RuntimeError("x")) if "tiktok" in q else [])
    with pytest.raises(SourceError, match="requests failed"):
        social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))


def test_free_social_index_drops_platform_chrome_and_unrelated_rows_and_keeps_linked_urls(monkeypatch):
    def search(query, max_results):
        if "site:instagram.com" in query:
            return [{"title": "fulizalimit4314 on Instagram", "url": "https://www.instagram.com/p/Abc/",
                     "summary": "Your Fuliza limit can now be raised https://le-fuliza-boost.vercel.app Good news!"},
                    {"title": "Instagram", "url": "https://instagram.com/", "summary": "fuliza limit"}]
        if "site:x.com" in query:
            return [{"title": "X help", "url": "https://help.x.com/tr", "summary": "fuliza limit"}]
        if "site:wa.me" in query:
            return [{"title": "DA/DR 80+", "url": "https://wa.me/seller", "summary": "Increase Brand Authority"}]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("Fuliza limit increase", _fetcher(lambda request: httpx.Response(500)))
    assert [i.url for i in items] == ["https://www.instagram.com/p/Abc/"]
    assert items[0].raw_meta["linked_urls"] == ["https://le-fuliza-boost.vercel.app"]
    assert items[0].raw_meta["term_score"] == 0.67


def test_free_social_index_validates_query_and_surfaces_provider_errors(monkeypatch):
    with pytest.raises(SourceError, match="at least 2 characters"):
        social_web_index(" ", _fetcher(lambda request: httpx.Response(500)))

    monkeypatch.setattr(
        "osint_discovery.search_duckduckgo",
        lambda query, max_results: (_ for _ in ()).throw(RuntimeError("rate limited")),
    )
    with pytest.raises(SourceError, match="free social index search failed: rate limited"):
        social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))


def test_socialcrawl_surfaces_402_credit_details(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(402, json={
        "success": False,
        "error": {
            "type": "INSUFFICIENT_CREDITS",
            "message": "Your account has 0 credits remaining. This endpoint requires 20 credits.",
            "status": 402,
        },
        "credits_used": 0,
        "credits_remaining": 0,
        "request_id": "req-test",
    }))
    with pytest.raises(SourceError) as caught:
        socialcrawl("query", fetcher)
    message = str(caught.value)
    assert "0 credits remaining" in message
    assert "requires 20 credits" in message
    assert "credits used: 0" in message


def test_bait_signals_flag_lures_but_not_advisories():
    from core.sources import _bait_signals
    sig, adv = _bait_signals("Fuliza limit increase", "Increment is assured 100%. Hit admin inbox. Be ready with the charges")
    assert not adv and {"guarantee_claims", "contact_funnel", "advance_fee"} <= set(sig)
    sig, adv = _bait_signals("Fake Fuliza boost: scammers promise guaranteed increases, hit admin inbox")
    assert adv and sig == []                       # an advisory quotes the bait; it is not the bait
    assert _bait_signals("Tahadhari: ulaghai wa fuliza, tuma pin")[0] == []      # Swahili advisory
    assert _bait_signals("Safaricom explains how to refresh your limit")[0] == []
    assert "link_hosting" in _bait_signals("limit now https://le-fuliza-boost.vercel.app")[0]
    # The topic's own words are not hosting evidence (hyphen == space in phrase matching).
    assert "link_hosting" not in _bait_signals("how the Fuliza limit works for Ziidi Trader users")[0]
    assert _bait_signals("Join t.me/somechannel or wa.me/254700000000")[0] == []


def test_synonyms_inside_one_family_count_once():
    from core.sources import _bait_analysis
    sig, terms, _ = _bait_analysis("Guaranteed, 100% sure, no risk, zero risk, assured returns")
    assert sig == ["guarantee_claims"] and len(terms["guarantee_claims"]) >= 3


def test_fraud_lexicon_is_large_unique_and_compiles():
    from core.fraud_lexicon import LEXICON, COMPILED, term_count, match
    assert term_count() >= 1000 and len(LEXICON) >= 15 and set(COMPILED) == set(LEXICON)
    total = sum(len(v) for v in LEXICON.values())
    assert total == term_count()                   # no phrase repeated within or across families
    assert all(t == t.strip() and t for terms in LEXICON.values() for t in terms)
    # every phrase matches itself (guards the \b / hyphen / punctuation handling)
    for cat, terms in LEXICON.items():
        for term in terms:
            assert cat in match(f"xx {term} yy") or cat in match(term), (cat, term)


def test_fraud_lexicon_covers_the_known_lures_in_three_languages():
    from core.fraud_lexicon import match
    cases = {
        "Fuliza limit increase . Hit admin inbox to get the same We make it happen": {"loan_limit_boost", "contact_funnel"},
        "Send your M-PESA PIN and OTP to verify your account": {"credential_theft"},
        "Pay a small registration fee to unlock your limit": {"advance_fee"},
        "Ziidi daily returns 10% daily guaranteed returns": {"investment_returns"},
        "Tuma ada ya usajili kwanza, faida ya uhakika": {"swahili"},
        "Tunaincrease limit, tuma kidogo kwanza": {"sheng"},
        "Sent to the wrong number, please reverse": {"reversal_wrong_transaction"},
        "You have won! Claim your prize": {"prize_giveaway"},
    }
    for text, expected in cases.items():
        assert expected <= set(match(text)), (text, set(match(text)))


def test_bait_signals_lift_score_only_when_two_agree_and_not_advisory():
    from core.models import Item
    from core.sweep import _adjust
    def item(**meta):
        return Item(url="https://t.me/x", source="social_web_index", source_type="social",
                    title="t", text="x" * 300, raw_meta=meta)
    base = _adjust(40, item())
    assert _adjust(40, item(bait_signals=["guarantee_claims"])) == base
    assert _adjust(40, item(bait_signals=["guarantee_claims", "advance_fee"])) == base + 12
    assert _adjust(40, item(bait_signals=["a", "b", "c", "d"], advisory=True)) == base
    assert _adjust(40, item(bait_signals=["a", "b", "c", "d"])) == base + 18


def test_free_social_index_deadline_turns_a_hung_request_into_a_reported_failure(monkeypatch):
    import threading
    monkeypatch.setattr("core.sources.SOCIAL_DEADLINE", 0.3)
    release = threading.Event()

    def search(query, max_results):
        if "site:wa.me" in query:                       # last platform in the plan
            release.wait(5)
            return []
        if "site:t.me" in query:
            return [{"title": "watch tower", "url": "https://t.me/chan", "summary": "x"}]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    try:
        items = social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))
    finally:
        release.set()
    assert [i.url for i in items] == ["https://t.me/chan"]
    assert items[0].raw_meta["requests_failed"] >= 1


def test_loose_phrasing_only_runs_where_the_exact_phrase_was_thin(monkeypatch):
    queries = []

    def search(query, max_results):
        queries.append(query)
        if query.startswith('"Fuliza limit"') and "site:t.me" in query:
            return [{"title": f"Fuliza limit {i}", "url": f"https://t.me/c{i}", "summary": "x"} for i in range(5)]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    social_web_index("Fuliza limit", _fetcher(lambda request: httpx.Response(500)))
    assert len(queries) == 13                                   # 7 exact + 6 loose; t.me was not thin
    assert "Fuliza limit site:t.me" not in queries


def test_deadline_stops_the_abandoned_worker_from_working_through_the_queue(monkeypatch):
    import threading
    monkeypatch.setattr("core.sources.SOCIAL_DEADLINE", 0.2)
    release, calls = threading.Event(), []

    def search(query, max_results):
        calls.append(query)
        release.wait(2)
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    with pytest.raises(SourceError):
        social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))
    release.set()
    import time as _t
    _t.sleep(0.5)
    assert len(calls) <= 2          # the stuck request (and at most its retry), not the other 6 platforms


def test_subject_family_alone_never_lifts_a_score_and_official_handles_are_not_scored():
    from core.models import Item
    from core.sweep import _adjust
    base = _adjust(40, Item(url="https://t.me/x", source="social_web_index", source_type="social",
                            title="t", text="x" * 300, raw_meta={}))
    one = Item(url="https://t.me/x", source="social_web_index", source_type="social", title="t",
               text="x" * 300, raw_meta={"bait_signals": ["loan_limit_boost", "advance_fee"]})
    assert _adjust(40, one) == base                       # one behavioural family + the subject = one signal
    two = Item(url="https://t.me/x", source="social_web_index", source_type="social", title="t",
               text="x" * 300, raw_meta={"bait_signals": ["loan_limit_boost", "advance_fee", "contact_funnel"]})
    assert _adjust(40, two) == base + 12


def test_official_brand_accounts_are_excluded_but_lookalikes_are_not(monkeypatch):
    def search(query, max_results):
        if "site:facebook.com" in query:
            return [{"title": "Increase your Fuliza limit. Hit admin inbox, guaranteed", "summary": "Fuliza limit",
                     "url": "https://www.facebook.com/SafaricomPLC/posts/1"},
                    {"title": "Increase your Fuliza limit. Hit admin inbox, guaranteed", "summary": "Fuliza limit",
                     "url": "https://www.facebook.com/SafaricomPLC.ke/posts/2"}]
        return []

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = {i.url.split("/")[3]: i for i in social_web_index("Fuliza limit", _fetcher(lambda r: httpx.Response(500)))}
    assert items["SafaricomPLC"].raw_meta["official_account"] and items["SafaricomPLC"].raw_meta["bait_signals"] == []
    assert not items["SafaricomPLC.ke"].raw_meta["official_account"] and items["SafaricomPLC.ke"].raw_meta["bait_signals"]
