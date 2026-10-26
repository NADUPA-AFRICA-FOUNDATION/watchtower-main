import asyncio
import gzip
import ipaddress
from pathlib import Path

import httpx
import pytest

from hunter.acquire import (
    KEEP_HEADERS, ContentAcquisitionProvider, NativeFetcher, Page, SiteCapture, decode_body,
)
from hunter.config import AcquisitionConfig
from watchtower.discovery.safe_fetch import SafeFetcher, UnsafeTarget

FIXTURE = (Path(__file__).parent / "fixtures" / "scam_page.html").read_text()
HTML = {"content-type": "text/html; charset=utf-8"}


def run(coro):
    return asyncio.run(coro)


async def resolver(host):
    """Like resolve_public's contract: names map to addresses, SafeFetcher rejects non-public ones."""
    if host in {"localhost"}:
        raise UnsafeTarget("localhost is not fetchable")
    if host == "nodns.example":
        raise UnsafeTarget("DNS resolution failed: NXDOMAIN")
    if host.startswith("internal"):
        return ["10.0.0.5"]
    try:
        ipaddress.ip_address(host)
        return [host]            # literals are returned as-is, so SafeFetcher must reject private ones
    except ValueError:
        return ["8.8.8.8"]


async def nosleep(_):
    return None


class Site:
    """Records every request; routes by (host, path) or path."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []

    async def __call__(self, request):
        self.requests.append((request.method, str(request.url)))
        route = self.routes.get((request.url.host, request.url.path)) or self.routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, text="nope", headers={"content-type": "text/html"})
        if callable(route):
            return await route(request)
        return route


def fetcher(site, **cfg):
    config = AcquisitionConfig(page_delay_seconds=0, **cfg)
    client = httpx.AsyncClient(transport=httpx.MockTransport(site))
    sf = SafeFetcher(client=client, resolver=resolver, max_bytes=config.max_bytes, keep_headers=KEEP_HEADERS)
    return NativeFetcher(sf, config, sleep=nosleep)


def page_resp(html=FIXTURE, **headers):
    return httpx.Response(200, text=html, headers={**HTML, **headers})


def landing(site, url="https://mpesa-fast.example/", **cfg):
    return run(fetcher(site, **cfg).fetch_page(url))


# -- parsing ---------------------------------------------------------------------------

def test_fixture_page_is_parsed_into_hunter_facts():
    site = Site({"/": page_resp(server="nginx/1.18", **{"x-powered-by": "PHP/8.1", "set-cookie": "sid=secret"})})
    p = landing(site)
    assert p.ok and p.analyzable and p.status == 200 and p.title == "M-PESA Fuliza Limit Upgrade"
    assert p.description == "Increase your Fuliza limit instantly"
    assert "Unlock your M-PESA account" in p.visible_text and p.favicon_url.endswith("/assets/icon.png")
    assert "https://wa.me/254712345678" in p.links and "https://t.me/mpesa_help" in p.links
    assert [i["type"] for i in p.forms[0]["inputs"]] == ["tel", "password", "number"]
    assert p.technology == {"server": "nginx/1.18", "powered_by": "PHP/8.1"}
    assert "set-cookie" not in p.headers                   # cookies are not collected
    assert len(p.body_sha256) == 64 and p.body_bytes == len(FIXTURE.encode())


def test_facts_hold_field_names_and_types_never_values():
    html = '<form action="/v" method="post"><input name="pin" type="password" value="1234"></form>'
    p = landing(Site({"/": page_resp(html)}))
    facts = p.facts()
    assert facts["forms"][0]["fields"][0] == {"name": "pin", "type": "password", "autocomplete": "", "placeholder": ""}
    assert "1234" not in str(facts)
    assert facts["js_rendering"] == "not_available"


def test_facts_are_deterministic_and_timestamp_free():
    a = landing(Site({"/": page_resp()})).facts()
    b = landing(Site({"/": page_resp()})).facts()
    assert a == b and "fetched_at" not in a


def test_generator_script_hosts_and_meta_refresh_are_recorded_not_followed():
    html = ('<meta name="generator" content="WordPress 6.4"><meta http-equiv="refresh" content="0; url=https://other-site.example/x">'
            '<script src="https://cdn.example/a.js"></script><p>hi</p>')
    site = Site({"/": page_resp(html)})
    p = landing(site)
    assert p.technology["generator"] == "WordPress 6.4" and p.technology["script_hosts"] == ["cdn.example"]
    assert p.meta_refresh == "https://other-site.example/x"
    assert all("other-site" not in u for _, u in site.requests)


def test_empty_javascript_shell_is_flagged_not_called_clean():
    p = landing(Site({"/": page_resp('<div id="root"></div><script src="/app.js"></script>')}))
    assert p.js_shell_suspected is True
    assert landing(Site({"/": page_resp(FIXTURE)})).js_shell_suspected is False


def test_charset_is_honoured():
    body = "<title>Kampuni ya Fedha é</title><p>Ongeza</p>".encode("latin-1")
    p = landing(Site({"/": httpx.Response(200, content=body, headers={"content-type": "text/html; charset=iso-8859-1"})}))
    assert p.title == "Kampuni ya Fedha é"
    assert decode_body(b'<meta charset="windows-1252">\x93hi\x94', "text/html") == '<meta charset="windows-1252">“hi”'
    assert decode_body(b"abc", "text/html; charset=nonsense-9") == "abc"


def test_malformed_and_binary_bodies_do_not_crash():
    for body in (b"<<<<>>>> <form <input", bytes(range(256)) * 50, b""):
        p = landing(Site({"/": httpx.Response(200, content=body, headers=HTML)}))
        assert p.status == 200 and (p.analyzable or p.error_kind == "parse_error")


def test_non_html_content_is_recorded_without_analysis():
    p = landing(Site({"/": httpx.Response(200, json={"a": 1}, headers={"content-type": "application/json"})}))
    assert p.ok and not p.analyzable and p.body_sha256


# -- safety ----------------------------------------------------------------------------

def test_redirect_chain_is_recorded_and_final_host_exposed():
    site = Site({("mpesa-fast.example", "/"): httpx.Response(302, headers={"location": "https://landing.example/go"}),
                 ("landing.example", "/go"): page_resp()})
    p = landing(site)
    assert p.ok and p.final_url == "https://landing.example/go" and p.final_host == "landing.example"
    assert p.redirect_chain == ["https://mpesa-fast.example/", "https://landing.example/go"]


@pytest.mark.parametrize("target", ["http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8080/",
                                    "http://[::1]/", "https://internal.example/x"])
def test_redirect_into_internal_space_is_blocked_and_recorded(target):
    site = Site({"/": httpx.Response(302, headers={"location": target})})
    p = landing(site)
    assert p.error_kind == "blocked" and "non-public" in p.error
    assert [u for _, u in site.requests] == ["https://mpesa-fast.example/robots.txt", "https://mpesa-fast.example/"]


def test_internal_and_unresolvable_targets_are_classified():
    assert landing(Site({}), "https://internal.example/").error_kind == "blocked"
    assert landing(Site({}), "https://nodns.example/").error_kind == "dns_failed"
    assert landing(Site({}), "http://localhost/").error_kind == "blocked"


def test_redirect_loop_and_limit():
    site = Site({"/": httpx.Response(302, headers={"location": "https://mpesa-fast.example/"})})
    p = landing(site)
    assert p.error_kind == "redirect_error" and "redirect limit" in p.error


def test_size_limit_declared_and_streamed():
    big = "x" * 300_000
    p = landing(Site({"/": page_resp(big)}), max_bytes=100_000)
    assert p.error_kind == "too_large"


def test_decompression_bomb_is_stopped_by_decoded_size():
    bomb = gzip.compress(b"0" * 20_000_000)
    assert len(bomb) < 100_000
    site = Site({"/": httpx.Response(200, content=bomb, headers={**HTML, "content-encoding": "gzip"})})
    assert landing(site, max_bytes=200_000).error_kind == "too_large"


@pytest.mark.parametrize("ctype", ["application/octet-stream", "application/vnd.android.package-archive",
                                   "application/x-msdownload", "application/zip"])
def test_dangerous_downloads_are_not_retrieved(ctype):
    p = landing(Site({"/": httpx.Response(200, content=b"MZ\x90", headers={"content-type": ctype})}))
    assert p.error_kind == "unsupported_content_type" and p.body_sha256 is None and not p.analyzable


def test_trickling_server_hits_the_wall_clock_deadline():
    async def slow(request):
        await asyncio.sleep(5)
    p = landing(Site({"/": slow}), total_timeout_seconds=0.2)
    assert p.error_kind == "timeout" and "0.2s" in p.error


def test_only_get_requests_are_ever_sent():
    html = '<form action="/x" method="post"><input name="pin" type="password"></form><a href="/login">l</a><a href="/verify">v</a>'
    site = Site({"/": page_resp(html), "/login": page_resp(html), "/verify": page_resp(html)})
    run(fetcher(site).capture("mpesa-fast.example"))
    assert site.requests and {m for m, _ in site.requests} == {"GET"}


def test_connection_failure_is_unreachable_not_a_clean_page():
    async def boom(request):
        raise httpx.ConnectError("refused")
    p = landing(Site({"/": boom}))
    assert p.error_kind == "unreachable" and not p.ok and p.body_sha256 is None


# -- robots ----------------------------------------------------------------------------

def robots(text="User-agent: *\nDisallow: /\n", status=200):
    return httpx.Response(status, text=text, headers={"content-type": "text/plain"})


def test_landing_ignores_robots_by_default_but_records_the_verdict():
    site = Site({"/robots.txt": robots(), "/": page_resp()})
    p = landing(site)
    assert p.ok and p.robots["verdict"] == "disallowed" and p.robots["enforced"] is False


def test_landing_obeys_robots_when_configured():
    site = Site({"/robots.txt": robots(), "/": page_resp()})
    p = landing(site, obey_robots_landing=True)
    assert p.error_kind == "robots_disallowed"
    assert not any(u == "https://mpesa-fast.example/" for _, u in site.requests)


def test_extra_pages_always_obey_robots():
    site = Site({"/robots.txt": robots("User-agent: *\nDisallow: /login\n"),
                 "/": page_resp('<a href="/login">l</a><a href="/verify">v</a>'),
                 "/login": page_resp("<p>secret</p>"), "/verify": page_resp("<p>ok</p>")})
    cap = run(fetcher(site).capture("mpesa-fast.example"))
    by_url = {p.requested_url: p for p in cap.pages}
    assert by_url["https://mpesa-fast.example/login"].error_kind == "robots_disallowed"
    assert by_url["https://mpesa-fast.example/verify"].ok
    assert not any(u.endswith("/login") for _, u in site.requests)


def test_robots_4xx_means_no_rules_and_5xx_stops_further_crawling():
    link = '<a href="/login">l</a>'
    ok = Site({"/robots.txt": robots(status=404), "/": page_resp(link), "/login": page_resp("<p>x</p>")})
    cap = run(fetcher(ok).capture("mpesa-fast.example"))
    assert len(cap.pages) == 2 and cap.pages[1].ok and cap.pages[0].robots["verdict"] == "allowed"
    sick = Site({"/robots.txt": robots(status=503), "/": page_resp(link), "/login": page_resp("<p>x</p>")})
    cap = run(fetcher(sick).capture("mpesa-fast.example"))
    assert cap.pages[0].ok and cap.pages[0].robots["verdict"] == "unreachable"   # landing still inspected
    assert cap.pages[1].error_kind == "robots_disallowed"
    assert not any(u.endswith("/login") for _, u in sick.requests)


def test_robots_is_fetched_once_per_origin_and_via_the_safe_fetcher():
    site = Site({"/robots.txt": robots("User-agent: *\nAllow: /\n"),
                 "/": page_resp('<a href="/a">a</a><a href="/b">b</a>'), "/a": page_resp("<p>a</p>"), "/b": page_resp("<p>b</p>")})
    run(fetcher(site).capture("mpesa-fast.example"))
    assert sum(u.endswith("/robots.txt") for _, u in site.requests) == 1


def test_hostile_robots_file_is_bounded():
    huge = "User-agent: *\n" + "Disallow: /x\n" * 400_000
    site = Site({"/robots.txt": robots(huge), "/": page_resp()})
    assert landing(site, max_bytes=300_000).ok


# -- capture ---------------------------------------------------------------------------

def test_https_failure_falls_back_to_http_and_keeps_the_failed_attempt():
    async def route(request):
        if request.url.scheme == "https":
            raise httpx.ConnectError("refused")
        return page_resp("<p>plain http site " + "x" * 300 + "</p>")
    site = Site({"/": route})
    cap = run(fetcher(site, max_pages_per_domain=1).capture("mpesa-fast.example"))
    assert cap.landing.ok and cap.landing.requested_url.startswith("http://")
    assert [a.error_kind for a in cap.attempts] == ["unreachable"] and "trying http" in cap.notes[0]


def test_capture_picks_priority_same_site_links_within_budget():
    html = ('<a href="/about">a</a><a href="/account/login">l</a><a href="/img/logo.png">i</a>'
            '<a href="https://evil-elsewhere.example/login">x</a><a href="/verify-otp">v</a><a href="/contact">c</a>'
            '<a href="https://wa.me/254700000000">w</a><a href="/">home</a>')
    routes = {"/": page_resp(html)} | {p: page_resp("<p>" + p + "</p>") for p in ("/about", "/account/login", "/verify-otp", "/contact")}
    site = Site(routes)
    cap = run(fetcher(site, max_pages_per_domain=3).capture("mpesa-fast.example"))
    assert [p.requested_url.split("example")[-1] for p in cap.pages] == ["/", "/verify-otp", "/account/login"]  # equal priority: shorter path first
    hosts = {u.split("/")[2] for _, u in site.requests}
    assert hosts == {"mpesa-fast.example"} and not any(u.endswith(".png") for _, u in site.requests)


def test_capture_without_extra_pages_when_budget_is_one_or_landing_failed():
    site = Site({"/": page_resp('<a href="/login">l</a>')})
    assert len(run(fetcher(site, max_pages_per_domain=1).capture("mpesa-fast.example")).pages) == 1
    dead = Site({"/": httpx.Response(200, content=b"MZ", headers={"content-type": "application/zip"})})
    assert len(run(fetcher(dead).capture("mpesa-fast.example")).pages) == 1


def test_page_delay_is_applied_between_pages():
    delays = []

    async def sleep(d):
        delays.append(d)
    site = Site({"/": page_resp('<a href="/login">l</a>'), "/login": page_resp("<p>x</p>")})
    f = fetcher(site)
    f._sleep, f.cfg.page_delay_seconds = sleep, 1.5
    run(f.capture("mpesa-fast.example"))
    assert delays == [1.5]


def test_provider_interface_can_be_implemented_by_another_backend():
    class Stub(ContentAcquisitionProvider):
        name = "stub"

        async def fetch_page(self, url, *, landing=True):
            return Page(url, url, 200, "text/html")

        async def map_domain(self, domain, landing, limit):
            return []

        def extract_links(self, page):
            return []

        async def capture(self, domain):
            return SiteCapture(domain, [await self.fetch_page(f"https://{domain}/")])
    cap = run(Stub().capture("x-example.com"))
    assert cap.landing.ok
    with pytest.raises(TypeError):
        ContentAcquisitionProvider()  # abstract


# -- content that cannot be assessed -----------------------------------------------------------------------

def test_blocked_and_challenge_pages_are_marked_unassessed_not_clean():
    blocked = httpx.Response(403, text="<html><body>Access Denied</body></html>", headers=HTML)
    p = landing(Site({"/": blocked}))
    assert p.ok and p.status == 403 and p.unassessed_reason.startswith("HTTP 403")
    cf = landing(Site({"/": page_resp("<title>Just a moment...</title><p>Checking your browser before accessing</p>")}))
    assert cf.unassessed_reason == "bot challenge"
    waf = landing(Site({"/": httpx.Response(403, text='<iframe src="/_Incapsula_Resource?x=1"></iframe>', headers=HTML)}))
    assert waf.unassessed_reason == "HTTP 403 (bot challenge)"


def test_normal_pages_and_real_content_that_mentions_captcha_are_assessed():
    assert landing(Site({"/": page_resp()})).unassessed_reason is None
    article = "<p>" + "A news story about how scammers defeat a captcha on bank sites. " * 20 + "</p>"
    assert landing(Site({"/": page_resp(article)})).unassessed_reason is None   # long real content is not a challenge


def test_js_shell_is_unassessed():
    p = landing(Site({"/": page_resp('<div id="root"></div><script src="/app.js"></script>')}))
    assert p.unassessed_reason == "JavaScript-rendered content not available"


def test_links_inside_a_block_page_are_not_crawled():
    site = Site({"/": httpx.Response(403, text='<a href="/_Incapsula_Resource?x=1">challenge</a><a href="/login">l</a>', headers=HTML),
                 "/login": page_resp("<p>x</p>"), "/_Incapsula_Resource": page_resp("<p>x</p>")})
    cap = run(fetcher(site).capture("mpesa-fast.example"))
    assert len(cap.pages) == 1 and cap.landing.unassessed_reason
    assert not any("/login" in u or "Incapsula" in u for _, u in site.requests)


def test_challenge_pages_are_never_bypassed():
    site = Site({"/": httpx.Response(403, text="<p>captcha</p>", headers=HTML)})
    run(fetcher(site).capture("mpesa-fast.example"))
    assert {m for m, _ in site.requests} == {"GET"} and sum(u.endswith("/") and "robots" not in u for _, u in site.requests) <= 2
