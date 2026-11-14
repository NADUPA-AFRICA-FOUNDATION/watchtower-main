"""Newly registered domains provider, offline from built archives."""
import asyncio
import base64
import io
import zipfile
from datetime import datetime, timezone

import httpx
import pytest

from hunter.config import ConfigError, load, parse
from hunter.ingest import run_discovery
from hunter.providers.nrd import NewlyRegisteredProvider
from hunter.store import HuntStore

NOW = datetime(2026, 11, 15, 9, 0, tzinfo=timezone.utc)
LIST = ["mpesa-verify-account.xyz", "safaricom-fuliza-boost.com", "bakery-nairobi.co.ke", "safaricom.co.ke",
        "m-pesa.co.ke.login-secure.top", "not a domain!", "gardening-tips.net"]


def zipped(names, member="domain-names.txt", extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, "\n".join(names) + "\n")
        if extra:
            zf.writestr(extra, "x")
    return buf.getvalue()


def day_of(request) -> str:
    token = request.url.path.split("/")[-2]
    return base64.b64decode(token).decode().removesuffix(".zip")


@pytest.fixture
def cfg():
    return load("hunter.yaml")


def provider(handler):
    return NewlyRegisteredProvider(httpx.AsyncClient(transport=httpx.MockTransport(handler)), clock=lambda: NOW)


def test_brand_like_names_become_candidates_and_the_rest_are_counted(cfg):
    calls = []

    def handler(request):
        calls.append(day_of(request))
        return httpx.Response(200, content=zipped(LIST))
    store = HuntStore(":memory:")
    p = provider(handler)
    summary = asyncio.run(run_discovery(store, p, cfg.brand(), cfg))
    assert summary.status == "operational"
    assert calls == ["2026-11-14", "2026-11-13", "2026-11-12"]                     # days_back: 3, newest first
    names = {c["canonical"] for c in store.list(limit=50)}
    assert {"mpesa-verify-account.xyz", "safaricom-fuliza-boost.com"} <= names
    assert "safaricom.co.ke" not in names and "bakery-nairobi.co.ke" not in names   # official, unrelated
    assert summary.noise_filtered >= 2
    # every day is marked done only after storing, so a second run downloads nothing
    calls.clear()
    again = asyncio.run(run_discovery(store, p, cfg.brand(), cfg))
    assert calls == [] and again.status == "operational" and "nothing new" in (again.detail or "")


def test_a_list_not_published_yet_is_not_an_error_but_a_failed_download_is(cfg):
    def handler(request):
        day = day_of(request)
        if day == "2026-11-14":
            return httpx.Response(404)
        if day == "2026-11-13":
            return httpx.Response(200, content=b"<html><body>not available</body></html>")
        return httpx.Response(503)
    store = HuntStore(":memory:")
    summary = asyncio.run(run_discovery(store, provider(handler), cfg.brand(), cfg))
    assert summary.status == "provider_error" and "HTTP 503" in (summary.error or "")
    assert "not published yet: 2026-11-14, 2026-11-13" in (summary.detail or "")
    assert store.get_state("newly_registered") == {}                                  # nothing marked done


def test_partial_when_some_days_fail(cfg):
    def handler(request):
        return httpx.Response(200, content=zipped(LIST)) if day_of(request) == "2026-11-14" else httpx.Response(500)
    store = HuntStore(":memory:")
    summary = asyncio.run(run_discovery(store, provider(handler), cfg.brand(), cfg))
    assert summary.status == "partial" and summary.created >= 2
    assert list(store.get_state("newly_registered").values()) == ["done"]


def test_hostile_archives_are_refused(cfg):
    for body in (zipped(LIST, extra="second.txt"), b"PK\x03\x04garbage-not-a-real-zip"):
        p = provider(lambda r, body=body: httpx.Response(200, content=body))
        result = asyncio.run(p.discover(cfg.brand(), cfg, {}))
        assert result.health.status == "provider_error" and result.candidates == []


def test_one_download_serves_every_brand(cfg):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, content=zipped(LIST))
    p = provider(handler)
    asyncio.run(p.discover(cfg.brand(), cfg, {}))
    asyncio.run(p.discover(cfg.brand(), cfg, {}))
    assert len(calls) == 3


def test_config_validates_and_coverage_lists_the_source(cfg):
    import yaml
    raw = yaml.safe_load(open("hunter.yaml"))
    raw["newly_registered"] = {"days_back": 0}
    with pytest.raises(ConfigError, match="newly_registered"):
        parse(raw)
    from hunter.coverage import source_coverage
    rows = {r["source"] for r in source_coverage(HuntStore(":memory:"), cfg)}
    assert "newly_registered" in rows


def test_buried_one_edit_matches_are_noise_but_misspellings_in_place_of_the_brand_are_not(cfg):
    from hunter.providers.nrd import strong_typo
    b = cfg.brand()
    for real in ("mpessa-verify.com", "rnpesa-login.top", "safaricorn.com", "mpeza-loans.com", "m-pesaa.online", "safarlcom-promo.net"):
        assert strong_typo(real, b), real
    # Every one of these came through on a real daily list before the rule was tightened.
    for noise in ("homies-app.com", "temperaturedelamer.fr", "mesaeoficio.com", "acessoriaempresa.com", "housemodernmesa.com",
                  "opesautomation.com", "apesarrat.fr", "mesa-festiva.com", "amber-mesa.online", "garnet-mesa.com",
                  "mr-mmesamoussa.com"):
        assert not strong_typo(noise, b), noise

    def handler(request):
        return httpx.Response(200, content=zipped(["homies-app.com", "temperaturedelamer.fr", "mpessa-verify.com",
                                                   "acessoriaempresa.com", "fuliza-boost.com"]))
    result = asyncio.run(provider(handler).discover(b, cfg, {}))
    assert {c.indicator for c in result.candidates} == {"mpessa-verify.com", "fuliza-boost.com"}


def test_the_fast_filter_never_drops_a_name_the_full_check_keeps(cfg):
    from hunter.prescore import plain, prescore, skeleton
    from hunter.providers.nrd import brand_pieces
    b = cfg.brand()
    pieces = brand_pieces(b)
    sample = ["mpesa-login.com", "rnpesa.top", "safaricorn.net", "fulizza-limit.xyz", "m-p3sa.site", "mshwarri.app",
              "vodacom-tz.online", "homies-app.com", "garden-tools.net", "empresa.com", "safari-tours.co.ke"]
    for name in sample:
        if prescore(name, b, cfg.prescore).has_brand_signal:
            assert any(p in plain(name) or p in skeleton(name) for p in pieces), name
